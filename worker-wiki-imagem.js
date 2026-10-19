/* ==========================================================================
   WIKI — ENVIO DE IMAGENS E DOCUMENTOS + SERVIR O SISTEMA (Worker do patrimonios-sedef)
   --------------------------------------------------------------------------
   Este arquivo É o Worker do projeto (entry point no wrangler.jsonc):
     · /api/imagens e /wiki-img/... → as imagens da Wiki (Workers KV grátis)
      · /api/anexos  e /wiki-doc/... → documentos anexados (PDF, Word, Excel, txt, zip — até 8 MB; MESMA KV, lista branca de extensões, nome original nos metadados)
     · todo o resto                 → os arquivos estáticos (index.html etc.)
                                       exatamente como sempre foram servidos

     navegador  →  Worker  POST /api/imagens   (confere a sessão do Firebase)
                       ↓   grava em KV (namespace wiki-imagens)
                  Worker  GET  /wiki-img/<nome>  →  a imagem na página

   O sistema é Spark (grátis) e o Cloud Storage do Firebase exige o plano
   pago — as imagens ficam na Workers KV: 1 GB grátis, 100.000 leituras/dia,
   1.000 gravações/dia, sem prazo de validade. Nenhum token, nenhuma conta
   nova: só o Cloudflare que já é usado.

   ============================ O QUE FAZER ==================================
   Feito em 16/10/2026: namespace KV "wiki-imagens" criado no painel
   (id eacf841d17714d96893a22488e4de632), já referenciado no wrangler.jsonc.

   Para publicar: subir ESTE arquivo + o wrangler.jsonc no repositório
   (ramo main). O Cloudflare compila sozinho — o build roda
   "npx wrangler deploy" e usa o wrangler.jsonc do repo (sem ele, o wrangler
   gerava um automático e o Worker ficava SÓ com arquivos estáticos, sem
   script — era o estado anterior).

   Teste: entrar no sistema → Wiki → Ctrl+V com um print → deve aparecer
   "Imagem enviada e inserida." e a imagem aparecer no texto.

   =========================== LIMITES DO SERVIÇO ============================
   · Grátis: 1 GB de espaço (milhares de prints), 1.000 gravações/dia,
     100.000 leituras/dia — a cota zera à meia-noite (UTC).
   · Imagem: limitada a 1 MB por arquivo (o navegador já reduz para
     1600 px / JPEG antes de enviar — na prática 100 a 400 KB por print).
   · Sem prazo de validade: nada expira, nada precisa ser renovado.
   · As imagens vivem na KV — se um dia alguém apagar a namespace
     wiki-imagens, elas vão junto (a Wiki em si não é afetada).
========================================================================== */

const PROJETO_FIREBASE = 'patrimonio-395c5';
const ORIGENS_OK = [
  'https://patrimonios-sedef.mauricioliberato.workers.dev',
  'http://localhost:8766'
];

/* ---- auxiliares de base64 ------------------------------------------------ */
function b64ParaBytes(txt) {
  let s = String(txt).replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4 !== 0) s += '=';       /* completa o padding, por via das dúvidas */
  const bin = atob(s);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
function b64ParaTexto(txt) {
  return new TextDecoder().decode(b64ParaBytes(txt));
}
/* A chave pública do Google vem como JWK (n e e, em base64url). O WebCrypto
   importa JWK direto — é o caminho canônico. Se algum ambiente não aceitar,
   montamos o SPKI DER na mão a partir do mesmo n/e (mesma chave, no formato
   que o importKey('spki') entende). ANTES isto mandava o certificado X.509
   INTEIRO para 'spki' — e o WebCrypto só quer a chave embutida nele: dava
   rejeição e um 500 "Worker threw exception" no envio com sessão válida. */
function tlv(tag, corpo) {
  const n = corpo.length;
  const comprimento = n < 128 ? [n] : (n < 256 ? [0x81, n] : [0x82, (n >> 8) & 0xff, n & 0xff]);
  return Uint8Array.from([tag].concat(comprimento, Array.from(corpo)));
}
async function chaveVerificadora(jwk) {
  const algoritmo = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
  try {
    return await crypto.subtle.importKey(
      'jwk', { kty: 'RSA', n: jwk.n, e: jwk.e, alg: 'RS256', ext: true },
      algoritmo, false, ['verify']);
  } catch (e) {
    /* SEQ{ SEQ{ OID rsaEncryption, NULL }, BIT STRING{ 0, SEQ{ INT n, INT e } } } */
    const inteiro = function(b64url) {
      let b = b64ParaBytes(b64url);
      let i = 0;
      while (i < b.length - 1 && b[i] === 0) i++;      /* remove zeros à esquerda */
      b = b.slice(i);
      if (b[0] & 0x80) b = Uint8Array.from([0].concat(Array.from(b)));  /* inteiro positivo */
      return tlv(0x02, b);
    };
    const rsa = tlv(0x30, Uint8Array.from(
      Array.from(inteiro(jwk.n)).concat(Array.from(inteiro(jwk.e)))));
    const oid = Uint8Array.from([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]);
    const algId = tlv(0x30, oid);          /* SEQ{ OID rsaEncryption, NULL } */
    const spki = tlv(0x30, Uint8Array.from(
      Array.from(algId).concat(Array.from(tlv(0x03, Uint8Array.from([0].concat(Array.from(rsa))))))));
    return await crypto.subtle.importKey('spki', spki, algoritmo, false, ['verify']);
  }
}

/* ---- quem é o usuário (token do Firebase, RS256) -------------------------
   Confere a ASSINATURA do token contra os certificados públicos do Google
   (não é só "ler" o token: sem isso qualquer pessoa forjaria uma sessão).
   Só aceita e-mail @sedef.pr.gov.br, igual ao login do sistema. */
let cacheCertificados = { em: 0, mapa: {} };

async function usuarioDoToken(request) {
  const autoriza = request.headers.get('Authorization') || '';
  if (autoriza.indexOf('Bearer ') !== 0) return null;
  const token = autoriza.slice(7);
  const partes = token.split('.');
  if (partes.length !== 3) return null;

  let cabecalho, corpo;
  try {
    cabecalho = JSON.parse(b64ParaTexto(partes[0]));
    corpo = JSON.parse(b64ParaTexto(partes[1]));
  } catch (e) { return null; }

  const agora = Math.floor(Date.now() / 1000);
  if (corpo.iss !== 'https://securetoken.google.com/' + PROJETO_FIREBASE) return null;
  if (corpo.aud !== PROJETO_FIREBASE) return null;
  if (!corpo.exp || corpo.exp <= agora) return null;      /* token vencido */
  if (!corpo.email || !/@sedef\.pr\.gov\.br$/i.test(corpo.email)) return null;

  /* chave pública do Google (procurada pelo "kid" do cabeçalho), 1 h de guarda.
     O endpoint JWK entrega a chave pronta em n/e — muito mais simples do que
     abrir o certificado X.509 e extrair a chave de dentro dele. */
  let jwk;
  try {
    if (!cacheCertificados.mapa[cabecalho.kid] || Date.now() - cacheCertificados.em > 3600e3) {
      const r = await fetch('https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com');
      if (!r.ok) return null;
      const dados = await r.json();
      const mapa = {};
      (dados.keys || []).forEach(function (k) { if (k.kid) mapa[k.kid] = k; });
      cacheCertificados = { em: Date.now(), mapa: mapa };
    }
    jwk = cacheCertificados.mapa[cabecalho.kid];
  } catch (e) {
    throw new Error('etapa=chave, causa: ' + (e && e.message ? e.message : e));
  }
  if (!jwk) return null;

  try {
    const chave = await chaveVerificadora(jwk);
    const assinaturaOk = await crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5', chave,
      b64ParaBytes(partes[2]),
      new TextEncoder().encode(partes[0] + '.' + partes[1]));
    return assinaturaOk ? corpo : null;
  } catch (e) {
    throw new Error('etapa=assinatura, causa: ' + (e && e.message ? e.message : e));
  }
}

/* ---- resposta JSON com CORS ---------------------------------------------- */
function respostaImagem(json, status, origem) {
  const headers = {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': origem || '*',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS'
  };
  /* 204 não pode ter corpo (daria TypeError e viraria 500) */
  if (status === 204) return new Response(null, { status: 204, headers: headers });
  return new Response(JSON.stringify(json), { status: status, headers: headers });
}

function tipoDaImagem(nome) {
  if (/\.png$/i.test(nome)) return 'image/png';
  if (/\.gif$/i.test(nome)) return 'image/gif';
  if (/\.webp$/i.test(nome)) return 'image/webp';
  return 'image/jpeg';
}

/* ---- anexos de documento (mesma KV, rota /api/anexos) ---------------------
   Só extensões de DOCUMENTO (nada de executável/script: .exe, .js, .html e
   companhia ficam de fora — o arquivo é servido de volta com o Content-Type
   gravado aqui, e um HTML servido da nossa origem teria acesso aos dados). */
const TIPOS_DOC = {
  pdf: 'application/pdf',
  doc: 'application/msword',
  docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  xls: 'application/vnd.ms-excel',
  xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  ppt: 'application/vnd.ms-powerpoint',
  pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  odt: 'application/vnd.oasis.opendocument.text',
  ods: 'application/vnd.oasis.opendocument.spreadsheet',
  odp: 'application/vnd.oasis.opendocument.presentation',
  rtf: 'application/rtf',
  txt: 'text/plain; charset=utf-8',
  csv: 'text/csv; charset=utf-8',
  zip: 'application/zip',
  rar: 'application/vnd.rar',
  '7z': 'application/x-7z-compressed'
};
/* Abrem na própria aba (dá para ler no navegador); o resto baixa. */
const DOC_NA_ABA = { pdf: 1, txt: 1, csv: 1, rtf: 1 };
/* nome do arquivo: ASCII imprimível, no máximo 80 — para o cabeçalho
   Content-Disposition não quebrar com acento ou aspa de Windows. */
function nomeAscii(txt, reserva) {
  const limpo = String(txt || '').replace(/[\\"]/g, '').replace(/[^\x20-\x7e]+/g, ' ').trim().slice(0, 80);
  return limpo || reserva;
}

/* ---- medidor de uso (auto-contagem na própria KV) -------------------------
   A Workers KV de conta grátis não expõe o espaço usado em API — então o
   próprio Worker contabiliza: cada gravação soma no registro `_uso`, e o
   endpoint GET /api/uso devolve os totais para o Painel do sistema. O
   pedido /api/uso?recalc=1 varre a namespace inteira (list + get por
   arquivo) e semeia a base — protegido a 1 varredura por hora, para a
   cota de leituras (100.000/dia) não ser gasta à toa. */
const CHAVE_USO = '_uso';
async function lerUso(env) {
  try {
    const v = await env.WIKI_IMAGENS.get(CHAVE_USO, 'json');
    if (v && typeof v === 'object') return v;
  } catch (e) { }
  return { imagens: { qtd: 0, bytes: 0 }, documentos: { qtd: 0, bytes: 0 }, enviosHoje: 0, dataEnvios: '' };
}
async function salvarUso(env, uso) {
  await env.WIKI_IMAGENS.put(CHAVE_USO, JSON.stringify(uso));
}
async function registrarEnvio(env, bytes, tipo) {
  /* O envio já está gravado: o medidor nunca pode derrubar a resposta. */
  try {
    const uso = await lerUso(env);
    const hoje = new Date().toISOString().slice(0, 10);
    if (uso.dataEnvios !== hoje) { uso.dataEnvios = hoje; uso.enviosHoje = 0; }
    uso[tipo] = uso[tipo] || { qtd: 0, bytes: 0 };
    uso[tipo].qtd++;
    uso[tipo].bytes += bytes;
    uso.enviosHoje = (uso.enviosHoje || 0) + 1;
    await salvarUso(env, uso);
  } catch (e) { }
}
/* GET /api/uso — quanto de espaço as imagens e os documentos ocupam */
async function rotaUso(request, env) {
  const headers = {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, OPTIONS'
  };
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers });
  if (!env || !env.WIKI_IMAGENS) {
    return new Response(JSON.stringify({ erro: 'Worker sem o binding WIKI_IMAGENS.' }), { status: 500, headers });
  }
  const url = new URL(request.url);
  let uso = await lerUso(env);
  if (url.searchParams.get('recalc') === '1') {
    const agora = Date.now();
    const jaVarreu = uso.recalcEm && (agora - uso.recalcEm) < 3600e3;
    if (!jaVarreu) {
      const imagens = { qtd: 0, bytes: 0 }, documentos = { qtd: 0, bytes: 0 };
      let cursor, total = 0;
      do {
        const pag = await env.WIKI_IMAGENS.list({ prefix: '', cursor: cursor });
        for (const par of (pag.keys || [])) {
          if (par.name === CHAVE_USO) continue;
          try {
            const buf = await env.WIKI_IMAGENS.get(par.name, 'arrayBuffer');
            const n = buf ? buf.byteLength : 0;
            total++;
            if (par.name.indexOf('wiki-doc-') === 0) { documentos.qtd++; documentos.bytes += n; }
            else { imagens.qtd++; imagens.bytes += n; }
          } catch (e) { }
        }
        cursor = pag.list_complete ? undefined : pag.cursor;
      } while (cursor && total < 20000);
      const hoje = new Date().toISOString().slice(0, 10);
      uso = {
        imagens: imagens, documentos: documentos,
        enviosHoje: uso.enviosHoje || 0, dataEnvios: uso.dataEnvios || hoje,
        recalculadoEm: new Date().toISOString(), recalcEm: agora
      };
      try { await salvarUso(env, uso); } catch (e) { }
    }
  }
  const resposta = {
    espacoTotal: 1073741824,          /* 1 GB — cota grátis da Workers KV */
    gravacoesDia: 1000,
    imagens: uso.imagens || { qtd: 0, bytes: 0 },
    documentos: uso.documentos || { qtd: 0, bytes: 0 },
    enviosHoje: uso.enviosHoje || 0,
    dataEnvios: uso.dataEnvios || '',
    recalculadoEm: uso.recalculadoEm || ''
  };
  resposta.total = {
    qtd: (resposta.imagens.qtd || 0) + (resposta.documentos.qtd || 0),
    bytes: (resposta.imagens.bytes || 0) + (resposta.documentos.bytes || 0)
  };
  return new Response(JSON.stringify(resposta), { headers: headers });
}

/* GET /api/build — qual é a marca do index.html servido HOJE.
   O navegador pode estar com uma aba aberta de dias (código antigo — caso
   real: conta inativada continuava entrando porque a regra nova não existia
   na página velha). O app lê a própria marca (meta nii-build), compara com
   esta e, se forem diferentes, recarrega ANTES de deixar logar. A marca é
   lida do asset a cada 60 s (isolamento quente); sem ela o app simplesmente
   não recarrega — nunca tranca o acesso. */
let _marcaCache = { id: '', em: 0 };
async function rotaBuild(request, env) {
  const headers = {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, OPTIONS'
  };
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: headers });
  try {
    if (!_marcaCache.id || (Date.now() - _marcaCache.em) > 60000) {
      const resp = await env.ASSETS.fetch(new URL('/index.html', request.url).toString());
      const html = await resp.text();
      const m = html.match(/<meta name="nii-build" content="([0-9A-Za-z._-]+)">/);
      _marcaCache = { id: (m ? m[1] : ''), em: Date.now() };
    }
    return new Response(JSON.stringify({ build: _marcaCache.id, agora: new Date().toISOString() }), { headers: headers });
  } catch (e) {
    return new Response(JSON.stringify({ erro: String((e && e.message) || e) }), { status: 500, headers: headers });
  }
}

/* ---- rota única: /api/imagens (enviar) e /wiki-img/... (servir) ---------- */
async function rotaImagemWiki(request, env) {
  const url = new URL(request.url);
  if (url.pathname.indexOf('/wiki-img/') === 0) return servirImagem(url, env);
  return enviarImagem(request, env);
}

/* GET /wiki-img/<nome> — devolve a imagem guardada */
async function servirImagem(url, env) {
  if (!env || !env.WIKI_IMAGENS) {
    return new Response('Worker sem o binding WIKI_IMAGENS.', { status: 500 });
  }
  const nome = decodeURIComponent(url.pathname.slice('/wiki-img/'.length));
  if (!/^[a-zA-Z0-9._-]{1,120}$/.test(nome)) {
    return new Response('Endereço inválido.', { status: 400 });
  }
  let bytes;
  try { bytes = await env.WIKI_IMAGENS.get(nome, 'arrayBuffer'); } catch (e) { bytes = null; }
  if (!bytes) return new Response('Imagem não encontrada.', { status: 404 });
  return new Response(bytes, {
    headers: {
      'Content-Type': tipoDaImagem(nome),
      /* nome é único e nunca muda: pode ficar no cache para sempre */
      'Cache-Control': 'public, max-age=31536000, immutable',
      'Access-Control-Allow-Origin': '*'
    }
  });
}

/* POST /api/imagens — guarda a imagem enviada pelo sistema */
async function enviarImagem(request, env) {
  const origem = request.headers.get('Origin') || '';
  if (origem && ORIGENS_OK.indexOf(origem) < 0) {
    return respostaImagem({ erro: 'Origem não autorizada.' }, 403, '*');
  }
  if (request.method === 'OPTIONS') return respostaImagem({}, 204, origem);

  const usuario = await usuarioDoToken(request);
  if (!usuario) {
    return respostaImagem({ erro: 'Sessão inválida: entre de novo no sistema.' }, 401, origem);
  }

  let corpo;
  try { corpo = await request.json(); } catch (e) {
    return respostaImagem({ erro: 'Pedido malformado.' }, 400, origem);
  }
  const dados = String((corpo && corpo.dados) || '');
  const extensao = String((corpo && corpo.extensao) || '').toLowerCase();
  if (!dados || !/^[a-z0-9]{1,5}$/.test(extensao)) {
    return respostaImagem({ erro: 'Imagem ausente.' }, 400, origem);
  }
  if (dados.length > 1300000) {                 /* ~1 MB por imagem */
    return respostaImagem({ erro: 'Imagem grande demais (máximo 1 MB).' }, 413, origem);
  }

  if (!env || !env.WIKI_IMAGENS) {
    return respostaImagem({ erro: 'Worker sem o binding WIKI_IMAGENS (wrangler.jsonc).' }, 500, origem);
  }

  const nome = 'wiki-' + Date.now() + '-' + Math.random().toString(36).slice(2, 7) + '.' + extensao;
  const bytes = b64ParaBytes(dados);
  try {
    await env.WIKI_IMAGENS.put(nome, bytes, {
      metadata: { por: usuario.email, em: new Date().toISOString() }
    });
  } catch (e) {
    return respostaImagem({
      erro: 'Não deu para guardar a imagem: ' + (e && e.message ? e.message : 'erro na KV') +
            ' (a cota grátis é de 1.000 imagens por dia, e zera à meia-noite).'
    }, 502, origem);
  }

  await registrarEnvio(env, bytes.length, 'imagens');
  return respostaImagem({
    url: new URL(request.url).origin + '/wiki-img/' + nome,
    nome: nome,
    por: usuario.email
  }, 200, origem);
}

/* ---- rota de documentos: /api/anexos (enviar) e /wiki-doc/... (servir) ---- */
async function rotaAnexoWiki(request, env) {
  const url = new URL(request.url);
  if (url.pathname.indexOf('/wiki-doc/') === 0) return servirDocumento(url, env);
  return enviarDocumento(request, env);
}

/* GET /wiki-doc/<nome> — devolve o documento guardado */
async function servirDocumento(url, env) {
  if (!env || !env.WIKI_IMAGENS) {
    return new Response('Worker sem o binding WIKI_IMAGENS.', { status: 500 });
  }
  const nome = decodeURIComponent(url.pathname.slice('/wiki-doc/'.length));
  if (!/^[a-zA-Z0-9._-]{1,120}$/.test(nome)) {
    return new Response('Endereço inválido.', { status: 400 });
  }
  let par = null;
  try { par = await env.WIKI_IMAGENS.getWithMetadata(nome, 'arrayBuffer'); } catch (e) { par = null; }
  const bytes = par && par.value;
  if (!bytes) return new Response('Documento não encontrado.', { status: 404 });
  const meta = (par && par.metadata) || {};
  const ext = (nome.split('.').pop() || '').toLowerCase();
  const tipo = TIPOS_DOC[ext] || 'application/octet-stream';
  const ascii = nomeAscii(meta.nome, nome);
  const disp = (DOC_NA_ABA[ext] ? 'inline' : 'attachment') +
    '; filename="' + ascii + '"' +
    '; filename*=UTF-8\'\'' + encodeURIComponent(meta.nome || ascii);
  return new Response(bytes, {
    headers: {
      'Content-Type': tipo,
      'Content-Disposition': disp,
      /* nome é único e nunca muda: pode ficar no cache para sempre */
      'Cache-Control': 'public, max-age=31536000, immutable',
      'Access-Control-Allow-Origin': '*'
    }
  });
}

/* POST /api/anexos — guarda o documento enviado pelo sistema (mesmo esquema
   da imagem: sessão do Firebase conferida pela ASSINATURA do token, e-mail
   @sedef.pr.gov.br, e tipos de arquivo na lista branca). */
async function enviarDocumento(request, env) {
  const origem = request.headers.get('Origin') || '';
  if (origem && ORIGENS_OK.indexOf(origem) < 0) {
    return respostaImagem({ erro: 'Origem não autorizada.' }, 403, '*');
  }
  if (request.method === 'OPTIONS') return respostaImagem({}, 204, origem);

  const usuario = await usuarioDoToken(request);
  if (!usuario) {
    return respostaImagem({ erro: 'Sessão inválida: entre de novo no sistema.' }, 401, origem);
  }

  let corpo;
  try { corpo = await request.json(); } catch (e) {
    return respostaImagem({ erro: 'Pedido malformado.' }, 400, origem);
  }
  const dados = String((corpo && corpo.dados) || '');
  const extensao = String((corpo && corpo.extensao) || '').toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 5);
  const nomeOriginal = String((corpo && corpo.nome) || '').slice(0, 120);
  if (!dados || !extensao) {
    return respostaImagem({ erro: 'Documento ausente.' }, 400, origem);
  }
  if (!TIPOS_DOC[extensao]) {
    return respostaImagem({ erro: 'Tipo de arquivo não permitido (.' + extensao + '). Permitidos: ' + Object.keys(TIPOS_DOC).join(', ') + '.' }, 415, origem);
  }
  if (dados.length > 11000000) {                  /* ~8 MB depois de decodificar */
    return respostaImagem({ erro: 'Documento grande demais (máximo 8 MB).' }, 413, origem);
  }

  if (!env || !env.WIKI_IMAGENS) {
    return respostaImagem({ erro: 'Worker sem o binding WIKI_IMAGENS (wrangler.jsonc).' }, 500, origem);
  }

  const nome = 'wiki-doc-' + Date.now() + '-' + Math.random().toString(36).slice(2, 7) + '.' + extensao;
  const bytes = b64ParaBytes(dados);
  try {
    await env.WIKI_IMAGENS.put(nome, bytes, {
      metadata: {
        por: usuario.email,
        em: new Date().toISOString(),
        nome: nomeOriginal || nome,
        tipo: TIPOS_DOC[extensao]
      }
    });
  } catch (e) {
    return respostaImagem({
      erro: 'Não deu para guardar o documento: ' + (e && e.message ? e.message : 'erro na KV') +
            ' (a cota grátis é de 1.000 gravações por dia, zera à meia-noite; 1 GB de espaço).'
    }, 502, origem);
  }

  await registrarEnvio(env, bytes.length, 'documentos');
  return respostaImagem({
    url: new URL(request.url).origin + '/wiki-doc/' + nome,
    nome: nomeOriginal || nome,
    por: usuario.email
  }, 200, origem);
}

/* ============================ O WORKER =====================================
   As rotas novas vêm PRIMEIRO; o resto continua sendo servido pela camada de
   arquivos estáticos (assets) — mesmo comportamento de sempre para o
   index.html e companhia. O try/catch devolve QUALQUER exceção como JSON
   legível (a página HTML padrão do Cloudflare esconde a causa — foi assim
   que um erro 500 demorou a ser caçado). */
export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      /* o "await" aqui não é decoração: SEM ele a rejeição do promise
         escapa do try/catch e o Cloudflare volta com a página HTML
         "Worker threw exception" (1101) em vez do nosso JSON. */
      if (url.pathname === '/api/imagens' || url.pathname.indexOf('/wiki-img/') === 0) {
        return await rotaImagemWiki(request, env);
      }
      if (url.pathname === '/api/anexos' || url.pathname.indexOf('/wiki-doc/') === 0) {
        return await rotaAnexoWiki(request, env);
      }
      if (url.pathname === '/api/uso') {
        return await rotaUso(request, env);
      }
      if (url.pathname === '/api/build') {
        return await rotaBuild(request, env);
      }
      /* qualquer outro endereço volta para os arquivos estáticos do projeto */
      return await env.ASSETS.fetch(request);
    } catch (e) {
      return new Response(JSON.stringify({
        erro: 'Erro interno no servidor de imagens: ' + (e && e.message ? e.message : String(e)),
        pista: String((e && e.stack) || '').slice(0, 300)
      }), {
        status: 500,
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'Access-Control-Allow-Origin': '*'
        }
      });
    }
  }
};
