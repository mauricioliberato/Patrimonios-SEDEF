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
/* `_lista` é o cache da listagem de arquivos (rotaArquivos) — por ser
   chave "_*", fica de fora tanto do recálculo de uso quanto da listagem. */
const CHAVE_LISTA = '_lista';
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
    /* e invalida a listagem de arquivos — ela deve mostrar o recém-enviado */
    try { await env.WIKI_IMAGENS.delete(CHAVE_LISTA); } catch (e2) { }
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
          if (par.name.charAt(0) === '_') continue;   /* _uso, _lista…: não são arquivos */
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

/* GET /api/arquivos — TODOS os prints e documentos guardados na wiki, com
   nome original, tamanho, quem enviou e quando (visto na wiki e no Painel).
   Exige a MESMA sessão dos envios (token Bearer conferido). A listagem
   nasce do list() da KV + metadados gravados no envio; o tamanho veio do
   metadata a partir de agora e arquivo antigo sem metadata é medido na
   leitura. O resultado fica 5 min em `_lista` (KV) — e é apagado a cada
   envio novo (registrarEnvio), para nunca mostrar lista velha. */
async function montarListaArquivos(env) {
  const arquivos = [];
  let cursor, total = 0;
  do {
    const pag = await env.WIKI_IMAGENS.list({ prefix: '', cursor: cursor });
    for (const par of (pag.keys || [])) {
      if (par.name.charAt(0) === '_') continue;           /* _uso, _lista… */
      if (par.name.indexOf('wiki-') !== 0) continue;
      const meta = par.metadata || {};
      let bytes = (typeof meta.tamanho === 'number') ? meta.tamanho : -1;
      if (bytes < 0) {                                    /* arquivo antigo: mede na hora */
        try {
          const buf = await env.WIKI_IMAGENS.get(par.name, 'arrayBuffer');
          bytes = buf ? buf.byteLength : 0;
        } catch (e) { bytes = 0; }
      }
      const ehDoc = par.name.indexOf('wiki-doc-') === 0;
      arquivos.push({
        chave: par.name,
        tipo: ehDoc ? 'documento' : 'imagem',
        nome: meta.nome || par.name,
        ext: (par.name.split('.').pop() || '').toLowerCase(),
        bytes: bytes,
        por: meta.por || '',
        em: meta.em || ''
      });
      total++;
    }
    cursor = pag.list_complete ? undefined : pag.cursor;
  } while (cursor && total < 20000);
  arquivos.sort(function (a, b) { return String(b.em).localeCompare(String(a.em)); });
  return arquivos;
}
async function rotaArquivos(request, env) {
  const origem = request.headers.get('Origin') || '';
  const headers = {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': origem || '*',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
  };
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: headers });
  if (request.method === 'POST') return rotaExcluirArquivo(request, env);
  if (!env || !env.WIKI_IMAGENS) {
    return new Response(JSON.stringify({ erro: 'Worker sem o binding WIKI_IMAGENS.' }), { status: 500, headers: headers });
  }
  let usuario = null;
  try { usuario = await usuarioDoToken(request); } catch (e) { usuario = null; }
  if (!usuario) {
    return new Response(JSON.stringify({ erro: 'Entre no sistema para ver os arquivos da wiki.' }), { status: 401, headers: headers });
  }
  try {
    let lista = null;
    try {
      const salvo = await env.WIKI_IMAGENS.get(CHAVE_LISTA, 'json');
      if (salvo && salvo.em && (Date.now() - salvo.em) < 300e3 && Array.isArray(salvo.arquivos)) lista = salvo.arquivos;
    } catch (e) { }
    if (!lista) {
      lista = await montarListaArquivos(env);
      try { await env.WIKI_IMAGENS.put(CHAVE_LISTA, JSON.stringify({ em: Date.now(), arquivos: lista })); } catch (e) { }
    }
    let imagens = 0, docs = 0, bytes = 0;
    lista.forEach(function (a) { if (a.tipo === 'imagem') imagens++; else docs++; bytes += (a.bytes || 0); });
    return new Response(JSON.stringify({
      arquivos: lista,
      total: { qtd: lista.length, bytes: bytes, imagens: imagens, documentos: docs },
      geradoEm: new Date().toISOString()
    }), { headers: headers });
  } catch (e) {
    return new Response(JSON.stringify({ erro: String((e && e.message) || e) }), { status: 500, headers: headers });
  }
}

/* POST /api/arquivos — exclui um arquivo (print ou documento) e libera o
   espaço de verdade: apaga da KV, BAIXA o contador de uso na hora (sem
   isso o cartão do Painel só voltaria ao lugar certo com ?recalc=1) e
   invalida a listagem em cache.

   Só ADMIN — conferido NO SERVIDOR, no próprio Firestore: o Worker lê
   sistema/admins com o MESMO token da requisição (as regras permitem a
   leitura a qualquer autenticado). O uid do admin principal vale sozinho,
   igual à regra do Firestore, para uma lista corrompida nunca trancar a
   limpeza. Se qualquer etapa falhar, NÃO exclui — fecha por padrão. */
const UID_ADMIN_PRINCIPAL = 'Go5FiE8ukfSTdBfs4F3Ik4Q2mQy2';
function listaDoCampo(campo) {
  /* formato REST do Firestore: fields.uids.arrayValue.values = [{stringValue}] */
  if (!campo || !campo.arrayValue || !Array.isArray(campo.arrayValue.values)) return [];
  return campo.arrayValue.values.map(function (v) { return v.stringValue || ''; }).filter(Boolean);
}
async function ehAdminFirestore(token, usuario) {
  const uid = usuario.user_id || usuario.sub || '';
  if (uid === UID_ADMIN_PRINCIPAL) return true;
  try {
    const r = await fetch('https://firestore.googleapis.com/v1/projects/' + PROJETO_FIREBASE +
      '/databases/(default)/documents/sistema/admins',
      { headers: { 'Authorization': 'Bearer ' + token } });
    if (!r.ok) return false;                 /* inclui 404: doc ainda não existe */
    const doc = await r.json();
    const f = (doc && doc.fields) || {};
    if (uid && listaDoCampo(f.uids).indexOf(uid) >= 0) return true;
    const email = String(usuario.email || '').toLowerCase();
    return !!(email && listaDoCampo(f.emails).indexOf(email) >= 0);
  } catch (e) { return false; }
}
async function rotaExcluirArquivo(request, env) {
  const origem = request.headers.get('Origin') || '';
  const headers = {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': origem || '*',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS'
  };
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: headers });
  if (!env || !env.WIKI_IMAGENS) {
    return new Response(JSON.stringify({ erro: 'Worker sem o binding WIKI_IMAGENS.' }), { status: 500, headers: headers });
  }
  const autoriza = request.headers.get('Authorization') || '';
  let usuario = null;
  try { usuario = await usuarioDoToken(request); } catch (e) { usuario = null; }
  if (!usuario) {
    return new Response(JSON.stringify({ erro: 'Sessão necessária: entre no sistema.' }), { status: 401, headers: headers });
  }
  if (!(await ehAdminFirestore(autoriza.slice(7), usuario))) {
    return new Response(JSON.stringify({ erro: 'Só um administrador pode excluir arquivos da wiki.' }), { status: 403, headers: headers });
  }
  let chave = '';
  try { const corpo = await request.json(); chave = String((corpo && corpo.chave) || ''); } catch (e) { }
  /* chave de ARQUIVO de verdade: prefixo wiki-, nada de `_uso`/`_lista` */
  if (!/^wiki-[A-Za-z0-9._-]{1,120}$/.test(chave)) {
    return new Response(JSON.stringify({ erro: 'Chave de arquivo inválida.' }), { status: 400, headers: headers });
  }
  let par = null;
  try { par = await env.WIKI_IMAGENS.getWithMetadata(chave, 'arrayBuffer'); } catch (e) { par = null; }
  const valor = par && par.value;
  if (!valor) {
    return new Response(JSON.stringify({ erro: 'Arquivo não encontrado — talvez já tenha sido excluído.' }), { status: 404, headers: headers });
  }
  const meta = par.metadata || {};
  const bytes = (typeof meta.tamanho === 'number') ? meta.tamanho : valor.byteLength;
  const ehDoc = chave.indexOf('wiki-doc-') === 0;
  await env.WIKI_IMAGENS.delete(chave);
  try {                                          /* contador de uso desce na hora (piso zero) */
    const uso = await lerUso(env);
    const grupo = ehDoc ? 'documentos' : 'imagens';
    uso[grupo] = uso[grupo] || { qtd: 0, bytes: 0 };
    uso[grupo].qtd = Math.max(0, (uso[grupo].qtd || 0) - 1);
    uso[grupo].bytes = Math.max(0, (uso[grupo].bytes || 0) - bytes);
    await salvarUso(env, uso);
  } catch (e) { }
  try { await env.WIKI_IMAGENS.delete(CHAVE_LISTA); } catch (e) { }   /* listagem nova */
  return new Response(JSON.stringify({
    ok: true, chave: chave, liberado: bytes, tipo: ehDoc ? 'documento' : 'imagem'
  }), { headers: headers });
}

/* ============== POST /api/trocar-senha — admin troca a senha de outro ==============
   O navegador NÃO pode: updatePassword só vale para o usuário que está
   logado. Quem pode é o backend autenticado como CONTA DE SERVIÇO do
   Firebase (permissão firebaseauth.users.update, papel Firebase
   Authentication Admin). A chave JSON entra como segredo
   FIREBASE_SERVICE_ACCOUNT no Worker (Cloudflare → Settings → Variables
   and Secrets) e NUNCA vai para o repositório.
   Sem o segredo, respondemos 501 sem-segredo e o app cai no link de
   redefinição (fluxo do código 73) — nada trava, só não troca sozinho.
   Ordem dos portões: segredo → sessão → admin → corpo → Firebase. A senha
   viaja só nesta chamada HTTPS e não é escrita em log nem em mensagem. */
function b64urlTexto(txt) {
  const enc = new TextEncoder().encode(txt);
  let s = '';
  for (let i = 0; i < enc.length; i++) s += String.fromCharCode(enc[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlBytes(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function pemPkcs8(pem) {
  /* chave de conta de serviço vem em PEM ("BEGIN PRIVATE KEY") → DER cru */
  const corpo = String(pem).replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  const bin = atob(corpo);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
async function tokenServico(conta) {
  /* JWT assinado RS256 com a chave privada da conta → troca por um
     access_token de 1 h no https://oauth2.googleapis.com/token
     (grant urn:ietf:params:oauth:grant-type:jwt-bearer). */
  const agora = Math.floor(Date.now() / 1000);
  const base = b64urlTexto(JSON.stringify({ alg: 'RS256', typ: 'JWT' })) + '.' +
    b64urlTexto(JSON.stringify({
      iss: conta.client_email,
      scope: 'https://www.googleapis.com/auth/cloud-platform',
      aud: 'https://oauth2.googleapis.com/token',
      iat: agora, exp: agora + 3600
    }));
  const chave = await crypto.subtle.importKey('pkcs8', pemPkcs8(conta.private_key).buffer,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', chave,
    new TextEncoder().encode(base));
  const assertion = base + '.' + b64urlBytes(new Uint8Array(sig));
  const r = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'grant_type=' + encodeURIComponent('urn:ietf:params:oauth:grant-type:jwt-bearer') +
      '&assertion=' + assertion
  });
  if (!r.ok) throw new Error('oauth ' + r.status);
  const j = await r.json();
  if (!j.access_token) throw new Error('oauth sem access_token');
  return j.access_token;
}
async function rotaTrocarSenha(request, env) {
  const origem = request.headers.get('Origin') || '';
  const headers = {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': origem || '*',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS'
  };
  const json = function (obj, status) {
    return new Response(JSON.stringify(obj), { status: status || 200, headers: headers });
  };
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: headers });
  if (request.method !== 'POST') return json({ ok: false, motivo: 'metodo' }, 405);
  const bruto = env && env.FIREBASE_SERVICE_ACCOUNT ? String(env.FIREBASE_SERVICE_ACCOUNT) : '';
  if (!bruto) return json({ ok: false, motivo: 'sem-segredo' }, 501);
  let conta = null;
  try { conta = JSON.parse(bruto); } catch (e) { conta = null; }
  if (!conta || !conta.client_email || !conta.private_key)
    return json({ ok: false, motivo: 'segredo-invalido' }, 501);
  const autoriza = request.headers.get('Authorization') || '';
  let usuario = null;
  try { usuario = await usuarioDoToken(request); } catch (e) { usuario = null; }
  if (!usuario) return json({ ok: false, motivo: 'sessao' }, 401);
  if (!(await ehAdminFirestore(autoriza.slice(7), usuario)))
    return json({ ok: false, motivo: 'admin' }, 403);
  let uid = '', senha = '';
  try {
    const corpo = await request.json();
    uid = String((corpo && corpo.uid) || '');
    senha = String((corpo && corpo.senha) || '');
  } catch (e) { }
  /* sem uid gravado no cadastro não dá para localizar a conta no Auth:
     o app cai no link de redefinição (resposta honesta, não erro) */
  if (!/^[A-Za-z0-9_-]{1,128}$/.test(uid)) return json({ ok: false, motivo: 'sem-uid' }, 400);
  if (!/^[^\s]{6,128}$/.test(senha)) return json({ ok: false, motivo: 'senha' }, 400);
  try {
    const tok = await tokenServico(conta);
    const r = await fetch('https://identitytoolkit.googleapis.com/v1/projects/' +
      PROJETO_FIREBASE + '/accounts:update', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + tok },
        body: JSON.stringify({ localId: uid, password: senha })
      });
    if (r.ok) return json({ ok: true, aplicada: true });
    const resp = await r.json().catch(function () { return null; });
    const msg = String((resp && resp.error && resp.error.message) || '');
    /* conta ainda não existe: o primeiro login cria com a senha do
       cadastro (ponte de migração) — avisa que já vale, sem link */
    if (msg.indexOf('USER_NOT_FOUND') >= 0) return json({ ok: true, aplicada: false, conta: false });
    return json({ ok: false, motivo: 'firebase', status: r.status, detalhe: msg.slice(0, 160) }, 502);
  } catch (e) {
    return json({ ok: false, motivo: 'firebase', detalhe: String((e && e.message) || e).slice(0, 160) }, 502);
  }
}

/* GET /api/backup-wiki — ZIP com TODOS os prints e documentos guardados.
   É o irmão do "⬇ Exportar backup" do menu: o JSON leva as seções do
   Firestore, este ZIP leva os BINÁRIOS da KV (que o JSON nunca alcança).
   Mesma sessão dos envios. O ZIP é montado na mão, sem compressão
   (STORED): o projeto não tem build nem bibliotecas, e deflate não
   valeria o trabalho — os arquivos são poucos e pequenos. Limites
   defensivos (1.000 arquivos ou 64 MB) mandam quem passar baixar pela
   lista, um a um. */
const TABELA_CRC = (function () {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    t[n] = c;
  }
  return t;
})();
function crc32(bytes) {
  let c = 0xFFFFFFFF;
  for (let i = 0; i < bytes.length; i++) c = TABELA_CRC[(c ^ bytes[i]) & 0xFF] ^ (c >>> 8);
  return (c ^ 0xFFFFFFFF) >>> 0;
}
function junta(lista) {
  let total = 0;
  for (let i = 0; i < lista.length; i++) total += lista[i].length;
  const saida = new Uint8Array(total);
  let off = 0;
  for (let i = 0; i < lista.length; i++) { saida.set(lista[i], off); off += lista[i].length; }
  return saida;
}
function dosDataHora(d) {
  const ano = Math.max(1980, d.getFullYear());
  const data = ((ano - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate();
  const hora = (d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1);
  return { data: data, hora: hora };
}
function montarZip(itens) {
  const encoder = new TextEncoder();
  const dh = dosDataHora(new Date());
  const corpo = [], central = [];
  let offset = 0;
  for (let i = 0; i < itens.length; i++) {
    const nomeB = encoder.encode(itens[i].nome);
    const bytes = itens[i].bytes;
    const crc = crc32(bytes), tam = bytes.length;
    /* header local (30 bytes) + nome */
    const local = new Uint8Array(30 + nomeB.length);
    const dv = new DataView(local.buffer);
    dv.setUint32(0, 0x04034b50, true);   /* assinatura "PK\x03\x04" */
    dv.setUint16(4, 20, true);           /* versão que criou */
    dv.setUint16(6, 0x0800, true);       /* flags: nomes em UTF-8 */
    dv.setUint16(8, 0, true);            /* método 0 = STORED (sem compactar) */
    dv.setUint16(10, dh.hora, true);
    dv.setUint16(12, dh.data, true);
    dv.setUint32(14, crc, true);
    dv.setUint32(18, tam, true);         /* tamanho já compactado */
    dv.setUint32(22, tam, true);         /* tamanho original */
    dv.setUint16(26, nomeB.length, true);
    dv.setUint16(28, 0, true);           /* extra */
    local.set(nomeB, 30);
    corpo.push(local, bytes);
    /* entrada do diretório central (46 bytes) + nome */
    const c = new Uint8Array(46 + nomeB.length);
    const cv = new DataView(c.buffer);
    cv.setUint32(0, 0x02014b50, true);   /* "PK\x01\x02" */
    cv.setUint16(4, 20, true);           /* versão por */
    cv.setUint16(6, 20, true);           /* versão mínimo */
    cv.setUint16(8, 0x0800, true);
    cv.setUint16(10, 0, true);           /* método */
    cv.setUint16(12, dh.hora, true);
    cv.setUint16(14, dh.data, true);
    cv.setUint32(16, crc, true);
    cv.setUint32(20, tam, true);
    cv.setUint32(24, tam, true);
    cv.setUint16(28, nomeB.length, true);
    cv.setUint16(30, 0, true);           /* extra */
    cv.setUint16(32, 0, true);           /* comentário */
    cv.setUint16(34, 0, true);           /* disco */
    cv.setUint16(36, 0, true);           /* atributos internos */
    cv.setUint32(38, 0, true);           /* atributos externos */
    cv.setUint32(42, offset, true);      /* offset do header local */
    c.set(nomeB, 46);
    central.push(c);
    offset += local.length + tam;
  }
  const dirCentral = junta(central);
  /* fim do diretório central (22 bytes) */
  const fim = new Uint8Array(22);
  const ev = new DataView(fim.buffer);
  ev.setUint32(0, 0x06054b50, true);     /* "PK\x05\x06" */
  ev.setUint16(4, 0, true);
  ev.setUint16(6, 0, true);
  ev.setUint16(8, itens.length, true);
  ev.setUint16(10, itens.length, true);
  ev.setUint32(12, dirCentral.length, true);
  ev.setUint32(16, offset, true);
  ev.setUint16(20, 0, true);
  return junta(corpo.concat([dirCentral, fim]));
}
function respostaZipErro(json, status, origem) {
  const headers = {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': origem || '*',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type',
    'Access-Control-Allow-Methods': 'GET, OPTIONS'
  };
  return new Response(JSON.stringify(json), { status: status, headers: headers });
}
async function rotaBackupWiki(request, env) {
  const origem = request.headers.get('Origin') || '';
  const headers = {
    'Content-Type': 'application/zip',
    'Access-Control-Allow-Origin': origem || '*',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type',
    'Access-Control-Allow-Methods': 'GET, OPTIONS'
  };
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: headers });
  if (!env || !env.WIKI_IMAGENS) {
    return respostaZipErro({ erro: 'Worker sem o binding WIKI_IMAGENS.' }, 500, origem);
  }
  let usuario = null;
  try { usuario = await usuarioDoToken(request); } catch (e) { usuario = null; }
  if (!usuario) {
    return respostaZipErro({ erro: 'Entre no sistema para baixar os arquivos da wiki.' }, 401, origem);
  }
  try {
    const lista = await montarListaArquivos(env);
    if (!lista.length) {
      return respostaZipErro({ erro: 'Não há nenhum arquivo guardado para baixar.' }, 404, origem);
    }
    if (lista.length > 1000) {
      return respostaZipErro({ erro: 'Backup com ' + lista.length + ' arquivos — baixe pela lista 📁, um a um.' }, 413, origem);
    }
    const itens = [];
    const usados = {};
    let total = 0;
    for (const a of lista) {
      let buf = null;
      try { buf = await env.WIKI_IMAGENS.get(a.chave, 'arrayBuffer'); } catch (e) { buf = null; }
      if (!buf) continue;
      total += buf.byteLength;
      if (total > 67108864) {                                /* 64 MB */
        return respostaZipErro({ erro: 'Backup passaria de 64 MB (' + fmtZip(total) + ') — baixe pela lista 📁, um a um.' }, 413, origem);
      }
      /* nome legível dentro do ZIP: o original, sem caracteres proibidos, e sem colisão */
      let nome = String(a.nome || a.chave).replace(/[\\/:*?"<>|]/g, '_').slice(0, 120);
      if (!nome) nome = a.chave;
      let final = nome, k = 2;
      while (usados[final]) {
        const ponto = nome.lastIndexOf('.');
        final = (ponto > 0) ? nome.slice(0, ponto) + ' (' + k + ')' + nome.slice(ponto) : nome + ' (' + k + ')';
        k++;
      }
      usados[final] = 1;
      itens.push({ nome: final, bytes: new Uint8Array(buf) });
    }
    if (!itens.length) {
      return respostaZipErro({ erro: 'Não deu para ler nenhum arquivo para o backup.' }, 500, origem);
    }
    const zip = montarZip(itens);
    const hoje = new Date().toISOString().slice(0, 10).replace(/-/g, '');
    headers['Content-Disposition'] = 'attachment; filename="backup-wiki-' + hoje + '.zip"';
    return new Response(zip, { headers: headers });
  } catch (e) {
    return respostaZipErro({ erro: String((e && e.message) || e) }, 500, origem);
  }
}
function fmtZip(bytes) {
  return (bytes >= 1048576) ? (Math.round(bytes / 104857.6) / 10) + ' MB' : Math.ceil(bytes / 1024) + ' KB';
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
      metadata: { por: usuario.email, em: new Date().toISOString(), tamanho: bytes.length }
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
        tipo: TIPOS_DOC[extensao],
        tamanho: bytes.length
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
      if (url.pathname === '/api/arquivos') {
        return await rotaArquivos(request, env);
      }
      if (url.pathname === '/api/backup-wiki') {
        return await rotaBackupWiki(request, env);
      }
      if (url.pathname === '/api/trocar-senha') {
        return await rotaTrocarSenha(request, env);
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
