/* ==========================================================================
   WIKI — ENVIO DE IMAGENS + SERVIR O SISTEMA (Worker do patrimonios-sedef)
   --------------------------------------------------------------------------
   Este arquivo É o Worker do projeto (entry point no wrangler.jsonc):
     · /api/imagens e /wiki-img/... → as imagens da Wiki (Workers KV grátis)
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
  try {
    await env.WIKI_IMAGENS.put(nome, b64ParaBytes(dados), {
      metadata: { por: usuario.email, em: new Date().toISOString() }
    });
  } catch (e) {
    return respostaImagem({
      erro: 'Não deu para guardar a imagem: ' + (e && e.message ? e.message : 'erro na KV') +
            ' (a cota grátis é de 1.000 imagens por dia, e zera à meia-noite).'
    }, 502, origem);
  }

  return respostaImagem({
    url: new URL(request.url).origin + '/wiki-img/' + nome,
    nome: nome,
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
