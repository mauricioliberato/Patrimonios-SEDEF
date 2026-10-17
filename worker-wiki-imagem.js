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
  const s = String(txt).replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(s);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
function b64ParaTexto(txt) {
  return new TextDecoder().decode(b64ParaBytes(txt));
}
function pemParaDer(pem) {
  const b64 = String(pem)
    .replace(/-----BEGIN CERTIFICATE-----/g, '')
    .replace(/-----END CERTIFICATE-----/g, '')
    .replace(/\s+/g, '');
  return b64ParaBytes(b64);               /* o corpo do PEM é base64 comum */
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

  /* certificados do Google (procurados pelo "kid" do cabeçalho), 1 h de guarda */
  if (!cacheCertificados.mapa[cabecalho.kid] || Date.now() - cacheCertificados.em > 3600e3) {
    const r = await fetch('https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com');
    if (!r.ok) return null;
    cacheCertificados = { em: Date.now(), mapa: await r.json() };
  }
  const pem = cacheCertificados.mapa[cabecalho.kid];
  if (!pem) return null;

  const chave = await crypto.subtle.importKey(
    'spki', pemParaDer(pem),
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false, ['verify']);
  const assinaturaOk = await crypto.subtle.verify(
    'RSASSA-PKCS1-v1_5', chave,
    b64ParaBytes(partes[2]),
    new TextEncoder().encode(partes[0] + '.' + partes[1]));
  return assinaturaOk ? corpo : null;
}

/* ---- resposta JSON com CORS ---------------------------------------------- */
function respostaImagem(json, status, origem) {
  return new Response(JSON.stringify(json), {
    status: status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Access-Control-Allow-Origin': origem || '*',
      'Access-Control-Allow-Headers': 'Authorization, Content-Type',
      'Access-Control-Allow-Methods': 'POST, OPTIONS'
    }
  });
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
   index.html e companhia. */
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/api/imagens' || url.pathname.indexOf('/wiki-img/') === 0) {
      return rotaImagemWiki(request, env);
    }
    /* qualquer outro endereço volta para os arquivos estáticos do projeto */
    return env.ASSETS.fetch(request);
  }
};
