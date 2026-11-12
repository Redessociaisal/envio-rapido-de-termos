
'use strict';

const express = require('express');
const helmet = require('helmet');
const multer = require('multer');
const rateLimit = require('express-rate-limit');
const { google } = require('googleapis');
const { Readable } = require('stream');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.set('trust proxy', 1);
// Armazena temporariamente o token durante a configuração.
// O token não será salvo no GitHub nem exibido nos logs.
let pendingRefreshToken = null;
let pendingTokenExpiresAt = 0;
let pendingTokenNonce = null;
app.disable('x-powered-by');

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      formAction: ["'self'"]
    }
  }
}));

app.use(express.static(path.join(__dirname, 'public')));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024,
    files: 1,
    fields: 4,
    parts: 5
  }
});

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 12,
  standardHeaders: 'draft-7',
  legacyHeaders: false
});

function safe(s) {
  return String(s)
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-zA-Z0-9_-]+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 65);
}

function validDate(s) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
  const d = new Date(s + 'T12:00:00Z');
  return !isNaN(d.getTime()) &&
    d.toISOString().slice(0, 10) === s;
}

function oauthClient() {
  const id = process.env.GOOGLE_CLIENT_ID;
  const secret = process.env.GOOGLE_CLIENT_SECRET;
  const redirect = process.env.GOOGLE_REDIRECT_URI;

  if (!id || !secret || !redirect) {
    throw new Error('OAuth não configurado');
  }

  return new google.auth.OAuth2(id, secret, redirect);
}

function setupKey() {
  const key = process.env.ADMIN_SETUP_KEY;
  if (!key || key.length < 32) {
    throw new Error('ADMIN_SETUP_KEY não configurada');
  }
  return key;
}

function authorized(req) {
  const supplied = req.get('x-admin-key') || '';
  const expected = setupKey();

  const a = Buffer.from(supplied);
  const b = Buffer.from(expected);

  return a.length === b.length &&
    crypto.timingSafeEqual(a, b);
}

const setupLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: 'draft-7',
  legacyHeaders: false
});

// Gera uma URL de autorização.
// A chave deve ser enviada em um cabeçalho,
// nunca na URL.

app.get('/admin/autorizar', (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.type('html').send(`
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
      <meta charset="UTF-8">
      <title>Autorizar Google Drive</title>
    </head>
    <body>
      <h2>Autorizar Google Drive</h2>
      <p>Digite sua chave administrativa:</p>
      <input id="chave" type="password">
      <button id="autorizar">Autorizar</button>
      <button id="recuperar" type="button">Recuperar token</button>
      <p id="mensagem"></p>
      <script>
        document.getElementById('autorizar').onclick = async () => {
          const chave = document.getElementById('chave').value;
          const mensagem = document.getElementById('mensagem');
          try {
            const resposta = await fetch('/admin/oauth/start', {
              headers: { 'x-admin-key': chave }
            });
            if (!resposta.ok) throw new Error('Autorização recusada');
            const dados = await resposta.json();
            window.location.assign(dados.authorizationUrl);
          } catch (erro) {
            mensagem.textContent = 'Não foi possível iniciar a autorização.';
          }
        };

              document.getElementById('recuperar').onclick = async () => {
          const chave = document.getElementById('chave').value;
          const mensagem = document.getElementById('mensagem');

          try {
            const resposta = await fetch('/admin/oauth/token', {
              headers: { 'x-admin-key': chave },
              cache: 'no-store'
            });

            if (!resposta.ok) {
              throw new Error('Token indisponível ou acesso recusado.');
            }

            const dados = await resposta.json();

            await navigator.clipboard.writeText(dados.refresh_token);

            mensagem.textContent =
              'Token copiado! Cole-o no campo GOOGLE_REFRESH_TOKEN do Render.';
          } catch (erro) {
            mensagem.textContent =
              'Não foi possível recuperar ou copiar o token.';
          }
        };
        </script>
    </body>
    </html>
  `);
});

app.get('/admin/oauth/start', setupLimiter, (req, res) => {
  try {
    if (!authorized(req)) {
      return res.sendStatus(403);
      if (process.env.GOOGLE_REFRESH_TOKEN) {
  return res.status(403).json({
    error: 'O Google Drive já está configurado.'
  });
}
    }
if (pendingRefreshToken &&
    Date.now() < pendingTokenExpiresAt) {
  return res.status(409).json({
    error: 'Existe uma autorização aguardando recuperação.'
  });
}

    const state = crypto.randomBytes(24).toString('hex');
    res.cookie('oauth_setup_state', state, {
  httpOnly: true,
  secure: true,
  sameSite: 'lax',
  maxAge: 10 * 60 * 1000,
  path: '/'
});
    const client = oauthClient();

    // O estado é assinado e expira em 10 minutos.
    const expires = Date.now() + 10 * 60 * 1000;
    const payload = `${state}.${expires}`;
    const signature = crypto
      .createHmac('sha256', setupKey())
      .update(payload)
      .digest('hex');

    const url = client.generateAuthUrl({
      access_type: 'offline',
      prompt: 'consent',
      scope: [
        'https://www.googleapis.com/auth/drive.file'
      ],
      state: `${payload}.${signature}`
    });

    res.json({ authorizationUrl: url });
  } catch (err) {
    console.error('Erro OAuth:', err.message);
    res.status(500).json({
      error: 'Não foi possível iniciar a autorização.'
    });
  }
});

// Recebe a autorização do Google.
// Não publica tokens na página nem nos logs.
app.get('/oauth2callback', setupLimiter, async (req, res) => {
  try {
    const { code, state } = req.query;

    if (typeof code !== 'string' ||
        typeof state !== 'string') {
      return res.status(400).send('Autorização inválida.');
    }

    const parts = state.split('.');
    if (parts.length !== 3) {
      return res.status(400).send('Estado inválido.');
    }

    const [nonce, expiry, signature] = parts;
    const cookieState = (req.headers.cookie || '')
  .split(';')
  .map(item => item.trim())
  .find(item => item.startsWith('oauth_setup_state='))
  ?.slice('oauth_setup_state='.length);

if (!cookieState ||
    cookieState.length !== nonce.length ||
    !crypto.timingSafeEqual(
      Buffer.from(cookieState),
      Buffer.from(nonce)
    )) {
  return res.status(403).send(
    'Autorização não iniciada neste navegador.'
  );
}


    const payload = `${nonce}.${expiry}`;

    if (!/^[a-f0-9]{48}$/.test(nonce) ||
        !/^\d+$/.test(expiry) ||
        Date.now() > Number(expiry) ||
        !/^[a-f0-9]{64}$/.test(signature)) {
      return res.status(400).send('Estado expirado ou inválido.');
    }

    const expected = crypto
      .createHmac('sha256', setupKey())
      .update(payload)
      .digest();

    const actual = Buffer.from(signature, 'hex');

    if (!crypto.timingSafeEqual(expected, actual)) {
      return res.status(403).send('Estado não autorizado.');
    }

    const client = oauthClient();
    if (pendingRefreshToken &&
    Date.now() < pendingTokenExpiresAt) {
  return res.status(409).send(
    'Já existe uma autorização aguardando recuperação.'
  );
}
    const { tokens } = await client.getToken(code);

    if (!tokens.refresh_token) {
      return res.status(400).send(
        'O Google não forneceu uma autorização permanente.'
      );
    }

    // Não armazenamos tokens no disco temporário
    // nem os exibimos em uma página pública.
    // A configuração final requer armazenamento seguro.
    pendingRefreshToken = tokens.refresh_token;
    pendingTokenNonce = nonce;
pendingTokenExpiresAt = Date.now() + 5 * 60 * 1000;
    console.log('Autorização OAuth recebida.');

    return res.status(200).send(
      'Autorização recebida. ' +
      'É necessário concluir o armazenamento seguro do token.'
    );
  } catch (err) {
    console.error('Falha OAuth:', err.message);
    return res.status(500).send('Falha na autorização.');
  }
});
// Recupera o token somente com a chave administrativa.
app.get('/admin/oauth/token', setupLimiter, (req, res) => {
  res.set('Cache-Control', 'no-store');

  try {
    if (!authorized(req)) {
      return res.sendStatus(403);
    }
    if (process.env.GOOGLE_REFRESH_TOKEN) {
      return res.status(403).json({
        error: 'A configuração do Google Drive já foi concluída.'
      });
    }
    if (!pendingRefreshToken ||
        Date.now() > pendingTokenExpiresAt) {
      pendingRefreshToken = null;
      pendingTokenExpiresAt = 0;
pendingTokenNonce = null;
      return res.status(404).json({
        error: 'Token indisponível ou expirado.'
      });
    }
const cookieNonce = (req.headers.cookie || '')
  .split(';')
  .map(item => item.trim())
  .find(item => item.startsWith('oauth_setup_state='))
  ?.slice('oauth_setup_state='.length);

if (
  !pendingTokenNonce ||
  !cookieNonce ||
  cookieNonce.length !== pendingTokenNonce.length ||
  !crypto.timingSafeEqual(
    Buffer.from(cookieNonce),
    Buffer.from(pendingTokenNonce)
  )
) {
  return res.status(403).json({
    error: 'Autorização não corresponde a este navegador.'
  });
}
    const token = pendingRefreshToken;

    pendingRefreshToken = null;
    pendingTokenExpiresAt = 0;
pendingTokenNonce = null;

res.clearCookie('oauth_setup_state', {
  path: '/',
  secure: true,
  sameSite: 'lax',
  httpOnly: true
});
    return res.json({ refresh_token: token });
  } catch (err) {
    return res.status(500).json({
      error: 'Não foi possível recuperar o token.'
    });
  }
});
app.post(
  '/api/enviar',
  limiter,
  upload.single('arquivo'),
  async (req, res) => {
    try {
      const { nome, igreja, data, responsavel } = req.body;

      if (
        [nome, igreja, data, responsavel].some(
          x => typeof x !== 'string' ||
            !x.trim() || x.length > 180
        ) ||
        !validDate(data)
      ) {
        return res.status(400).json({
          error: 'Preencha corretamente todos os campos.'
        });
      }

      const file = req.file;

      if (!file) {
        return res.status(400).json({
          error: 'Selecione um arquivo PDF ou JPG.'
        });
      }

      const ext = (
        file.originalname.split('.').pop() || ''
      ).toLowerCase();

      const pdf =
        ext === 'pdf' &&
        file.mimetype === 'application/pdf' &&
        file.buffer.subarray(0, 5)
          .equals(Buffer.from('%PDF-'));

      const jpg =
        ['jpg', 'jpeg'].includes(ext) &&
        file.mimetype === 'image/jpeg' &&
        file.buffer[0] === 255 &&
        file.buffer[1] === 216 &&
        file.buffer[2] === 255;

      if (!pdf && !jpg) {
        return res.status(400).json({
          error: 'Formato inválido. Envie PDF ou JPG.'
        });
      }

      const folderId = process.env.DRIVE_FOLDER_ID;
      const refreshToken = process.env.GOOGLE_REFRESH_TOKEN;

      if (!folderId || !refreshToken) {
        throw new Error(
          'Google Drive ainda não está autorizado.'
        );
      }

      const auth = oauthClient();
      auth.setCredentials({
        refresh_token: refreshToken
      });

      const drive = google.drive({
        version: 'v3',
        auth
      });

      const name = [
        data,
        safe(nome),
        safe(igreja),
        crypto.randomUUID().slice(0, 8)
      ].join('_') + '.' + (pdf ? 'pdf' : 'jpg');

      const description =
        `Pessoa: ${nome}\n` +
        `Igreja: ${igreja}\n` +
        `Data: ${data}\n` +
        `Responsável: ${responsavel}\n` +
        `Nome original: ${file.originalname}`;

      const result = await drive.files.create({
        requestBody: {
          name,
          parents: [folderId],
          description
        },
        media: {
          mimeType: pdf
            ? 'application/pdf'
            : 'image/jpeg',
          body: Readable.from(file.buffer)
        },
        fields: 'id'
      });

      return res.json({
        nome,
        igreja,
        data,
        responsavel,
        arquivo: file.originalname,
        protocolo: result.data.id.slice(-12)
      });
    } catch (err) {
      console.error('Falha no upload:', err.message);
      return res.status(500).json({
        error: 'Não foi possível salvar o arquivo.'
      });
    }
  }
);

app.use((err, req, res, next) => {
  return res.status(
    err instanceof multer.MulterError ? 400 : 500
  ).json({
    error: err.code === 'LIMIT_FILE_SIZE'
      ? 'Arquivo acima de 10 MB.'
      : 'Não foi possível processar o envio.'
  });
});

app.listen(
  process.env.PORT || 3000,
  () => console.log('Servidor iniciado')
);
