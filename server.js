
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
app.disable('x-powered-by');
app.set('trust proxy', 1);

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

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: 'draft-7',
  legacyHeaders: false
});

const BASE_URL = 'https://envio-rapido-de-termos.onrender.com';
const REDIRECT_URI = BASE_URL + '/oauth2callback';
const SCOPES = ['https://www.googleapis.com/auth/drive.file'];

function oauthClient() {
  return new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    REDIRECT_URI
  );
}

function safe(s) {
  return String(s).normalize('NFD')
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

function adminAuthorized(req) {
  const configured = process.env.ADMIN_SETUP_KEY;
  const supplied = req.query.key;

  if (!configured || typeof supplied !== 'string') return false;

  const a = Buffer.from(configured);
  const b = Buffer.from(supplied);

  return a.length === b.length &&
    crypto.timingSafeEqual(a, b);
}

app.get('/admin/autorizar', authLimiter, (req, res) => {
  if (!adminAuthorized(req)) {
    return res.status(403).send('Acesso negado.');
  }

  const state = crypto.randomBytes(24).toString('hex');
  const stateHash = crypto.createHash('sha256')
    .update(state).digest('hex');

  const signature = crypto.createHmac(
    'sha256',
    process.env.ADMIN_SETUP_KEY
  ).update(state).digest('hex');

  res.cookie('oauth_state', stateHash, {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    maxAge: 600000
  });

  const url = oauthClient().generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent',
    scope: SCOPES,
    state: state + '.' + signature
  });

  res.redirect(url);
});

app.get('/oauth2callback', authLimiter, async (req, res) => {
  try {
    const state = req.query.state;
    const code = req.query.code;

    if (typeof state !== 'string' ||
        typeof code !== 'string' ||
        !req.headers.cookie) {
      return res.status(403).send('Autorização inválida.');
    }

    const [nonce, signature] = state.split('.');
    const expected = crypto.createHmac(
      'sha256',
      process.env.ADMIN_SETUP_KEY
    ).update(nonce || '').digest('hex');

    const a = Buffer.from(signature || '');
    const b = Buffer.from(expected);

    if (a.length !== b.length ||
        !crypto.timingSafeEqual(a, b)) {
      return res.status(403).send('Estado inválido.');
    }

    const cookie = req.headers.cookie.split(';')
      .map(x => x.trim())
      .find(x => x.startsWith('oauth_state='));

    const saved = cookie ? cookie.slice(12) : '';
    const actual = crypto.createHash('sha256')
      .update(nonce).digest('hex');

    if (saved !== actual) {
      return res.status(403).send('Sessão inválida.');
    }

    res.clearCookie('oauth_state');

    const { tokens } = await oauthClient().getToken(code);

    if (!tokens.refresh_token) {
      return res.status(400).send(
        'Token de atualização não recebido.'
      );
    }

    // Nunca mostrar o refresh token em uma página pública.
    // A configuração definitiva será feita pelo administrador.
    console.log('OAuth autorizado; token recebido.');

    return res.send(
      'Autorização recebida. A configuração do token ' +
      'no servidor ainda precisa ser concluída.'
    );
  } catch (err) {
    console.error('Erro OAuth:', err.message);
    return res.status(500).send('Falha na autorização.');
  }
});

app.post('/api/enviar', limiter,
  (req, res, next) => upload.single('arquivo')(req, res, next),
  async (req, res) => {
    try {
      const { nome, igreja, data, responsavel } = req.body;

      if ([nome, igreja, data, responsavel].some(
        x => typeof x !== 'string' ||
          !x.trim() || x.length > 180
      ) || !validDate(data)) {
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

      const ext = (file.originalname.split('.').pop() || '')
        .toLowerCase();

      const pdf = ext === 'pdf' &&
        file.mimetype === 'application/pdf' &&
        file.buffer.subarray(0, 5)
          .equals(Buffer.from('%PDF-'));

      const jpg = ['jpg', 'jpeg'].includes(ext) &&
        file.mimetype === 'image/jpeg' &&
        file.buffer[0] === 255 &&
        file.buffer[1] === 216 &&
        file.buffer[2] === 255;

      if (!pdf && !jpg) {
        return res.status(400).json({
          error: 'Formato inválido. Envie PDF ou JPG.'
        });
      }

      if (!process.env.GOOGLE_REFRESH_TOKEN ||
          !process.env.DRIVE_FOLDER_ID) {
        return res.status(503).json({
          error: 'Integração com Google Drive ainda não configurada.'
        });
      }

      const auth = oauthClient();
      auth.setCredentials({
        refresh_token: process.env.GOOGLE_REFRESH_TOKEN
      });

      const drive = google.drive({ version: 'v3', auth });

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
          parents: [process.env.DRIVE_FOLDER_ID],
          description
        },
        media: {
          mimeType: pdf ? 'application/pdf' : 'image/jpeg',
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
  res.status(err instanceof multer.MulterError ? 400 : 500)
    .json({
      error: err.code === 'LIMIT_FILE_SIZE'
        ? 'Arquivo acima de 10 MB.'
        : 'Não foi possível processar o envio.'
    });
});

app.listen(process.env.PORT || 3000, () => {
  console.log('Servidor iniciado');
});
