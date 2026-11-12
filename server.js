
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
    parts: 10
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
  console.error('ERRO DETALHADO NO ENVIO:', err);
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
