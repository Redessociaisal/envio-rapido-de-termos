'use strict';
const express = require('express');
const helmet = require('helmet');
const multer = require('multer');
const rateLimit = require('express-rate-limit');
const {google} = require('googleapis');
const {Readable} = require('stream');
const crypto = require('crypto');
const path = require('path');
const app = express();
app.disable('x-powered-by');
app.use(helmet({contentSecurityPolicy:{directives:{defaultSrc:["'self'"],scriptSrc:["'self'","'unsafe-inline'"],styleSrc:["'self'","'unsafe-inline'"],imgSrc:["'self'","data:"],formAction:["'self'"]}}}));
app.use(express.static(path.join(__dirname, 'public')));
const upload = multer({storage:multer.memoryStorage(),limits:{fileSize:10*1024*1024,files:1,fields:4,parts:5}});
const limiter = rateLimit({windowMs:15*60*1000,limit:12,standardHeaders:'draft-7',legacyHeaders:false});
function safe(s){return String(s).normalize('NFD').replace(/[\u0300-\u036f]/g,'').replace(/[^a-zA-Z0-9_-]+/g,'-').replace(/^-|-$/g,'').slice(0,65)}
function validDate(s){if(!/^\d{4}-\d{2}-\d{2}$/.test(s))return false;const d=new Date(s+'T12:00:00Z');return !isNaN(d.getTime())&&d.toISOString().slice(0,10)===s}
function credentials(){if(!process.env.GOOGLE_SERVICE_ACCOUNT_JSON)throw new Error('Credenciais do Drive não configuradas');return JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON)}
app.post('/api/enviar',limiter,(req,res,next)=>upload.single('arquivo')(req,res,next),async(req,res)=>{
  try{
    const {nome,igreja,data,responsavel}=req.body;
    if([nome,igreja,data,responsavel].some(x=>typeof x!=='string'||!x.trim()||x.length>180)||!validDate(data))return res.status(400).json({error:'Preencha corretamente todos os campos.'});
    const file=req.file;
    if(!file)return res.status(400).json({error:'Selecione um arquivo PDF ou JPG.'});
    const ext=(file.originalname.split('.').pop()||'').toLowerCase();
    const pdf=ext==='pdf'&&file.mimetype==='application/pdf'&&file.buffer.subarray(0,5).equals(Buffer.from('%PDF-'));
    const jpg=['jpg','jpeg'].includes(ext)&&file.mimetype==='image/jpeg'&&file.buffer[0]===255&&file.buffer[1]===216&&file.buffer[2]===255;
    if(!pdf&&!jpg)return res.status(400).json({error:'Formato inválido. Envie PDF ou JPG.'});
    const folderId=process.env.DRIVE_FOLDER_ID;
    if(!folderId)throw new Error('Pasta do Drive não configurada');
    const auth=new google.auth.GoogleAuth({credentials:credentials(),scopes:['https://www.googleapis.com/auth/drive']});
    const drive=google.drive({version:'v3',auth});
    const name=[data,safe(nome),safe(igreja),crypto.randomUUID().slice(0,8)].join('_')+'.'+(pdf?'pdf':'jpg');
    const description=`Pessoa: ${nome}\nIgreja: ${igreja}\nData: ${data}\nResponsável: ${responsavel}\nNome original: ${file.originalname}`;
    const result=await drive.files.create({requestBody:{name,parents:[folderId],description},media:{mimeType:pdf?'application/pdf':'image/jpeg',body:Readable.from(file.buffer)},fields:'id',supportsAllDrives:true});
    return res.json({nome,igreja,data,responsavel,arquivo:file.originalname,protocolo:result.data.id.slice(-12)});
  }catch(err){console.error('Falha no upload:',err.message);return res.status(500).json({error:'Não foi possível salvar o arquivo. Contate o administrador.'})}
});
app.use((err,req,res,next)=>res.status(err instanceof multer.MulterError?400:500).json({error:err.code==='LIMIT_FILE_SIZE'?'Arquivo acima de 10 MB.':'Não foi possível processar o envio.'}));
app.listen(process.env.PORT||3000,()=>console.log('Servidor iniciado'));
