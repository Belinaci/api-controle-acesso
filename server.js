import express from "express";
import cors from "cors";
import helmet from "helmet";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import https from "https";
import tls from "tls";

dotenv.config();

const app = express();

// ----------------------------------------------------------------------
// 🔧 MIDDLEWARES
// ----------------------------------------------------------------------
app.use(cors());
app.use(helmet());
app.use(express.json());

// Trust proxy (importante para Render)
app.set('trust proxy', 1);

/**
 * 🔐 Middleware de Autenticação JWT
 * Garante que apenas requisições com token válido prossigam.
 */
const requireAuthToken = (req, res, next) => {
  // Tenta extrair o token do cabeçalho "Authorization: Bearer <token>"
  const token = req.header("Authorization")?.replace("Bearer ", "");

  if (!token) {
    return res.status(401).json({ erro: "Token de autorização ausente" });
  }

  try {
    // Verifica se o token é válido usando o segredo de ambiente
    jwt.verify(token, process.env.TOKEN_SECRETO);
    next(); // Token válido, pode prosseguir
  } catch (err) {
    console.error("Erro ao verificar token:", err.message);
    return res.status(401).json({ erro: "Token inválido ou expirado" });
  }
};


// ----------------------------------------------------------------------
// 🔐 FUNÇÕES DE CERTIFICADO
// ----------------------------------------------------------------------

/**
 * Obtém o certificado SSL do próprio servidor usando TLS.
 */
async function obterCertificadoViaTLS() {
  const hostname = process.env.RENDER_EXTERNAL_URL 
    ? new URL(process.env.RENDER_EXTERNAL_URL).hostname 
    : 'localhost';

  return new Promise((resolve, reject) => {
    // Tenta conectar na porta 443 (HTTPS) para obter o certificado
    const socket = tls.connect(443, hostname, { 
      rejectUnauthorized: false, // Necessário para evitar falhas de self-signed localmente
      servername: hostname 
    }, () => {
      const cert = socket.getPeerCertificate(true);
      
      if (!cert || Object.keys(cert).length === 0) {
        socket.destroy();
        reject(new Error('Certificado não encontrado'));
        return;
      }

      // Converte o buffer RAW do certificado para o formato PEM (base64 com quebras de linha)
      const certPEM = '-----BEGIN CERTIFICATE-----\n' + 
                      cert.raw.toString('base64').match(/.{1,64}/g).join('\n') + 
                      '\n-----END CERTIFICATE-----';

      // Informações detalhadas
      const certInfo = {
        subject: cert.subject,
        issuer: cert.issuer,
        validFrom: cert.valid_from,
        validTo: cert.valid_to,
        daysRemaining: Math.floor((new Date(cert.valid_to) - new Date()) / (1000 * 60 * 60 * 24)),
        serialNumber: cert.serialNumber,
        fingerprint: cert.fingerprint,
        fingerprint256: cert.fingerprint256,
        subjectaltname: cert.subjectaltname,
        infoAccess: cert.infoAccess
      };

      socket.destroy();
      resolve({ pem: certPEM, info: certInfo });
    });

    socket.on('error', (err) => {
      reject(err);
    });
  });
}

// ----------------------------------------------------------------------
// 💚 Endpoint /health — Para manter o serviço ativo (PING/UPTIMEROBOT)
// ----------------------------------------------------------------------
app.get("/health", (req, res) => {
  // NÃO protegido pelo requireAuthToken. Deve ser acessível por serviços de terceiros.
  console.log(`💚 Health Check (Ping) recebido.`);
  res.status(200).json({ 
    status: "ok", 
    service: "smartlock-api",
    uptime_seconds: process.uptime(),
    timestamp: new Date().toISOString()
  });
});

// ----------------------------------------------------------------------
// ✅ Endpoint principal (PROTEGIDO) — valida permissão de abertura
// ----------------------------------------------------------------------
// Aplica o middleware requireAuthToken
app.get("/", requireAuthToken, (req, res) => {
  const lockId = req.header("X-Lock-ID");

  if (!lockId) {
    return res.status(400).json({ erro: "Header X-Lock-ID ausente" });
  }

  // A lógica de autorização agora só precisa checar o ID da fechadura, pois o token já é válido.
  if (lockId === process.env.LOCK_ID_PERMITIDO) {
    console.log(`🔓 Fechadura autorizada: ${lockId}`);
    return res.json({ 
      permitido: true, 
      timestamp: new Date().toISOString() 
    });
  } else {
    console.log(`🚫 Fechadura não reconhecida: ${lockId}`);
    return res.json({ permitido: false });
  }
});

// ----------------------------------------------------------------------
// 📜 Endpoint /cert (PROTEGIDO) — retorna o certificado em formato PEM
// ----------------------------------------------------------------------
// Aplica o middleware requireAuthToken
app.get("/cert", requireAuthToken, async (req, res) => {
  try {
    const { pem, info } = await obterCertificadoViaTLS();
    
    res.set("Content-Type", "application/x-pem-file");
    res.set("X-Cert-Expires", info.validTo);
    res.set("X-Cert-Days-Remaining", info.daysRemaining.toString());
    
    console.log(`📤 Certificado (protegido) enviado. Expira em ${info.daysRemaining} dias.`);
    res.send(pem);
    
  } catch (error) {
    console.error("Erro ao obter certificado:", error.message);
    res.status(500).json({ 
      erro: "Não foi possível obter o certificado",
      detalhes: error.message 
    });
  }
});

// ----------------------------------------------------------------------
// 📊 Endpoint /certinfo (PROTEGIDO) — retorna informações do certificado em JSON
// ----------------------------------------------------------------------
// Aplica o middleware requireAuthToken
app.get("/certinfo", requireAuthToken, async (req, res) => {
  try {
    const { pem, info } = await obterCertificadoViaTLS();
    
    // Adiciona o PEM ao retorno se solicitado
    const incluirPem = req.query.pem === 'true';
    
    const response = {
      info: info,
      pemIncluded: incluirPem,
      ...(incluirPem && { pem: pem })
    };
    
    console.log(`📊 Informações do certificado (protegidas) enviadas. Expira em ${info.daysRemaining} dias.`);
    res.json(response);
    
  } catch (error) {
    console.error("Erro ao obter informações do certificado:", error.message);
    res.status(500).json({ 
      erro: "Não foi possível obter informações do certificado",
      detalhes: error.message 
    });
  }
});

// ----------------------------------------------------------------------
// 🚀 Inicializa servidor HTTP
// ----------------------------------------------------------------------
const port = process.env.PORT || 3000;

app.listen(port, () => {
  console.log(`✅ API rodando na porta ${port}`);
  console.log(`🔒 HTTPS gerenciado automaticamente pelo Render`);
  console.log(`🌍 URL: ${process.env.RENDER_EXTERNAL_URL || 'http://localhost:' + port}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('👋 SIGTERM recebido, encerrando gracefully...');
  process.exit(0);
});