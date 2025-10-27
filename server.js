import fs from "fs";
import https from "https";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import jwt from "jsonwebtoken";
import forge from "node-forge";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(cors());
app.use(helmet());
app.use(express.json());

// ----------------------------------------------------------------------
// 🔐 CONFIGURAÇÕES DE CERTIFICADO (gerenciado automaticamente)
// ----------------------------------------------------------------------
const CERT_PATH = "./certs/fullchain.pem";
const KEY_PATH = "./certs/privkey.pem";

if (!fs.existsSync(CERT_PATH) || !fs.existsSync(KEY_PATH)) {
  console.error("❌ Certificado SSL não encontrado. Gere usando Let's Encrypt (certbot).");
  process.exit(1);
}

const sslOptions = {
  cert: fs.readFileSync(CERT_PATH),
  key: fs.readFileSync(KEY_PATH)
};

// ----------------------------------------------------------------------
// 🔍 Função utilitária — Lê validade do certificado e informa se expira logo
// ----------------------------------------------------------------------
function diasParaExpirar(certPem) {
  try {
    const cert = forge.pki.certificateFromPem(certPem);
    const expira = cert.validity.notAfter;
    const diff = (expira - new Date()) / (1000 * 60 * 60 * 24);
    return Math.floor(diff);
  } catch (err) {
    console.error("Erro ao ler validade do certificado:", err);
    return 0;
  }
}

// ----------------------------------------------------------------------
// ✅ Endpoint principal — valida permissão de abertura
// ----------------------------------------------------------------------
app.get("/", (req, res) => {
  const token = req.header("Authorization")?.replace("Bearer ", "");
  const lockId = req.header("X-Lock-ID");

  if (!token || !lockId) {
    return res.status(400).json({ erro: "Headers ausentes" });
  }

  try {
    const decoded = jwt.verify(token, process.env.TOKEN_SECRETO);
    if (lockId === process.env.LOCK_ID_PERMITIDO) {
      console.log(`🔓 Fechadura autorizada: ${lockId}`);
      return res.json({ permitido: true });
    } else {
      console.log(`🚫 Fechadura não reconhecida: ${lockId}`);
      return res.json({ permitido: false });
    }
  } catch {
    return res.status(401).json({ erro: "Token inválido" });
  }
});

// ----------------------------------------------------------------------
// 📜 Endpoint /cert — retorna o PEM atual (para o ESP baixar)
// ----------------------------------------------------------------------
app.get("/cert", (req, res) => {
  const cert = fs.readFileSync(CERT_PATH, "utf8");
  const dias = diasParaExpirar(cert);

  res.set("Content-Type", "text/plain");
  res.send(cert);

  console.log(`📤 Certificado enviado. Expira em ${dias} dias.`);
});

// ----------------------------------------------------------------------
// 🚀 Inicializa servidor HTTPS
// ----------------------------------------------------------------------
const port = process.env.PORT || 443;

https.createServer(sslOptions, app).listen(port, () => {
  console.log(`✅ API HTTPS rodando na porta ${port}`);
});
