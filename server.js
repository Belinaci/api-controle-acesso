import express from "express";
import cors from "cors";
import helmet from "helmet";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import crypto from "crypto";

dotenv.config();

const app = express();

// ----------------------------------------------------------------------
// 🔧 MIDDLEWARES
// ----------------------------------------------------------------------
app.use(cors());
app.use(helmet());
app.use(express.json());

// ----------------------------------------------------------------------
// 🔐 Middleware de autenticação JWT
// ----------------------------------------------------------------------
const requireAuthToken = (req, res, next) => {
  const token = req.header("Authorization")?.replace("Bearer ", "");

  if (!token) {
    return res.status(401).json({ erro: "Token de autorização ausente" });
  }

  try {
    jwt.verify(token, process.env.TOKEN_SECRETO);
    req.token = token;
    next();
  } catch (err) {
    console.error("Erro ao verificar token:", err.message);
    return res.status(401).json({ erro: "Token inválido ou expirado" });
  }
};

// ----------------------------------------------------------------------
// 💚 Endpoint de teste — /health
// ----------------------------------------------------------------------
app.get("/health", (req, res) => {
  res.status(200).json({
    status: "ok",
    service: "smartlock-api",
    uptime_seconds: process.uptime(),
    timestamp: new Date().toISOString(),
  });
});

// ----------------------------------------------------------------------
// ✅ Endpoint para obter JWT — /login
// ----------------------------------------------------------------------
app.post("/login", (req, res) => {
  const { lockId, senha } = req.body;

  const senhaEsperada = process.env.SECRET_KEY;
  
  // Valide a senha (em produção, use hash bcrypt)
  if (senha !== senhaEsperada) {
    return res.status(401).json({ erro: "Senha inválida" });
  }
  
  // Valida se o lockId é permitido
  const idsPermitidos = process.env.LOCK_IDS_PERMITIDOS.split(",");
  if (!idsPermitidos.includes(lockId)) {
    return res.status(403).json({ erro: "Fechadura não autorizada" });
  }
  
  // Gera token JWT
  const token = jwt.sign(
    { lockId, type: 'smartlock' },
    process.env.TOKEN_SECRETO,
    { expiresIn: '30d' } // Token válido por 30 dias
  );
  
  res.json({ token });
});

// ----------------------------------------------------------------------
// ✅ Endpoint principal — /acesso
// ----------------------------------------------------------------------
app.get("/acesso", requireAuthToken, (req, res) => {
  const lockId = req.header("X-Lock-ID");
  const timestamp = req.header("X-Timestamp");
  const signature = req.header("X-Signature");

  if (!lockId || !timestamp || !signature) {
    return res.status(400).json({ erro: "Headers obrigatórios ausentes" });
  }

  // 🔑 Chave secreta armazenada no servidor (.env)
  const secretKey = process.env.SECRET_KEY;

  // 🧮 Gera assinatura esperada
  const data = req.token + lockId + timestamp;
  const expectedSignature = crypto
    .createHmac("sha256", secretKey)
    .update(data)
    .digest("hex");

  // 🧩 Valida assinatura
  if (expectedSignature !== signature) {
    console.warn(`🚫 Assinatura inválida para LockID ${lockId}`);
    return res.status(401).json({ erro: "Assinatura inválida" });
  }

  // 🔓 Autorização da fechadura
  const idsPermitidos = process.env.LOCK_IDS_PERMITIDOS.split(",");

  if (idsPermitidos.includes(lockId)) {
    console.log(`✅ Acesso permitido para fechadura ${lockId}`);
    return res.json({ permitido: true, timestamp: new Date().toISOString() });
  } else {
    console.log(`🚫 Fechadura não autorizada: ${lockId}`);
    return res.json({ permitido: false });
  }
});

// ----------------------------------------------------------------------
// 🚀 Inicializa servidor HTTP
// ----------------------------------------------------------------------
const port = parseInt(process.env.PORT) || 3000;
app.listen(port, () => {
  console.log(`✅ API rodando na porta ${port}`);
    console.log(`🌐 Acesse em: http://localhost:${port}/`);
});
