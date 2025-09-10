import express from "express";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import { Pool } from "pg";
import fs from "fs";
import multer from "multer";
import path from "path";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET;

// Pool de conexões com PostgreSQL
const pool = new Pool({
  host: process.env.PG_HOST,
  user: process.env.PG_USER,
  password: process.env.PG_PASSWORD,
  database: process.env.PG_DATABASE,
  port: process.env.PG_PORT,
  ssl: {
    rejectUnauthorized: false,
  },
});

// Middlewares
app.use(express.json());
app.use(
  cors({
    origin: "http://localhost:8080",
    methods: ["GET", "POST", "PUT"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Token não fornecido" });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Token inválido ou expirado" });
    }
    req.user = user;
    next();
  });
}

const fileFilter = (req, file, cb) => {
  const allowedExtensions = /\.(jpg|jpeg|png|gif)$/i;
  if (!file.originalname.match(allowedExtensions)) {
    return cb(
      new Error("Apenas imagens (jpg, jpeg, png, gif) são permitidas!"),
      false
    );
  }
  cb(null, true);
};

// Configuração do multer
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const dir = "uploads/";
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname);
    cb(null, `perfil_${req.user.id}${ext}`);
  },
});

const upload = multer({ storage, fileFilter });

// Rota de teste para PostgreSQL
app.get("/db-test", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW() as agora");
    res.json({
      message: "Conexão com PostgreSQL funcionando!",
      servidor: result.rows[0].agora,
    });
  } catch (error) {
    console.error("Erro na conexão com o banco:", error);
    res.status(500).json({ error: "Erro ao conectar ao PostgreSQL" });
  }
});

// Rota de cadastro com PostgreSQL
app.post("/cadastro", async (req, res) => {
  try {
    const { username, email, senha, tipo_user } = req.body || {};

    if (!username || !email || !senha || !tipo_user) {
      return res
        .status(400)
        .json({ error: "Todos os campos são obrigatórios!" });
    }

    // Hash da senha
    const senha_hash = await bcrypt.hash(senha, 12);

    // Data de cadastro atual
    const data_cadastro = new Date();

    // Inserção no banco
    const query = `
      INSERT INTO usuario (username, senha_hash, email, tipo_user, data_cadastro)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING user_id, username, email, tipo_user, data_cadastro
    `;
    const values = [username, senha_hash, email, tipo_user, data_cadastro];

    const result = await pool.query(query, values);

    const novoUsuario = result.rows[0];

    res.status(201).json({
      message: "Usuário cadastrado com sucesso!",
      usuario: novoUsuario,
    });
  } catch (error) {
    console.error("Erro no cadastro:", error);

    // Caso já exista email duplicado
    if (error.code === "23505") {
      return res.status(400).json({ error: "Email já cadastrado!" });
    }

    res.status(500).json({ error: "Erro ao cadastrar usuário" });
  }
});

// Rota de login com PostgreSQL
app.post("/login", async (req, res) => {
  try {
    const { email, senha } = req.body || {};

    if (!email || !senha) {
      return res.status(400).json({ error: "Email e senha são obrigatórios!" });
    }

    // Validação simples de email usando regex
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: "Email inválido!" });
    }

    // Busca usuário no banco
    const query = "SELECT * FROM usuario WHERE email = $1";
    const result = await pool.query(query, [email]);

    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Credenciais inválidas" });
    }

    const usuario = result.rows[0];

    // Verifica senha
    const senhaValida = await bcrypt.compare(senha, usuario.senha_hash);
    if (!senhaValida) {
      return res.status(401).json({ error: "Credenciais inválidas" });
    }

    // Gera token JWT
    const token = jwt.sign(
      {
        id: usuario.user_id,
        email: usuario.email,
        tipo_user: usuario.tipo_user,
      },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ message: "Login realizado com sucesso!", token });
  } catch (error) {
    console.error("Erro no login:", error);
    res.status(500).json({ error: "Erro ao realizar login" });
  }
});

// Rota GET - Perfil do usuário logado
app.get("/perfil", authenticateToken, async (req, res) => {
  try {
    const query = `
      SELECT perfil_id, user_id, nome, bio, telefone, link, data_criacao
      FROM perfil
      WHERE user_id = $1
    `;
    const result = await pool.query(query, [req.user.id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Perfil não encontrado" });
    }

    res.json({ perfil: result.rows[0] });
  } catch (error) {
    console.error("Erro ao buscar perfil:", error);
    res.status(500).json({ error: "Erro ao buscar perfil" });
  }
});

// Rota PUT - Atualizar perfil
app.put("/perfil", authenticateToken, async (req, res) => {
  try {
    const { nome, bio, telefone } = req.body || {};

    // Validação do nome (apenas letras, espaços e alguns acentos)
    if (nome && !/^[a-zA-ZÀ-ÿ\s]+$/.test(nome)) {
      return res.status(400).json({ erro: "Nome inválido!" });
    }

    // Validação do telefone (padrão internacional ou nacional)
    // Ex: +5511999998888 ou 11999998888
    if (telefone && !/^(\+?\d{1,3}?)?(\d{10,11})$/.test(telefone)) {
      return res.status(400).json({ error: "Telefone inválido!" });
    }

    const query = `
      UPDATE perfil
      SET nome = COALESCE($1, nome),
          bio = COALESCE($2, bio),
          telefone = COALESCE($3, telefone)
      WHERE user_id = $4
      RETURNING perfil_id, user_id, nome, bio, telefone, link, data_criacao
    `;
    const values = [nome, bio, telefone, req.user_id];

    const result = await pool.query(query, values);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Perfil não encontrado!" });
    }

    res.json({
      message: "Perfil atualizado com sucesso!",
      perfil: result.rows[0],
    });
  } catch {
    console.error("Erro ao atualizar perfil:", error);
    res.status(500).json({ error: "Erro ao atualizar perfil" });
  }
});

// Rota de upload de foto de perfil
app.post(
  "/perfil/foto",
  authenticateToken,
  upload.single("link"),
  async (req, res) => {
    try {
      const link = req.file ? req.file.path : null;
      if (!link) return res.status(400).json({ error: "Arquivo não enviado" });

      // Atualiza tabela perfil
      const query = `
      UPDATE perfil
      SET link = $1
      WHERE user_id = $2
      RETURNING perfil_id, user_id, link
    `;
      const values = [link, req.user.id];
      const result = await pool.query(query, values);

      if (result.rows.length === 0) {
        return res.status(404).json({ error: "Perfil não encontrado" });
      }

      res.json({
        message: "Foto de perfil atualizada com sucesso!",
        perfil: result.rows[0],
      });
    } catch (error) {
      console.error("Erro ao atualizar foto de perfil:", error);
      res.status(500).json({ error: "Erro ao atualizar foto de perfil" });
    }
  }
);

app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});
