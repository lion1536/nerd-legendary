import express from "express";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET;

// Middlewares
app.use(cors({ origin: "*" }));
app.use(express.json());

app.post("/cadastro", async (req, res) => {
  try {
    const { nome, email, senha } = req.body;

    if (!nome || !email || !senha) {
      return res
        .status(400)
        .json({ error: "Todos os campos são obrigatórios!" });
    }

    // Criptografa a senha
    const hashedPassword = await bcrypt.hash(senha, 12);

    // Simulando "salvar usuário"
    const novoUsuario = {
      id: Date.now(),
      nome,
      email,
      senha: hashedPassword,
    };

    // Gera um token JWT
    const token = jwt.sign(
      { id: novoUsuario.id, email: novoUsuario.email },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.status(201).json({
      message: "Usuário cadastrado com sucesso!",
      usuario: {
        id: novoUsuario.id,
        nome: novoUsuario.nome,
        email: novoUsuario.email,
      },
      token, // ✅ devolve o token
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Erro ao cadastrar usuário" });
  }
});

// Inicializa o servidor
app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});
