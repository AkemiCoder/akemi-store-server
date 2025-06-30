const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();
const port = 3001;

// --- CORS Middleware ---
const allowedOrigins = ['https://www.akemi.store', 'https://akemi.store', 'http://localhost:5173'];
const corsOptions = {
  origin: (origin, callback) => {
    // allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) === -1) {
      const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
      return callback(new Error(msg), false);
    }
    return callback(null, true);
  },
  credentials: true,
  methods: 'GET, POST, OPTIONS, PUT, PATCH, DELETE',
  allowedHeaders: 'X-Requested-With,content-type,Authorization'
};
app.use(cors(corsOptions));

// --- Middlewares ---
app.use(express.json());

// Initialize database pool
const pool = new Pool({
  connectionString: `${process.env.POSTGRES_URL}?sslmode=require`,
});

// Function to create users table
const createTable = async () => {
  const createTableQuery = `
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      createdAt TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    )
  `;
  try {
    const client = await pool.connect();
    await client.query(createTableQuery);
    client.release();
    console.log('Tabela "users" verificada/criada com sucesso.');
  } catch (error) {
    console.error('Erro ao conectar ou criar a tabela:', error);
  }
};

// Call function to ensure table exists
createTable();

// Registration endpoint
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email e senha são obrigatórios.' });
  }

  if (password.length < 8) {
    return res.status(400).json({ message: 'A senha deve ter pelo menos 8 caracteres.' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const insertQuery = 'INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id';
    
    const result = await pool.query(insertQuery, [email, hashedPassword]); 
    
    console.log(`Novo usuário registrado: ${email}, ID: ${result.rows[0].id}`);
    res.status(201).json({ message: 'Usuário registrado com sucesso!', userId: result.rows[0].id });

  } catch (error) {
    if (error.code === '23505') { // Unique violation
      return res.status(409).json({ message: 'Este e-mail já está em uso.' });
    }
    console.error('Erro detalhado ao registrar usuário:', error);
    res.status(500).json({ message: 'Ocorreu um erro no servidor ao tentar registrar.', error: error.message });
  }
});

// Login endpoint
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email e senha são obrigatórios.' });
  }

  try {
    const findUserQuery = 'SELECT * FROM users WHERE email = $1';
    const result = await pool.query(findUserQuery, [email]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado.' });
    }

    const user = result.rows[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Senha inválida.' });
    }
    
    // Login bem-sucedido (em um app real, você geraria um token JWT aqui)
    res.status(200).json({ message: 'Login bem-sucedido!', userId: user.id });

  } catch (error) {
    console.error('Erro detalhado ao fazer login:', error);
    res.status(500).json({ message: 'Ocorreu um erro no servidor ao tentar fazer login.', error: error.message });
  }
});

module.exports = app; 