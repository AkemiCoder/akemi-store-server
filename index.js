const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
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
  connectionString: process.env.POSTGRES_URL,
  ssl: {
    rejectUnauthorized: false
  }
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
    await pool.query(createTableQuery);
    console.log('Tabela "users" verificada/criada com sucesso.');
  } catch (error) {
    console.error('Erro ao criar a tabela:', error);
  }
};

// Call function to ensure table exists
createTable();

// Registration endpoint
app.post('/register', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email e senha são obrigatórios.' });
  }

  if (password.length < 8) {
    return res.status(400).json({ message: 'A senha deve ter pelo menos 8 caracteres.' });
  }

  const insertQuery = 'INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id';
  
  try {
    // Note: Storing plain text password for simplicity. In production, ALWAYS hash passwords.
    const result = await pool.query(insertQuery, [email, password]); 
    
    console.log(`Novo usuário registrado: ${email}, ID: ${result.rows[0].id}`);
    res.status(201).json({ message: 'Usuário registrado com sucesso!', userId: result.rows[0].id });

  } catch (error) {
    if (error.code === '23505') { // Unique violation
      return res.status(409).json({ message: 'Este e-mail já está em uso.' });
    }
    console.error('Erro ao registrar usuário:', error);
    res.status(500).json({ message: 'Ocorreu um erro no servidor.' });
  }
});

module.exports = app; 