require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');

const app = express();
const port = 3001;

// --- Middlewares ---
app.use(cors()); // Simplified CORS
app.use(express.json());

// Initialize database pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
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

app.listen(port, () => {
  console.log(`Servidor rodando em http://localhost:${port}`);
}); 