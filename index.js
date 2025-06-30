const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

if (!process.env.POSTGRES_URL || process.env.POSTGRES_URL.trim() === '') {
  throw new Error('FATAL: A variável de ambiente POSTGRES_URL está VAZIA ou não foi encontrada no ambiente da Vercel!');
}
if (!process.env.JWT_SECRET) {
  throw new Error('FATAL: A variável de ambiente JWT_SECRET não foi encontrada no ambiente da Vercel!');
}

const app = express();
const port = 3001;

// --- Middlewares ---
app.use(express.json());

// Adicionado para depuração
console.log('Verificando POSTGRES_URL:', process.env.POSTGRES_URL ? 'Definida' : 'NÃO DEFINIDA');

// Initialize database pool
const pool = new Pool({
  connectionString: `${process.env.POSTGRES_URL}?sslmode=require`,
});

// Function to create users table
const createTable = async () => {
  const createTableQuery = `
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT,
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
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ message: 'Nome, email e senha são obrigatórios.' });
  }

  if (password.length < 8) {
    return res.status(400).json({ message: 'A senha deve ter pelo menos 8 caracteres.' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const insertQuery = 'INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id';
    
    const result = await pool.query(insertQuery, [name, email, hashedPassword]); 
    
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
    
    // Login bem-sucedido, gerar token JWT
    const token = jwt.sign(
      { userId: user.id, email: user.email, name: user.name },
      process.env.JWT_SECRET,
      { expiresIn: '1d' } // Token expira em 1 dia
    );

    res.status(200).json({ message: 'Login bem-sucedido!', token });

  } catch (error) {
    console.error('Erro detalhado ao fazer login:', error);
    res.status(500).json({ message: 'Ocorreu um erro no servidor ao tentar fazer login.', error: error.message });
  }
});

// Middleware para verificar token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Formato "Bearer TOKEN"

  if (token == null) {
    return res.sendStatus(401); // Não autorizado se não houver token
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.sendStatus(403); // Proibido se o token for inválido
    }
    req.user = user;
    next();
  });
};

// Rota para buscar dados do usuário
app.get('/api/user', authenticateToken, async (req, res) => {
  try {
    const findUserQuery = 'SELECT id, name, email FROM users WHERE id = $1';
    const result = await pool.query(findUserQuery, [req.user.userId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado.' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Erro ao buscar dados do usuário:', error);
    res.status(500).json({ message: 'Ocorreu um erro no servidor.' });
  }
});

// Rota para atualizar perfil do usuário (nome, email)
app.patch('/api/user/profile', authenticateToken, async (req, res) => {
  const { name, email } = req.body;
  const { userId } = req.user;

  if (!name && !email) {
    return res.status(400).json({ message: 'Pelo menos um campo (nome ou email) deve ser fornecido.' });
  }

  try {
    // Lógica para atualizar e-mail, se fornecido
    if (email) {
      // Opcional: Adicionar verificação se o novo e-mail já existe
      const emailExistsQuery = 'SELECT id FROM users WHERE email = $1 AND id != $2';
      const emailExistsResult = await pool.query(emailExistsQuery, [email, userId]);
      if (emailExistsResult.rows.length > 0) {
        return res.status(409).json({ message: 'Este e-mail já está em uso por outra conta.' });
      }
      const updateEmailQuery = 'UPDATE users SET email = $1 WHERE id = $2';
      await pool.query(updateEmailQuery, [email, userId]);
    }

    // Lógica para atualizar nome, se fornecido
    if (name) {
      const updateNameQuery = 'UPDATE users SET name = $1 WHERE id = $2';
      await pool.query(updateNameQuery, [name, userId]);
    }

    // Busca os dados atualizados para gerar um novo token
    const findUserQuery = 'SELECT id, name, email FROM users WHERE id = $1';
    const updatedUserResult = await pool.query(findUserQuery, [userId]);
    const updatedUser = updatedUserResult.rows[0];

    // Gera um novo token com os dados atualizados
    const token = jwt.sign(
      { userId: updatedUser.id, email: updatedUser.email, name: updatedUser.name },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );

    res.status(200).json({ message: 'Perfil atualizado com sucesso!', token });

  } catch (error) {
    console.error('Erro ao atualizar perfil:', error);
    res.status(500).json({ message: 'Ocorreu um erro no servidor ao atualizar o perfil.' });
  }
});

// Rota para atualizar a senha
app.patch('/api/user/password', authenticateToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const { userId } = req.user;

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ message: 'Senha atual e nova senha são obrigatórias.' });
  }
  
  if (newPassword.length < 8) {
    return res.status(400).json({ message: 'A nova senha deve ter pelo menos 8 caracteres.' });
  }

  try {
    // Busca a senha atual do usuário no banco
    const findUserQuery = 'SELECT password FROM users WHERE id = $1';
    const userResult = await pool.query(findUserQuery, [userId]);
    const user = userResult.rows[0];

    // Verifica se a senha atual está correta
    const isPasswordValid = await bcrypt.compare(currentPassword, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'A senha atual está incorreta.' });
    }

    // Criptografa e salva a nova senha
    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    const updatePasswordQuery = 'UPDATE users SET password = $1 WHERE id = $2';
    await pool.query(updatePasswordQuery, [hashedNewPassword, userId]);
    
    res.status(200).json({ message: 'Senha alterada com sucesso!' });

  } catch (error) {
    console.error('Erro ao alterar senha:', error);
    res.status(500).json({ message: 'Ocorreu um erro no servidor ao alterar a senha.' });
  }
});

module.exports = app; 