const express = require('express');git 
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { Resend } = require('resend');
const multer = require('multer');
const { put } = require('@vercel/blob');
const Pusher = require('pusher');

if (!process.env.POSTGRES_URL || process.env.POSTGRES_URL.trim() === '') {
  throw new Error('FATAL: A variável de ambiente POSTGRES_URL está VAZIA ou não foi encontrada no ambiente da Vercel!');
}
if (!process.env.JWT_SECRET) {
  throw new Error('FATAL: A variável de ambiente JWT_SECRET não foi encontrada no ambiente da Vercel!');
}
if (!process.env.RESEND_API_KEY) {
  throw new Error('FATAL: A variável de ambiente RESEND_API_KEY não foi encontrada!');
}
if (!process.env.BASE_URL) {
    throw new Error('FATAL: A variável de ambiente BASE_URL não foi encontrada!');
}
if (!process.env.BLOB_READ_WRITE_TOKEN) {
  throw new Error('FATAL: A variável de ambiente BLOB_READ_WRITE_TOKEN não foi encontrada!');
}
if (!process.env.PUSHER_APP_ID) throw new Error('FATAL: PUSHER_APP_ID não foi encontrada!');
if (!process.env.PUSHER_KEY) throw new Error('FATAL: PUSHER_KEY não foi encontrada!');
if (!process.env.PUSHER_SECRET) throw new Error('FATAL: PUSHER_SECRET não foi encontrada!');
if (!process.env.PUSHER_CLUSTER) throw new Error('FATAL: PUSHER_CLUSTER não foi encontrada!');

const app = express();
const port = 3001;
const resend = new Resend(process.env.RESEND_API_KEY);

const pusher = new Pusher({
  appId: process.env.PUSHER_APP_ID,
  key: process.env.PUSHER_KEY,
  secret: process.env.PUSHER_SECRET,
  cluster: process.env.PUSHER_CLUSTER,
  useTLS: true
});

// --- Middlewares ---
// Estes devem vir ANTES da definição das rotas
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Adicionado para depuração
console.log('Verificando POSTGRES_URL:', process.env.POSTGRES_URL ? 'Definida' : 'NÃO DEFINIDA');

// Initialize database pool
const pool = new Pool({
  connectionString: `${process.env.POSTGRES_URL}?sslmode=require`,
});

// Configuração do Multer para upload em memória
const storage = multer.memoryStorage();
const upload = multer({ storage });

let migrationPromise = null;

// Migração e criação da tabela
const runMigration = async () => {
  // Se a migração já foi concluída com sucesso, não faz nada.
  if (migrationPromise) return migrationPromise;

  migrationPromise = new Promise(async (resolve, reject) => {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // 1. Garante que a tabela exista
      await client.query(`
        CREATE TABLE IF NOT EXISTS users (
          id SERIAL PRIMARY KEY,
          email TEXT UNIQUE NOT NULL,
          password TEXT NOT NULL
        )
      `);

      // 2. Adiciona cada coluna necessária, uma por uma, se ela não existir.
      // Esta abordagem é muito mais robusta que a anterior.
      await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS name TEXT');
      await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url TEXT');
      await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS is_owner BOOLEAN DEFAULT FALSE');
      await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS is_email_verified BOOLEAN DEFAULT FALSE');
      await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verification_token TEXT');
      await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS password_reset_token TEXT');
      await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS password_reset_expires TIMESTAMPTZ');
      await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS bio TEXT');
      await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT \'user\'');
      await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS "createdAt" TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP');
      
      // Garante que a conta principal seja sempre admin
      await client.query(`UPDATE users SET role = 'admin' WHERE email = 'hunteqy@gmail.com'`);

      await client.query('COMMIT');
      console.log('Banco de dados verificado e migrado com sucesso (método robusto).');
      resolve();
    } catch (error) {
      await client.query('ROLLBACK');
      console.error('Erro ao conectar ou criar/migrar a tabela:', error);
      reject(error);
    } finally {
      client.release();
    }
  });
  return migrationPromise;
};

// Middleware para garantir que a migração foi concluída
const ensureDbIsReady = async (req, res, next) => {
  try {
    await runMigration();
    next();
  } catch (error) {
    console.error('CRÍTICO: Migração do banco de dados falhou. A aplicação não pode continuar.');
    res.status(503).json({ message: 'O servidor não está pronto para receber requisições. Tente novamente mais tarde.' });
  }
};

// Aplica o middleware a todas as rotas
app.use(ensureDbIsReady);

// Função para enviar e-mail de verificação
const sendVerificationEmail = async (email, token) => {
    const verificationUrl = `${process.env.BASE_URL}/verify-email?token=${token}`;
    try {
        await resend.emails.send({
            from: 'AkemiSoft <noreply@akemi.store>',
            to: email,
            subject: 'Verifique seu e-mail na AkemiSoft',
            html: `<h1>Bem-vindo à AkemiSoft!</h1><p>Clique no link abaixo para verificar seu e-mail:</p><a href="${verificationUrl}">${verificationUrl}</a>`
        });
        console.log(`E-mail de verificação enviado para ${email}`);
    } catch (error) {
        console.error("Erro detalhado ao enviar e-mail de verificação:", JSON.stringify(error, null, 2));
    }
};

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
    const verificationToken = crypto.randomBytes(32).toString('hex');
    
    const insertQuery = 'INSERT INTO users (name, email, password, email_verification_token) VALUES ($1, $2, $3, $4) RETURNING id';
    const result = await pool.query(insertQuery, [name, email, hashedPassword, verificationToken]); 
    
    await sendVerificationEmail(email, verificationToken);

    res.status(201).json({ message: 'Usuário registrado com sucesso! Por favor, verifique seu e-mail.'});

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
    const findUserQuery = 'SELECT id, name, email, password, avatar_url, is_email_verified, role, "createdAt" FROM users WHERE email = $1';
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
      { userId: user.id, email: user.email, name: user.name, avatar_url: user.avatar_url, is_email_verified: user.is_email_verified, role: user.role, createdAt: user.createdAt },
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
    const findUserQuery = 'SELECT id, name, email, avatar_url, is_email_verified, role, bio, "createdAt" FROM users WHERE id = $1';
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
  const { name, email, bio } = req.body;
  const { userId } = req.user;

  if (!name && !email && !bio) {
    return res.status(400).json({ message: 'Pelo menos um campo (nome, email ou bio) deve ser fornecido.' });
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
    
    // Lógica para atualizar bio, se fornecido
    if (bio || bio === '') { // Permite limpar a bio
      const updateBioQuery = 'UPDATE users SET bio = $1 WHERE id = $2';
      await pool.query(updateBioQuery, [bio, userId]);
    }

    // Busca os dados atualizados para gerar um novo token
    const findUserQuery = 'SELECT id, name, email, avatar_url, is_email_verified, role, "createdAt" FROM users WHERE id = $1';
    const updatedUserResult = await pool.query(findUserQuery, [userId]);
    const updatedUser = updatedUserResult.rows[0];

    // Gera um novo token com os dados atualizados
    const token = jwt.sign(
      { userId: updatedUser.id, email: updatedUser.email, name: updatedUser.name, avatar_url: updatedUser.avatar_url, is_email_verified: updatedUser.is_email_verified, role: updatedUser.role, createdAt: updatedUser.createdAt },
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

// Rota para verificar e-mail
app.post('/api/auth/verify-email', async (req, res) => {
    const { token } = req.body;
    if (!token) return res.status(400).json({ message: 'Token é obrigatório.' });

    try {
        const findUserQuery = 'SELECT id FROM users WHERE email_verification_token = $1';
        const userResult = await pool.query(findUserQuery, [token]);

        if (userResult.rows.length === 0) {
            return res.status(400).json({ message: 'Token inválido ou expirado.' });
        }

        const userId = userResult.rows[0].id;
        const updateUserQuery = 'UPDATE users SET is_email_verified = TRUE, email_verification_token = NULL WHERE id = $1';
        await pool.query(updateUserQuery, [userId]);

        res.status(200).json({ message: 'E-mail verificado com sucesso!' });
    } catch (error) {
        console.error('Erro ao verificar e-mail:', error);
        res.status(500).json({ message: 'Ocorreu um erro no servidor.' });
    }
});

// Rota de "Esqueci minha senha"
app.post('/api/auth/forgot-password', async (req, res) => {
    const { email } = req.body;
    try {
        const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (userResult.rows.length === 0) {
            // Não revele se o usuário existe ou não
            return res.status(200).json({ message: 'Se um usuário com este e-mail existir, um link de redefinição será enviado.' });
        }

        const resetToken = crypto.randomBytes(32).toString('hex');
        const resetExpires = new Date(Date.now() + 3600000); // Expira em 1 hora

        await pool.query('UPDATE users SET password_reset_token = $1, password_reset_expires = $2 WHERE email = $3', [resetToken, resetExpires, email]);

        const resetUrl = `${process.env.BASE_URL}/reset-password?token=${resetToken}`;
        await resend.emails.send({
            from: 'AkemiSoft <noreply@akemi.store>',
            to: email,
            subject: 'Redefinição de Senha - AkemiSoft',
            html: `<p>Você solicitou uma redefinição de senha. Clique no link para continuar:</p><a href="${resetUrl}">${resetUrl}</a>`
        });

        res.status(200).json({ message: 'Se um usuário com este e-mail existir, um link de redefinição será enviado.' });
    } catch (error) {
        console.error('Erro detalhado no forgot-password:', JSON.stringify(error, null, 2));
        res.status(500).json({ message: 'Ocorreu um erro no servidor.' });
    }
});

// Rota para redefinir a senha
app.post('/api/auth/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;
    if (!token || !newPassword) {
        return res.status(400).json({ message: 'Token e nova senha são obrigatórios.' });
    }

    try {
        const findUserQuery = 'SELECT * FROM users WHERE password_reset_token = $1 AND password_reset_expires > NOW()';
        const userResult = await pool.query(findUserQuery, [token]);
        
        if (userResult.rows.length === 0) {
            return res.status(400).json({ message: 'Token inválido ou expirado.' });
        }

        const user = userResult.rows[0];
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        const updateUserQuery = 'UPDATE users SET password = $1, password_reset_token = NULL, password_reset_expires = NULL WHERE id = $2';
        await pool.query(updateUserQuery, [hashedPassword, user.id]);

        res.status(200).json({ message: 'Senha redefinida com sucesso!' });
    } catch (error) {
        console.error('Erro no reset-password:', error);
        res.status(500).json({ message: 'Ocorreu um erro no servidor.' });
    }
});

// Rota para fazer upload do avatar
app.post('/api/user/avatar', authenticateToken, upload.single('avatar'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ message: 'Nenhum arquivo foi enviado.' });
  }

  const { userId } = req.user;
  const filename = `avatars/${userId}-${Date.now()}`;

  try {
    const blob = await put(filename, req.file.buffer, {
      access: 'public',
      contentType: req.file.mimetype,
    });

    // Atualiza a URL do avatar no banco de dados
    await pool.query('UPDATE users SET avatar_url = $1 WHERE id = $2', [blob.url, userId]);

    // Busca os dados atualizados para gerar um novo token
    const findUserQuery = 'SELECT id, name, email, avatar_url, is_email_verified, role, "createdAt" FROM users WHERE id = $1';
    const updatedUserResult = await pool.query(findUserQuery, [userId]);
    const updatedUser = updatedUserResult.rows[0];

    // Gera um novo token com a URL do avatar
    const token = jwt.sign(
      { userId: updatedUser.id, email: updatedUser.email, name: updatedUser.name, avatar_url: updatedUser.avatar_url, is_email_verified: updatedUser.is_email_verified, role: updatedUser.role, createdAt: updatedUser.createdAt },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );

    res.status(200).json({ message: 'Avatar atualizado com sucesso!', token, avatar_url: blob.url });

  } catch (error) {
    console.error('Erro ao fazer upload do avatar:', error);
    res.status(500).json({ message: 'Ocorreu um erro no servidor ao processar o avatar.' });
  }
});

// Rota para reenviar o e-mail de verificação
app.post('/api/auth/resend-verification', authenticateToken, async (req, res) => {
  const { userId } = req.user;

  try {
    const userResult = await pool.query('SELECT email, is_email_verified FROM users WHERE id = $1', [userId]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado.' });
    }

    const user = userResult.rows[0];
    if (user.is_email_verified) {
      return res.status(400).json({ message: 'Este e-mail já foi verificado.' });
    }

    // Gera um novo token e envia o e-mail
    const verificationToken = crypto.randomBytes(32).toString('hex');
    await pool.query('UPDATE users SET email_verification_token = $1 WHERE id = $2', [verificationToken, userId]);
    
    await sendVerificationEmail(user.email, verificationToken);

    res.status(200).json({ message: 'E-mail de verificação reenviado com sucesso!' });
  } catch (error) {
    console.error('Erro ao reenviar e-mail de verificação:', error);
    res.status(500).json({ message: 'Ocorreu um erro no servidor.' });
  }
});

// Rota para autenticar usuários no canal de presença do Pusher
app.post('/api/pusher/auth', authenticateToken, (req, res) => {
  const socketId = req.body.socket_id;
  const channel = req.body.channel_name;

  if (!socketId || !channel) {
    return res.status(400).send('Requisição inválida: socket_id e channel_name são obrigatórios.');
  }
  
  const user = req.user;
  const userData = {
    user_id: user.userId.toString(),
    user_info: {
      name: user.name,
      email: user.email,
      avatar_url: user.avatar_url,
      is_owner: !!user.is_owner,
      role: user.role,
      createdAt: user.createdAt
    }
  };

  try {
    const authResponse = pusher.authorizeChannel(socketId, channel, userData);
    res.send(authResponse);
  } catch (error) {
    console.error('Pusher auth ERRO na chamada authorizeChannel:', error);
    res.status(500).send('Erro na autorização do Pusher');
  }
});

// Rota para buscar o perfil público de um usuário
app.get('/api/user-profile/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const findUserQuery = 'SELECT id, name, avatar_url, role, bio, "createdAt" FROM users WHERE id = $1';
    const result = await pool.query(findUserQuery, [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado.' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error(`Erro ao buscar perfil do usuário ${id}:`, error);
    res.status(500).json({ message: 'Ocorreu um erro no servidor.' });
  }
});

// Middleware para verificar se o usuário é admin
const isAdmin = (req, res, next) => {
  if (req.user && req.user.role === 'admin') {
    next();
  } else {
    res.status(403).json({ message: 'Acesso negado. Apenas administradores podem executar esta ação.' });
  }
};

// Rota para buscar todos os usuários (para a lista da comunidade)
app.get('/api/users/all', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, name, avatar_url, role FROM users ORDER BY name ASC');
    res.json(result.rows);
  } catch (error) {
    console.error('Erro ao buscar todos os usuários:', error);
    res.status(500).json({ message: 'Ocorreu um erro no servidor.' });
  }
});

// Rota para atualizar o cargo de um usuário (apenas para admins)
app.patch('/api/users/:id/role', authenticateToken, isAdmin, async (req, res) => {
  const { id } = req.params;
  const { role } = req.body;

  const validRoles = ['user', 'gamer', 'premium', 'moderator', 'admin', 'dev', 'youtuber', 'famous'];
  if (!validRoles.includes(role)) {
    return res.status(400).json({ message: 'Cargo inválido.' });
  }

  try {
    const result = await pool.query('UPDATE users SET role = $1 WHERE id = $2 RETURNING id, role', [role, id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado.' });
    }
    res.status(200).json({ message: 'Cargo atualizado com sucesso!', user: result.rows[0] });
  } catch (error) {
    console.error(`Erro ao atualizar cargo para o usuário ${id}:`, error);
    res.status(500).json({ message: 'Ocorreu um erro no servidor.' });
  }
});

module.exports = app; 