console.log('[SERVER_INIT] Inicializando o servidor AkemiSoft - Build Seguro');
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { Resend } = require('resend');
const multer = require('multer');
const { put } = require('@vercel/blob');
const Pusher = require('pusher');
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const hpp = require('hpp');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const validator = require('validator');

// Validação de variáveis de ambiente críticas
const requiredEnvVars = [
  'POSTGRES_URL', 'JWT_SECRET', 'RESEND_API_KEY', 'BASE_URL', 
  'BLOB_READ_WRITE_TOKEN', 'PUSHER_APP_ID', 'PUSHER_KEY', 
  'PUSHER_SECRET', 'PUSHER_CLUSTER', 'DISCORD_CLIENT_ID', 
  'DISCORD_CLIENT_SECRET'
];

requiredEnvVars.forEach(envVar => {
  if (!process.env[envVar] || process.env[envVar].trim() === '') {
    throw new Error(`FATAL: A variável de ambiente ${envVar} está VAZIA ou não foi encontrada!`);
  }
});

// Variáveis opcionais com avisos
if (!process.env.SPOTIFY_CLIENT_ID) console.warn('AVISO: SPOTIFY_CLIENT_ID não foi encontrada! A funcionalidade do Spotify não funcionará.');
if (!process.env.SPOTIFY_CLIENT_SECRET) console.warn('AVISO: SPOTIFY_CLIENT_SECRET não foi encontrada! A funcionalidade do Spotify não funcionará.');

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

// === CONFIGURAÇÕES DE SEGURANÇA AVANÇADAS ===

// Helmet com configurações mais restritivas
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https:", "blob:"],
      scriptSrc: ["'self'"],
      connectSrc: ["'self'", "https://api.spotify.com", "https://discord.com", "https://ip-api.com"],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: []
    }
  },
  crossOriginResourcePolicy: { policy: "same-site" },
  crossOriginEmbedderPolicy: false,
  dnsPrefetchControl: { allow: false },
  frameguard: { action: "deny" },
  hidePoweredBy: true,
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  ieNoOpen: true,
  noSniff: true,
  permittedCrossDomainPolicies: { permittedPolicies: "none" },
  referrerPolicy: { policy: "strict-origin-when-cross-origin" },
  xssFilter: true
}));

// CORS restrito com origens específicas
const allowedOrigins = [
  'https://seusite.com.br', 
  'http://localhost:5173',
  'https://akemi.store',
  'https://www.akemi.store'
];

app.use(cors({
  origin: function (origin, callback) {
    // Permitir requisições sem origin (como mobile apps)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      console.warn(`Tentativa de acesso de origem não autorizada: ${origin}`);
      callback(new Error('Não permitido pelo CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  credentials: true,
  maxAge: 86400 // 24 horas
}));

// Rate Limiting específico por rota
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 5, // 5 tentativas de login/registro
  message: { message: 'Muitas tentativas de autenticação. Tente novamente em 15 minutos.' },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100, // 100 requisições por IP
  message: { message: 'Muitas requisições deste IP. Tente novamente mais tarde.' },
  standardHeaders: true,
  legacyHeaders: false
});

const uploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hora
  max: 10, // 10 uploads por hora
  message: { message: 'Limite de uploads excedido. Tente novamente em 1 hora.' },
  standardHeaders: true,
  legacyHeaders: false
});

// Proteções contra ataques
app.use(hpp()); // Proteção contra HTTP Parameter Pollution
app.use(mongoSanitize()); // Sanitização contra NoSQL Injection
app.use(xss()); // Proteção contra XSS

// Middlewares de parsing com limites
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Middleware para remover headers sensíveis
app.use((req, res, next) => {
  res.removeHeader('X-Powered-By');
  next();
});

// Middleware de logging de segurança
app.use((req, res, next) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  const userAgent = req.headers['user-agent'];
  const timestamp = new Date().toISOString();
  
  console.log(`[SECURITY_LOG] ${timestamp} - IP: ${ip} - Method: ${req.method} - Path: ${req.path} - User-Agent: ${userAgent}`);
  
  // Log de tentativas suspeitas
  if (req.path.includes('admin') || req.path.includes('login') || req.path.includes('register')) {
    console.log(`[AUTH_ATTEMPT] ${timestamp} - IP: ${ip} - Path: ${req.path}`);
  }
  
  next();
});

// Validação de entrada melhorada
const validateEmail = (email) => {
  return validator.isEmail(email) && email.length <= 254;
};

const validatePassword = (password) => {
  // Senha deve ter pelo menos 8 caracteres, incluindo maiúscula, minúscula, número e caractere especial
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
  return passwordRegex.test(password);
};

const sanitizeInput = (input) => {
  if (typeof input !== 'string') return input;
  return validator.escape(input.trim());
};

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
      await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS banner_url TEXT');
      await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS is_owner BOOLEAN DEFAULT FALSE');
      await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS is_email_verified BOOLEAN DEFAULT FALSE');
      await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verification_token TEXT');
      await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS password_reset_token TEXT');
      await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS password_reset_expires TIMESTAMPTZ');
      await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS bio TEXT');
      await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT \'user\'');
      await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS "createdAt" TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP');
      
      // Novas colunas para integração com o Discord
      await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS discord_id TEXT');
      await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS discord_username TEXT');
      await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS discord_avatar_url TEXT');
      await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_color TEXT');

      // Novas colunas para integração com o Spotify
      await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS spotify_id TEXT');
      await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS spotify_username TEXT');
      await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS spotify_avatar_url TEXT');
      await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS spotify_access_token TEXT');
      await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS spotify_refresh_token TEXT');
      await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS spotify_token_expires TIMESTAMPTZ');

      // Novas colunas para efeitos de perfil
      await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_effect TEXT');

      // Nova coluna para música de perfil
      await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS music_url TEXT');

      // Novas colunas para Geolocalização
      await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS last_ip TEXT');
      await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS city TEXT');
      await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS state TEXT');
      await client.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS country TEXT');

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

// Aplicar rate limiting global
app.use(apiLimiter);

// Middleware para rotas não encontradas (sempre JSON)
app.use('*', (req, res) => {
  res.status(404).json({ message: 'Rota não encontrada.' });
});

// Middleware de tratamento de erros global (sempre JSON)
app.use((err, req, res, next) => {
  // Se a resposta já foi enviada, delega para o handler padrão do Express
  if (res.headersSent) {
    return next(err);
  }

  // Se o erro for de CORS
  if (err && err.message && err.message.includes('CORS')) {
    return res.status(403).json({ message: 'Erro de CORS: origem não permitida.' });
  }

  // Se o erro for do rate limiter
  if (err && err.status === 429) {
    return res.status(429).json({ message: err.message || 'Muitas requisições, tente novamente mais tarde.' });
  }

  // Outros erros
  console.error('Erro não tratado:', err);
  if (process.env.NODE_ENV === 'production') {
    res.status(500).json({ message: 'Erro interno do servidor.' });
  } else {
    res.status(500).json({
      message: 'Erro interno do servidor.',
      error: err.message,
      stack: err.stack
    });
  }
});

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

// Registration endpoint com validação melhorada
app.post('/api/register', authLimiter, async (req, res) => {
  const { name, email, password } = req.body;

  // Validação rigorosa dos dados de entrada
  if (!name || !email || !password) {
    return res.status(400).json({ message: 'Nome, email e senha são obrigatórios.' });
  }

  // Sanitização dos dados
  const sanitizedName = sanitizeInput(name);
  const sanitizedEmail = sanitizeInput(email);

  // Validação de email
  if (!validateEmail(sanitizedEmail)) {
    return res.status(400).json({ message: 'Formato de email inválido.' });
  }

  // Validação de nome
  if (sanitizedName.length < 2 || sanitizedName.length > 50) {
    return res.status(400).json({ message: 'Nome deve ter entre 2 e 50 caracteres.' });
  }

  // Validação de senha mais rigorosa
  if (!validatePassword(password)) {
    return res.status(400).json({ 
      message: 'A senha deve ter pelo menos 8 caracteres, incluindo maiúscula, minúscula, número e caractere especial (@$!%*?&).' 
    });
  }

  try {
    // Verificar se o email já existe antes de tentar inserir
    const existingUser = await pool.query('SELECT id FROM users WHERE email = $1', [sanitizedEmail]);
    if (existingUser.rows.length > 0) {
      return res.status(409).json({ message: 'Este e-mail já está em uso.' });
    }

    const hashedPassword = await bcrypt.hash(password, 12); // Aumentado para 12 rounds
    const verificationToken = crypto.randomBytes(32).toString('hex');
    
    const insertQuery = 'INSERT INTO users (name, email, password, email_verification_token) VALUES ($1, $2, $3, $4) RETURNING id';
    const result = await pool.query(insertQuery, [sanitizedName, sanitizedEmail, hashedPassword, verificationToken]); 
    
    await sendVerificationEmail(sanitizedEmail, verificationToken);

    // Log de registro bem-sucedido
    console.log(`[REGISTER_SUCCESS] Novo usuário registrado: ${sanitizedEmail}`);

    res.status(201).json({ message: 'Usuário registrado com sucesso! Por favor, verifique seu e-mail.'});

  } catch (error) {
    console.error('Erro detalhado ao registrar usuário:', error);
    res.status(500).json({ message: 'Ocorreu um erro no servidor ao tentar registrar.' });
  }
});

// Login endpoint com proteções de segurança
app.post('/api/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email e senha são obrigatórios.' });
  }

  // Sanitização do email
  const sanitizedEmail = sanitizeInput(email);

  // Validação de email
  if (!validateEmail(sanitizedEmail)) {
    return res.status(400).json({ message: 'Formato de email inválido.' });
  }

  try {
    const findUserQuery = 'SELECT id, name, email, password, avatar_url, is_email_verified, role, "createdAt" FROM users WHERE email = $1';
    const result = await pool.query(findUserQuery, [sanitizedEmail]);

    if (result.rows.length === 0) {
      // Não revelar se o usuário existe ou não (timing attack protection)
      await bcrypt.hash(password, 10); // Simular tempo de processamento
      return res.status(401).json({ message: 'Credenciais inválidas.' });
    }

    const user = result.rows[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      // Log de tentativa de login falhada
      const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
      console.log(`[LOGIN_FAILED] Tentativa de login falhada para ${sanitizedEmail} - IP: ${ip}`);
      return res.status(401).json({ message: 'Credenciais inválidas.' });
    }
    
    if (!user.is_email_verified) {
      return res.status(403).json({ 
        message: 'Por favor, verifique seu e-mail antes de fazer login.',
        userId: user.id 
      });
    }
    
    // Inicia a busca de geolocalização em segundo plano, sem bloquear a resposta de login
    (async () => {
      try {
        const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        if (ip) {
          // Usamos um provedor de Geo-IP. ip-api.com é gratuito para uso não comercial.
          const geoResponse = await fetch(`https://ip-api.com/json/${ip}?fields=status,message,country,regionName,city,query`);
          const geoData = await geoResponse.json();
          
          if (geoData.status === 'success') {
            await pool.query(
              'UPDATE users SET last_ip = $1, country = $2, state = $3, city = $4 WHERE id = $5',
              [geoData.query, geoData.country, geoData.regionName, geoData.city, user.id]
            );
          }
        }
      } catch (geoError) {
        // Se a geolocalização falhar, não impede o login. Apenas registramos o erro.
        console.error('Erro ao buscar ou salvar geolocalização:', geoError);
      }
    })();

    // Login bem-sucedido, gerar token JWT com claims mais seguros
    const token = jwt.sign(
      { 
        userId: user.id, 
        email: user.email, 
        name: user.name, 
        avatar_url: user.avatar_url, 
        is_email_verified: user.is_email_verified, 
        role: user.role, 
        createdAt: user.createdAt,
        iat: Math.floor(Date.now() / 1000),
        iss: 'akemi-soft',
        aud: 'akemi-users'
      },
      process.env.JWT_SECRET,
      { 
        expiresIn: '1d',
        algorithm: 'HS256'
      }
    );

    // Log de login bem-sucedido
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    console.log(`[LOGIN_SUCCESS] Login bem-sucedido para ${sanitizedEmail} - IP: ${ip}`);

    res.status(200).json({ message: 'Login bem-sucedido!', token });

  } catch (error) {
    console.error('Erro detalhado ao fazer login:', error);
    res.status(500).json({ message: 'Ocorreu um erro no servidor ao tentar fazer login.' });
  }
});

// Middleware para verificar token com validação melhorada
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Formato "Bearer TOKEN"

  if (!token) {
    return res.status(401).json({ message: 'Token de acesso é obrigatório.' });
  }

  // Verificar formato do token
  if (!/^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$/.test(token)) {
    return res.status(401).json({ message: 'Formato de token inválido.' });
  }

  jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] }, (err, user) => {
    if (err) {
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({ message: 'Token expirado. Faça login novamente.' });
      } else if (err.name === 'JsonWebTokenError') {
        return res.status(401).json({ message: 'Token inválido.' });
      }
      return res.status(403).json({ message: 'Token malformado.' });
    }

    // Validação adicional dos claims
    if (!user.userId || !user.email || !user.role) {
      return res.status(403).json({ message: 'Token com claims inválidos.' });
    }

    // Verificar se o token não é muito antigo (opcional)
    const tokenAge = Math.floor(Date.now() / 1000) - (user.iat || 0);
    if (tokenAge > 86400) { // 24 horas
      return res.status(401).json({ message: 'Token muito antigo. Faça login novamente.' });
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

// Rota para atualizar o perfil do usuário
app.patch('/api/user/profile', authenticateToken, async (req, res) => {
  const { name, email, bio, profile_color, profile_effect, music_url } = req.body;
  const { userId } = req.user;

  // Validação básica
  if (!name || !email) {
    return res.status(400).json({ message: 'Nome e email são obrigatórios.' });
  }

  try {
    const client = await pool.connect();
    
    // Constrói a query de atualização dinamicamente
    const fieldsToUpdate = [];
    const values = [];
    let queryIndex = 1;

    if (name) {
      fieldsToUpdate.push(`name = $${queryIndex++}`);
      values.push(name);
    }
    if (email) {
      // Adicional: verificar se o novo email já não está em uso por outro usuário
      const emailCheck = await client.query('SELECT id FROM users WHERE email = $1 AND id != $2', [email, userId]);
      if (emailCheck.rows.length > 0) {
        return res.status(409).json({ message: 'Este email já está em uso por outra conta.' });
      }
      fieldsToUpdate.push(`email = $${queryIndex++}`);
      values.push(email);
    }
    if (bio || bio === '') { // Permite limpar a bio
      fieldsToUpdate.push(`bio = $${queryIndex++}`);
      values.push(bio);
    }
    if (profile_color) {
        fieldsToUpdate.push(`profile_color = $${queryIndex++}`);
        values.push(profile_color);
    }
    if (profile_effect || profile_effect === 'none' || profile_effect === '') {
        fieldsToUpdate.push(`profile_effect = $${queryIndex++}`);
        values.push(profile_effect);
    }
    if (music_url || music_url === '') { // Permite limpar a URL
        fieldsToUpdate.push(`music_url = $${queryIndex++}`);
        values.push(music_url);
    }

    if (fieldsToUpdate.length === 0) {
      return res.status(400).json({ message: 'Nenhuma informação para atualizar.' });
    }

    values.push(userId);
    const updateQuery = `UPDATE users SET ${fieldsToUpdate.join(', ')} WHERE id = $${queryIndex} RETURNING *`;

    const result = await client.query(updateQuery, values);
    client.release();

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado para atualização.' });
    }
    const updatedUser = result.rows[0];

    // Gerar um novo token com as informações atualizadas
    const newToken = jwt.sign(
      { userId: updatedUser.id, email: updatedUser.email, name: updatedUser.name, avatar_url: updatedUser.avatar_url, is_email_verified: updatedUser.is_email_verified, role: updatedUser.role, bio: updatedUser.bio, profile_color: updatedUser.profile_color, profile_effect: updatedUser.profile_effect, music_url: updatedUser.music_url },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );
    
    res.status(200).json({ 
      message: 'Perfil atualizado com sucesso!',
      token: newToken
    });

  } catch (error) {
    console.error('Erro detalhado ao atualizar perfil:', error);
    if (error.code === '23505' && error.constraint === 'users_email_key') {
         return res.status(409).json({ message: 'Este email já está em uso por outra conta.' });
    }
    res.status(500).json({ message: 'Ocorreu um erro no servidor ao tentar atualizar o perfil.', error: error.message });
  }
});

// Rota para trocar a senha
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

        // Notifica o cliente via Pusher que o e-mail foi verificado
        pusher.trigger(`user-${userId}`, 'email-verified', {
            message: 'E-mail verificado com sucesso!',
            verified: true
        });

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

// Rota para fazer upload do avatar com validação de segurança
app.post('/api/user/avatar', uploadLimiter, authenticateToken, upload.single('avatar'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ message: 'Nenhum arquivo foi enviado.' });
  }

  // Validação de tipo de arquivo
  const allowedMimeTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp'];
  if (!allowedMimeTypes.includes(req.file.mimetype)) {
    return res.status(400).json({ message: 'Tipo de arquivo não suportado. Use apenas JPEG, PNG ou WebP.' });
  }

  // Validação de tamanho (máximo 5MB)
  const maxSize = 5 * 1024 * 1024; // 5MB
  if (req.file.size > maxSize) {
    return res.status(400).json({ message: 'Arquivo muito grande. Tamanho máximo: 5MB.' });
  }

  const { userId } = req.user;
  const filename = `avatars/${userId}-${Date.now()}-${crypto.randomBytes(8).toString('hex')}`;

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
      { 
        userId: updatedUser.id, 
        email: updatedUser.email, 
        name: updatedUser.name, 
        avatar_url: updatedUser.avatar_url, 
        is_email_verified: updatedUser.is_email_verified, 
        role: updatedUser.role, 
        createdAt: updatedUser.createdAt,
        iat: Math.floor(Date.now() / 1000),
        iss: 'akemi-soft',
        aud: 'akemi-users'
      },
      process.env.JWT_SECRET,
      { 
        expiresIn: '1d',
        algorithm: 'HS256'
      }
    );

    res.status(200).json({ message: 'Avatar atualizado com sucesso!', token, avatar_url: blob.url });

  } catch (error) {
    console.error('Erro ao fazer upload do avatar:', error);
    res.status(500).json({ message: 'Ocorreu um erro no servidor ao processar o avatar.' });
  }
});

// Rota para fazer upload do banner
app.post('/api/user/banner', authenticateToken, upload.single('banner'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ message: 'Nenhum arquivo foi enviado.' });
  }

  const { userId } = req.user;
  const filename = `banners/${userId}-${Date.now()}`;

  try {
    const blob = await put(filename, req.file.buffer, {
      access: 'public',
      contentType: req.file.mimetype,
    });

    // Atualiza a URL do banner no banco de dados
    await pool.query('UPDATE users SET banner_url = $1 WHERE id = $2', [blob.url, userId]);

    // Busca os dados atualizados para gerar um novo token
    const findUserQuery = 'SELECT id, name, email, avatar_url, banner_url, is_email_verified, role, "createdAt" FROM users WHERE id = $1';
    const updatedUserResult = await pool.query(findUserQuery, [userId]);
    const updatedUser = updatedUserResult.rows[0];

    // Gera um novo token com a URL do banner
    const token = jwt.sign(
      { userId: updatedUser.id, email: updatedUser.email, name: updatedUser.name, avatar_url: updatedUser.avatar_url, banner_url: updatedUser.banner_url, is_email_verified: updatedUser.is_email_verified, role: updatedUser.role, createdAt: updatedUser.createdAt },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );

    res.status(200).json({ message: 'Banner atualizado com sucesso!', token, banner_url: blob.url });

  } catch (error) {
    console.error('Erro ao fazer upload do banner:', error);
    res.status(500).json({ message: 'Ocorreu um erro no servidor ao processar o banner.' });
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

// Rota para buscar um perfil de usuário PÚBLICO
app.get('/api/user-profile/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const findUserQuery = 'SELECT id, name, avatar_url, bio, banner_url, profile_color, profile_effect, music_url, discord_username, spotify_username FROM users WHERE id = $1';
    const result = await pool.query(findUserQuery, [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado.' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Erro ao buscar perfil de usuário:', error);
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

// Rota para buscar todos os usuários (para a comunidade)
app.get('/api/users/all', authenticateToken, isAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, name, email, role, last_ip, city, state, country, avatar_url FROM users ORDER BY name ASC');
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

// Rota para um admin atualizar os dados de um usuário
app.patch('/api/admin/users/:id', authenticateToken, isAdmin, async (req, res) => {
  const { id } = req.params;
  const { email, password } = req.body;

  if (!email && !password) {
    return res.status(400).json({ message: 'Nenhum dado para atualizar (email ou senha).' });
  }

  try {
    const fieldsToUpdate = [];
    const values = [];
    let queryIndex = 1;

    if (email) {
      fieldsToUpdate.push(`email = $${queryIndex++}`);
      values.push(email);
    }

    if (password) {
      if (password.length < 8) {
        return res.status(400).json({ message: 'A nova senha deve ter pelo menos 8 caracteres.' });
      }
      const hashedPassword = await bcrypt.hash(password, 10);
      fieldsToUpdate.push(`password = $${queryIndex++}`);
      values.push(hashedPassword);
    }

    values.push(id);
    const updateQuery = `UPDATE users SET ${fieldsToUpdate.join(', ')} WHERE id = $${queryIndex} RETURNING id, email`;

    const result = await pool.query(updateQuery, values);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado.' });
    }

    res.status(200).json({ message: 'Usuário atualizado com sucesso!', user: result.rows[0] });

  } catch (error) {
    if (error.code === '23505') { // unique_violation (email)
      return res.status(409).json({ message: 'Este e-mail já está em uso por outra conta.' });
    }
    console.error(`Erro ao atualizar usuário ${id} pelo admin:`, error);
    res.status(500).json({ message: 'Ocorreu um erro no servidor.' });
  }
});

// Rota para um admin DELETAR um usuário
app.delete('/api/admin/users/:id', authenticateToken, isAdmin, async (req, res) => {
  const { id } = req.params;
  const adminUserId = req.user.userId;

  // Prevenção de auto-deleção
  if (id.toString() === adminUserId.toString()) {
    return res.status(403).json({ message: 'Você não pode remover sua própria conta de administrador.' });
  }

  try {
    const result = await pool.query('DELETE FROM users WHERE id = $1 RETURNING id', [id]);
    
    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado.' });
    }

    res.status(200).json({ message: 'Usuário removido com sucesso!' });

  } catch (error) {
    console.error(`Erro ao remover usuário ${id} pelo admin:`, error);
    res.status(500).json({ message: 'Ocorreu um erro no servidor ao tentar remover o usuário.' });
  }
});

// --- Integração com Discord ---

// Callback que o Discord chama após a autorização
app.get('/api/auth/discord/callback', async (req, res) => {
  const { code, state: userId } = req.query;

  if (!code || !userId) {
    return res.redirect('/settings?error=discord_auth_failed');
  }

  try {
    const redirectUriForToken = `${process.env.BASE_URL}/api/auth/discord/callback`;
    console.log(`[DEBUG] Enviando para o Discord a redirect_uri: ${redirectUriForToken}`);

    // Trocar o código por um token de acesso
    const tokenResponse = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        client_id: process.env.DISCORD_CLIENT_ID,
        client_secret: process.env.DISCORD_CLIENT_SECRET,
        grant_type: 'authorization_code',
        code: code.toString(),
        redirect_uri: redirectUriForToken,
      }),
    });

    const tokenData = await tokenResponse.json();

    // Log detalhado para depuração
    console.log('Resposta do token do Discord:', tokenData);

    if (!tokenResponse.ok || !tokenData.access_token) {
      throw new Error('Falha ao obter token de acesso do Discord. Resposta: ' + JSON.stringify(tokenData));
    }

    // Usar o token de acesso para buscar os dados do usuário do Discord
    const userResponse = await fetch('https://discord.com/api/users/@me', {
      headers: {
        Authorization: `Bearer ${tokenData.access_token}`,
      },
    });

    const discordUser = await userResponse.json();

    const avatarHash = discordUser.avatar;
    const discordUserId = discordUser.id;
    const discordAvatarUrl = avatarHash 
      ? `https://cdn.discordapp.com/avatars/${discordUserId}/${avatarHash}.png`
      : `https://cdn.discordapp.com/embed/avatars/${parseInt(discordUser.discriminator) % 5}.png`;
    
    // Salvar os dados do Discord no nosso banco de dados
    const query = `
      UPDATE users 
      SET discord_id = $1, discord_username = $2, discord_avatar_url = $3 
      WHERE id = $4
    `;
    await pool.query(query, [discordUser.id, discordUser.username, discordAvatarUrl, userId]);

    // Buscar todos os dados atualizados do usuário para gerar um novo token
    const findUserQuery = 'SELECT * FROM users WHERE id = $1';
    const updatedUserResult = await pool.query(findUserQuery, [userId]);
    const fullUser = updatedUserResult.rows[0];

    // Gerar um novo token com todos os dados, incluindo os do Discord
    const newTokenPayload = {
        userId: fullUser.id,
        email: fullUser.email,
        name: fullUser.name,
        avatar_url: fullUser.avatar_url,
        is_email_verified: fullUser.is_email_verified,
        role: fullUser.role,
        bio: fullUser.bio,
        createdAt: fullUser.createdAt,
        discord_id: fullUser.discord_id,
        discord_username: fullUser.discord_username,
    };

    const newToken = jwt.sign(newTokenPayload, process.env.JWT_SECRET, { expiresIn: '1d' });
    
    // Redireciona de volta para a página de configurações com sucesso e o novo token
    res.redirect(`/settings?success=discord_linked&token=${newToken}`);

  } catch (error) {
    console.error('Erro na autenticação com Discord:', error);
    res.redirect('/settings?error=discord_link_failed');
  }
});

// Rota para iniciar a autenticação com o Spotify
app.get('/api/auth/spotify', authenticateToken, (req, res) => {
  const state = req.user.userId; // Usar o userId para segurança
  const scope = 'user-read-private user-read-email';
  
  if (!process.env.SPOTIFY_CLIENT_ID) {
    return res.status(500).send('Configuração do Spotify no servidor está incompleta.');
  }

  res.redirect('https://accounts.spotify.com/authorize?' +
    new URLSearchParams({
      response_type: 'code',
      client_id: process.env.SPOTIFY_CLIENT_ID,
      scope: scope,
      redirect_uri: `${process.env.BASE_URL}/api/auth/spotify/callback`,
      state: state
    }).toString());
});

// Rota de callback do Spotify
app.get('/api/auth/spotify/callback', authenticateToken, async (req, res) => {
  const { code, state } = req.query;
  const userId = req.user.userId;

  // Medida de segurança: verificar se o 'state' corresponde ao userId
  if (state !== userId.toString()) {
    return res.redirect(`${process.env.BASE_URL}/settings?error=spotify_state_mismatch`);
  }

  const authOptions = {
    method: 'POST',
    url: 'https://accounts.spotify.com/api/token',
    headers: {
      'Authorization': 'Basic ' + (Buffer.from(process.env.SPOTIFY_CLIENT_ID + ':' + process.env.SPOTIFY_CLIENT_SECRET).toString('base64')),
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: new URLSearchParams({
      code: code,
      redirect_uri: `${process.env.BASE_URL}/api/auth/spotify/callback`,
      grant_type: 'authorization_code'
    }).toString()
  };

  try {
    // 1. Trocar o código de autorização por um token de acesso
    const authResponse = await fetch(authOptions.url, { method: authOptions.method, headers: authOptions.headers, body: authOptions.body });
    const tokenData = await authResponse.json();

    if (tokenData.error) {
      throw new Error(`Erro do Spotify: ${tokenData.error_description}`);
    }

    const { access_token, refresh_token, expires_in } = tokenData;

    // 2. Usar o token de acesso para buscar o perfil do usuário no Spotify
    const userProfileResponse = await fetch('https://api.spotify.com/v1/me', {
      headers: { 'Authorization': `Bearer ${access_token}` }
    });
    const spotifyProfile = await userProfileResponse.json();

    // 3. Salvar as informações no banco de dados
    const tokenExpires = new Date(Date.now() + expires_in * 1000);
    const spotifyAvatar = spotifyProfile.images?.[0]?.url;

    const updateQuery = `
      UPDATE users 
      SET 
        spotify_id = $1, 
        spotify_username = $2,
        spotify_avatar_url = $3,
        spotify_access_token = $4, 
        spotify_refresh_token = $5,
        spotify_token_expires = $6
      WHERE id = $7
    `;
    await pool.query(updateQuery, [
      spotifyProfile.id,
      spotifyProfile.display_name,
      spotifyAvatar,
      access_token,
      refresh_token,
      tokenExpires,
      userId
    ]);
    
    // 4. Redirecionar de volta para as configurações com uma mensagem de sucesso
    res.redirect(`${process.env.BASE_URL}/settings?success=spotify_linked`);

  } catch (error) {
    console.error('Erro ao vincular conta do Spotify:', error);
    res.redirect(`${process.env.BASE_URL}/settings?error=spotify_link_failed`);
  }
});

// --- Integração com Game Status ---
app.get('/api/gamestatus', async (req, res) => {
  try {
    const gamesToFetch = {
      minecraft: 'https://api.mcsrvstat.us/3/hypixel.net', // Usando Hypixel como exemplo
      valorant: 'https://riotstatus.vercel.app/valorant',
      leagueoflegends: 'https://riotstatus.vercel.app/lol',
    };

    const promises = Object.entries(gamesToFetch).map(async ([game, url]) => {
      try {
        const response = await fetch(url);
        if (!response.ok) {
          console.warn(`A API de status para ${game} falhou com status: ${response.status}`);
          return { game, status: 'unknown' };
        }
        const data = await response.json();
        
        let status = 'unknown';
        if (game === 'minecraft') {
          status = data.online ? 'online' : 'offline';
        } else if (game === 'valorant' || game === 'leagueoflegends') {
          // A API da Riot retorna um array de incidentes. Se não houver incidentes, está online.
          // Isso é uma simplificação. A API real pode ter uma estrutura mais complexa.
          const hasIncidents = data.incidents && data.incidents.length > 0;
          const hasMaintenances = data.maintenances && data.maintenances.length > 0;
          if (hasMaintenances) {
            status = 'maintenance';
          } else if (!hasIncidents) {
            status = 'online';
          } else {
            // Poderíamos ser mais específicos sobre o tipo de incidente aqui
            status = 'offline'; 
          }
        }
        return { game, status };
      } catch (error) {
        console.error(`Erro ao buscar status para ${game}:`, error);
        return { game, status: 'unknown' };
      }
    });

    const results = await Promise.all(promises);

    const gameStatus = results.reduce((acc, curr) => {
      acc[curr.game] = curr.status;
      return acc;
    }, {});
    
    // Adicionando placeholders para os jogos que ainda não têm API
    const allGames = ['minecraft', 'leagueoflegends', 'cs2', 'fortnite', 'valorant', 'thefinals', 'gta5'];
    allGames.forEach(game => {
      if (!gameStatus[game]) {
        gameStatus[game] = 'unknown';
      }
    });

    res.json(gameStatus);

  } catch (error) {
    console.error('Erro geral na rota /api/gamestatus:', error);
    res.status(500).json({ message: 'Erro ao buscar status dos jogos.' });
  }
});

module.exports = app; 