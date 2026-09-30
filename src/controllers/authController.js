const crypto = require('crypto');
const { sendVerificationEmail } = require('../services/emailService');
const argon2 = require('argon2');
const pool = require('../db/pool');
const { registerSchema } = require('../validators/authValidator');
const { loginSchema } = require('../validators/authValidator');
const { generateAccessToken, generateRefreshToken, hashToken } = require('../services/tokenService');
const { sendPasswordResetEmail } = require('../services/emailService');
const { forgotPasswordSchema, resetPasswordSchema } = require('../validators/authValidator');

async function register(req, res) {
  const parsed = registerSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: 'Datos inválidos' });
  }

  const { email, password } = parsed.data;

  try {
    const passwordHash = await argon2.hash(password, { type: argon2.argon2id });

    const result = await pool.query(
      'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email',
      [email, passwordHash]
    );
    const verificationToken = crypto.randomBytes(32).toString('hex');

await pool.query(
  `UPDATE users SET verification_token = $1, verification_expires = now() + interval '1 hour' WHERE id = $2`,
  [verificationToken, result.rows[0].id]
);

await sendVerificationEmail(email, verificationToken);

    return res.status(201).json({ user: result.rows[0] });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'No se pudo completar el registro' });
    }
    console.error(err);
    return res.status(500).json({ error: 'Error del servidor' });
  }
}
const MAX_ATTEMPTS = 5;
const LOCK_MINUTES = 15;

async function login(req, res) {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: 'Datos inválidos' });
  }

  const { email, password } = parsed.data;

  try {
    const result = await pool.query(
      
  'SELECT id, email, password_hash, failed_attempts, locked_until, email_verified FROM users WHERE email = $1',
  [email]
);
    
    const user = result.rows[0];

    // Mensaje genérico siempre, exista o no el usuario
    const genericError = () => res.status(401).json({ error: 'Credenciales inválidas' });

    if (!user) return genericError();
    if (!user.email_verified) {
  return res.status(403).json({ error: 'Debes verificar tu correo antes de iniciar sesión' });
}

    // Revisa si la cuenta está bloqueada
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      return res.status(423).json({ error: 'Cuenta bloqueada temporalmente. Intenta más tarde.' });
    }

    const validPassword = await argon2.verify(user.password_hash, password);

    if (!validPassword) {
      const attempts = user.failed_attempts + 1;
      const shouldLock = attempts >= MAX_ATTEMPTS;

      await pool.query(
        `UPDATE users SET failed_attempts = $1, locked_until = $2 WHERE id = $3`,
        [
          shouldLock ? 0 : attempts,
          shouldLock ? new Date(Date.now() + LOCK_MINUTES * 60000) : null,
          user.id
        ]
      );

      return genericError();
    }

    // Login correcto: resetear intentos fallidos
    await pool.query(
      'UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = $1',
      [user.id]
    );

    // Generar tokens
    const accessToken = generateAccessToken(user.id);
    const { token: refreshToken, tokenHash } = generateRefreshToken();

    await pool.query(
      `INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
       VALUES ($1, $2, now() + interval '7 days')`,
      [user.id, tokenHash]
    );

    // Cookies seguras
    res.cookie('accessToken', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 15 * 60 * 1000
    });
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    return res.json({ user: { id: user.id, email: user.email } });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Error del servidor' });
  }
}

async function refresh(req, res) {
  const token = req.cookies.refreshToken;
  if (!token) {
    return res.status(401).json({ error: 'No autenticado' });
  }

  const tokenHash = hashToken(token);

  try {
    const result = await pool.query(
      `SELECT id, user_id, expires_at, revoked FROM refresh_tokens WHERE token_hash = $1`,
      [tokenHash]
    );
    const stored = result.rows[0];

    if (!stored || stored.revoked || new Date(stored.expires_at) < new Date()) {
      return res.status(401).json({ error: 'Sesión inválida, inicia sesión de nuevo' });
    }

    // Rotación: se invalida el token viejo y se crea uno nuevo
    await pool.query('UPDATE refresh_tokens SET revoked = true WHERE id = $1', [stored.id]);

    const accessToken = generateAccessToken(stored.user_id);
    const { token: newRefreshToken, tokenHash: newHash } = generateRefreshToken();

    await pool.query(
      `INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
       VALUES ($1, $2, now() + interval '7 days')`,
      [stored.user_id, newHash]
    );

    res.cookie('accessToken', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 15 * 60 * 1000
    });
    res.cookie('refreshToken', newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    return res.json({ message: 'Token renovado' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Error del servidor' });
  }
}

async function logout(req, res) {
  const token = req.cookies.refreshToken;

  if (token) {
    const tokenHash = hashToken(token);
    await pool.query('UPDATE refresh_tokens SET revoked = true WHERE token_hash = $1', [tokenHash]);
  }

  res.clearCookie('accessToken');
  res.clearCookie('refreshToken');
  return res.json({ message: 'Sesión cerrada' });
}
async function me(req, res) {
  try {
    const result = await pool.query('SELECT id, email FROM users WHERE id = $1', [req.userId]);
    return res.json({ user: result.rows[0] });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Error del servidor' });
  }
}
async function verifyEmail(req, res) {
  const { token } = req.query;

  if (!token) {
    return res.status(400).json({ error: 'Token requerido' });
  }

  try {
    const result = await pool.query(
      `SELECT id, verification_expires FROM users WHERE verification_token = $1`,
      [token]
    );
    const user = result.rows[0];

    if (!user || new Date(user.verification_expires) < new Date()) {
      return res.status(400).json({ error: 'Token inválido o expirado' });
    }

    await pool.query(
      `UPDATE users SET email_verified = true, verification_token = NULL, verification_expires = NULL WHERE id = $1`,
      [user.id]
    );

    return res.json({ message: 'Correo verificado exitosamente' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Error del servidor' });
  }
}

async function forgotPassword(req, res) {
  const parsed = forgotPasswordSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: 'Datos inválidos' });
  }

  const { email } = parsed.data;

  try {
    const result = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

    // Respuesta genérica siempre, exista o no el correo (evita filtrar qué correos están registrados)
    if (user) {
      const resetToken = crypto.randomBytes(32).toString('hex');

      await pool.query(
        `UPDATE users SET reset_token = $1, reset_expires = now() + interval '1 hour' WHERE id = $2`,
        [resetToken, user.id]
      );

      await sendPasswordResetEmail(email, resetToken);
    }

    return res.json({ message: 'Si el correo existe, se envió un enlace de recuperación' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Error del servidor' });
  }
}

async function resetPassword(req, res) {
  const parsed = resetPasswordSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: 'Datos inválidos' });
  }

  const { token, password } = parsed.data;

  try {
    const result = await pool.query(
      'SELECT id, reset_expires FROM users WHERE reset_token = $1',
      [token]
    );
    const user = result.rows[0];

    if (!user || new Date(user.reset_expires) < new Date()) {
      return res.status(400).json({ error: 'Token inválido o expirado' });
    }

    const passwordHash = await argon2.hash(password, { type: argon2.argon2id });

    await pool.query(
      `UPDATE users SET password_hash = $1, reset_token = NULL, reset_expires = NULL WHERE id = $2`,
      [passwordHash, user.id]
    );

    // Por seguridad, invalida todas las sesiones activas de este usuario
    await pool.query('UPDATE refresh_tokens SET revoked = true WHERE user_id = $1', [user.id]);

    return res.json({ message: 'Contraseña actualizada exitosamente' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Error del servidor' });
  }
}


module.exports = { register, login, refresh, logout, me, verifyEmail, forgotPassword, resetPassword };