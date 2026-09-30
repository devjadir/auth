const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 10, // máximo 10 intentos por IP en ese periodo
  message: { error: 'Demasiados intentos. Intenta más tarde.' },
  standardHeaders: true,
  legacyHeaders: false
});

module.exports = { loginLimiter };