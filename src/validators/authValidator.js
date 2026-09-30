const { z } = require('zod');

const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8).max(72)
});
const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1)
});
const forgotPasswordSchema = z.object({
  email: z.string().email()
});

const resetPasswordSchema = z.object({
  token: z.string().min(1),
  password: z.string().min(8).max(72)
});

module.exports = { registerSchema, loginSchema, forgotPasswordSchema, resetPasswordSchema };