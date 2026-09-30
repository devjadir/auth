const { Resend } = require('resend');

const resend = new Resend(process.env.RESEND_API_KEY);

async function sendVerificationEmail(to, token) {
  const verifyUrl = `${process.env.FRONTEND_URL}/verify.html?token=${token}`;

  await resend.emails.send({
    from: 'onboarding@resend.dev',
    to,
    subject: 'Verifica tu correo',
    html: `
      <p>Gracias por registrarte. Haz clic para verificar tu correo:</p>
      <p><a href="${verifyUrl}">${verifyUrl}</a></p>
      <p>Este enlace expira en 1 hora.</p>
    `
  });
}
async function sendPasswordResetEmail(to, token) {
  const resetUrl = `${process.env.FRONTEND_URL}/reset-password.html?token=${token}`;

  await resend.emails.send({
    from: 'onboarding@resend.dev',
    to,
    subject: 'Recupera tu contraseña',
    html: `
      <p>Solicitaste recuperar tu contraseña. Haz clic para crear una nueva:</p>
      <p><a href="${resetUrl}">${resetUrl}</a></p>
      <p>Si no fuiste tú, ignora este correo. Este enlace expira en 1 hora.</p>
    `
  });
}
module.exports = { sendVerificationEmail, sendPasswordResetEmail };

