const nodemailer = require('nodemailer');

// Returns null when SMTP is not configured — callers must check
function createTransport() {
  const host = process.env.SMTP_HOST;
  if (!host) return null;
  return nodemailer.createTransport({
    host,
    port:   parseInt(process.env.SMTP_PORT || '587'),
    secure: process.env.SMTP_SECURE === 'true',
    auth: process.env.SMTP_USER ? {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    } : undefined,
  });
}

const FROM = process.env.SMTP_FROM || 'Flowdit <no-reply@flowdit.app>';

async function sendTicketReplyNotification({ toEmail, toName, projectName, ticketTitle, replyBody, replyAuthor, portalUrl }) {
  const transport = createTransport();
  if (!transport) return; // SMTP not configured — silently skip

  const displayName = toName || toEmail;
  const body        = replyBody.length > 500 ? replyBody.slice(0, 500) + '…' : replyBody;

  await transport.sendMail({
    from:    FROM,
    to:      toEmail,
    subject: `Re: ${ticketTitle} — ${projectName}`,
    text: [
      `Hi ${displayName},`,
      '',
      `${replyAuthor} replied to your query "${ticketTitle}":`,
      '',
      body,
      '',
      portalUrl ? `View the full conversation: ${portalUrl}` : '',
      '',
      '— Flowdit',
    ].join('\n'),
    html: `
      <div style="font-family:sans-serif;max-width:560px;color:#111">
        <p>Hi <strong>${esc(displayName)}</strong>,</p>
        <p><strong>${esc(replyAuthor)}</strong> replied to your query
          "<strong>${esc(ticketTitle)}</strong>" on <strong>${esc(projectName)}</strong>:</p>
        <blockquote style="border-left:3px solid #f59e0b;margin:16px 0;padding:8px 16px;background:#fafafa;color:#333">
          ${esc(body).replace(/\n/g, '<br>')}
        </blockquote>
        ${portalUrl ? `<p><a href="${portalUrl}" style="color:#f59e0b">View the full conversation →</a></p>` : ''}
        <hr style="border:none;border-top:1px solid #eee;margin:24px 0">
        <p style="font-size:12px;color:#999">Sent by Flowdit · Do not reply to this email</p>
      </div>`,
  });
}

// ROADMAP.md § "Notificación al celular cuando el AI Agent necesita
// atención" — el feed de Activity (ai_scan_needs_attention, ver
// notifyNeedsAttention() en agentLoop.js) es solo in-app/WS, nada llega
// afuera del navegador. Reusa esta misma infra de SMTP (ya configurable vía
// env vars, no-op si no está seteado) en vez de levantar un canal nuevo —
// no es push nativo al celular, pero cualquier app de mail con
// notificaciones activadas se acerca bastante, y es el canal de menor
// esfuerzo dado lo que ya existe.
async function sendAiScanNeedsAttentionNotification({ toEmail, toName, projectName, message, appUrl }) {
  const transport = createTransport();
  if (!transport) return; // SMTP not configured — silently skip

  const displayName = toName || toEmail;

  await transport.sendMail({
    from:    FROM,
    to:      toEmail,
    subject: `AI Agent needs your attention — ${projectName}`,
    text: [
      `Hi ${displayName},`,
      '',
      `The AI Pentest Agent on "${projectName}" needs your attention:`,
      '',
      message,
      '',
      appUrl ? `Open the session: ${appUrl}` : '',
      '',
      '— Flowdit',
    ].join('\n'),
    html: `
      <div style="font-family:sans-serif;max-width:560px;color:#111">
        <p>Hi <strong>${esc(displayName)}</strong>,</p>
        <p>The AI Pentest Agent on <strong>${esc(projectName)}</strong> needs your attention:</p>
        <blockquote style="border-left:3px solid #f59e0b;margin:16px 0;padding:8px 16px;background:#fafafa;color:#333">
          ${esc(message)}
        </blockquote>
        ${appUrl ? `<p><a href="${appUrl}" style="color:#f59e0b">Open the session →</a></p>` : ''}
        <hr style="border:none;border-top:1px solid #eee;margin:24px 0">
        <p style="font-size:12px;color:#999">Sent by Flowdit · Do not reply to this email</p>
      </div>`,
  });
}

function esc(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

module.exports = { sendTicketReplyNotification, sendAiScanNeedsAttentionNotification };
