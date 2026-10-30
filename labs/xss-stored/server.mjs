// LAB — INTENTIONALLY VULNERABLE. Runs only inside an isolated lab container
// (no network egress, read-only, unprivileged). Never copy this code anywhere.
//
// Guestbook with moderation. The public page escapes messages; the moderation
// page does not (stored XSS, CWE-79). A moderator bot, a real headless browser,
// reviews every new message with its session cookie, which is the flag, and
// that cookie is readable by scripts (no HttpOnly).
import { createServer } from 'node:http';
import { launchBot } from './bot.mjs';

const FLAG = process.env.FLAG;
if (!FLAG) {
  console.error('FLAG is required');
  process.exit(1);
}
const PORT = Number(process.env.PORT ?? 8080);
const MAX_MESSAGES = 200;

/** @type {{ id: number, auteur: string, message: string, reviewed: boolean, at: string }[]} */
const messages = [{ id: 1, auteur: 'Équipe', message: 'Bienvenue sur notre livre d’or ! Les messages sont relus par un modérateur.', reviewed: true, at: '09:00' }];
let nextId = 2;

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const page = (title, body) => `<!doctype html><html lang="fr"><meta charset="utf-8"><title>${title}</title>
<style>body{font-family:system-ui,sans-serif;max-width:46rem;margin:3rem auto;padding:0 1rem}
article{border:1px solid #ddd;border-radius:8px;padding:.6rem 1rem;margin:.6rem 0}textarea,input{display:block;width:100%;margin:.3rem 0 .8rem;padding:.4rem}</style>
<h1>${title}</h1>${body}</html>`;

const cookieOf = (req, name) =>
  (req.headers.cookie ?? '')
    .split(';')
    .map((c) => c.trim().split('='))
    .find(([k]) => k === name)?.[1];

// The moderator: one browser, one visit at a time. Messages posted while the
// browser is still starting are queued, not dropped.
let bot = null;
let botReady = null;
let queue = Promise.resolve();
let base = `http://127.0.0.1:${PORT}`; // fixed once the server knows its real port
function review() {
  if (!botReady) return;
  queue = queue
    .then(() => botReady)
    .then((b) => b.visit(`${base}/admin/moderation`, { name: 'session_moderateur', value: FLAG, httpOnly: false }))
    .catch((err) => console.error('moderation visit failed:', err.message));
}

const readForm = (req) =>
  new Promise((resolve) => {
    let raw = '';
    req.setEncoding('utf8');
    req.on('data', (c) => {
      raw += c;
      if (raw.length > 10_000) req.destroy();
    });
    req.on('end', () => resolve(new URLSearchParams(raw)));
  });

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', 'http://lab');
  const send = (status, html) => {
    res.writeHead(status, { 'content-type': 'text/html; charset=utf-8' });
    res.end(html);
  };

  if (req.method === 'GET' && url.pathname === '/') {
    // Public page: correctly escaped.
    const list = messages.map((m) => `<article><strong>${esc(m.auteur)}</strong> <small>${esc(m.at)}</small><p>${esc(m.message)}</p></article>`).join('');
    return send(
      200,
      page(
        'Livre d’or',
        `<form method="post" action="/messages"><label>Ton nom<input name="auteur" maxlength="60"></label>
<label>Ton message<textarea name="message" rows="4" maxlength="2000"></textarea></label><button>Publier</button></form>
<p><small>${botReady ? 'Un modérateur relit chaque nouveau message dans les secondes qui suivent.' : 'Modérateur indisponible.'}</small></p>${list}`,
      ),
    );
  }

  if (req.method === 'POST' && url.pathname === '/messages') {
    const form = await readForm(req);
    if (messages.length >= MAX_MESSAGES) messages.splice(1, 1);
    messages.push({
      id: nextId++,
      auteur: (form.get('auteur') ?? 'anonyme').slice(0, 60) || 'anonyme',
      message: (form.get('message') ?? '').slice(0, 2000),
      reviewed: false,
      at: new Date().toISOString().slice(11, 19),
    });
    review();
    res.writeHead(303, { location: '/' });
    return res.end();
  }

  if (req.method === 'GET' && url.pathname === '/admin/moderation') {
    if (cookieOf(req, 'session_moderateur') !== FLAG) return send(403, page('Modération', '<p>Réservé aux modérateurs.</p>'));
    const pending = messages.filter((m) => !m.reviewed);
    for (const m of pending) m.reviewed = true;
    // VULNERABLE: messages are inserted as raw HTML in the moderator's page.
    const list = pending.map((m) => `<article><strong>${m.auteur}</strong><p>${m.message}</p></article>`).join('');
    return send(200, page('Modération', list || '<p>Rien à relire.</p>'));
  }

  return send(404, page('Introuvable', '<p>Page introuvable.</p>'));
});

server.listen(PORT, process.env.HOST ?? '0.0.0.0', () => {
  base = `http://127.0.0.1:${server.address().port}`;
  console.log(`lab xss-stored listening on ${server.address().port}`);
  botReady = launchBot(process.env.CHROME_BIN ?? '/usr/bin/chromium');
  botReady.then(
    (b) => {
      bot = b;
      console.log('moderator bot ready');
    },
    (err) => {
      botReady = null;
      console.error('moderator bot unavailable:', err.message);
    },
  );
});

for (const signal of ['SIGTERM', 'SIGINT']) {
  process.on(signal, () => {
    bot?.close();
    server.close(() => process.exit(0));
  });
}
