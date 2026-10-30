// LAB — INTENTIONALLY VULNERABLE. Runs only inside an isolated lab container
// (no network egress, read-only, unprivileged). Never copy this code anywhere.
//
// Sign-up API that copies the whole request body into the new account
// (mass assignment, OWASP API3:2023). The admin report holds the flag.
import { randomBytes } from 'node:crypto';
import { createServer } from 'node:http';

const FLAG = process.env.FLAG;
if (!FLAG) {
  console.error('FLAG is required');
  process.exit(1);
}

const accounts = new Map();
const sessions = new Map();

const json = (res, status, body) => {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(body));
};
const readBody = (req) =>
  new Promise((resolve) => {
    let raw = '';
    req.setEncoding('utf8');
    req.on('data', (c) => {
      raw += c;
      if (raw.length > 10_000) req.destroy();
    });
    req.on('end', () => {
      try {
        const v = JSON.parse(raw || '{}');
        resolve(v && typeof v === 'object' && !Array.isArray(v) ? v : {});
      } catch {
        resolve({});
      }
    });
  });

const HOME = `<!doctype html><html lang="fr"><meta charset="utf-8"><title>Espace membres</title>
<style>body{font-family:system-ui,sans-serif;max-width:46rem;margin:3rem auto;padding:0 1rem}pre{background:#eee;padding:1rem}</style>
<h1>API de l'espace membres</h1>
<pre>POST /api/inscription      {"email": "...", "mot_de_passe": "..."}  → {"jeton": "...", "compte": {...}}
GET  /api/moi              (Authorization: Bearer &lt;jeton&gt;)
GET  /api/admin/rapport    (Authorization: Bearer &lt;jeton&gt;, réservé aux administrateurs)</pre></html>`;

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', 'http://lab');
  if (req.method === 'GET' && url.pathname === '/') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    return res.end(HOME);
  }
  if (req.method === 'POST' && url.pathname === '/api/inscription') {
    const body = await readBody(req);
    if (typeof body.email !== 'string' || typeof body.mot_de_passe !== 'string') {
      return json(res, 400, { erreur: 'email et mot_de_passe sont requis' });
    }
    // VULNERABLE: every field the client sends lands in the account, defaults first.
    const account = { role: 'membre', verifie: false, ...body };
    delete account.mot_de_passe;
    accounts.set(account.email, account);
    const token = randomBytes(24).toString('hex');
    sessions.set(token, account.email);
    return json(res, 201, { jeton: token, compte: account });
  }
  const me = accounts.get(sessions.get((req.headers.authorization ?? '').replace(/^Bearer /, '')));
  if (!me) return json(res, 401, { erreur: 'authentification requise' });
  if (req.method === 'GET' && url.pathname === '/api/moi') return json(res, 200, me);
  if (req.method === 'GET' && url.pathname === '/api/admin/rapport') {
    if (me.role !== 'admin') return json(res, 403, { erreur: 'réservé aux administrateurs' });
    return json(res, 200, { rapport: 'Chiffre d’affaires confidentiel', flag: FLAG });
  }
  return json(res, 404, { erreur: 'introuvable' });
});

server.listen(Number(process.env.PORT ?? 8080), process.env.HOST ?? '0.0.0.0', () => {
  console.log(`lab mass-assignment listening on ${server.address().port}`);
});
