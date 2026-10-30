// LAB — INTENTIONALLY VULNERABLE. Runs only inside an isolated lab container
// (no network egress, read-only, unprivileged). Never copy this code anywhere.
//
// A chain, as in a real penetration test: no single flaw gives the flag.
//   1. path traversal in the document download (CWE-22) reads the app config;
//   2. the config holds the JWT signing secret (CWE-798, secret in a readable file);
//   3. with it, an admin token can be forged; the admin report holds the flag.
// JWT verification itself is correct (algorithm pinned to HS256): the leak is the bug.
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const FLAG = process.env.FLAG;
if (!FLAG) {
  console.error('FLAG is required');
  process.exit(1);
}

const SECRET = randomBytes(32).toString('hex');
const root = join(tmpdir(), 'portail');
const docs = join(root, 'documents');
mkdirSync(docs, { recursive: true });
mkdirSync(join(root, 'config'), { recursive: true });
writeFileSync(join(docs, 'charte-informatique.txt'), 'Charte informatique\n\nLes mots de passe ne se partagent pas.\n');
writeFileSync(join(docs, 'organigramme.txt'), 'Direction : M. Roux\nInformatique : équipe de 3 personnes\n');
writeFileSync(
  join(root, 'config', 'app.env'),
  `# Portail RH — configuration de production\nNODE_ENV=production\nDB_HOST=10.0.4.12\nJWT_ALG=HS256\nJWT_SECRET=${SECRET}\n`,
);

const b64url = (v) => Buffer.from(v).toString('base64url');
const sign = (data) => createHmac('sha256', SECRET).update(data).digest('base64url');
const issue = (claims) => {
  const head = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = b64url(JSON.stringify(claims));
  return `${head}.${body}.${sign(`${head}.${body}`)}`;
};
function verify(token) {
  const [head, body, sig] = String(token).split('.');
  if (!head || !body || !sig) return null;
  try {
    if (JSON.parse(Buffer.from(head, 'base64url').toString()).alg !== 'HS256') return null; // pinned: no alg confusion here
    const a = Buffer.from(sig);
    const b = Buffer.from(sign(`${head}.${body}`));
    if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
    return JSON.parse(Buffer.from(body, 'base64url').toString());
  } catch {
    return null;
  }
}

const json = (res, status, body) => {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(body));
};
const HOME = `<!doctype html><html lang="fr"><meta charset="utf-8"><title>Portail RH</title>
<style>body{font-family:system-ui,sans-serif;max-width:46rem;margin:3rem auto;padding:0 1rem}pre{background:#eee;padding:1rem}</style>
<h1>Portail RH</h1>
<h2>Documents</h2><ul>
<li><a href="/documents?nom=charte-informatique.txt">charte-informatique.txt</a></li>
<li><a href="/documents?nom=organigramme.txt">organigramme.txt</a></li></ul>
<h2>API</h2>
<pre>POST /api/connexion       {"identifiant": "invite", "mot_de_passe": "invite"}  → {"jeton": "..."}
GET  /api/profil          (Authorization: Bearer &lt;jeton&gt;)
GET  /api/admin/rapport   (Authorization: Bearer &lt;jeton&gt;, rôle admin)</pre></html>`;

const server = createServer((req, res) => {
  const url = new URL(req.url ?? '/', 'http://lab');
  if (req.method === 'GET' && url.pathname === '/') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    return res.end(HOME);
  }
  if (req.method === 'GET' && url.pathname === '/documents') {
    const name = url.searchParams.get('nom') ?? '';
    const path = join(docs, name);
    // Blocks only the shortcut (/proc/self/environ holds the flag injected at start-up),
    // so that the chain is the way in. The traversal itself stays open.
    if (path.startsWith('/proc/') || path === '/proc') {
      res.writeHead(403, { 'content-type': 'text/plain; charset=utf-8' });
      return res.end('Accès interdit (filtre de sécurité).');
    }
    try {
      // VULNERABLE: "../" segments are resolved and never checked to stay under `docs`.
      const content = readFileSync(path, 'utf8');
      res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
      return res.end(content);
    } catch {
      // VULNERABLE: the error reveals where documents live on disk.
      res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
      return res.end(`Introuvable : ${path}`);
    }
  }
  if (req.method === 'POST' && url.pathname === '/api/connexion') {
    let raw = '';
    req.setEncoding('utf8');
    req.on('data', (c) => {
      raw += c;
      if (raw.length > 10_000) req.destroy();
    });
    req.on('end', () => {
      let body = {};
      try {
        body = JSON.parse(raw || '{}');
      } catch {
        // ignore
      }
      if (body.identifiant !== 'invite' || body.mot_de_passe !== 'invite') return json(res, 401, { erreur: 'identifiants incorrects' });
      return json(res, 200, { jeton: issue({ sub: 'invite', role: 'lecteur', iat: Math.floor(Date.now() / 1000) }) });
    });
    return undefined;
  }
  const claims = verify((req.headers.authorization ?? '').replace(/^Bearer /, ''));
  if (url.pathname.startsWith('/api/') && !claims) return json(res, 401, { erreur: 'jeton invalide' });
  if (req.method === 'GET' && url.pathname === '/api/profil') return json(res, 200, claims);
  if (req.method === 'GET' && url.pathname === '/api/admin/rapport') {
    if (claims.role !== 'admin') return json(res, 403, { erreur: 'rôle admin requis' });
    return json(res, 200, { rapport: 'Masse salariale 2026 (confidentiel)', reference: FLAG });
  }
  return json(res, 404, { erreur: 'introuvable' });
});

server.listen(Number(process.env.PORT ?? 8080), process.env.HOST ?? '0.0.0.0', () => {
  console.log(`lab chained-intranet listening on ${server.address().port}`);
});
