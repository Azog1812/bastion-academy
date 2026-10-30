// LAB — INTENTIONALLY VULNERABLE. Runs only inside an isolated lab container
// (no network egress, read-only, unprivileged). Never copy this code anywhere.
//
// An API whose JWT check trusts the token's own "alg" header: a token with
// "alg": "none" and no signature is accepted (CVE-2015-9235 family).
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:http';

const FLAG = process.env.FLAG;
if (!FLAG) {
  console.error('FLAG is required');
  process.exit(1);
}

const SECRET = randomBytes(32); // strong secret: cracking it is not the way in
const b64url = (v) => Buffer.from(v).toString('base64url');
const sign = (data) => createHmac('sha256', SECRET).update(data).digest('base64url');

function issue(claims) {
  const head = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = b64url(JSON.stringify({ ...claims, iat: Math.floor(Date.now() / 1000) }));
  return `${head}.${body}.${sign(`${head}.${body}`)}`;
}

function verify(token) {
  const [head, body, sig = ''] = String(token).split('.');
  if (!head || !body) return null;
  try {
    const header = JSON.parse(Buffer.from(head, 'base64url').toString());
    // VULNERABLE: the algorithm is chosen by the token, and "none" skips the signature.
    if (String(header.alg).toLowerCase() === 'none') return JSON.parse(Buffer.from(body, 'base64url').toString());
    if (header.alg !== 'HS256') return null;
    const expected = Buffer.from(sign(`${head}.${body}`));
    const given = Buffer.from(sig);
    if (expected.length !== given.length || !timingSafeEqual(expected, given)) return null;
    return JSON.parse(Buffer.from(body, 'base64url').toString());
  } catch {
    return null;
  }
}

const json = (res, status, body) => {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(body));
};

const HOME = `<!doctype html><html lang="fr"><meta charset="utf-8"><title>API partenaires</title>
<style>body{font-family:system-ui,sans-serif;max-width:46rem;margin:3rem auto;padding:0 1rem}pre{background:#eee;padding:1rem}</style>
<h1>API partenaires</h1>
<pre>POST /api/invite            → {"jeton": "..."}  (accès invité, sans compte)
GET  /api/profil            (Authorization: Bearer &lt;jeton&gt;)
GET  /api/admin/secrets     (Authorization: Bearer &lt;jeton&gt;, rôle admin)</pre></html>`;

const server = createServer((req, res) => {
  const url = new URL(req.url ?? '/', 'http://lab');
  if (req.method === 'GET' && url.pathname === '/') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    return res.end(HOME);
  }
  if (req.method === 'POST' && url.pathname === '/api/invite') return json(res, 200, { jeton: issue({ sub: 'invite', role: 'invite' }) });
  const claims = verify((req.headers.authorization ?? '').replace(/^Bearer /, ''));
  if (!claims) return json(res, 401, { erreur: 'jeton invalide' });
  if (req.method === 'GET' && url.pathname === '/api/profil') return json(res, 200, claims);
  if (req.method === 'GET' && url.pathname === '/api/admin/secrets') {
    if (claims.role !== 'admin') return json(res, 403, { erreur: 'rôle admin requis' });
    return json(res, 200, { secret: FLAG });
  }
  return json(res, 404, { erreur: 'introuvable' });
});

server.listen(Number(process.env.PORT ?? 8080), process.env.HOST ?? '0.0.0.0', () => {
  console.log(`lab jwt-none listening on ${server.address().port}`);
});
