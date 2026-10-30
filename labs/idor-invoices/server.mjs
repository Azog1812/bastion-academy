// LAB — INTENTIONALLY VULNERABLE. Runs only inside an isolated lab container
// (no network egress, read-only, unprivileged). Never copy this code anywhere.
//
// Invoicing API: authentication is fine, authorisation is missing. Any logged-in
// user can read any invoice by its id (IDOR, OWASP API1:2023 BOLA).
import { randomBytes } from 'node:crypto';
import { createServer } from 'node:http';

const FLAG = process.env.FLAG;
if (!FLAG) {
  console.error('FLAG is required');
  process.exit(1);
}

const users = new Map([
  ['alice', { password: 'alice', name: 'Alice Martin' }],
  ['direction', { password: randomBytes(24).toString('hex'), name: 'Direction générale' }],
]);
const invoices = new Map();
const add = (id, owner, client, amount, note) => invoices.set(id, { id, owner, client, amount, note });
add(1001, 'direction', 'Fonds stratégique', 250000, `Accord confidentiel, référence ${FLAG}`);
add(1002, 'direction', 'Cabinet de conseil', 48000, 'Audit annuel');
add(1003, 'alice', 'Librairie du Port', 320, 'Commande de manuels');
add(1004, 'direction', 'Agence immobilière', 12000, 'Loyer du siège');
add(1005, 'alice', 'Imprimerie Dupuis', 145, 'Cartes de visite');

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
        resolve(JSON.parse(raw || '{}'));
      } catch {
        resolve({});
      }
    });
  });
const userOf = (req) => sessions.get((req.headers.authorization ?? '').replace(/^Bearer /, ''));

const HOME = `<!doctype html><html lang="fr"><meta charset="utf-8"><title>Factures</title>
<style>body{font-family:system-ui,sans-serif;max-width:46rem;margin:3rem auto;padding:0 1rem}code,pre{background:#eee;padding:.1rem .3rem}</style>
<h1>API de facturation</h1>
<p>Compte de démonstration : <code>alice</code> / <code>alice</code>.</p>
<pre>POST /api/connexion        {"identifiant": "...", "mot_de_passe": "..."}  → {"jeton": "..."}
GET  /api/mes-factures     (Authorization: Bearer &lt;jeton&gt;)
GET  /api/factures/{id}    (Authorization: Bearer &lt;jeton&gt;)</pre></html>`;

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', 'http://lab');
  if (req.method === 'GET' && url.pathname === '/') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    return res.end(HOME);
  }
  if (req.method === 'POST' && url.pathname === '/api/connexion') {
    const { identifiant, mot_de_passe: password } = await readBody(req);
    const u = users.get(String(identifiant));
    if (!u || u.password !== password) return json(res, 401, { erreur: 'identifiants incorrects' });
    const token = randomBytes(24).toString('hex');
    sessions.set(token, String(identifiant));
    return json(res, 200, { jeton: token });
  }
  const me = userOf(req);
  if (url.pathname.startsWith('/api/') && !me) return json(res, 401, { erreur: 'authentification requise' });
  if (req.method === 'GET' && url.pathname === '/api/mes-factures') {
    return json(res, 200, [...invoices.values()].filter((f) => f.owner === me).map(({ id, client, amount }) => ({ id, client, montant: amount })));
  }
  const m = /^\/api\/factures\/(\d+)$/.exec(url.pathname);
  if (req.method === 'GET' && m) {
    // VULNERABLE: the invoice is found by id alone; its owner is never compared with `me`.
    const f = invoices.get(Number(m[1]));
    if (!f) return json(res, 404, { erreur: 'facture introuvable' });
    return json(res, 200, { id: f.id, client: f.client, montant: f.amount, note: f.note });
  }
  return json(res, 404, { erreur: 'introuvable' });
});

server.listen(Number(process.env.PORT ?? 8080), process.env.HOST ?? '0.0.0.0', () => {
  console.log(`lab idor-invoices listening on ${server.address().port}`);
});
