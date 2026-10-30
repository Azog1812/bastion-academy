// LAB — INTENTIONALLY VULNERABLE. Runs only inside an isolated lab container
// (no network egress, read-only, unprivileged). Never copy this code anywhere.
//
// "Back-office" login whose SQL query is built by string concatenation.
// The flag is shown to whoever ends up logged in as admin.
import { randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import { DatabaseSync } from 'node:sqlite';

const FLAG = process.env.FLAG;
if (!FLAG) {
  console.error('FLAG is required');
  process.exit(1);
}

const db = new DatabaseSync(':memory:');
db.exec(`
  CREATE TABLE utilisateurs (id INTEGER PRIMARY KEY, identifiant TEXT, mot_de_passe TEXT, role TEXT);
  CREATE TABLE coffre (cle TEXT, valeur TEXT);
`);
// The admin password is random: guessing it is not the way in.
db.prepare('INSERT INTO utilisateurs (identifiant, mot_de_passe, role) VALUES (?, ?, ?)').run('admin', randomBytes(24).toString('hex'), 'admin');
db.prepare('INSERT INTO utilisateurs (identifiant, mot_de_passe, role) VALUES (?, ?, ?)').run('stagiaire', 'stagiaire', 'lecteur');
db.prepare('INSERT INTO coffre (cle, valeur) VALUES (?, ?)').run('flag', FLAG);

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const page = (body) => `<!doctype html><html lang="fr"><meta charset="utf-8"><title>Back-office</title>
<style>body{font-family:system-ui,sans-serif;max-width:40rem;margin:3rem auto;padding:0 1rem;background:#f6f7f9}
form,section{background:#fff;padding:1.5rem;border-radius:8px;box-shadow:0 1px 3px #0002}input{display:block;margin:.3rem 0 1rem;padding:.4rem;width:100%}
pre{background:#222;color:#eee;padding:1rem;white-space:pre-wrap;word-break:break-all}</style>
<h1>Back-office · Boutique Bastion</h1>${body}</html>`;

const form = (msg = '') => page(`${msg}<form method="post" action="/connexion">
<label>Identifiant<input name="identifiant" autocomplete="off"></label>
<label>Mot de passe<input name="mot_de_passe" type="password"></label>
<button>Se connecter</button></form>
<p><small>Compte de démonstration : <code>stagiaire</code> / <code>stagiaire</code></small></p>`);

function login(identifiant, motDePasse) {
  // VULNERABLE: user input concatenated into SQL.
  const sql = `SELECT identifiant, role FROM utilisateurs WHERE identifiant = '${identifiant}' AND mot_de_passe = '${motDePasse}'`;
  try {
    return { row: db.prepare(sql).get(), sql };
  } catch (err) {
    // VULNERABLE: verbose errors echo the query, a gift for the attacker.
    return { error: `${err.message}\n\n${sql}` };
  }
}

const server = createServer((req, res) => {
  const send = (status, html) => {
    res.writeHead(status, { 'content-type': 'text/html; charset=utf-8' });
    res.end(html);
  };
  if (req.method === 'GET' && req.url === '/') return send(200, form());
  if (req.method === 'POST' && req.url === '/connexion') {
    let raw = '';
    req.setEncoding('utf8');
    req.on('data', (chunk) => {
      raw += chunk;
      if (raw.length > 10_000) req.destroy();
    });
    req.on('end', () => {
      const p = new URLSearchParams(raw);
      const { row, error } = login(p.get('identifiant') ?? '', p.get('mot_de_passe') ?? '');
      if (error) return send(500, page(`<section><h2>Erreur SQL</h2><pre>${esc(error)}</pre></section>`));
      if (!row) return send(401, form('<p><strong>Identifiants incorrects.</strong></p>'));
      if (row.role === 'admin') {
        const secret = db.prepare("SELECT valeur FROM coffre WHERE cle = 'flag'").get();
        return send(200, page(`<section><h2>Bienvenue, ${esc(row.identifiant)}</h2><p>Coffre de l'administrateur :</p><pre>${esc(secret.valeur)}</pre></section>`));
      }
      return send(200, page(`<section><h2>Bienvenue, ${esc(row.identifiant)}</h2><p>Rôle : ${esc(row.role)}. Rien à voir ici pour un simple lecteur.</p></section>`));
    });
    return undefined;
  }
  return send(404, page('<p>Page introuvable.</p>'));
});

server.listen(Number(process.env.PORT ?? 8080), process.env.HOST ?? '0.0.0.0', () => {
  console.log(`lab sqli-login listening on ${server.address().port}`);
});
