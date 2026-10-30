// LAB — INTENTIONALLY VULNERABLE. Runs only inside an isolated lab container
// (no network egress, read-only, unprivileged). Never copy this code anywhere.
//
// A single-use gift card checked, then (after an await) credited, then marked
// used: requests sent in parallel all pass the check before any of them marks
// the card (race condition, TOCTOU, CWE-362). One learner per container, so the
// state is a plain in-memory object.
import { createServer } from 'node:http';

const FLAG = process.env.FLAG;
if (!FLAG) {
  console.error('FLAG is required');
  process.exit(1);
}

const CARD = { code: 'BIENVENUE10', amount: 10 };
const SHOP = {
  'mug-bastion': { name: 'Mug Bastion Academy', price: 8 },
  'sticker-pack': { name: 'Lot d’autocollants', price: 3 },
  'rapport-confidentiel': { name: 'Rapport confidentiel', price: 50 },
};
let state;
const reset = () => {
  state = { balance: 0, cardUsed: false, purchases: [] };
};
reset();

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
// Stands for a call to the card issuer's fraud check: a real network round trip.
const issuerCheck = () => sleep(300);

async function redeem(code) {
  if (code !== CARD.code) return [404, { erreur: 'Carte inconnue.' }];
  // VULNERABLE: check…
  if (state.cardUsed) return [409, { erreur: 'Cette carte a déjà été utilisée.' }];
  // …await (every concurrent request is now past the check)…
  await issuerCheck();
  // …then use. The fix: claim the card atomically BEFORE any await
  // (UPDATE cartes SET utilisee = 1 WHERE code = ? AND utilisee = 0).
  state.balance += CARD.amount;
  state.cardUsed = true;
  return [200, { message: `Carte acceptée : ${String(CARD.amount)} € crédités.`, solde: state.balance }];
}

function buy(id) {
  const item = Object.hasOwn(SHOP, id) ? SHOP[id] : undefined;
  if (!item) return [404, { erreur: 'Article inconnu.' }];
  // No await here: the purchase itself is not racy, only the gift card is.
  if (state.balance < item.price) return [402, { erreur: `Solde insuffisant : ${String(state.balance)} €, il en faut ${String(item.price)}.` }];
  state.balance -= item.price;
  state.purchases.push(item.name);
  const body = { message: `Achat réussi : ${item.name}.`, solde: state.balance };
  if (id === 'rapport-confidentiel') body.contenu = `Rapport confidentiel — code d'accès : ${FLAG}`;
  return [200, body];
}

const page = `<!doctype html><html lang="fr"><meta charset="utf-8"><title>Boutique</title>
<style>body{font-family:system-ui,sans-serif;max-width:46rem;margin:3rem auto;padding:0 1rem}code{background:#eee;padding:.1rem .3rem}td,th{padding:.2rem .6rem;text-align:left}</style>
<h1>Boutique Bastion</h1>
<p>Bienvenue ! Ton compte est vide, mais voici une carte cadeau de <strong>10 €</strong>, utilisable <strong>une seule fois</strong> : <code>${CARD.code}</code>.</p>
<table><tr><th>Article</th><th>Identifiant</th><th>Prix</th></tr>
${Object.entries(SHOP).map(([id, i]) => `<tr><td>${i.name}</td><td><code>${id}</code></td><td>${String(i.price)} €</td></tr>`).join('\n')}
</table>
<h2>API</h2>
<ul>
<li><code>GET /api/compte</code> : ton solde et l'état de la carte</li>
<li><code>POST /api/cartes/utiliser</code> avec <code>{"code": "…"}</code></li>
<li><code>POST /api/acheter</code> avec <code>{"article": "…"}</code></li>
<li><code>POST /api/reinitialiser</code> : remet le compte à zéro</li>
</ul></html>`;

function readJson(req) {
  return new Promise((resolve) => {
    let raw = '';
    req.setEncoding('utf8');
    req.on('data', (chunk) => {
      raw += chunk;
      if (raw.length > 1024) req.destroy();
    });
    req.on('end', () => {
      try {
        const v = JSON.parse(raw);
        resolve(typeof v === 'object' && v !== null ? v : {});
      } catch {
        resolve({});
      }
    });
  });
}

const server = createServer(async (req, res) => {
  const send = (status, body) => {
    res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify(body));
  };
  const url = new URL(req.url ?? '/', 'http://lab');
  if (req.method === 'GET' && url.pathname === '/') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    return res.end(page);
  }
  if (req.method === 'GET' && url.pathname === '/api/compte') {
    return send(200, { solde: state.balance, carteUtilisee: state.cardUsed, achats: state.purchases });
  }
  if (req.method === 'POST' && url.pathname === '/api/cartes/utiliser') {
    const body = await readJson(req);
    return send(...(await redeem(String(body.code ?? ''))));
  }
  if (req.method === 'POST' && url.pathname === '/api/acheter') {
    const body = await readJson(req);
    return send(...buy(String(body.article ?? '')));
  }
  if (req.method === 'POST' && url.pathname === '/api/reinitialiser') {
    reset();
    return send(200, { message: 'Compte remis à zéro.' });
  }
  return send(404, { erreur: 'Page introuvable.' });
});

server.listen(Number(process.env.PORT ?? 8080), process.env.HOST ?? '0.0.0.0', () => {
  console.log(`lab race-coupon listening on ${server.address().port}`);
});
