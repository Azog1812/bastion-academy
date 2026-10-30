// LAB — INTENTIONALLY VULNERABLE. Runs only inside an isolated lab container
// (no network egress, read-only, unprivileged). Never copy this code anywhere.
//
// "Link preview" feature: the server fetches any URL the user gives it (SSRF,
// OWASP API7:2023). An internal admin service, bound to 127.0.0.1 and never
// published, holds the flag: only the server itself can reach it.
import { createServer } from 'node:http';

const FLAG = process.env.FLAG;
if (!FLAG) {
  console.error('FLAG is required');
  process.exit(1);
}

// Internal service: "safe" because it only listens on the loopback interface.
const INTERNAL_PORT = Number(process.env.INTERNAL_PORT ?? 9000);
const internal = createServer((req, res) => {
  res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
  if (req.url === '/admin/config') return res.end(JSON.stringify({ service: 'config-interne', cle_api_partenaire: FLAG }));
  return res.end(JSON.stringify({ service: 'config-interne', routes: ['/admin/config'] }));
});
internal.listen(INTERNAL_PORT, '127.0.0.1');

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const page = (body) => `<!doctype html><html lang="fr"><meta charset="utf-8"><title>Aperçu de liens</title>
<style>body{font-family:system-ui,sans-serif;max-width:46rem;margin:3rem auto;padding:0 1rem}input{width:70%;padding:.4rem}
pre{background:#222;color:#eee;padding:1rem;white-space:pre-wrap;word-break:break-all}</style>
<h1>Aperçu de liens</h1><p>Colle une adresse, notre serveur va la chercher pour toi et t'en montre le début.</p>
<form method="get" action="/apercu"><input name="url" placeholder="http://exemple.test/"> <button>Aperçu</button></form>${body}</html>`;

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', 'http://lab');
  const send = (status, html) => {
    res.writeHead(status, { 'content-type': 'text/html; charset=utf-8' });
    res.end(html);
  };
  if (url.pathname === '/') return send(200, page(''));
  if (url.pathname === '/apercu') {
    const target = url.searchParams.get('url') ?? '';
    // VULNERABLE: any scheme-valid URL is fetched, including loopback and internal addresses.
    if (!/^https?:\/\//i.test(target)) return send(400, page('<p>Adresse invalide : http:// ou https:// attendu.</p>'));
    try {
      const r = await fetch(target, { signal: AbortSignal.timeout(3000), redirect: 'follow' });
      const text = (await r.text()).slice(0, 2000);
      return send(200, page(`<h2>Aperçu de ${esc(target)} (HTTP ${r.status})</h2><pre>${esc(text)}</pre>`));
    } catch (err) {
      return send(502, page(`<p>Impossible de récupérer cette adresse (${esc(err.cause?.code ?? err.name)}).</p>`));
    }
  }
  return send(404, page('<p>Page introuvable.</p>'));
});

server.listen(Number(process.env.PORT ?? 8080), process.env.HOST ?? '0.0.0.0', () => {
  console.log(`lab ssrf-preview listening on ${server.address().port}`);
});
