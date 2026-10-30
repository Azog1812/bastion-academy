// LAB — INTENTIONALLY VULNERABLE. Runs only inside an isolated lab container
// (no network egress, read-only, unprivileged). Never copy this code anywhere.
//
// "DNS diagnostic" page that pastes user input into a shell command
// (OS command injection, CWE-78). This lab ships a real shell ON PURPOSE:
// the learner gets code execution and can check for themselves that the
// container lets them go nowhere (ADR 0009).
import { exec } from 'node:child_process';
import { createServer } from 'node:http';

if (!process.env.FLAG) {
  console.error('FLAG is required');
  process.exit(1);
}

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const page = (body) => `<!doctype html><html lang="fr"><meta charset="utf-8"><title>Diagnostic DNS</title>
<style>body{font-family:system-ui,sans-serif;max-width:46rem;margin:3rem auto;padding:0 1rem}input{width:60%;padding:.4rem}
pre{background:#222;color:#eee;padding:1rem;white-space:pre-wrap;word-break:break-all}</style>
<h1>Outil de diagnostic DNS</h1><p>Vérifie qu'un nom de domaine se résout depuis le serveur.</p>
<form method="get" action="/diagnostic"><input name="domaine" placeholder="exemple.test"> <button>Tester</button></form>${body}</html>`;

const server = createServer((req, res) => {
  const url = new URL(req.url ?? '/', 'http://lab');
  const send = (status, html) => {
    res.writeHead(status, { 'content-type': 'text/html; charset=utf-8' });
    res.end(html);
  };
  if (url.pathname === '/') return send(200, page(''));
  if (url.pathname === '/diagnostic') {
    const domaine = url.searchParams.get('domaine') ?? '';
    // VULNERABLE: user input concatenated into a command run by /bin/sh.
    const command = `timeout 3 nslookup ${domaine}`;
    exec(command, { shell: '/bin/sh', timeout: 10_000, maxBuffer: 64 * 1024 }, (_err, stdout, stderr) => {
      send(200, page(`<h2>Commande exécutée</h2><pre>${esc(command)}</pre><h2>Résultat</h2><pre>${esc(stdout + stderr)}</pre>`));
    });
    return undefined;
  }
  return send(404, page('<p>Page introuvable.</p>'));
});

server.listen(Number(process.env.PORT ?? 8080), process.env.HOST ?? '0.0.0.0', () => {
  console.log(`lab command-injection listening on ${server.address().port}`);
});
