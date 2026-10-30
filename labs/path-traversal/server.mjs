// LAB — INTENTIONALLY VULNERABLE. Runs only inside an isolated lab container
// (no network egress, read-only, unprivileged). Never copy this code anywhere.
//
// Document download endpoint that joins a user-supplied name to its folder
// without checking where the result lands (path traversal, CWE-22).
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const FLAG = process.env.FLAG;
if (!FLAG) {
  console.error('FLAG is required');
  process.exit(1);
}

// The root filesystem is read-only: the lab writes its files in /tmp (tmpfs) at start-up.
const root = join(tmpdir(), 'intranet');
const docs = join(root, 'documents', 'public');
mkdirSync(docs, { recursive: true });
mkdirSync(join(root, 'secrets'), { recursive: true });
writeFileSync(join(docs, 'reglement-interieur.txt'), 'Règlement intérieur\n\nArticle 1 : les badges se portent de façon visible.\n');
writeFileSync(join(docs, 'planning-conges.txt'), 'Planning des congés : voir avec ton responsable.\n');
writeFileSync(join(root, 'secrets', 'sauvegarde.conf'), `# Identifiants du serveur de sauvegarde\nutilisateur=backup\nmot_de_passe=${FLAG}\n`);

const page = (body) => `<!doctype html><html lang="fr"><meta charset="utf-8"><title>Intranet</title>
<style>body{font-family:system-ui,sans-serif;max-width:46rem;margin:3rem auto;padding:0 1rem}code{background:#eee;padding:.1rem .3rem}</style>
<h1>Intranet · Documents publics</h1>${body}</html>`;

const server = createServer((req, res) => {
  const url = new URL(req.url ?? '/', 'http://lab');
  if (url.pathname === '/') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    return res.end(
      page(`<ul>
<li><a href="/telecharger?fichier=reglement-interieur.txt">reglement-interieur.txt</a></li>
<li><a href="/telecharger?fichier=planning-conges.txt">planning-conges.txt</a></li></ul>
<p><small>Les documents sont rangés dans <code>${root}/documents/public/</code>.</small></p>`),
    );
  }
  if (url.pathname === '/telecharger') {
    const name = url.searchParams.get('fichier') ?? '';
    try {
      // VULNERABLE: join() resolves "../" segments; the result is never checked to stay under `docs`.
      const content = readFileSync(join(docs, name), 'utf8');
      res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
      return res.end(content);
    } catch {
      res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
      return res.end('Fichier introuvable.');
    }
  }
  res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
  return res.end('Page introuvable.');
});

server.listen(Number(process.env.PORT ?? 8080), process.env.HOST ?? '0.0.0.0', () => {
  console.log(`lab path-traversal listening on ${server.address().port}`);
});
