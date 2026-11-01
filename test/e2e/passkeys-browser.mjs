// Browser end-to-end check of passkeys (ADR 0016): a real Chromium, Chromium's own
// virtual authenticator (DevTools protocol, WebAuthn domain), and the real web UI.
// Run by test/e2e/passkeys-browser.sh inside the xss-stored lab image (pinned Chromium),
// sharing the platform container's network, so the page really is http://localhost:3000.
import { spawn } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const BASE = 'http://localhost:3000';
const EMAIL = `passkey-${Date.now()}@example.com`;
const PASSWORD = 'correct horse battery staple 42';

const profile = mkdtempSync(join(tmpdir(), 'e2e-'));
const chrome = spawn(
  process.env.CHROME_BIN ?? 'chromium',
  ['--headless=new', '--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage', '--no-first-run', '--remote-debugging-address=127.0.0.1', '--remote-debugging-port=0', `--user-data-dir=${profile}`, 'about:blank'],
  { stdio: ['ignore', 'ignore', 'pipe'], env: { ...process.env, HOME: profile } },
);
const wsUrl = await new Promise((resolve, reject) => {
  let log = '';
  const timer = setTimeout(() => reject(new Error('chromium did not start')), 30_000);
  chrome.stderr.on('data', (d) => {
    log += d;
    const m = /DevTools listening on (ws:\/\/\S+)/.exec(log);
    if (m) {
      clearTimeout(timer);
      resolve(m[1]);
    }
  });
});

const ws = new WebSocket(wsUrl);
await new Promise((r, j) => {
  ws.addEventListener('open', r, { once: true });
  ws.addEventListener('error', j, { once: true });
});
let next = 0;
const pending = new Map();
ws.addEventListener('message', (e) => {
  const msg = JSON.parse(String(e.data));
  const p = pending.get(msg.id);
  if (!p) return;
  pending.delete(msg.id);
  if (msg.error) p.reject(new Error(`${msg.error.message}`));
  else p.resolve(msg.result);
});
const send = (method, params = {}, sessionId) =>
  new Promise((resolve, reject) => {
    const id = ++next;
    pending.set(id, { resolve, reject });
    ws.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
  });

const { targetId } = await send('Target.createTarget', { url: 'about:blank' });
const { sessionId: s } = await send('Target.attachToTarget', { targetId, flatten: true });
await send('Page.enable', {}, s);
await send('Runtime.enable', {}, s);
// A USB security key with user verification, as Chrome DevTools' "WebAuthn" panel offers.
await send('WebAuthn.enable', {}, s);
const { authenticatorId } = await send(
  'WebAuthn.addVirtualAuthenticator',
  { options: { protocol: 'ctap2', transport: 'usb', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } },
  s,
);

const evaluate = async (expression) => {
  const r = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true }, s);
  if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description ?? r.exceptionDetails.text);
  return r.result.value;
};
const waitFor = async (expression, what, ms = 15_000) => {
  const end = Date.now() + ms;
  for (;;) {
    const v = await evaluate(expression).catch(() => undefined);
    if (v) return v;
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}; page says: ${await evaluate('document.body.innerText.slice(0, 300)')}`);
    await new Promise((r) => setTimeout(r, 200));
  }
};
const step = (msg) => process.stdout.write(`- ${msg}\n`);
// Sets inputs of the form that contains `anchor`, then submits it the way a user would.
const fill = (anchor, values) =>
  evaluate(`(() => {
    const form = document.querySelector(${JSON.stringify(anchor)}).form;
    for (const [name, value] of Object.entries(${JSON.stringify(values)})) form.querySelector('[name="' + name + '"]').value = value;
    form.requestSubmit();
    return true;
  })()`);

try {
  await send('Page.navigate', { url: `${BASE}/#/inscription` }, s);
  await waitFor(`document.querySelector('input[name=email]')`, 'the sign-up form');
  await fill('input[name=email]', { email: EMAIL, password: PASSWORD });
  await waitFor(`location.hash === '#/' && document.body.innerText.includes('Compte')`, 'the catalogue after sign-up');
  step('account created');

  await evaluate(`location.hash = '#/compte'`);
  await waitFor(`document.querySelector('input[name=name]')`, 'the passkey form');
  await fill('input[name=name]', { name: 'Clé virtuelle', password: PASSWORD });
  const codes = await waitFor(
    `[...document.querySelectorAll('pre.artifact')].map((p) => p.innerText).find((t) => t.split('\\n').length >= 10)`,
    'the recovery codes',
  );
  step(`passkey registered in the browser, ${codes.trim().split('\n').length} recovery codes shown once`);
  const { credentials } = await send('WebAuthn.getCredentials', { authenticatorId }, s);
  if (credentials.length !== 1 || credentials[0].rpId !== 'localhost') throw new Error(`unexpected credentials: ${JSON.stringify(credentials)}`);
  step(`the authenticator holds 1 credential for RP ID "${credentials[0].rpId}"`);

  await evaluate(`[...document.querySelectorAll('button')].find((b) => b.textContent === 'Déconnexion').click()`);
  await waitFor(`location.hash === '#/connexion'`, 'the login page after logout');
  await fill('input[name=email]', { email: EMAIL, password: PASSWORD });
  await waitFor(`[...document.querySelectorAll('button')].some((b) => b.textContent === 'Utiliser une passkey')`, 'the MFA step');
  step('the password alone is not enough: second step asked');
  await evaluate(`[...document.querySelectorAll('button')].find((b) => b.textContent === 'Utiliser une passkey').click()`);
  await waitFor(`location.hash === '#/' && document.body.innerText.includes('Compte')`, 'the catalogue after the passkey');
  const signCount = (await send('WebAuthn.getCredentials', { authenticatorId }, s)).credentials[0].signCount;
  step(`logged in with the passkey (authenticator counter now ${signCount})`);

  // Passwordless (ADR 0017): no e-mail, no password; the discoverable credential names the account.
  await evaluate(`[...document.querySelectorAll('button')].find((b) => b.textContent === 'Déconnexion').click()`);
  await waitFor(`[...document.querySelectorAll('button')].some((b) => b.textContent === 'Se connecter avec une passkey')`, 'the passwordless button');
  await evaluate(`[...document.querySelectorAll('button')].find((b) => b.textContent === 'Se connecter avec une passkey').click()`);
  await waitFor(`location.hash === '#/' && document.body.innerText.includes('Compte')`, 'the catalogue after a passwordless login');
  step('logged in without e-mail or password: the passkey alone, with user verification');
  process.stdout.write('OK: passkeys work end to end in a real browser\n');
} catch (err) {
  process.stdout.write(`FAILED: ${err.message}\n`);
  process.exitCode = 1;
} finally {
  ws.close();
  chrome.kill();
}
