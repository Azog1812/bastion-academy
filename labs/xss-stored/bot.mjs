// LAB helper: the "victim". A headless Chromium driven over the DevTools
// protocol with Node's built-in WebSocket (no npm dependency). It runs inside
// the lab container only, with the lab's own isolation.
import { spawn } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export async function launchBot(chromePath) {
  const profile = mkdtempSync(join(tmpdir(), 'bot-'));
  const chrome = spawn(
    chromePath,
    [
      '--headless=new',
      // The container is the sandbox: no capabilities, read-only, no route out (ADR 0009).
      '--no-sandbox',
      '--disable-gpu',
      '--disable-dev-shm-usage',
      '--disable-extensions',
      '--disable-breakpad',
      '--disable-crash-reporter',
      '--no-first-run',
      '--no-default-browser-check',
      '--remote-debugging-address=127.0.0.1',
      '--remote-debugging-port=0',
      `--user-data-dir=${profile}`,
      'about:blank',
    ],
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
    chrome.on('exit', (code) => reject(new Error(`chromium exited with ${code}`)));
  });

  const ws = new WebSocket(wsUrl);
  await new Promise((resolve, reject) => {
    ws.addEventListener('open', resolve, { once: true });
    ws.addEventListener('error', reject, { once: true });
  });
  let next = 0;
  const pending = new Map();
  ws.addEventListener('message', (e) => {
    const msg = JSON.parse(String(e.data));
    const p = pending.get(msg.id);
    if (!p) return;
    pending.delete(msg.id);
    if (msg.error) p.reject(new Error(msg.error.message));
    else p.resolve(msg.result);
  });
  const send = (method, params = {}, sessionId) =>
    new Promise((resolve, reject) => {
      const id = ++next;
      pending.set(id, { resolve, reject });
      ws.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
    });

  return {
    /** Opens `url` with `cookie` set, lets the page run for `ms`, then closes the tab. */
    async visit(url, cookie, ms = 3000) {
      const { targetId } = await send('Target.createTarget', { url: 'about:blank' });
      try {
        const { sessionId } = await send('Target.attachToTarget', { targetId, flatten: true });
        await send('Network.enable', {}, sessionId);
        await send('Network.setCookie', { ...cookie, url }, sessionId);
        await send('Page.navigate', { url }, sessionId);
        await new Promise((r) => setTimeout(r, ms));
      } finally {
        await send('Target.closeTarget', { targetId }).catch(() => undefined);
      }
    },
    close() {
      ws.close();
      chrome.kill();
    },
  };
}
