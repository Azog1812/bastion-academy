import { api, type EnvironmentView } from './api.js';
import { h } from './dom.js';
import { alert, errorMessage } from './ui.js';

/**
 * Start / open / stop a shared real environment, such as Wazuh (ADR 0013), from its
 * module card. The server decides who may act and reports the live state; the page
 * only refreshes this panel (never the whole catalogue, which would lose the scroll).
 */

/** Only the loopback URLs of the catalogue ever become links. */
const ENV_URL = /^https:\/\/localhost:\d{1,5}$/;
const POLL_MS = 5000;

export function environmentPanel(initial: EnvironmentView): HTMLElement {
  const box = h('div', { class: 'environment', 'aria-live': 'polite' });
  const path = `/v1/environments/${encodeURIComponent(initial.id)}`;
  let timer: number | undefined;

  const refresh = async () => {
    const { items } = await api<{ items: EnvironmentView[] }>('GET', '/v1/environments');
    const env = items.find((e) => e.id === initial.id);
    if (env) render(env);
  };

  const button = (label: string, action: () => Promise<void>, secondary = false) => {
    const b = h('button', { type: 'button', class: secondary ? 'secondary' : undefined }, label);
    b.addEventListener('click', () => {
      b.disabled = true;
      action().catch((err: unknown) => {
        b.disabled = false;
        box.append(alert(errorMessage(err)));
      });
    });
    return b;
  };
  const start = button('Démarrer Wazuh', async () => {
    render(await api<EnvironmentView>('POST', `${path}/start`, {}));
  });
  const stop = () =>
    button(
      'Arrêter',
      async () => {
        await api<undefined>('POST', `${path}/stop`, {});
        await refresh();
      },
      true,
    );

  function render(env: EnvironmentView): void {
    window.clearTimeout(timer);
    // Poll only while it boots, and only while the panel is on screen.
    if (env.state === 'starting') {
      timer = window.setTimeout(() => {
        if (box.isConnected) void refresh().catch(() => undefined);
      }, POLL_MS);
    }
    const title = h('h4', {}, `Environnement réel : ${env.title}`);
    switch (env.state) {
      case 'unavailable':
        box.replaceChildren(title, alert('Le lab runner ne répond pas : lance Bastion avec « docker compose up » pour piloter Wazuh depuis ici.', 'info'));
        return;
      case 'missing':
        box.replaceChildren(
          title,
          alert('Wazuh n’est pas encore installé sur cette machine. Lance une fois « docker compose --profile wazuh up -d » (environ 4 Go de RAM et 7 Go de disque), puis reviens ici.', 'info'),
        );
        return;
      case 'stopped':
        box.replaceChildren(title, h('p', { class: 'meta' }, 'Arrêté. Le démarrage prend une à deux minutes ; il s’arrête tout seul au bout de 8 heures.'), start);
        start.disabled = false;
        return;
      case 'starting':
        box.replaceChildren(title, h('p', {}, 'Démarrage en cours… (une à deux minutes)'), stop());
        return;
      case 'running': {
        const until = env.stopsAt ? new Date(env.stopsAt).toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' }) : null;
        const parts: (Node | null)[] = [
          title,
          env.url && ENV_URL.test(env.url)
            ? h('p', {}, 'Tableau de bord : ', h('a', { href: env.url, target: '_blank', rel: 'noopener noreferrer' }, env.url))
            : null,
          env.login ? h('p', { class: 'meta' }, `${env.login}. Le navigateur signale un certificat inconnu : il vient de l’autorité locale créée à l’installation.`) : null,
          until ? h('p', { class: 'meta' }, `Arrêt automatique à ${until}.`) : null,
          stop(),
        ];
        box.replaceChildren(...parts.filter((n): n is Node => n !== null));
        return;
      }
    }
  }

  render(initial);
  return box;
}
