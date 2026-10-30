import {
  api,
  ApiError,
  type Challenge,
  type ChallengeSummary,
  type DetectionInfo,
  type DetectionResult,
  type LabInstance,
  type LabState,
  type Scoreboard,
  type Submission,
} from './api.js';
import { h, renderBlocks } from './dom.js';
import { parseMarkdown } from './markdown.js';
import { alert, errorMessage, onSubmit, show } from './ui.js';

/** Challenges (#/defis, #/defi/<id>) and the scoreboard (#/classement). Flags are checked server-side only. */

/** Only a gateway URL the platform could have built is ever turned into a link (never javascript:, never elsewhere). */
const LAB_URL = /^http:\/\/l[0-9a-f]{32}\.lab\.localhost:\d{1,5}\/$/;

/** Start / open / stop the learner's own lab instance (ADR 0009). */
function labPanel(challengeId: string, lab: LabState): HTMLElement {
  const box = h('section', { class: 'card lab', 'aria-live': 'polite' });
  const path = `/v1/challenges/${encodeURIComponent(challengeId)}/lab`;

  const button = (label: string, action: () => Promise<void>) => {
    const b = h('button', { type: 'button' }, label);
    b.addEventListener('click', () => {
      b.disabled = true;
      action().catch((err: unknown) => {
        b.disabled = false;
        box.append(alert(errorMessage(err)));
      });
    });
    return b;
  };

  const render = (instance: LabInstance | null) => {
    if (!lab.enabled) {
      box.replaceChildren(
        h('h2', {}, 'Ton lab'),
        alert('Les labs ne sont pas activés sur cette installation : lance Bastion avec Docker Compose (voir le README) pour en profiter.', 'info'),
      );
      return;
    }
    if (instance && LAB_URL.test(instance.url)) {
      const until = new Date(instance.expiresAt).toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' });
      box.replaceChildren(
        h('h2', {}, 'Ton lab est démarré'),
        h('p', {}, 'Adresse : ', h('a', { href: instance.url, target: '_blank', rel: 'noopener noreferrer' }, instance.url)),
        h('p', { class: 'meta' }, `Il s'arrête tout seul à ${until}. S'il ne répond pas tout de suite, patiente quelques secondes.`),
        button('Arrêter le lab', async () => {
          await api<undefined>('DELETE', path);
          render(null);
        }),
      );
      return;
    }
    box.replaceChildren(
      h('h2', {}, 'Ton lab'),
      h(
        'p',
        {},
        `Une application vulnérable, rien que pour toi, isolée du réseau. Elle s'arrête toute seule après ${String(Math.round(lab.ttlSeconds / 60))} minutes.`,
      ),
      button('Démarrer mon lab', async () => {
        render(await api<LabInstance>('POST', path, {}));
      }),
    );
  };
  render(lab.instance);
  return box;
}

/** Blue-team challenges: a rule editor instead of a flag field; the server evaluates the rule (ADR 0010). */
function detectionForm(challengeId: string, info: DetectionInfo): HTMLElement {
  const starter =
    info.unit === 'entity'
      ? { match: { [info.fields[1] ?? 'ts']: 'à compléter' }, threshold: { groupBy: info.entityField ?? '', min: 10, windowSeconds: 600 } }
      : { match: [{ [`${info.fields[info.fields.length - 1] ?? 'ts'}|contains`]: ['à compléter'] }] };
  const rule = h('textarea', { name: 'rule', rows: '12', spellcheck: 'false', autocomplete: 'off', class: 'code' });
  rule.value = JSON.stringify(starter, null, 2);
  const status = h('div', { 'aria-live': 'polite' });
  const form = h(
    'form',
    { class: 'card' },
    h(
      'p',
      { class: 'meta' },
      `Champs disponibles : ${info.fields.join(', ')}. Unité de détection : ${info.unit === 'entity' ? `l'entité « ${info.entityField ?? ''} »` : "l'événement"}.`,
    ),
    h('label', {}, 'Ta règle (JSON)', rule),
    status,
    h('button', { type: 'submit' }, 'Évaluer ma règle'),
  );
  onSubmit(form, status, async () => {
    let parsed: unknown;
    try {
      parsed = JSON.parse(rule.value);
    } catch {
      status.replaceChildren(alert("Ce n'est pas du JSON valide : vérifie les guillemets et les virgules."));
      return;
    }
    const r = await api<DetectionResult>('POST', `/v1/challenges/${encodeURIComponent(challengeId)}/detect`, { rule: parsed });
    const examples = (label: string, list: string[]) => (list.length ? h('p', { class: 'meta' }, `${label} : ${list.join(', ')}`) : null);
    const lines = [
      r.solved
        ? alert(r.alreadySolved ? 'Règle parfaite, défi déjà résolu.' : `Règle parfaite ! Toutes les attaques, aucune fausse alerte. +${String(r.points)} points.`, 'info')
        : alert(`Détectées : ${String(r.detected)}/${String(r.total)} · Manquées : ${String(r.missed)} · Fausses alertes : ${String(r.falsePositives)}`),
      examples('Exemples manqués', r.examples.missed),
      examples('Exemples de fausses alertes', r.examples.falsePositives),
    ].filter((n) => n !== null);
    status.replaceChildren(...lines);
  });
  return form;
}

function challengeCard(c: ChallengeSummary): HTMLElement {
  const state = c.solved ? 'Terminé' : c.unlocked ? 'Disponible' : 'Verrouillé';
  return h(
    'section',
    { class: `card module ${c.unlocked ? '' : 'locked'}` },
    h('header', {}, h('h3', {}, c.unlocked ? h('a', { href: `#/defi/${c.id}` }, c.title) : c.title), h('span', { class: `badge badge-${state.toLowerCase()}` }, state)),
    h('p', { class: 'meta' }, `${c.points} points${c.unlocked ? '' : ' · se débloque avec son module dans le parcours'}`),
  );
}

export async function challengesView(): Promise<void> {
  const { items } = await api<{ items: ChallengeSummary[] }>('GET', '/v1/challenges');
  const solved = items.filter((c) => c.solved);
  show(
    h('h1', {}, 'Défis'),
    h(
      'p',
      {},
      "Chaque défi cache un flag de la forme BASTION{…}. Il est calculé pour ton compte : celui d'un autre apprenant ne marchera pas chez toi, et le partage se voit dans le journal d'audit.",
    ),
    h('p', { class: 'meta' }, `${solved.length} / ${items.length} résolus · ${solved.reduce((n, c) => n + c.points, 0)} points`),
    ...items.map(challengeCard),
  );
}

export async function challengeView(id: string): Promise<void> {
  let c: Challenge;
  try {
    c = await api<Challenge>('GET', `/v1/challenges/${encodeURIComponent(id)}`);
  } catch (err) {
    if (err instanceof ApiError && [400, 403, 404].includes(err.status)) {
      show(
        h('h1', {}, err.status === 403 ? 'Défi verrouillé' : 'Défi introuvable'),
        alert(err.status === 403 ? 'Avance dans le parcours pour débloquer ce défi.' : "Ce défi n'existe pas.", 'info'),
        h('p', {}, h('a', { href: '#/defis' }, 'Retour aux défis')),
      );
      return;
    }
    throw err;
  }

  const flag = h('input', { type: 'text', name: 'flag', required: true, maxlength: '100', autocomplete: 'off', spellcheck: 'false', placeholder: 'BASTION{…}' });
  const status = h('div', { 'aria-live': 'polite' });
  const form = h('form', { class: 'card' }, h('label', {}, 'Ton flag', flag), status, h('button', { type: 'submit' }, 'Valider'));
  onSubmit(form, status, async () => {
    const r = await api<Submission>('POST', `/v1/challenges/${encodeURIComponent(c.id)}/submit`, { flag: flag.value });
    status.replaceChildren(
      r.correct
        ? alert(r.alreadySolved ? 'Déjà résolu, bien joué quand même.' : `Bravo ! +${r.points} points.`, 'info')
        : alert("Ce n'est pas le bon flag. Relis l'énoncé et réessaie."),
    );
  });

  show(
    h('p', { class: 'breadcrumb' }, h('a', { href: '#/defis' }, 'Défis'), ` › ${c.title}`),
    h(
      'article',
      { class: 'lesson' },
      h('h1', {}, c.title),
      h('p', { class: 'meta' }, `${c.points} points${c.solved ? ' · résolu ✓' : ''}`),
      ...renderBlocks(parseMarkdown(c.brief)),
      ...(c.lab === null
        ? [
            h('h2', {}, c.detection === null ? 'Ce que tu as récupéré' : 'Les journaux à analyser'),
            // Artifact values are attacker-style data: shown as text in <pre>, never interpreted.
            ...Object.entries(c.artifact).flatMap(([name, value]) => [h('h3', {}, name), h('pre', { class: 'artifact' }, value)]),
          ]
        : []),
    ),
    c.lab === null ? null : labPanel(c.id, c.lab),
    c.detection === null ? form : detectionForm(c.id, c.detection),
  );
  if (c.detection === null) flag.focus();
}

export async function scoreboardView(): Promise<void> {
  const board = await api<Scoreboard>('GET', '/v1/scoreboard');
  const rows = board.entries.map((e) =>
    h('tr', { class: e.displayName === board.me.displayName ? 'me' : undefined }, h('td', {}, String(e.rank)), h('td', {}, e.displayName), h('td', {}, String(e.score))),
  );
  show(
    h('h1', {}, 'Classement'),
    h(
      'p',
      { class: 'meta' },
      `Ton score : ${board.me.score} points`,
      board.me.rank === null ? '' : ` · rang ${board.me.rank}`,
      ' (10 points par leçon validée, plus les points des défis).',
    ),
    board.me.displayName === null
      ? alert('Tu n\'apparais pas au classement. Choisis un pseudonyme dans ton compte pour y figurer : ton e-mail n\'est jamais affiché.', 'info')
      : null,
    board.entries.length === 0
      ? h('p', { class: 'hint' }, 'Personne au classement pour le moment.')
      : h(
          'div',
          { class: 'table-wrap' },
          h('table', {}, h('thead', {}, h('tr', {}, h('th', {}, 'Rang'), h('th', {}, 'Pseudonyme'), h('th', {}, 'Points'))), h('tbody', {}, ...rows)),
        ),
    h('p', {}, h('a', { href: '#/compte' }, 'Gérer mon pseudonyme')),
  );
}
