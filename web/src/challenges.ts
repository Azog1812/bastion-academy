import { api, ApiError, type Challenge, type ChallengeSummary, type Scoreboard, type Submission } from './api.js';
import { h, renderBlocks } from './dom.js';
import { parseMarkdown } from './markdown.js';
import { alert, onSubmit, show } from './ui.js';

/** Challenges (#/defis, #/defi/<id>) and the scoreboard (#/classement). Flags are checked server-side only. */

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
      h('h2', {}, 'Ce que tu as récupéré'),
      // Artifact values are attacker-style data: shown as text in <pre>, never interpreted.
      ...Object.entries(c.artifact).flatMap(([name, value]) => [h('h3', {}, name), h('pre', { class: 'artifact' }, value)]),
    ),
    form,
  );
  flag.focus();
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
