import { accountView } from './account.js';
import {
  api,
  ApiError,
  completeMfa,
  isLoggedIn,
  login,
  logout,
  register,
  restoreSession,
  type Completion,
  type Curriculum,
  type Lesson,
  type LoginStep,
  type ModuleView,
} from './api.js';
import { challengesView, challengeView, scoreboardView } from './challenges.js';
import { h, renderBlocks } from './dom.js';
import { parseMarkdown } from './markdown.js';
import { alert, errorMessage, onSubmit, show } from './ui.js';

/**
 * Single-page app with hash routes (#/, #/connexion, #/lecon/<id>): the
 * server only serves static files and never has to guess which URL is a page.
 * Every gate shown here (locked modules, quiz results) is decided by the API;
 * the UI only displays it.
 */

const nav = document.getElementById('nav') as HTMLElement;

function renderNav(): void {
  if (!isLoggedIn()) {
    nav.replaceChildren(h('a', { href: '#/connexion' }, 'Connexion'));
    return;
  }
  const out = h('button', { type: 'button', class: 'link' }, 'Déconnexion');
  out.addEventListener('click', () => {
    void logout().then(() => {
      location.hash = '#/connexion';
    });
  });
  nav.replaceChildren(
    h('a', { href: '#/' }, 'Parcours'),
    h('a', { href: '#/defis' }, 'Défis'),
    h('a', { href: '#/classement' }, 'Classement'),
    h('a', { href: '#/compte' }, 'Compte'),
    out,
  );
}

/* ---------- authentication ---------- */

/** Second login step: the password was right, the account has TOTP enabled. */
function mfaView(mfaToken: string): void {
  const code = h('input', { type: 'text', name: 'code', required: true, inputmode: 'numeric', autocomplete: 'one-time-code', maxlength: '19' });
  const status = h('div', { 'aria-live': 'polite' });
  const form = h(
    'form',
    { class: 'card narrow' },
    h('h1', {}, 'Vérification en deux étapes'),
    h('p', { class: 'hint' }, "Saisis le code à 6 chiffres de ton application d'authentification, ou un code de secours."),
    h('label', {}, 'Code', code),
    status,
    h('button', { type: 'submit' }, 'Vérifier'),
    h('p', { class: 'hint' }, h('a', { href: '#/connexion' }, 'Recommencer la connexion')),
  );
  onSubmit(form, status, async () => {
    try {
      await completeMfa(mfaToken, code.value.replaceAll(' ', ''));
      location.hash = '#/';
    } finally {
      code.value = '';
    }
  });
  show(form);
  code.focus();
}

const afterLogin = (step: LoginStep): void => {
  if (step.done) location.hash = '#/';
  else mfaView(step.mfaToken);
};

function authView(mode: 'login' | 'register'): void {
  const email = h('input', { type: 'email', name: 'email', required: true, autocomplete: 'username', maxlength: '254' });
  const password = h('input', {
    type: 'password',
    name: 'password',
    required: true,
    minlength: mode === 'register' ? '12' : undefined,
    maxlength: '128',
    autocomplete: mode === 'register' ? 'new-password' : 'current-password',
  });
  const status = h('div', { 'aria-live': 'polite' });
  const submit = h('button', { type: 'submit' }, mode === 'login' ? 'Se connecter' : 'Créer mon compte');

  const form = h(
    'form',
    { class: 'card narrow' },
    h('h1', {}, mode === 'login' ? 'Connexion' : 'Créer un compte'),
    h('label', {}, 'Adresse e-mail', email),
    h('label', {}, 'Mot de passe', password),
    mode === 'register'
      ? h('p', { class: 'hint' }, 'Au moins 12 caractères. Une phrase de passe est plus simple à retenir et plus solide.')
      : null,
    status,
    submit,
    h(
      'p',
      { class: 'hint' },
      mode === 'login' ? h('a', { href: '#/inscription' }, 'Pas encore de compte ? Inscris-toi') : h('a', { href: '#/connexion' }, "J'ai déjà un compte"),
    ),
  );

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    submit.disabled = true;
    status.replaceChildren();
    const action = mode === 'login' ? login(email.value, password.value) : register(email.value, password.value);
    action
      .then(afterLogin)
      .catch((err: unknown) => {
        status.replaceChildren(alert(errorMessage(err)));
      })
      .finally(() => {
        submit.disabled = false;
        password.value = '';
      });
  });

  show(form);
  email.focus();
}

/* ---------- catalogue ---------- */

function progressBar(done: number, total: number): HTMLElement {
  const pct = total === 0 ? 0 : Math.round((done / total) * 100);
  const bar = h('progress', { max: String(total), value: String(done), 'aria-label': 'Progression' });
  return h('div', { class: 'progress' }, bar, h('span', {}, `${done} / ${total} leçons (${pct} %)`));
}

function moduleCard(m: ModuleView, titles: ReadonlyMap<string, string>): HTMLElement {
  const state = m.completed ? 'Terminé' : m.unlocked ? 'Disponible' : 'Verrouillé';
  const lessons = m.unlocked
    ? h(
        'ol',
        { class: 'lessons' },
        ...m.lessons.map((l) =>
          h(
            'li',
            { class: l.completed ? 'done' : undefined },
            h('a', { href: `#/lecon/${l.id}` }, l.title),
            h('span', { class: 'meta' }, `${l.minutes} min${l.hasQuiz ? ' · quiz' : ''}${l.completed ? ' · ✓' : ''}`),
          ),
        ),
      )
    : h('p', { class: 'hint' }, `Termine d'abord : ${m.prerequisites.map((p) => titles.get(p) ?? p).join(', ')}.`);
  return h(
    'section',
    { class: `card module ${m.unlocked ? '' : 'locked'}` },
    h('header', {}, h('h3', {}, m.title), h('span', { class: `badge badge-${state.toLowerCase()}` }, state)),
    h('p', {}, m.summary),
    lessons,
  );
}

async function catalogView(): Promise<void> {
  const cur = await api<Curriculum>('GET', '/v1/curriculum');
  const titles = new Map(cur.paths.flatMap((p) => p.modules.map((m) => [m.id, m.title] as const)));

  const levels = cur.levels.map((lvl) => {
    const paths = cur.paths.filter((p) => p.level === lvl.level);
    return h(
      'section',
      { class: `level ${paths.length === 0 ? 'soon' : ''}` },
      h('h2', {}, `Niveau ${lvl.level} · ${lvl.title}`),
      h('p', { class: 'goal' }, lvl.goal),
      ...(paths.length === 0
        ? [h('p', { class: 'hint' }, 'Bientôt disponible.')]
        : paths.map((p) =>
            h('div', { class: 'path' }, h('h3', {}, p.title), h('p', {}, p.summary), ...p.modules.map((m) => moduleCard(m, titles))),
          )),
    );
  });

  show(h('h1', {}, 'Ton parcours'), progressBar(cur.progress.completed, cur.progress.total), ...levels);
}

/* ---------- lesson ---------- */

function nextLessonId(cur: Curriculum, lessonId: string): string | null {
  const ordered = cur.paths.flatMap((p) => p.modules.flatMap((m) => m.lessons.map((l) => l.id)));
  const i = ordered.indexOf(lessonId);
  return i >= 0 && i + 1 < ordered.length ? (ordered[i + 1] ?? null) : null;
}

function quizForm(lesson: Lesson, onDone: (r: Completion) => void): HTMLElement {
  const status = h('div', { 'aria-live': 'polite' });
  const submit = h('button', { type: 'submit' }, lesson.quiz.length > 0 ? 'Valider mes réponses' : 'Marquer comme terminée');

  const questions = lesson.quiz.map((q, qi) =>
    h(
      'fieldset',
      { 'data-question': q.id },
      h('legend', {}, `${qi + 1}. ${q.prompt}`),
      q.multiple ? h('p', { class: 'hint' }, 'Plusieurs réponses possibles.') : null,
      ...q.choices.map((c, ci) =>
        h(
          'label',
          { class: 'choice' },
          h('input', { type: q.multiple ? 'checkbox' : 'radio', name: `q-${q.id}`, value: String(ci) }),
          c,
        ),
      ),
    ),
  );

  const form = h('form', { class: 'quiz card' }, lesson.quiz.length > 0 ? h('h2', {}, 'Quiz') : null, ...questions, status, submit);

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const answers = lesson.quiz.map((q) => ({
      question: q.id,
      choices: [...form.querySelectorAll<HTMLInputElement>(`input[name="q-${q.id}"]:checked`)].map((i) => Number(i.value)),
    }));
    if (answers.some((a) => a.choices.length === 0)) {
      status.replaceChildren(alert('Réponds à toutes les questions.'));
      return;
    }
    submit.disabled = true;
    api<Completion>('POST', `/v1/lessons/${encodeURIComponent(lesson.id)}/complete`, { answers })
      .then((r) => {
        for (const fs of form.querySelectorAll('fieldset')) {
          fs.classList.toggle('wrong', !r.passed && r.incorrect.includes(fs.dataset.question ?? ''));
        }
        if (!r.passed) {
          const n = r.incorrect.length;
          status.replaceChildren(alert(`${n} réponse${n > 1 ? 's' : ''} à revoir. Relis la leçon, puis réessaie.`));
        } else {
          status.replaceChildren();
        }
        onDone(r);
      })
      .catch((err: unknown) => {
        status.replaceChildren(alert(errorMessage(err)));
      })
      .finally(() => {
        submit.disabled = false;
      });
  });
  return form;
}

async function lessonView(id: string): Promise<void> {
  let lesson: Lesson;
  const curriculum = api<Curriculum>('GET', '/v1/curriculum');
  curriculum.catch(() => undefined); // awaited below; avoids an unhandled rejection if we return early
  try {
    lesson = await api<Lesson>('GET', `/v1/lessons/${encodeURIComponent(id)}`);
  } catch (err) {
    if (err instanceof ApiError && (err.status === 403 || err.status === 404 || err.status === 400)) {
      show(
        h('h1', {}, err.status === 403 ? 'Leçon verrouillée' : 'Leçon introuvable'),
        alert(err.status === 403 ? "Termine d'abord les modules prérequis." : "Cette leçon n'existe pas.", 'info'),
        h('p', {}, h('a', { href: '#/' }, 'Retour au parcours')),
      );
      return;
    }
    throw err;
  }

  const outcome = h('div', { class: 'outcome', 'aria-live': 'polite' });
  const done = (r: Completion) => {
    if (!r.passed) return;
    void curriculum.then((cur) => {
      const next = nextLessonId(cur, lesson.id);
      outcome.replaceChildren(
        alert(r.alreadyCompleted ? 'Leçon déjà validée.' : 'Bravo, leçon validée !', 'info'),
        h('p', {}, next ? h('a', { href: `#/lecon/${next}`, class: 'button' }, 'Leçon suivante') : null, ' ', h('a', { href: '#/' }, 'Retour au parcours')),
      );
    });
  };

  const cur = await curriculum;
  const path = cur.paths.find((p) => p.id === lesson.pathId);
  const mod = path?.modules.find((m) => m.id === lesson.moduleId);

  show(
    h('p', { class: 'breadcrumb' }, h('a', { href: '#/' }, 'Parcours'), ` › ${path?.title ?? lesson.pathId} › ${mod?.title ?? lesson.moduleId}`),
    h('article', { class: 'lesson' }, h('h1', {}, lesson.title), h('p', { class: 'meta' }, `${lesson.minutes} min${lesson.completed ? ' · déjà validée ✓' : ''}`), ...renderBlocks(parseMarkdown(lesson.body))),
    lesson.references.length > 0
      ? h(
          'aside',
          { class: 'card references' },
          h('h2', {}, 'Pour aller plus loin'),
          h('ul', {}, ...lesson.references.map((r) => h('li', {}, h('a', { href: r.url, target: '_blank', rel: 'noopener noreferrer' }, r.label)))),
        )
      : null,
    quizForm(lesson, done),
    outcome,
  );
}

/* ---------- router ---------- */

async function route(): Promise<void> {
  const target = location.hash || '#/';
  renderNav();
  try {
    const lesson = /^#\/lecon\/([a-z0-9-]{1,64})$/.exec(target);
    const challenge = /^#\/defi\/([a-z0-9-]{1,64})$/.exec(target);
    if (target === '#/connexion') authView('login');
    else if (target === '#/inscription') authView('register');
    else if (!isLoggedIn()) location.hash = '#/connexion';
    else if (lesson?.[1]) await lessonView(lesson[1]);
    else if (challenge?.[1]) await challengeView(challenge[1]);
    else if (target === '#/defis') await challengesView();
    else if (target === '#/classement') await scoreboardView();
    else if (target === '#/compte') await accountView();
    else await catalogView();
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) {
      location.hash = '#/connexion';
      return;
    }
    show(alert(errorMessage(err)));
  }
}

window.addEventListener('hashchange', () => void route());
void restoreSession().then(() => route());
