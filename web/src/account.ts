import { api, type Me } from './api.js';
import { h } from './dom.js';
import { passkeysCard } from './passkeys.js';
import { alert, onSubmit, show } from './ui.js';

/** #/compte: scoreboard pseudonym, two-factor authentication (TOTP) and passkeys. */

const passwordInput = () =>
  h('input', { type: 'password', name: 'password', required: true, maxlength: '128', autocomplete: 'current-password' });

const codeInput = (label = 'Code à 6 chiffres') =>
  h('input', { type: 'text', name: 'code', required: true, inputmode: 'numeric', autocomplete: 'one-time-code', maxlength: '19', 'aria-label': label });

function profileCard(me: Me): HTMLElement {
  const name = h('input', { type: 'text', name: 'displayName', minlength: '3', maxlength: '24', value: me.displayName ?? '', autocomplete: 'nickname' });
  const status = h('div', { 'aria-live': 'polite' });
  const form = h(
    'form',
    { class: 'card' },
    h('h2', {}, 'Classement'),
    h('p', { class: 'hint' }, "Le classement est facultatif. Seul ton pseudonyme et ton score sont publiés, jamais ton e-mail. Laisse vide pour ne pas y figurer."),
    h('label', {}, 'Pseudonyme', name),
    status,
    h('button', { type: 'submit' }, 'Enregistrer'),
  );
  onSubmit(form, status, async () => {
    const value = name.value.trim();
    const r = await api<{ displayName: string | null }>('PUT', '/v1/me/profile', { displayName: value === '' ? null : value });
    status.replaceChildren(alert(r.displayName === null ? 'Tu ne figures plus au classement.' : `Tu apparais au classement sous le nom ${r.displayName}.`, 'info'));
  });
  return form;
}

function recoveryCodesCard(codes: string[]): HTMLElement {
  return h(
    'section',
    { class: 'card' },
    h('h2', {}, 'Double authentification activée'),
    alert('Note ces codes de secours maintenant, hors de ton ordinateur. Ils ne seront plus jamais affichés. Chacun ne sert qu\'une fois, si tu perds ton téléphone.', 'info'),
    h('pre', { class: 'artifact' }, codes.join('\n')),
    h('p', {}, h('a', { href: '#/compte', class: 'button' }, "C'est noté")),
  );
}

function enableMfaCard(): HTMLElement {
  const card = h('section', { class: 'card' });
  const password = passwordInput();
  const status = h('div', { 'aria-live': 'polite' });
  const start = h(
    'form',
    {},
    h('h2', {}, 'Double authentification (TOTP)'),
    h('p', { class: 'hint' }, "Avec une application d'authentification (Aegis, FreeOTP, Google Authenticator…), un mot de passe volé ne suffit plus pour entrer dans ton compte."),
    h('label', {}, 'Confirme ton mot de passe', password),
    status,
    h('button', { type: 'submit' }, 'Configurer'),
  );
  onSubmit(start, status, async () => {
    const r = await api<{ secret: string; otpauthUri: string }>('POST', '/v1/me/mfa/setup', { password: password.value });
    password.value = '';
    const code = codeInput();
    const confirmStatus = h('div', { 'aria-live': 'polite' });
    const confirm = h(
      'form',
      {},
      h('h2', {}, 'Ajoute Bastion à ton application'),
      h('p', {}, 'Dans ton application, choisis « saisir une clé » et recopie cette clé :'),
      h('pre', { class: 'artifact' }, (r.secret.match(/.{1,4}/g) ?? []).join(' ')),
      h('details', {}, h('summary', {}, 'Lien otpauth (pour un gestionnaire de mots de passe)'), h('pre', { class: 'artifact' }, r.otpauthUri)),
      h('label', {}, 'Puis saisis le code affiché', code),
      confirmStatus,
      h('button', { type: 'submit' }, 'Activer'),
    );
    onSubmit(confirm, confirmStatus, async () => {
      const done = await api<{ recoveryCodes: string[] }>('POST', '/v1/me/mfa/enable', { code: code.value.replaceAll(' ', '') });
      card.replaceWith(recoveryCodesCard(done.recoveryCodes));
    });
    card.replaceChildren(confirm);
    code.focus();
  });
  card.append(start);
  return card;
}

function disableMfaCard(): HTMLElement {
  const password = passwordInput();
  const code = codeInput('Code à 6 chiffres ou code de secours');
  const status = h('div', { 'aria-live': 'polite' });
  const form = h(
    'form',
    { class: 'card' },
    h('h2', {}, 'Double authentification (TOTP)'),
    alert('Activée. Ton compte demande un code à chaque connexion.', 'info'),
    h('p', { class: 'hint' }, 'Pour la désactiver, il faut les deux facteurs : ton mot de passe et un code.'),
    h('label', {}, 'Mot de passe', password),
    h('label', {}, 'Code à 6 chiffres ou code de secours', code),
    status,
    h('button', { type: 'submit' }, 'Désactiver'),
  );
  onSubmit(form, status, async () => {
    await api('POST', '/v1/me/mfa/disable', { password: password.value, code: code.value.replaceAll(' ', '') });
    location.hash = '#/compte';
    window.dispatchEvent(new HashChangeEvent('hashchange'));
  });
  return form;
}

export async function accountView(): Promise<void> {
  const me = await api<Me>('GET', '/v1/me');
  const passkeys = await passkeysCard(me, (codes) => {
    show(h('h1', {}, 'Mon compte'), recoveryCodesCard(codes));
  });
  show(h('h1', {}, 'Mon compte'), profileCard(me), me.totpEnabled ? disableMfaCard() : enableMfaCard(), passkeys);
}
