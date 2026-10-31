import { api, type Me } from './api.js';
import { h } from './dom.js';
import { alert, onSubmit } from './ui.js';

/**
 * Passkeys (WebAuthn, ADR 0016): the browser and the authenticator do the cryptography;
 * this page only converts between the server's base64url JSON and the ArrayBuffers of
 * the WebAuthn API. Nothing here decides whether a passkey is valid: the server checks
 * the origin, the RP ID, the challenge and the signature.
 */

export const passkeysSupported = (): boolean => typeof window.PublicKeyCredential === 'function';

const fromB64u = (s: string): ArrayBuffer => {
  const bin = atob(s.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - (s.length % 4)) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
};
const toB64u = (buf: ArrayBuffer): string => {
  let bin = '';
  for (const b of new Uint8Array(buf)) bin += String.fromCharCode(b);
  return btoa(bin).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
};

interface Descriptor {
  type: 'public-key';
  id: string;
}
interface CreationOptions {
  challenge: string;
  rp: { id: string; name: string };
  user: { id: string; name: string; displayName: string };
  pubKeyCredParams: { type: 'public-key'; alg: number }[];
  timeout: number;
  attestation: AttestationConveyancePreference;
  authenticatorSelection: AuthenticatorSelectionCriteria;
  excludeCredentials: Descriptor[];
}
export interface RequestOptions {
  challenge: string;
  rpId: string;
  timeout: number;
  userVerification: UserVerificationRequirement;
  allowCredentials: Descriptor[];
}

const descriptors = (list: Descriptor[]): PublicKeyCredentialDescriptor[] => list.map((d) => ({ type: d.type, id: fromB64u(d.id) }));

/** Calls navigator.credentials.create() and returns exactly the fields the server's strict schema accepts. */
async function createCredential(o: CreationOptions) {
  const cred = (await navigator.credentials.create({
    publicKey: {
      challenge: fromB64u(o.challenge),
      rp: o.rp,
      user: { ...o.user, id: fromB64u(o.user.id) },
      pubKeyCredParams: o.pubKeyCredParams,
      timeout: o.timeout,
      attestation: o.attestation,
      authenticatorSelection: o.authenticatorSelection,
      excludeCredentials: descriptors(o.excludeCredentials),
    },
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error('Création annulée');
  const r = cred.response as AuthenticatorAttestationResponse;
  return { id: cred.id, type: 'public-key', response: { clientDataJSON: toB64u(r.clientDataJSON), attestationObject: toB64u(r.attestationObject) } };
}

/** Calls navigator.credentials.get() for the MFA step. */
export async function getAssertion(o: RequestOptions) {
  const cred = (await navigator.credentials.get({
    publicKey: { challenge: fromB64u(o.challenge), rpId: o.rpId, timeout: o.timeout, userVerification: o.userVerification, allowCredentials: descriptors(o.allowCredentials) },
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error('Vérification annulée');
  const r = cred.response as AuthenticatorAssertionResponse;
  return {
    id: cred.id,
    type: 'public-key',
    response: { clientDataJSON: toB64u(r.clientDataJSON), authenticatorData: toB64u(r.authenticatorData), signature: toB64u(r.signature) },
  };
}

/** The WebAuthn API fails with DOMExceptions whose messages are in English and technical. */
export function webauthnMessage(err: unknown): string | null {
  if (!(err instanceof DOMException)) return null;
  if (err.name === 'NotAllowedError') return "Opération annulée, ou délai dépassé. Réessaie et confirme sur ta clé ou ton téléphone.";
  if (err.name === 'InvalidStateError') return 'Cette passkey est déjà enregistrée sur ton compte.';
  if (err.name === 'SecurityError') return 'Les passkeys exigent une adresse comme http://localhost:3000 (pas 127.0.0.1) ou HTTPS.';
  return null;
}

interface PasskeyItem {
  id: string;
  name: string;
  createdAt: string;
  lastUsedAt: string | null;
}

const date = (iso: string) => new Date(iso).toLocaleDateString('fr-FR', { day: 'numeric', month: 'long', year: 'numeric' });
const passwordInput = () => h('input', { type: 'password', name: 'password', required: true, maxlength: '128', autocomplete: 'current-password' });

export async function passkeysCard(me: Me, onRecoveryCodes: (codes: string[]) => void): Promise<HTMLElement> {
  const { items } = await api<{ items: PasskeyItem[] }>('GET', '/v1/me/passkeys');
  const card = h('section', { class: 'card' }, h('h2', {}, 'Passkeys'));
  card.append(
    h(
      'p',
      { class: 'hint' },
      "Une passkey (clé de sécurité, téléphone, Windows Hello…) remplace le code à 6 chiffres. Elle résiste à l'hameçonnage : elle ne signe que pour ce site, donc une fausse page n'en tire rien.",
    ),
  );
  if (!passkeysSupported()) {
    card.append(alert("Ce navigateur ne gère pas les passkeys.", 'info'));
    return card;
  }

  const last = !me.totpEnabled && items.length === 1;
  for (const p of items) {
    const password = passwordInput();
    const code = h('input', { type: 'text', name: 'code', required: last, maxlength: '19', autocomplete: 'one-time-code' });
    const status = h('div', { 'aria-live': 'polite' });
    const form = h(
      'form',
      { class: 'passkey' },
      h('h3', {}, p.name),
      h('p', { class: 'meta' }, `Ajoutée le ${date(p.createdAt)}${p.lastUsedAt ? ` · utilisée le ${date(p.lastUsedAt)}` : ' · jamais utilisée'}`),
      h('details', {}, h('summary', {}, 'Supprimer'), h('label', {}, 'Mot de passe', password), ...(last ? [h('label', {}, 'Dernier second facteur : un code de secours', code)] : []), status, h('button', { type: 'submit', class: 'secondary' }, 'Supprimer cette passkey')),
    );
    onSubmit(form, status, async () => {
      await api('DELETE', `/v1/me/passkeys/${encodeURIComponent(p.id)}`, last ? { password: password.value, code: code.value.replaceAll(' ', '') } : { password: password.value });
      window.dispatchEvent(new HashChangeEvent('hashchange'));
    });
    card.append(form);
  }

  const name = h('input', { type: 'text', name: 'name', required: true, maxlength: '40', placeholder: 'Clé USB, téléphone…' });
  const password = passwordInput();
  const status = h('div', { 'aria-live': 'polite' });
  const add = h('form', {}, h('h3', {}, 'Ajouter une passkey'), h('label', {}, 'Nom', name), h('label', {}, 'Confirme ton mot de passe', password), status, h('button', { type: 'submit' }, 'Ajouter'));
  onSubmit(add, status, async () => {
    const options = await api<CreationOptions>('POST', '/v1/me/passkeys/options', { password: password.value });
    password.value = '';
    let credential;
    try {
      credential = await createCredential(options);
    } catch (err) {
      const message = webauthnMessage(err);
      if (message) {
        status.replaceChildren(alert(message));
        return;
      }
      throw err;
    }
    const r = await api<{ recoveryCodes: string[] | null }>('POST', '/v1/me/passkeys', { name: name.value.trim(), credential });
    if (r.recoveryCodes) onRecoveryCodes(r.recoveryCodes);
    else window.dispatchEvent(new HashChangeEvent('hashchange'));
  });
  card.append(add);
  return card;
}
