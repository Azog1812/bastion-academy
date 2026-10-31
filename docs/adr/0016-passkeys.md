# 0016 — Passkeys (WebAuthn) as a phishing-resistant second factor

**Status:** accepted (1 Nov 2026). Supersedes the "WebAuthn rejected for now" of ADR 0008.

## Context
TOTP (ADR 0008) stops a stolen password, not a phishing proxy: an adversary-in-the-middle
page (Evilginx, Modlishka) relays the password and the 6-digit code to the real site within
their 30 seconds, and keeps the session. The threat model listed it as an accepted risk,
with WebAuthn as the way out. Passkeys bind every signature to the page's origin and to the
RP ID they were made for, so what a look-alike site obtains is worthless on the real one
(NIST SP 800-63B: phishing-resistant, "verifier impersonation resistance").

## Decision
- **A second factor next to TOTP.** After the password, the MFA step accepts a TOTP code, a
  recovery code, or a passkey assertion (`POST /v1/auth/mfa` and `/v1/session/mfa` with
  `{mfaToken, passkey}`). An account with either factor gets the MFA step; the same attempt
  cap and lockout apply to wrong assertions as to wrong codes. Passwordless login is left
  for later: it changes account recovery, not only the login form.
- **Verified on the server with node:crypto, no library** (`src/crypto/webauthn.ts`,
  invariant 11). For every ceremony: `type`; the challenge (constant-time); the **exact**
  origin (`WEBAUTHN_ORIGINS`); `crossOrigin` refused; `rpIdHash` (`WEBAUTHN_RP_ID`); the
  user-presence flag; for logins the signature over `authenticatorData || SHA-256(clientDataJSON)`
  with the stored key, and the signature counter.
- **Three algorithms, chosen by the server**: Ed25519 (-8), ES256 (-7), RS256 (-257, at
  least 2048 bits). COSE keys are converted to node KeyObjects (JWK import, which also
  rejects points off the curve) and stored as SPKI DER: public keys only.
- **A strict, bounded CBOR decoder** (`src/crypto/cbor.ts`): the attestation object and the
  COSE key are parsed before any signature is checked, so they are attacker input. Definite
  lengths only, no tags or floats, every length checked against the bytes left before
  allocating, depth and item caps, duplicate map keys refused, keys in a Map.
- **Challenges**: 32 random bytes, stored as SHA-256, valid 5 minutes, deleted as soon as
  they are presented (whatever the outcome), bound to their user, their purpose
  (register/login) and, for a login, to the MFA step that asked for them.
- **Clone detection.** A counter that does not increase (when either side is non-zero) means
  two copies of the key: refused and audited `passkey.clone_detected` (Wazuh rule 100211,
  level 12). Synced passkeys keep 0 and never trip it. The counter update is a
  compare-and-set (invariant 5).
- **Scoped in SQL.** Every passkey query carries `user_id` (Semgrep rule extended); the
  credential id is UNIQUE across accounts, so one key cannot be enrolled twice nor claimed
  by a second account. A foreign passkey id answers 404 like a missing one.
- **Enrolment and removal.** Adding a passkey needs the password, in a session that already
  passed MFA. The first second factor of an account returns recovery codes, once. Removing
  a passkey needs the password; removing the **last** second factor also needs a code, as
  disabling TOTP does (invariant 14). Recovery codes stay while any factor remains.
- **No attestation** (`attestation: "none"`): the platform does not restrict authenticator
  brands, and not asking keeps the user's device model private.
- **Configuration fails closed**: an IP address or a scheme as RP ID, an origin that is not
  exact, not HTTPS off localhost, or outside the RP ID stops the boot.

## Rejected options
- *A WebAuthn library* (SimpleWebAuthn, fido2-lib): convenient, but a dependency tree on the
  most sensitive path, against invariant 11. The relying-party checks are a page of code
  against W3C §7, and each is tested.
- *Verifying attestation*: needs FIDO metadata (MDS) and its update chain, and serves to
  restrict authenticator models, which a learning platform does not want.
- *Requiring user verification (PIN/biometrics)*: the password already is the "something
  you know"; `preferred` lets plain security keys work.

## Consequences
- The local install must be opened at `http://localhost:3000`: WebAuthn refuses IP
  addresses as RP ID, so `http://127.0.0.1:3000` cannot use passkeys (the UI says so).
- Tests use a software authenticator (`test/webauthn-authenticator.ts`) producing real
  structures, and play the attacker: phishing origin, foreign RP ID, replayed and
  cross-step challenges, a foreign key, a cloned key, hostile CBOR, IDOR on passkey ids.
  `test/e2e/passkeys-browser.sh` runs the real UI in Chromium with its virtual authenticator.
- Lessons "Hameçonner un second facteur" and "Les passkeys dans le code de Bastion"
  (level 2) teach it, break-it-then-fix-it style.
