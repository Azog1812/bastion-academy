# 0017 — Passwordless login with a discoverable passkey, and account recovery

**Status:** accepted (1 Nov 2026). Follows ADR 0016, which left passwordless "for later:
it changes account recovery, not only the login form".

## Context
With ADR 0016 a passkey is a second factor: the learner still types an e-mail and a
password, then signs. The password is still what a phishing page, a credential-stuffing
list or a keylogger goes after, and the e-mail field still drives the lockout. A passkey
can carry the whole login on its own: the authenticator holds the key (possession) and
checks a PIN or a biometric before signing (knowledge or inherence). NIST SP 800-63B calls
that a *multi-factor cryptographic authenticator*: AAL2 by itself, and phishing-resistant.

What changes is not the cryptography (the checks of ADR 0016 stay) but three questions:
who is logging in when nobody typed an e-mail, what the factor must prove when it is the
only one, and how a learner gets back in when the passkey is gone.

## Decision
- **Discoverable credentials.** `POST /v1/auth/passkey/options` returns a challenge with an
  empty `allowCredentials`: the browser lists the passkeys it holds for the RP ID, the
  learner picks one, and the authenticator returns the *user handle* stored at
  registration (the account id, already sent as `user.id` since ADR 0016; never the
  e-mail). `POST /v1/auth/passkey` (API) and `POST /v1/session/passkey` (browser, refresh
  token in the `__Host-` cookie, same-origin only, ADR 0007) verify it.
- **The handle names the account, the lookup proves it** (W3C WebAuthn §7.2 step 6). The
  credential is searched with `WHERE user_id = <handle> AND credential_id = <id>`: a valid
  key of account A presented with B's handle finds nothing. The query keeps `user_id`
  (Semgrep rule), the handle must be a UUID, and an unknown credential, a forged handle,
  a bad signature and a missing PIN all answer the same `401 Passkey not recognised`. The
  audit says which (`auth.login` failure, `method: passkey`, `reason`), and names an actor
  only once a real credential of that account was found.
- **User verification required** (`userVerification: "required"`, UV flag checked on the
  server, `UserVerificationRequired` in `crypto/webauthn.ts`). As a second factor,
  presence was enough: the password was the other factor. Alone, a security key without a
  PIN would let whoever picks it up open the account.
- **Its own challenge table** (`webauthn_login_challenges`, migration v7): the challenge is
  issued before anyone is identified, so it has no user. A nullable `user_id` in
  `webauthn_challenges` would have made every existing query there one `IS NULL` away from
  matching a user-less row. Single use (deleted when presented), 5 minutes, SHA-256 only,
  and an MFA-step challenge and a passwordless challenge can never answer for each other.
- **A global cap on pending challenges** (10 000). The options endpoint is unauthenticated
  and writes a row: the per-address rate limit brakes one client, the cap bounds what many
  addresses can make the database hold. Expired rows are swept first; past the cap, 503.
- **The password lockout does not apply, and is not fed.** The lockout exists to stop the
  online guessing of a password or a code; a signature cannot be guessed. So a valid
  passkey logs in while the account is locked by someone hammering its password, and the
  lock is neither lifted nor reset: the guesser stays locked out. Conversely a failed
  assertion is not a failed login: the user handle comes from the request, so counting it
  would give anyone a button that locks any account. Failures are still audited, still
  feed Wazuh rules 100208-100210 (brute force, credential stuffing), and the auth rate
  limit applies.
- **The password stays.** Passwordless is a way in, not a different kind of account.

### Account recovery
Recovery is where passwordless designs usually fail: the strongest login is only as
strong as the way around it. The choices, from the most to the least common case:

1. *A passkey is lost, others remain*: log in with another one, remove the lost one
   (password needed, ADR 0016). Learners are told to register two.
2. *Every passkey is lost*: log in with the password, then the second factor (TOTP, or one
   of the recovery codes given once with the first factor, ADR 0008/0016). Passkeys are
   then removed and re-added from the account page.
3. *Password and every factor lost*: the operator, on the host (`node dist/cli.js`), as
   for admin promotion and key rotation (invariant 9). On a local install the learner is
   that operator.

Recovery **never downgrades to something weaker than a factor**: no e-mail link (there is
no mail channel, and it would make the mailbox the real authenticator), no security
questions (NIST 800-63B forbids them), no recovery over HTTP that skips the second
factor. The recovery path (password plus a second factor) keeps its own lockout and the
attempt cap of the MFA step.

## Rejected options
- *Passkey-only accounts (no password at all)*: the cleanest end state, but recovery would
  then rest on recovery codes alone, or on an e-mail channel the platform does not have.
  Revisit with hosting and verified e-mail.
- *Conditional UI* (`mediation: "conditional"`, passkeys offered in the e-mail field's
  autofill): nicer, but browser support is still uneven and the explicit button keeps the
  ceremony visible, which suits a platform that teaches it. Can be added later in
  `web/src/passkeys.ts` without touching the server.
- *`residentKey: "required"` at registration*: would refuse plain security keys that store
  no credential. They stay usable as second factors; the login page says so when the
  chosen passkey carries no user handle.
- *Sending the e-mail first and then an `allowCredentials` list*: works with
  non-discoverable keys, but tells anyone which e-mail has which passkeys
  (credential-id enumeration), the thing this design removes.

## Consequences
- Login has three doors: password then second factor, password alone (accounts without
  MFA), or a passkey alone. All three issue the same tokens through `issue()`.
- An attacker with a full session (password and second factor) can add a passkey and keep
  a way in after a password change. Mitigations: the password is asked again to add one
  (ADR 0016), `passkey.register` is audited and reaches Wazuh, and the account page lists
  every passkey with its last use. Revoking passkeys on password change was rejected: a
  learner changing a leaked password would lose the factor that was never leaked.
- Tests (`test/security/passkey-login.test.ts`) play: another account's handle, a forged
  handle, an unknown key, a key without PIN, replayed and cross-ceremony challenges, an
  expired one, a phishing origin and RP ID, a cloned key, the lockout both ways, a
  challenge flood, foreign Origin on the cookie route, non-strict bodies.
  `test/e2e/passkeys-browser.sh` logs in without a password in real Chromium.
