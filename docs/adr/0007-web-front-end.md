# 0007 — Web front-end: zero dependencies, HttpOnly refresh cookie, Trusted Types

**Status:** accepted (v3, 29 Oct 2026)

## Context
Learners need a browser UI, not `curl`. A front-end is where most web applications
lose their security: tokens in `localStorage` stolen by any XSS, Markdown rendered
with `innerHTML`, a framework plus hundreds of transitive packages in the supply
chain, and CORS configured loosely to make a separate dev server work.

## Decision
**Same origin, static files.** The UI is served by the API process (`src/http/web.ts`)
from `web/public` and the compiled `dist/web`. No CORS configuration exists, so no
other origin can call the API from a browser with credentials.

**No new dependency.** TypeScript is compiled by the `tsc` already in the toolchain
and shipped as native ES modules. No framework, no bundler, no Markdown library.
The supply-chain surface of the front-end is the code in `web/src`, about 600 lines.

**Tokens.**
- The access token (15 min) lives in a module variable, never in `localStorage`,
  `sessionStorage` or a readable cookie. ESLint bans both storages in `web/`.
- The refresh token is set by `POST /v1/session/login` in a cookie
  `__Host-bastion_rt; HttpOnly; Secure; SameSite=Strict; Path=/`. JavaScript, including
  injected JavaScript, cannot read it. `__Host-` prevents subdomain cookie tossing.
- On reload, `POST /v1/session/refresh` rotates the cookie (same single-use rotation and
  reuse detection as the API, RFC 9700) and returns a new access token.
- A failed refresh clears the cookie; logout revokes the family server-side.

**CSRF.** The cookie routes are the only cookie-authenticated ones. They are protected
by `SameSite=Strict`, JSON-only bodies (a cross-origin `fetch` with JSON triggers a
preflight that no origin passes, and an HTML form cannot send JSON), and an explicit
`Origin` check that refuses any foreign origin.

**XSS, two independent barriers.**
1. *Code*: the UI is built only with `createElement` and text nodes (`web/src/dom.ts`).
   Markdown is parsed into a tree (`web/src/markdown.ts`) and rendered node by node.
   Raw HTML in a lesson stays text; links keep only `https:` and in-app `#/` targets.
   ESLint bans every HTML-from-string sink (`innerHTML`, `outerHTML`,
   `insertAdjacentHTML`, `document.write`, `srcdoc`, …) in `web/`.
2. *Browser*: page CSP `script-src 'self'` (no inline, no eval) and
   `require-trusted-types-for 'script'; trusted-types` with **no policy allowed**. Any
   string-to-HTML sink throws a `TypeError`, even one introduced by a future
   dependency or a bug. Verified in Chrome during development.

## Rejected alternatives
- **React/Vue + Vite**: better developer ergonomics, but hundreds of packages, native
  binaries in the toolchain (esbuild, rollup) and a separate dev origin. Not worth it
  for a handful of views. Revisit if the UI grows a lot.
- **Refresh token in `localStorage`**: one XSS and a 7-day session leaks.
- **Session cookie for every request** (no bearer token): would make every API route
  cookie-authenticated, so every route would need CSRF protection. Keeping cookies to
  three routes keeps the CSRF surface tiny.
- **`marked` + DOMPurify**: solid libraries, but sanitising HTML strings is still
  building HTML from strings. Not producing HTML at all is simpler to prove, and is
  what lets the CSP forbid every Trusted Types policy.

## Consequences
- The Markdown dialect is a subset. A test parses every shipped lesson and fails if
  unsupported syntax would show up raw.
- `Secure` cookies require HTTPS, except on `localhost`, which browsers treat as a
  secure context. A remote deployment needs TLS, which it needs anyway.
- Hash-based routes (`#/lecon/<id>`): the server only serves files and never maps
  arbitrary paths to pages.
