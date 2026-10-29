# 0006 — Curriculum as code, progress in the database

**Status:** accepted (v3, 29 Oct 2026)

## Context
Bastion becomes Bastion Academy, a learning platform. Lessons, modules, prerequisites
and quizzes need a home. The usual answer is a CMS: content stored in the database and
edited through admin endpoints. That adds a privileged write surface (admin forms,
rich-text input, file uploads), the classic path to stored XSS and to content tampering
by anyone who compromises an admin account.

The platform is distributed for local use (`git clone` + Docker), and its content is
open source by design.

## Decision
- Content lives in `content/` as JSON (structure, quizzes) and Markdown (lesson bodies),
  versioned in git. It changes only through pull requests, so it gets the same review,
  CI gates and signed image as the code.
- At startup, `loadCurriculum()` validates the whole tree with strict schemas: slug ids
  (`[a-z0-9-]`, which makes path traversal impossible), unique ids, existing
  prerequisites, no prerequisite cycles, valid quiz answers, `https:` links only.
  **Any inconsistency stops the boot**, like invalid configuration.
- Content is loaded once into memory. Routes look ids up in a map and never build a
  file path from a request.
- The database only stores progress (`lesson_progress`), scoped by `user_id`.
- Gating is enforced server-side: prerequisites, quiz grading, idempotent completion.
  Quiz answers are never sent to the client.

## Rejected alternatives
- **Content in the database with admin endpoints**: more attack surface for no benefit
  while there is a single maintainer and no hosted instance.
- **Markdown files read on every request**: request-driven file access is exactly what
  turns into path traversal; loading once at boot removes the question.
- **Hiding quiz answers** (hashing them in the repo): pointless, the code that checks
  them is public too. The quiz checks learning, it is not an exam. Integrity-sensitive
  scoring arrives in v4 with per-user HMAC flags.

## Consequences
- Adding a lesson = a PR touching `content/`. CI proves the tree is valid
  (`curriculum.test.ts` loads the real `content/`).
- The image ships `content/` read-only (root-owned, mode 0555).
- Lesson bodies are Markdown from a trusted source, but the future front-end must still
  render them without trusting raw HTML (defence in depth, see threat model).
- Changing content requires a restart, which is acceptable for a locally run platform.
