# 0010 — Blue-team detection challenges

**Status:** accepted (v6, 30 Oct 2026)

## Context
Levels 1 to 3 train the attacker. A security engineer spends more time on the
other side: deciding what to log, writing detections, and living with their false
positives. Flag-based challenges cannot teach that, because detection has no single
secret answer: a rule is good when it catches every attack *and* stays quiet on
legitimate activity. Grading that means **running learner-written rules on the
server**, the first place where the platform executes learner input.

## Decision

### Learners write rules; the server scores them
A detection challenge gives each learner a log dataset (JSON Lines) generated from
their own HMAC seed: attacks mixed with benign activity, including **traps** built to
catch the naive rule (`O'Connor` against "an apostrophe means SQL injection", a
service account with an expired password against "many failures means brute force",
`certutil -hashfile` against "certutil is malicious", a slow attacker against a short
window). `POST /v1/challenges/:id/detect` evaluates the rule against the learner's
dataset and returns detected / missed / false positives with three examples of each.
The challenge is solved at **100 % recall and 100 % precision**. No flag is involved.

### A small, Sigma-shaped language
Sigma is the industry's portable detection format; the challenges use a JSON subset
so that what is learnt transfers:

- `match`: a block (AND of conditions) or a list of blocks (OR); a list of values for
  one field is an OR; `exclude` removes known-benign activity;
- modifiers `contains`, `startswith`, `endswith` (case-insensitive, as in Sigma) and
  `gte` / `lte` for numbers;
- `threshold` for behavioural detection: per `groupBy` value, at least `min` events,
  or `min` distinct values of `distinct`, within `windowSeconds` (sliding window).

### What the language deliberately leaves out
- **No regular expressions.** A learner regex runs on the platform's event loop; one
  catastrophic pattern (`(a+)+$`, ReDoS) on a crafted string would stall every user.
  Node has no linear-time engine built in (RE2 would be a native dependency, against
  invariant 11). Substring, prefix and suffix tests are linear and enough to teach.
- **No field outside the dataset.** Keys are validated against the dataset's field
  list before evaluation, and values are read with `Object.hasOwn`: `__proto__`,
  `constructor` or any non-data property can never be reached.
- **No unbounded input.** At most 10 blocks, 10 conditions per block, 20 values per
  condition, 200 characters per value, thresholds bounded; datasets stay under 400
  events. Evaluation is linear in their product. Evaluations are rate-limited per
  account (twice the quiz budget: writing a rule is iterative).

### Answers never leave the server
Labels (which events or entities are malicious) exist only in the evaluator. The
learner sees counts and up to three examples of misses and false positives: enough
to learn, not enough to reconstruct the answer key in one request. Event ids follow
time order, so position carries no hint.

## Rejected
- **Flags hidden in the logs** ("find the attacker's IP"): tests reading, not
  detection; one `grep` solves it and nothing about false positives is learnt.
- **Running real Sigma through a SIEM backend**: a heavy dependency or a container per
  learner for what a 150-line evaluator does, with an attack surface we cannot bound.
- **Free-form JavaScript predicates**: arbitrary code execution, even sandboxed
  (`node:vm` is explicitly not a security boundary).

## Consequences
- A detection challenge is solved by a rule, not a flag; flags submitted to it never
  match (they are never revealed).
- The language cannot express everything Sigma can (no `|re`, no `1 of selection*`).
  The lesson says so and explains why.
- New datasets are code (`src/detection/datasets.ts`), each with a test proving that a
  careful rule is perfect on any seed **and** that the naive rules fall into the traps.
