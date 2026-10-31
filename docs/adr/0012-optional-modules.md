# 0012 — Optional modules: each learner shapes their training

**Status:** accepted (31 Oct 2026)

## Context
Bastion Academy runs on the learner's own machine. Some hands-on parts are heavy: a
real SIEM such as Wazuh needs about 8 GiB of RAM on its own. Making them mandatory
would lock learners with a modest laptop out of everything that follows; leaving
them out of the curriculum would deprive everyone else. Learners asked to add or
remove such modules from the web UI, depending on their machine.

## Decision
- **Content declares it.** A module can be `"optional": true` with
  `"requirements": { "docker": true, "ramGb": 8 }`. The requirements are shown before
  the learner adds the module; they are information, not a check of the machine (the
  browser cannot measure free RAM, and a learner may run the stack elsewhere).
- **Validated at boot (fail closed, ADR 0006).** A mandatory module may not require
  an optional one: leaving an optional module out must never lock the rest of the
  path. Optional on optional, or optional on mandatory, is allowed.
- **Off by default, chosen per learner.** `PUT /v1/me/modules/:id {"added": bool}`
  writes a row in `module_choices (user_id, module_id)`; no row means "left out".
  Mandatory modules cannot be removed (400). The route takes no user id: the
  choice is always the authenticated learner's (same model as progress, invariant 12,
  and the Semgrep rule `bastion-progress-query-without-user` now covers the table).
- **Enforced server-side.** A left-out module's lessons, quizzes, challenges and labs
  answer 403 even when its prerequisites are complete; the learning service is the
  single gate (`isModuleUnlocked` is used by challenges and labs). Denials are audited
  with the reason `not_added`, real changes as `module.select`.
- **Progress follows the training.** The progress bar counts only the modules in the
  learner's training. Removing a module keeps its progress in `lesson_progress`;
  adding it back restores it.

## Rejected options
- *A global switch for the whole installation*: a local install may still have
  several learners (a classroom on one server), each with their own constraints.
- *Detecting the machine's resources*: the platform runs in a container and sees
  its own limits, not the learner's machine; a guess would be wrong in both directions.
- *Hiding optional modules entirely*: the learner would not know what they could add.

## Consequences
- The first optional module is **Wazuh** (level 5). Starting and stopping a real Wazuh
  from the UI comes next, through the lab runner, which stays the only component with
  access to Docker (invariant 15).
- Scoreboard totals are unaffected: points come from challenges solved, whatever the
  training.
