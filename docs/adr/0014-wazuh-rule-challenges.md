# 0014 — Wazuh rule challenges: real XML rules, read by a closed parser

**Status:** accepted (31 Oct 2026)

## Context
The optional Wazuh module (ADR 0012) teaches Wazuh's rule language, and learners can
now run a real Wazuh (ADR 0013). The JSON detection challenges (ADR 0010) teach the
ideas (precision and recall, traps for naive rules) but not the syntax a SOC engineer
writes on the job: `local_rules.xml`, `if_sid`, correlation with `frequency`, level 0
children to silence noise. Learners should write that, and be graded on it.

Grading XML written by learners means parsing untrusted XML on the server, the classic
source of XXE (reading local files, SSRF through external entities) and of entity
expansion ("billion laughs", a few hundred bytes that grow to gigabytes). It also means
facing Wazuh's own pattern languages: OS_Regex and PCRE2 are regular expressions, and a
learner regex is a ReDoS (ADR 0010).

## Decision
- **Learners submit the XML text of their rules**, exactly as in `local_rules.xml`, to
  the existing `POST /v1/challenges/:id/detect` (a string for Wazuh challenges, an object
  for JSON ones; each challenge accepts only its own format). Scoring, rate limit,
  audit and the "100 % recall, 0 false positive" rule are unchanged.
- **A closed XML reader, no general-purpose parser** (`src/detection/wazuh.ts`). It knows
  elements, attributes, text, comments and the five predefined entities. `<!DOCTYPE`,
  `<!ENTITY`, CDATA and processing instructions are refused before anything else, and any
  other `&` is an error, so there is nothing to resolve and nothing to expand. Input is
  capped (8000 characters, depth 4, 300 elements, 10 rules, 8 conditions per rule).
- **A subset of Wazuh's rule syntax, compiled to closures.** Parents: `if_sid`,
  `if_group`, `if_matched_sid`; correlation: `frequency`, `timeframe`, `same_srcip` (and
  its old name `same_source_ip`), `same_user`; tests: `match`, `user`, `program_name`,
  `srcip` (address or CIDR), `action type="osmatch"`, `field type="osmatch"`,
  `negate="yes"`; plus `description`, `group` and `mitre`. Everything else is refused with
  a line number and what to write instead; `regex`, `pcre2` and `<field>` without
  `type="osmatch"` are refused with the reason (ReDoS).
- **Only behaviour checked against the real Wazuh is taught.** Where Wazuh 4.14 does not
  do what a rule reads like, the construct is refused with what `wazuh-logtest` showed:
  `<srcip>!x</srcip>` (the `!` is ignored: it matches x), `<if_matched_group>` (never
  fired on the sshd rules), `<field>` on a static field (`action`, `srcuser`: Wazuh
  itself refuses it), `<action>` without `type="osmatch"`.
- **OS_Match only**: substring, `^`, `$`, `|`, case-insensitive. Linear in the input.
  Field names come from the dataset's closed list and are read with `Object.hasOwn`.
- **The tree cannot loop.** Ids are in the local range (100000-120000) and unique; a rule
  may only refer to stock rules or to rules defined above it; each rule is visited at
  most once per event.
- **Evaluation follows Wazuh's tree**: an event starts at the root of its stock path
  (5700 → 5716 → 5760 for "Failed password") and, at each rule, tries local children
  first, then the stock child it goes on to, then correlation children; the last rule
  decides, and a level 0 child silences its parent. Correlation rules count, within
  `timeframe`, the events that reached the named rule, this one included. An alert
  counts from the challenge's level (10: the level that pages the SOC).
- **Checked against the real engine in CI** (`test/wazuh-real/`, workflow `wazuh.yml`):
  each challenge's reference rules are replayed through `wazuh-logtest` in the pinned
  wazuh-manager image, with no network, and must alert on exactly what Bastion's
  evaluator alerts on. Stock correlation rules, absent from the challenges, are
  neutralised for the replay.
- **Datasets look like Wazuh output** (`src/detection/wazuh-datasets.ts`): one alert per
  line in the `alerts.json` shape, with the stock rule reached and the decoded data.
  The `full_log` lines are real `sshd` syslog and JSON lines: a learner can replay them in
  `wazuh-logtest` on the real stack. Labels stay on the server.

## Rejected options
- *Sending the rules to the real Wazuh* (`PUT /rules/files`, then logtest): it needs the
  stack running for every learner, write access to the manager's configuration over its
  API, and a manager restart per attempt; grading would depend on an optional module.
- *A full XML library*: a native or large dependency (invariant 11), whose safe
  configuration (no DTD, no external entities) is one option away from XXE.
- *Supporting OS_Regex with a linear-time engine (Thompson NFA)*: feasible, but the exact
  semantics of OS_Regex (character classes, case) would have to be reproduced faithfully
  or learners would learn something false. OS_Match is enough to write every expected rule.

## Consequences
- Rules that solve a challenge paste unchanged into `local_rules.xml`. The reverse is
  not always true: a rule using `<regex>` works in Wazuh but is refused here, with the
  reason.
- `frequency="N"` fires on the Nth event, this one included (checked). Wazuh measures
  `timeframe` with the time it *receives* events, the evaluator with their timestamps:
  a replay in `wazuh-logtest` compresses time, so a too-short window the challenge
  rejects can still fire there. The lesson says so; the differential check uses
  reference rules whose windows hold either way.
- Two challenges ship: SSH brute force (one correlation per stock rule, 5760 and 5710,
  a narrow exclusion, a compromised neighbour on the excluded subnet) and Bastion's own
  audit log (JSON decoder, static `action`, a level 0 child for the CI's DAST scan).
- A Wazuh upgrade can change these behaviours: bump the image in `docker-compose.yml`
  and the differential check tells what moved.
