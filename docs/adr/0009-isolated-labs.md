# 0009 — Isolated per-learner labs

**Status:** accepted (v5, 30 Oct 2026)

## Context
Artifact challenges (ADR 0008) teach analysis, but XSS, SQL injection, IDOR or mass
assignment are learnt by attacking a running service. That service must be
intentionally vulnerable, which raises three problems a learning platform cannot dodge:

1. **Containment.** Code execution inside a lab is expected (it is the point of some
   labs). It must not lead to the host, the platform, other learners or the Internet.
2. **Control of Docker.** Starting containers on demand needs the Docker API, and access
   to the Docker socket is root on the host.
3. **Flags.** A flag baked into a lab image can be read from the image; it must be the
   learner's own and only reachable by exploiting the lab.

## Decision

```
browser ─► bastion :3000 ──(lab-control, internal, token)──► lab-runner ── /var/run/docker.sock
browser ─► lab-gateway :8088 ──(one internal network per instance)──► lab container
```

### Only the runner touches Docker
The platform never gets the socket. A separate **lab runner** (`src/labs/runner/`) holds
it and exposes four operations to the platform only: start, stop, health, and nothing
else. It sits on an `internal` network that only the platform joins, publishes no port,
and requires a 256-bit shared token (compared as SHA-256 digests in constant time).
Its input is a closed lab id, a 32-hex instance id, a flag matching `BASTION{32 hex}`
and a bounded TTL (strict schema): **no request can name an image, command, mount,
port or capability**. Every Docker object name is derived from the instance id.

### Each lab is boxed
`src/labs/runner/spec.ts` is the one place that decides what a lab container may do:
non-root user, read-only root filesystem, all capabilities dropped, no-new-privileges,
`noexec` tmpfs, 128 MiB memory without swap, half a CPU, 64 processes, no published
port, no mount, no restart. An optional OCI runtime (`LAB_RUNTIME=runsc`, gVisor) puts
a user-space kernel between the lab and the host where available.

### Each instance has its own network, with no route out
The runner creates an `Internal` bridge per instance: no Internet (no tool download, no
reverse shell, no exfiltration), and no other learner's lab on the same segment. Only
the **gateway** is attached besides the lab.

### One gateway, one origin per lab
`lab-gateway` is the only published entry (`127.0.0.1:8088`). It routes
`l<instance>.lab.localhost` to `bastion-lab-<instance>:8080`; the upstream is built from
the 32-hex id, never read from the request, so it cannot be used as an open proxy
(SSRF). Browsers resolve `*.localhost` to the loopback address, and every lab is its
own origin, different from the platform's: an XSS inside a lab cannot read the Bastion
session, and lab cookies never reach the platform. The gateway holds no secret and has
no Docker access.

### Flags come from the platform, per learner
At start-up the lab receives `FLAG=HMAC(FLAG_HMAC_KEY, challenge, learner)`, the same
flag ADR 0008 already validates. Images contain no flag. Exploiting the lab is the only
way to read it, and it scores for that learner only.

### Bounded by design
One running lab per learner (`UNIQUE(user_id)` in `lab_instances`, so concurrent starts
cannot both win), a TTL (2 h by default, 4 h max) enforced **twice**: by the platform's
reaper and by the runner's, which works from container labels even if the platform or
its database is gone. Starts are rate-limited per account. The runner also re-attaches
the gateway to live lab networks at start-up, so a stack restart does not strand labs.

### Lab code stays out of `src/`
Vulnerable apps live in `labs/`, excluded from ESLint and Semgrep on purpose (they are
meant to be vulnerable) and from CodeQL (which scans `src/`). The code that runs them,
`src/labs/`, is held to every platform rule. Each lab has a test proving the intended
attack works **and** that the honest path does not reveal the flag.

## Rejected
- **Docker socket in the platform container**: one RCE in the platform would own the
  host. The runner split keeps that power in ~200 lines with no user-facing surface.
- **A socket proxy with an allow-list of API paths** (e.g. docker-socket-proxy): it
  filters endpoints, not their bodies, so `POST /containers/create` with `Privileged`
  or a host bind mount would still pass. Validation must happen on our side, on intent.
- **Publishing a host port per lab**: exposes ports to the host, collides between
  learners, and needs a non-internal network (egress) for the lab.
- **Path-based routing** (`/lab/<id>/…`): labs would share the gateway's origin with
  each other, and apps with absolute paths break.
- **Kubernetes Jobs now**: the right target for a hosted version (RuntimeClass gVisor,
  NetworkPolicy, ResourceQuota), but the platform is local-only for now. The runner's
  interface (start/stop/TTL) is what would be re-implemented there.

## Consequences
- New secret `LAB_RUNNER_TOKEN` (from `cli gen-secrets`); labs stay off unless
  `LAB_RUNNER_URL` is set, which `docker-compose.yml` does.
- The runner runs as root inside its container to open the socket (root:root 0660 on
  most engines). It is read-only and cap-less, but whoever controls the runner controls
  the host: its attack surface is the platform (token) and its own code, both reviewed.
- Lab images must be built locally (`docker compose --profile labs build`); a missing
  image is reported to the learner with that command.
- One lab (command injection) ships a shell on purpose, on an Alpine base: code
  execution is the lesson. Containment therefore never relies on "no shell in the
  image"; it relies on what the runner enforces, and that lab asks the learner to
  verify it from inside (no route out, read-only root, `noexec` /tmp, zero capabilities).
- Containment relies on the container runtime. A kernel or runtime escape bypasses all
  of the above except gVisor; that residual risk is listed in the threat model.
