# 0005 — Distroless runtime, signed images, admission control

**Status:** accepted

## Context
A container that ships a shell, a package manager and root makes post-exploitation easy.
A registry that accepts any push makes supply-chain attacks easy.

## Decision
- Runtime image `gcr.io/distroless/nodejs24-debian13:nonroot`: no shell, no package manager, UID 65532.
- CI pushes only the exact image it tested and scanned, then signs it with cosign
  (keyless, GitHub OIDC → Fulcio certificate, logged in Rekor) and attaches a signed
  CycloneDX SBOM and SLSA provenance.
- Kyverno refuses any pod whose image is not signed by this repository's workflow.

## Consequences
- No `kubectl exec … sh` for debugging: use ephemeral debug containers instead.
- No long-lived signing key to steal or rotate.
- Anyone can verify an image's origin with `cosign verify` / `gh attestation verify`.
