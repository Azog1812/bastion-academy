# Security policy

## Reporting a vulnerability

Please **do not open a public issue**. Report privately through
[GitHub Security Advisories](https://github.com/Azog1812/web-app/security/advisories/new)
or by e-mail to florent.roch@hotmail.fr.

Include the affected version or commit, reproduction steps and the impact you
observed. You can expect an acknowledgement within 72 hours and a status
update within 7 days. Coordinated disclosure: please allow up to 90 days for a
fix before publishing. Good-faith research is welcome and will be credited.

## Scope

In scope: the application code in `src/`, the container image, the Kubernetes
manifests in `deploy/` and the CI/CD workflows in `.github/workflows/`.

Known, accepted risks are documented in
[docs/threat-model.md](docs/threat-model.md#accepted-risks) and are not
considered vulnerabilities.

## Supported versions

Only the latest commit on `main` (and the image published from it) is supported.

## Verifying a release

Every image published to GHCR is signed with Sigstore (keyless, via GitHub OIDC)
and carries a signed CycloneDX SBOM and SLSA build provenance:

```bash
IMAGE=ghcr.io/azog1812/web-app:main
cosign verify "$IMAGE" \
  --certificate-identity https://github.com/Azog1812/web-app/.github/workflows/container.yml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify "oci://$IMAGE" --repo Azog1812/web-app
```
