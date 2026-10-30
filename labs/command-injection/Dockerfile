# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
#
# The one lab that ships a shell, ON PURPOSE: command injection is meant to give the
# learner code execution. Containment therefore cannot rely on "no shell in the image";
# it relies on what the lab runner enforces (ADR 0009): non-root, read-only root,
# no capabilities, no-new-privileges, noexec /tmp, resource caps, and a network with no
# route out. The learner can verify all of it from inside.
#
# docker compose --profile labs build   (or: docker build -f labs/command-injection/Dockerfile -t bastion-lab-command-injection:local labs/)
FROM node:24-alpine@sha256:8a32c8cf649a49915a66e81e7a609223c708d0adabf288ee3f4077d765542f85

LABEL org.opencontainers.image.title="bastion-lab-command-injection" \
      org.opencontainers.image.description="Intentionally vulnerable Bastion Academy lab. Run only through the lab runner." \
      org.opencontainers.image.source="https://github.com/Azog1812/bastion-academy"

WORKDIR /lab
COPY --chown=0:0 --chmod=0444 command-injection/server.mjs ./server.mjs

USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:8080/').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]
CMD ["node", "server.mjs"]
