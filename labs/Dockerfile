# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
#
# One image per lab: docker build --build-arg LAB=sqli-login -t bastion-lab-sqli-login:local labs/
# (or `docker compose --profile labs build`).
#
# The application inside is vulnerable ON PURPOSE; the container around it is
# not. Same distroless base as Bastion (no shell, no package manager), non-root,
# and the lab runner adds the rest at start-up: read-only root filesystem, no
# capabilities, no-new-privileges, CPU/memory/PID limits, and a network with no
# route out.
FROM gcr.io/distroless/nodejs24-debian13:nonroot@sha256:a6c34457f6da4295807e051411c7783739c65b997a324fed14e4fa292615ae91

ARG LAB
LABEL org.opencontainers.image.title="bastion-lab-${LAB}" \
      org.opencontainers.image.description="Intentionally vulnerable Bastion Academy lab. Run only through the lab runner." \
      org.opencontainers.image.source="https://github.com/Azog1812/bastion-academy"

WORKDIR /lab
COPY --chown=0:0 --chmod=0444 ${LAB}/server.mjs ./server.mjs

USER 65532:65532
EXPOSE 8080
# No shell in the image: the probe is a Node one-liner, like Bastion's.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/nodejs/bin/node", "-e", "fetch('http://127.0.0.1:8080/').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]
CMD ["--disable-warning=ExperimentalWarning", "server.mjs"]
