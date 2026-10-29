# syntax=docker/dockerfile:1
#
# Hardened multi-stage build.
#  - build stage: full toolchain, compiles TypeScript, then prunes dev dependencies;
#  - runtime stage: Google "distroless" image — no shell, no package manager,
#    no coreutils. An attacker who gets code execution has almost nothing to
#    work with (no `sh`, no `curl`, no `apt`).
#  - runs as UID 65532 (nonroot), designed for a read-only root filesystem.
#
# Base images are referenced by tag; Dependabot keeps them current and CI
# (Trivy) fails the build on any fixable HIGH/CRITICAL CVE. For a production
# fork, pin them by digest: `docker buildx imagetools inspect <image>`.

ARG NODE_MAJOR=24

############################ build ############################
FROM node:${NODE_MAJOR}-trixie-slim AS build
WORKDIR /src
ENV NODE_ENV=development \
    npm_config_fund=false \
    npm_config_audit=false \
    npm_config_update_notifier=false

# Dependencies first, for layer caching. `npm ci` installs exactly the lockfile
# (integrity hashes verified); `--ignore-scripts` blocks install-time code
# execution from third-party packages (a classic supply-chain attack vector).
COPY package.json package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --ignore-scripts

COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN npm run build \
 && npm prune --omit=dev --ignore-scripts \
 && mkdir -p /out/data \
 && cp -r dist node_modules package.json /out/

########################### runtime ###########################
FROM gcr.io/distroless/nodejs${NODE_MAJOR}-debian13:nonroot AS runtime

LABEL org.opencontainers.image.title="bastion" \
      org.opencontainers.image.description="Hardened encrypted-notes API with a full DevSecOps supply chain" \
      org.opencontainers.image.source="https://github.com/Azog1812/bastion-academy" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.authors="Florent Roch"

WORKDIR /app
ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=3000 \
    DATABASE_PATH=/data/bastion.db \
    UV_THREADPOOL_SIZE=4

COPY --from=build --chown=65532:65532 /out/data /data
COPY --from=build --chown=0:0 --chmod=0555 /out/dist ./dist
COPY --from=build --chown=0:0 /out/node_modules ./node_modules
COPY --from=build --chown=0:0 /out/package.json ./package.json

USER 65532:65532
EXPOSE 3000
VOLUME ["/data"]

# No shell in the image, so the probe is a tiny Node one-liner.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["/nodejs/bin/node", "-e", "fetch('http://127.0.0.1:3000/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]

# distroless/nodejs has ENTRYPOINT ["/nodejs/bin/node"]
CMD ["--disable-warning=ExperimentalWarning", "dist/server.js"]
