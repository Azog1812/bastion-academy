# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
#
# Stored XSS lab: the victim is a real headless Chromium, so this image ships a
# browser. Chromium runs with --no-sandbox because its own sandbox needs privileges
# the lab never gets; the container is the sandbox (non-root, read-only, no
# capabilities, no route out, ADR 0009). The catalog gives this lab more memory and
# processes than the others, still bounded.
#
# docker compose --profile labs build
FROM node:24-alpine@sha256:8a32c8cf649a49915a66e81e7a609223c708d0adabf288ee3f4077d765542f85

# Pinned: a browser update must be a reviewed change, like a base image bump.
RUN apk add --no-cache chromium=155.0.8059.84-r0 font-dejavu=2.37-r6

LABEL org.opencontainers.image.title="bastion-lab-xss-stored" \
      org.opencontainers.image.description="Intentionally vulnerable Bastion Academy lab. Run only through the lab runner." \
      org.opencontainers.image.source="https://github.com/Azog1812/bastion-academy"

WORKDIR /lab
COPY --chown=0:0 --chmod=0444 xss-stored/server.mjs xss-stored/bot.mjs ./

ENV CHROME_BIN=/usr/bin/chromium
USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:8080/').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]
CMD ["node", "server.mjs"]
