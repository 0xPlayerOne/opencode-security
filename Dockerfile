# syntax=docker/dockerfile:1@sha256:87999aa3d42bdc6bea60565083ee17e86d1f3339802f543c0d03998580f9cb89

FROM node:22-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3 AS package

WORKDIR /build/sdk/typescript

COPY sdk/typescript/package.json sdk/typescript/pnpm-lock.yaml ./

RUN corepack enable \
    && corepack prepare "$(node --print 'require("./package.json").packageManager')" --activate \
    && pnpm install --frozen-lockfile --ignore-scripts

COPY sdk/typescript/ ./

RUN pnpm run types \
    && pnpm run build \
    && pnpm pack --pack-destination /build/package \
    && node scripts/check-package.mjs /build/package/*.tgz

FROM node:22-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3

LABEL org.opencontainers.image.title="OpenCode Security" \
      org.opencontainers.image.description="Noninteractive, resumable OpenCode Security CSV repository scans" \
      org.opencontainers.image.source="https://github.com/0xPlayerOne/opencode-security"

RUN apt-get update \
    && apt-get install --no-install-recommends --yes \
        ca-certificates \
        git \
        openssh-client \
        python3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=package /build/package/ /tmp/opencode-security-package/

RUN npm install --global --include=optional --no-audit --no-fund \
        /tmp/opencode-security-package/*.tgz \
    && opencode-security --version \
    && opencode-security bulk-scan --help \
    && rm -rf /tmp/opencode-security-package \
    && npm cache clean --force

COPY --chmod=0555 docker/entrypoint.sh /usr/local/bin/opencode-security-entrypoint
COPY --chmod=0555 docker/git-credential.sh /usr/local/bin/opencode-security-git-credential

RUN groupadd --gid 10001 opencode-security \
    && useradd --uid 10001 --gid 10001 --no-create-home opencode-security \
    && mkdir -p /input /output /state \
    && chown 10001:10001 /output /state

ENV CODEX_HOME=/state \
    CODEX_SECURITY_STATE_DIR=/output/.opencode-security-state \
    GIT_TERMINAL_PROMPT=0 \
    HOME=/state \
    PYTHON=/usr/bin/python3

USER 10001:10001
WORKDIR /state

ENTRYPOINT ["/usr/local/bin/opencode-security-entrypoint"]
CMD ["--help"]
