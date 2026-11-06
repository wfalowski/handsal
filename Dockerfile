# ── Stage 1: Base ─────────────────────────────────────────────
FROM node:24-bookworm-slim AS base
RUN corepack enable && corepack prepare pnpm@9.15.0 --activate
WORKDIR /app

# ── Stage 2: Dependencies ────────────────────────────────────
FROM base AS deps

# Copy workspace structure for pnpm install
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json ./
COPY apps/api/package.json ./apps/api/
COPY apps/web/package.json ./apps/web/
COPY packages/db/package.json ./packages/db/
COPY packages/shared/package.json ./packages/shared/

RUN pnpm install --frozen-lockfile

# ── Stage 3: Build ───────────────────────────────────────────
FROM deps AS build

# Copy all source code
COPY . .

# Build packages in dependency order
RUN pnpm --filter @handsal/shared run build
RUN pnpm --filter @handsal/db run build
RUN pnpm --filter @handsal/web run build
RUN pnpm --filter @handsal/api run build

# Copy React build output into the API's public directory
RUN cp -r apps/web/dist apps/api/public

# Patch workspace package exports to point to compiled JS (not .ts)
RUN sed -i 's|"./src/index.ts"|"./dist/index.js"|g' packages/shared/package.json
RUN sed -i 's|"./src/index.ts"|"./dist/index.js"|g' packages/db/package.json

# ── Stage 4: Production ─────────────────────────────────────
FROM base AS production

# OCI metadata. No license has been chosen yet, hence UNLICENSED.
LABEL org.opencontainers.image.source="https://github.com/OWNER/handsal" \
      org.opencontainers.image.description="Handsal: multi-tenant M2M OAuth 2.0 authorization server" \
      org.opencontainers.image.licenses="UNLICENSED"

ENV NODE_ENV=production
ENV NODE_OPTIONS=--enable-source-maps

# Copy workspace structure for prod install
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json ./
COPY --from=build /app/packages/shared/package.json ./packages/shared/
COPY --from=build /app/packages/db/package.json ./packages/db/
COPY apps/api/package.json ./apps/api/
# Web app is already built as static files, no runtime deps needed
COPY apps/web/package.json ./apps/web/

RUN pnpm install --frozen-lockfile --prod

# Copy compiled packages
COPY --chown=node:node --from=build /app/packages/shared/dist ./packages/shared/dist
COPY --chown=node:node --from=build /app/packages/db/dist ./packages/db/dist

# Copy drizzle migration files (needed at runtime for programmatic migrations)
COPY --chown=node:node --from=build /app/packages/db/drizzle ./packages/db/drizzle

# Copy compiled API + static frontend
COPY --chown=node:node --from=build /app/apps/api/dist ./apps/api/dist
COPY --chown=node:node --from=build /app/apps/api/public ./apps/api/public

WORKDIR /app/apps/api

# Run unprivileged; node_modules stay root-owned (read-only for the app).
USER node

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://localhost:3000/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "dist/index.js"]
