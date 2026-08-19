# syntax=docker/dockerfile:1
#
# cloudflare-dns-mcp-server — Cloudflare API MCP server (typed DNS tools + guarded
# v4 API passthrough). Multi-stage build: compile TypeScript in a build stage, then
# ship only production dependencies + the built dist/ in a slim, non-root runtime.
#
# No secret is ever baked into this image. CLOUDFLARE_API_TOKEN, MCP_AUTH_TOKEN, etc.
# are supplied at `docker run` / `docker compose up` time. See README "Running with Docker".

# ---- Stage 1: build (compile TS -> dist/) ----------------------------------
FROM node:20-slim AS build
WORKDIR /app

# Install ALL deps (incl. devDependencies like typescript) against the lockfile.
COPY package.json package-lock.json ./
RUN npm ci

# Compile. Only the sources tsc needs — tsconfig limits compilation to src/.
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

# ---- Stage 2: runtime (prod deps + built dist/ only) -----------------------
FROM node:20-slim AS runtime
ENV NODE_ENV=production
WORKDIR /app

# Run as the unprivileged `node` user (uid 1000) shipped in the official image.
# Give it ownership of the workdir so `npm ci` can write node_modules here.
RUN chown node:node /app
USER node

# Production dependencies only — no typescript/toolchain in the runtime image.
COPY --chown=node:node package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

# The compiled output from the build stage (never the host's dist/).
COPY --chown=node:node --from=build /app/dist ./dist

# A container must bind all interfaces to be reachable via `-p`. Binding a
# non-loopback address makes the server REQUIRE MCP_AUTH_TOKEN (or
# ALLOW_UNAUTHENTICATED=true) — fail-closed behavior, supplied at run time.
ENV HOST=0.0.0.0
ENV PORT=8787
EXPOSE 8787

# Liveness probe against the unauthenticated /healthz endpoint. Uses Node's own
# http (no curl in the slim image, no extra packages, no secret required).
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["node","-e","const p=process.env.PORT||8787;require('http').get('http://127.0.0.1:'+p+'/healthz',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"]

CMD ["node","dist/index.js"]
