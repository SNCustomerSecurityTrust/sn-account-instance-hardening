# Build context must be the repo root (mcp-server/ needs its sibling scans/ dir):
#   docker build -t sn-hardening-mcp .
# Secrets are never baked into the image — see mcp-server/README.md for how to
# supply SN_CLIENT_SECRET_FILE (mounted volume) or SN_CLIENT_SECRET (env var).

FROM node:22-alpine AS builder
WORKDIR /app/mcp-server
COPY mcp-server/package.json mcp-server/package-lock.json ./
RUN npm ci
COPY mcp-server/ ./
RUN npm run build

FROM node:22-alpine
RUN addgroup -S mcp && adduser -S mcp -G mcp
WORKDIR /app/mcp-server
COPY mcp-server/package.json mcp-server/package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY --from=builder /app/mcp-server/dist ./dist
COPY --from=builder /app/mcp-server/data ./data
COPY scans /app/scans

USER mcp
ENV NODE_ENV=production
ENTRYPOINT ["node", "dist/index.js"]
