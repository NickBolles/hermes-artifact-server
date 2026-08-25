# syntax=docker/dockerfile:1.7
FROM node:22-alpine AS deps
WORKDIR /app
COPY package*.json ./
RUN npm ci

FROM deps AS build
COPY tsconfig.json ./
COPY src ./src
RUN npm run build
RUN npm prune --omit=dev

FROM node:22-alpine AS runtime
ENV NODE_ENV=production \
    PORT=3000 \
    ARTIFACT_ROOT=/data/artifacts \
    STATE_DB_PATH=/data/state/artifact-app.db
WORKDIR /app
RUN addgroup -S artifact && adduser -S artifact -G artifact \
  && mkdir -p /data/artifacts /data/state \
  && chown -R artifact:artifact /data /app
COPY --from=build --chown=artifact:artifact /app/package*.json ./
COPY --from=build --chown=artifact:artifact /app/node_modules ./node_modules
COPY --from=build --chown=artifact:artifact /app/dist ./dist
USER artifact
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3000/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "dist/server.js"]
