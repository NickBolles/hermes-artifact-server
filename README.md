# Hermes Artifact Server

A small hardened Node.js/Docker service for publishing browser-loadable artifacts from Hermes Agent or any other automation.

It is intentionally narrower than a general file-sharing app:

- serves a mounted artifact directory
- renders `index.html` when present
- shows a minimal file browser when directory listing is allowed
- creates tokenized links to artifact directories
- exposes a small bearer-token API for creating artifacts and uploading files
- provides an admin file browser behind HTTP Basic auth
- stores metadata beside each artifact in `.artifact-meta.json`

## Why not fork File Browser?

[File Browser](https://filebrowser.org/) is great for human file management, users, permissions, uploads, and shares. This repo is purpose-built for agent artifacts: deterministic API-first publishing, immutable-ish tokenized URLs, static `index.html` previews, and simple Docker hardening. You can still put File Browser next to the same volume if you want a richer human admin UI.

## Quick start

```bash
cp .env.example .env
# edit tokens/passwords
npm install
npm run build
npm test
npm start
```

Docker, local build:

```bash
docker compose -f docker-compose.example.yml up -d --build
```

GitHub Container Registry image, after the `main` branch workflow completes:

```bash
docker pull ghcr.io/nickbolles/hermes-artifact-server:latest
```

The included GitHub Actions workflow builds/tests the Node app, then builds a Docker image for `linux/amd64` by default. It pushes images to GHCR on `main`, version tags like `v0.1.0`, and manual workflow dispatches; pull requests build without pushing.

## API

All `/api/*` write/list operations require:

```http
Authorization: Bearer $API_TOKEN
```

### Create or register an artifact

```bash
curl -sS -X POST http://localhost:3000/api/artifacts \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "content-type: application/json" \
  -d '{"slug":"demo","title":"Demo artifact","allowDirectoryListing":true}'
```

### Upload a file with raw body

```bash
curl -sS -X PUT http://localhost:3000/api/artifacts/demo/files/index.html \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "content-type: text/html" \
  --data-binary '<h1>Hello from Hermes</h1>'
```

Then open the returned public URL.

### Multipart upload

```bash
curl -sS -X POST http://localhost:3000/api/artifacts/demo/files \
  -H "Authorization: Bearer $API_TOKEN" \
  -F "file=@dist/index.html;filename=index.html" \
  -F "path=index.html"
```

## Routes

- `GET /health` — health check
- `POST /api/artifacts` — create/register an artifact directory and tokenized link
- `GET /api/artifacts` — list artifacts and links
- `GET /api/artifacts/:slug` — metadata for one artifact
- `PUT /api/artifacts/:slug/files/*path` — upload raw file body
- `POST /api/artifacts/:slug/files` — multipart upload one file
- `GET /a/:slug/:token/*path?` — public tokenized artifact route; renders `index.html` when present
- `GET /admin/files/*path?` — admin browser over the artifact root

## Security notes

- The API token protects publishing and listing metadata.
- Public links include a random per-artifact token. Treat them as bearer links.
- Admin browsing uses Basic auth; put it behind Authelia/authentik/Cloudflare Access/Caddy auth if internet-facing.
- Path traversal is blocked by resolving every requested path under `ARTIFACT_ROOT`.
- Dotfiles and `.artifact-meta.json` are hidden from public listings.
- Docker image runs as a non-root user; example Compose uses read-only root FS, `no-new-privileges`, and drops Linux capabilities.
- This is not a multi-tenant authorization system. For untrusted users, put a real identity-aware proxy in front.

## Hermes usage pattern

Mount the same artifact volume into Hermes or publish through the API. For example, Hermes can write files locally into `/data/artifacts/demo`, then call `POST /api/artifacts` to mint a link, or use only the upload API.
