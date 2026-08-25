# Hermes Artifact Server

A hardened Node.js/Docker service for publishing browser-loadable Hermes artifacts **and** hosting an authenticated personal-app/action boundary.

## Security products

The service deliberately separates two trust models:

- **Artifacts** — read-only static snapshots served through revocable bearer URLs or per-artifact user access rules.
- **Artifact Apps** — invite-only, identity-authenticated pages that accept strict business actions and can dispatch bounded events/runs to Hermes.

An artifact token or viewer session never becomes an application session and no mutation route exists beneath `/a/*` or `/v/*`. Artifact HTML and authenticated pages must use **different hostnames**; otherwise uploaded same-origin JavaScript could act as the signed-in user.

## Features

### Static artifacts

- mounted artifact directory with `index.html` rendering
- tokenized viewer links and optional expiration
- `bearer`, `authenticated`, and `restricted` per-artifact visibility
- selected-user ACLs with an audited, one-time cross-origin login handoff
- a separate hashed, 15-minute viewer session bound to the source app session; logout/revocation invalidates both
- CSP sandboxing without `allow-same-origin`, preventing artifact JavaScript from reading viewer cookies, storage, or other ACL-protected artifacts
- bearer-token publishing API
- path-traversal protection, hidden metadata, upload limits
- optional legacy Basic-auth file browser

### Passkey-first application auth

- local, invite-only users and roles
- WebAuthn discoverable credentials with required user verification
- Argon2id recovery passwords used only to enter a restricted recovery flow
- recovery must enroll a new passkey before app/admin access
- hashed opaque session tokens; HttpOnly/SameSite cookies
- CSRF plus exact-origin mutation checks
- passkey, session, invitation, recovery, and authentication audit state
- console-only first-admin bootstrap; no default account/password

### Action broker

- strict Zod action registry (`job.feedback.submit`, `report.question.ask`)
- server-derived actors/scopes and app-level action manifests
- durable SQLite idempotency with request hashes
- durable per-action minute/day limits
- action/event/outbox/audit records
- deterministic job feedback writes
- HMAC V2 Hermes webhook dispatch for feedback events
- bounded Hermes `/v1/runs` dispatch for report questions
- retries and dead-letter failure state

## Quick start

```bash
cp .env.example .env
# Set BASE_URL, APP_ORIGIN, API_TOKEN, WEBAUTHN_RP_ID, and WEBAUTHN_ORIGIN.
npm install
npm run build
npm test
npm start
```

Production requires HTTPS. Keep Hermes webhook/API listeners on loopback or a private Docker network and expose only this service through the reverse proxy.

Route both public hostnames to this container:

- `BASE_URL=https://artifacts.example.com` — publishing API and read-only artifact viewer
- `APP_ORIGIN=https://artifact-apps.example.com` — login, app actions, and admin console

Production startup refuses to run if these hostnames are equal. The application session cookie is host-only and is never sent to the artifact origin.

## Bootstrap the first admin

There is no default password. Build/start the service once so the state directory exists, then supply the recovery password over stdin:

```bash
read -s PASSWORD
printf '\n'
printf '%s\n' "$PASSWORD" | npm run admin:bootstrap -- --username nick
unset PASSWORD
```

The password is never accepted as a command-line argument. Open `/recovery`, authenticate with it once, and register a passkey. The recovery session cannot open `/admin` or app routes until passkey enrollment completes.

In Docker:

```bash
read -s PASSWORD
printf '\n'
printf '%s\n' "$PASSWORD" | docker exec -i hermes-artifacts npm run admin:bootstrap -- --username nick
unset PASSWORD
```

## User and admin workflow

1. Admin signs in with a passkey at `/login`.
2. `/admin` creates a one-time invitation with role and scopes.
3. The invitee sets a recovery password and enrolls a passkey.
4. Admin can suspend/reactivate users, revoke sessions, remove passkeys, choose each artifact's visibility/allowed users, revoke artifacts, and inspect actions/audit state.
5. Authenticated users use `/app/jobs`. Private artifact visits reuse that login through a short-lived, one-time handoff and then remain read-only on the artifact hostname.

Changing an artifact back to `bearer` visibility rotates its bearer token. The previous viewer URL remains invalid and the admin API returns the replacement URL once.

The optional `ADMIN_USERNAME`/`ADMIN_PASSWORD` variables protect only the legacy `/admin/files/` route. They are not application credentials and may be left unset when the legacy browser is unnecessary.

## Persistent data

```text
/data/artifacts/                 # static artifact directories and metadata
/data/state/artifact-app.db      # users, passkeys, sessions, actions, audit
/data/state/artifact-app.db-wal  # SQLite WAL sidecar
/data/state/artifact-app.db-shm  # SQLite shared-memory sidecar
```

Back up both mounted directories. The Compose example uses named volumes so Docker preserves the image's non-root ownership; if you replace them with bind mounts, pre-create and chown both host directories for container UID 100 before startup. For SQLite, stop the container or use SQLite’s online backup mechanism; do not copy only the main database while WAL writes are active. The database and its containing directory are restricted to the container user where the filesystem supports POSIX modes.

## Hermes integration

### Fire-and-forget feedback events

Set:

```text
HERMES_WEBHOOK_URL=http://hermes:8644/p/artifact-actions/webhooks/job-feedback
HERMES_WEBHOOK_SECRET=<route-specific secret>
```

The worker signs the **exact bytes sent** using:

```text
X-Webhook-Timestamp: <unix seconds>
X-Webhook-Signature-V2: HMAC-SHA256("<timestamp>.<body>")
X-Request-ID: <action id>
```

### Page-visible agent runs

Set a private API Server URL and profile-scoped key:

```text
HERMES_API_URL=http://hermes:8642/p/artifact-actions
HERMES_API_KEY=<profile API server key>
```

The browser cannot choose the model, tool, destination, URL, or system prompt. The broker constructs a fixed prompt from validated report identifiers and treats the question as untrusted data.

## Publishing API

All `/api/*` publishing operations require:

```http
Authorization: Bearer $API_TOKEN
```

Create an artifact:

```bash
curl -sS -X POST http://localhost:3000/api/artifacts \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "content-type: application/json" \
  -d '{"slug":"demo","title":"Demo artifact","visibility":"restricted","allowedUsers":["nick"],"allowDirectoryListing":true}'
```

Upload a file:

```bash
curl -sS -X PUT http://localhost:3000/api/artifacts/demo/files/index.html \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "content-type: text/html" \
  --data-binary '<h1>Hello from Hermes</h1>'
```

## Routes

- `GET /health`
- `POST/GET /api/artifacts*` — publishing API
- `GET /a/:slug/:token/*` — read-only artifact viewer
- `GET /v/:slug/*` — authenticated/restricted read-only artifact viewer
- `GET /auth/artifacts/authorize/:handoffId`, `GET /viewer/handoff/:exchange` — one-time cross-origin viewer login
- `GET /login`, `GET /recovery`, `GET /invite/:token`
- `POST /auth/passkeys/*`, `POST /auth/recovery`, `POST /auth/logout`
- `GET /app/jobs`, `POST/GET /app/:appId/actions/*`
- `GET /admin`, `/admin/api/*` — passkey-authenticated admin console
- `GET /admin/files/*` — optional legacy Basic-auth browser

## Verification

```bash
npm run build
npm test
npm audit
```

CI builds/tests on Node 22 and builds the Docker image. A pull request does not deploy or push the image.

## Deployment note

This repository only builds the implementation. Enabling Hermes webhooks/API routing, bootstrapping the production admin, and replacing the running container are separate deployment operations and should be explicitly approved and verified.
