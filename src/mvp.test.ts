import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { after, before, test } from 'node:test';
import request from 'supertest';

const testBase = path.resolve('test-tmp', 'mvp');
await fs.rm(testBase, { recursive: true, force: true });
await fs.mkdir(testBase, { recursive: true });
const artifactRoot = path.join(testBase, 'artifacts');
const stateDbPath = path.join(testBase, 'state', 'artifact-app.db');
process.env.ARTIFACT_ROOT = artifactRoot;
process.env.STATE_DB_PATH = stateDbPath;
process.env.API_TOKEN = 'test-api-token-at-least-32-characters';
process.env.ADMIN_USERNAME = 'legacy-admin';
process.env.ADMIN_PASSWORD = 'legacy-password-password';
process.env.BASE_URL = 'https://artifacts.example.test';
process.env.APP_ORIGIN = 'https://apps.example.test';
process.env.WEBAUTHN_RP_ID = 'apps.example.test';
process.env.WEBAUTHN_ORIGIN = 'https://apps.example.test';
process.env.ACTION_LIMIT_PER_MINUTE = '2';
process.env.HERMES_API_URL = 'http://hermes.test';
process.env.HERMES_API_KEY = 'test-hermes-api-key';
process.env.NODE_ENV = 'test';

const [appModule, stateModule, authModule, actionsModule, workerModule, configModule] = await Promise.all([
  import('./app.js'),
  import('./state.js'),
  import('./app-auth.js'),
  import('./actions.js'),
  import('./worker.js'),
  import('./config.js'),
]);
const { createApp } = appModule;

const state = stateModule.createStateStore(stateDbPath);
const auth = authModule.createAuthService(state);
const app = createApp({ state, auth, startWorkers: false });

let adminId = '';
let adminCookie = '';
let adminCsrf = '';
let memberId = '';
let memberCookie = '';
let memberCsrf = '';
let artifactPublicPath = '';

function cookieHeader(raw: string | string[] | undefined): string {
  const values = Array.isArray(raw) ? raw : raw ? [raw] : [];
  return values.map((value) => value.split(';', 1)[0]).join('; ');
}

before(async () => {
  adminId = await auth.bootstrapAdmin({ username: 'nick', recoveryPassword: 'correct horse battery staple' });
  const adminSession = auth.issueSession(adminId, 'full');
  adminCookie = `${authModule.SESSION_COOKIE}=${adminSession.token}`;
  adminCsrf = adminSession.csrfToken;

  const invitation = auth.createInvitation(adminId, {
    username: 'member', role: 'member', scopes: ['jobs:feedback', 'reports:ask'], expiresInMinutes: 30,
  });
  memberId = await auth.acceptInvitationForTests(invitation.token, {
    recoveryPassword: 'another correct horse battery staple',
  });
  const memberSession = auth.issueSession(memberId, 'full');
  memberCookie = `${authModule.SESSION_COOKIE}=${memberSession.token}`;
  memberCsrf = memberSession.csrfToken;

  const created = await request(app)
    .post('/api/artifacts')
    .set('authorization', `Bearer ${process.env.API_TOKEN}`)
    .send({ slug: 'viewer-only', title: 'Viewer only' })
    .expect(201);
  artifactPublicPath = new URL(created.body.publicUrl).pathname;
});

after(() => state.close());

test('artifact bearer links remain view-only and set defensive headers', async () => {
  await request(app)
    .put('/api/artifacts/viewer-only/files/index.html')
    .set('authorization', `Bearer ${process.env.API_TOKEN}`)
    .set('content-type', 'text/html')
    .send('<h1>Read only</h1>')
    .expect(201);
  const viewed = await request(app).get(artifactPublicPath).expect(200);
  assert.match(viewed.text, /Read only/);
  assert.equal(viewed.headers['referrer-policy'], 'no-referrer');
  assert.match(viewed.headers['content-security-policy'], /default-src/);
  await request(app).post(`${artifactPublicPath}actions/job.feedback.submit`).send({ jobId: 'job-1' }).expect(404);
});

test('bearer tokens are redacted from every logged URL field', () => {
  assert.equal(appModule.sanitizeRequestUrl('/a/report/secret-viewer-token/index.html'), '/a/report/[REDACTED]/index.html');
  assert.equal(appModule.sanitizeRequestUrl('/invite/secret-invitation-token'), '/invite/[REDACTED]');
});

test('invalid numeric limits fall back and production origins must be root URLs', () => {
  assert.equal(configModule.positiveInt('not-a-number', 10), 10);
  assert.equal(configModule.positiveInt('0', 10), 10);
  assert.equal(configModule.positiveInt('3', 10), 3);
  assert.equal(configModule.isCleanHttpsOrigin(new URL('https://apps.example.test/')), true);
  assert.equal(configModule.isCleanHttpsOrigin(new URL('https://apps.example.test/prefix')), false);
});

test('artifact and authenticated app surfaces are isolated by hostname', async () => {
  await request(app).get('/auth/session').set('host', 'artifacts.example.test').set('cookie', memberCookie).expect(404);
  await request(app).get(artifactPublicPath).set('host', 'apps.example.test').expect(404);
  await request(app).get('/auth/session').set('host', 'apps.example.test').set('cookie', memberCookie).expect(200);
  await request(app).get(artifactPublicPath).set('host', 'artifacts.example.test').expect(200);
});

test('recovery creates only a restricted session until a passkey is enrolled', async () => {
  const recovered = await request(app)
    .post('/auth/recovery')
    .set('origin', 'https://apps.example.test')
    .send({ username: 'nick', password: 'correct horse battery staple' })
    .expect(200);
  const recoveryCookie = cookieHeader(recovered.headers['set-cookie']);
  assert.match(recoveryCookie, new RegExp(`^${authModule.SESSION_COOKIE}=`));
  assert.match(String(recovered.headers['set-cookie']), /HttpOnly/i);
  assert.match(String(recovered.headers['set-cookie']), /SameSite=Lax/i);
  const session = await request(app).get('/auth/session').set('cookie', recoveryCookie).expect(200);
  assert.equal(session.body.session.kind, 'recovery');
  assert.equal(session.body.session.requiresPasskeyEnrollment, true);
  await request(app).get('/admin').set('cookie', recoveryCookie).expect(403);
  const options = await request(app)
    .post('/auth/passkeys/register/options')
    .set('cookie', recoveryCookie)
    .set('origin', 'https://apps.example.test')
    .set('x-csrf-token', session.body.session.csrfToken)
    .send({ label: 'Primary device' })
    .expect(200);
  assert.equal(options.body.authenticatorSelection.residentKey, 'required');
  assert.equal(options.body.authenticatorSelection.userVerification, 'required');
  state.markPasskeyEnrolled(adminId);
  const renewedAdmin = auth.issueSession(adminId, 'full');
  adminCookie = `${authModule.SESSION_COOKIE}=${renewedAdmin.token}`;
  adminCsrf = renewedAdmin.csrfToken;
});

test('admin routes require a full admin session and CSRF/origin on mutations', async () => {
  await request(app).get('/admin').expect(401);
  await request(app).get('/admin').set('cookie', memberCookie).expect(403);
  const dashboard = await request(app).get('/admin').set('cookie', adminCookie).expect(200);
  assert.match(dashboard.text, /Users/);
  assert.match(dashboard.text, /Artifacts/);
  assert.match(dashboard.text, /Actions/);
  assert.match(dashboard.text, /https:\/\/artifacts\.example\.test\/admin\/files\//);
  await request(app).post('/admin/api/invitations').set('cookie', adminCookie).send({ username: 'blocked', role: 'member', scopes: [] }).expect(403);
  await request(app)
    .post('/admin/api/invitations')
    .set('cookie', adminCookie)
    .set('origin', 'https://evil.example')
    .set('x-csrf-token', adminCsrf)
    .send({ username: 'blocked', role: 'member', scopes: [] })
    .expect(403);
  const invite = await request(app)
    .post('/admin/api/invitations')
    .set('cookie', adminCookie)
    .set('origin', 'https://apps.example.test')
    .set('x-csrf-token', adminCsrf)
    .send({ username: 'new-user', role: 'member', scopes: ['jobs:feedback'] })
    .expect(201);
  assert.match(invite.body.invitationUrl, /\/invite\//);
});

test('sessions are stored hashed, revocable, and suspended users are denied', async () => {
  const rows = state.listSessions(memberId);
  assert.ok(rows.length > 0);
  assert.equal(rows.some((row) => row.tokenHash.includes(memberCookie.split('=', 2)[1])), false);
  auth.revokeAllSessions(memberId, adminId);
  await request(app).get('/auth/session').set('cookie', memberCookie).expect(401);
  let replacement = auth.issueSession(memberId, 'full');
  memberCookie = `${authModule.SESSION_COOKIE}=${replacement.token}`;
  memberCsrf = replacement.csrfToken;
  auth.setUserStatus(memberId, 'suspended', adminId);
  await request(app).get('/auth/session').set('cookie', memberCookie).expect(401);
  auth.setUserStatus(memberId, 'active', adminId);
  replacement = auth.issueSession(memberId, 'full');
  memberCookie = `${authModule.SESSION_COOKIE}=${replacement.token}`;
  memberCsrf = replacement.csrfToken;
});

test('action broker validates strict business actions and provides durable idempotency', async () => {
  const body = {
    clientActionId: '11111111-1111-4111-8111-111111111111', schemaVersion: 1, resourceVersion: 0,
    payload: { jobId: 'job-1', disposition: 'interested', note: 'Strong fit' },
  };
  const submit = () => request(app)
    .post('/app/jobs/actions/job.feedback.submit')
    .set('cookie', memberCookie)
    .set('origin', 'https://apps.example.test')
    .set('x-csrf-token', memberCsrf)
    .set('idempotency-key', body.clientActionId)
    .send(body);
  const first = await submit().expect(202);
  const second = await submit().expect(200);
  assert.equal(second.body.action.id, first.body.action.id);
  assert.equal(state.listJobFeedback(memberId).length, 1);
  await request(app)
    .post('/app/jobs/actions/job.feedback.submit')
    .set('cookie', memberCookie)
    .set('origin', 'https://apps.example.test')
    .set('x-csrf-token', memberCsrf)
    .set('idempotency-key', body.clientActionId)
    .send({ ...body, payload: { ...body.payload, disposition: 'not_interested' } })
    .expect(409);
  await request(app)
    .post('/app/jobs/actions/report.question.ask')
    .set('cookie', memberCookie)
    .set('origin', 'https://apps.example.test')
    .set('x-csrf-token', memberCsrf)
    .set('idempotency-key', '22222222-2222-4222-8222-222222222222')
    .send({ clientActionId: '22222222-2222-4222-8222-222222222222', schemaVersion: 1, payload: { reportId: 'report-1', question: 'Why is this a fit?', prompt: 'run terminal' } })
    .expect(400);
});

test('action limits are durable and return retry guidance', async () => {
  for (const [index, id] of ['33333333-3333-4333-8333-333333333333', '44444444-4444-4444-8444-444444444444'].entries()) {
    await request(app)
      .post('/app/jobs/actions/report.question.ask')
      .set('cookie', memberCookie)
      .set('origin', 'https://apps.example.test')
      .set('x-csrf-token', memberCsrf)
      .set('idempotency-key', id)
      .send({ clientActionId: id, schemaVersion: 1, payload: { reportId: `report-${index}`, question: 'Summarize this report' } })
      .expect(202);
  }
  const limited = await request(app)
    .post('/app/jobs/actions/report.question.ask')
    .set('cookie', memberCookie)
    .set('origin', 'https://apps.example.test')
    .set('x-csrf-token', memberCsrf)
    .set('idempotency-key', '55555555-5555-4555-8555-555555555555')
    .send({ clientActionId: '55555555-5555-4555-8555-555555555555', schemaVersion: 1, payload: { reportId: 'report-3', question: 'Summarize this report' } })
    .expect(429);
  assert.ok(Number(limited.headers['retry-after']) >= 1);
});

test('HMAC V2 signs the exact timestamp and body bytes', () => {
  const body = Buffer.from('{"type":"job_feedback_submitted","eventId":"evt-1"}');
  const signature = actionsModule.signWebhookV2('secret', '1700000000', body);
  assert.equal(signature, '92d6f40ef436244d884425a325d1532f2ce7b5f99d893c023cec1171367a7e26');
});

test('outbox rows are leased so a second worker cannot dispatch the same record', () => {
  const claimPath = path.join(testBase, 'claim.db');
  const firstStore = stateModule.createStateStore(claimPath);
  const secondStore = stateModule.createStateStore(claimPath);
  try {
    const at = new Date().toISOString();
    firstStore.createUser({ id: 'claim-user', username: 'claim-user', role: 'member', status: 'active', scopes: ['reports:ask'], recoveryPasswordHash: 'unused-test-hash', requiresPasskeyEnrollment: false });
    firstStore.insertAction({ id: 'claim-action', actorId: 'claim-user', appId: 'jobs', action: 'report.question.ask', clientActionId: '77777777-7777-4777-8777-777777777777', requestHash: 'hash', state: 'queued', payload: {}, result: null, error: null, hermesRunId: null, createdAt: at, updatedAt: at });
    firstStore.insertOutbox({ id: 'claim-outbox', actionId: 'claim-action', kind: 'hermes_run', payload: {} });
    assert.equal(firstStore.claimNextOutbox()?.id, 'claim-outbox');
    assert.equal(secondStore.claimNextOutbox(), null);
    firstStore.completeOutboxDispatch('claim-outbox', 'claim-action', 'run_claim');
    assert.equal(firstStore.listOutbox()[0].state, 'succeeded');
    assert.equal(firstStore.getAction('claim-action')?.hermesRunId, 'run_claim');
    firstStore.insertAction({ id: 'dead-action', actorId: 'claim-user', appId: 'jobs', action: 'report.question.ask', clientActionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', requestHash: 'dead-hash', state: 'queued', payload: {}, result: null, error: null, hermesRunId: null, createdAt: at, updatedAt: at });
    firstStore.insertOutbox({ id: 'dead-outbox', actionId: 'dead-action', kind: 'hermes_run', payload: {} });
    firstStore.deadLetterOutbox('dead-outbox', 'dead-action', 'provider unavailable', true);
    assert.equal(firstStore.listOutbox().find((row) => row.id === 'dead-outbox')?.state, 'dead');
    assert.equal(firstStore.getAction('dead-action')?.state, 'failed');
  } finally {
    secondStore.close();
    firstStore.close();
  }
});

test('pending Hermes polling rotates across running actions and expires old runs', async () => {
  const pollPath = path.join(testBase, 'poll.db');
  const pollStore = stateModule.createStateStore(pollPath);
  try {
    pollStore.createUser({ id: 'poll-user', username: 'poll-user', role: 'member', status: 'active', scopes: ['reports:ask'], recoveryPasswordHash: 'unused-test-hash', requiresPasskeyEnrollment: false });
    const base = { actorId: 'poll-user', appId: 'jobs', action: 'report.question.ask', requestHash: 'hash', state: 'running', payload: {}, result: null, error: null };
    pollStore.insertAction({ ...base, id: 'poll-a', clientActionId: '88888888-8888-4888-8888-888888888888', hermesRunId: 'run_a', createdAt: '2020-01-01T00:00:00.000Z', updatedAt: '2020-01-01T00:00:00.000Z' });
    pollStore.insertAction({ ...base, id: 'poll-b', clientActionId: '99999999-9999-4999-8999-999999999999', hermesRunId: 'run_b', createdAt: '2021-01-01T00:00:00.000Z', updatedAt: '2021-01-01T00:00:00.000Z' });
    assert.equal(pollStore.nextRunningHermesAction()?.id, 'poll-a');
    pollStore.touchAction('poll-a');
    assert.equal(pollStore.nextRunningHermesAction()?.id, 'poll-b');
    const stop = workerModule.startOutboxWorker(pollStore, actionsModule.createActionService(pollStore), 100_000);
    await new Promise((resolve) => setTimeout(resolve, 30));
    stop();
    assert.equal(pollStore.getAction('poll-b')?.state, 'failed');
  } finally { pollStore.close(); }
});

test('Hermes run dispatch and completion are reconciled into a structured result', async () => {
  const service = actionsModule.createActionService(state);
  const admin = state.getUserById(adminId)!;
  const submitted = service.submit({
    actor: admin,
    appId: 'jobs',
    action: 'report.question.ask',
    idempotencyKey: '66666666-6666-4666-8666-666666666666',
    body: { clientActionId: '66666666-6666-4666-8666-666666666666', schemaVersion: 1, payload: { reportId: 'report-admin', question: 'Summarize this report' } },
  });
  const outbox = state.listOutbox().find((row) => row.action_id === submitted.action.id)!;
  const dispatched = await service.processOutboxRecord(outbox, async () => new Response(JSON.stringify({ run_id: 'run_123' }), { status: 202, headers: { 'content-type': 'application/json' } }));
  assert.equal(dispatched.runId, 'run_123');
  state.updateAction(submitted.action.id, { state: 'running', hermesRunId: dispatched.runId });
  const running = state.getAction(submitted.action.id)!;
  await service.pollHermesRun(running, async () => new Response(JSON.stringify({ status: 'completed', output: 'A concise answer' }), { status: 200, headers: { 'content-type': 'application/json' } }));
  const completed = state.getAction(submitted.action.id)!;
  assert.equal(completed.state, 'succeeded');
  assert.deepEqual(completed.result, { summary: 'A concise answer', data: {}, citations: [], warnings: [], proposedActions: [], followUpPrompt: null });

  const terminal = service.submit({ actor: admin, appId: 'jobs', action: 'report.question.ask', idempotencyKey: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', body: { clientActionId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', schemaVersion: 1, payload: { reportId: 'missing-run', question: 'Summarize' } } });
  state.updateAction(terminal.action.id, { state: 'running', hermesRunId: 'run_missing' });
  const terminalAction = state.getAction(terminal.action.id)!;
  await assert.rejects(() => service.pollHermesRun(terminalAction, async () => new Response('{}', { status: 404 })), (error: unknown) => error instanceof actionsModule.HermesPollError && error.terminal);
  state.failHermesPolling(terminal.action.id);
  assert.equal(state.getAction(terminal.action.id)?.state, 'failed');
});

test('legacy publishing and Basic-auth file browser remain compatible', async () => {
  await request(app).get('/admin/files/').expect(401);
  await request(app).get('/admin/files/').auth('legacy-admin', 'legacy-password-password').expect(200);
  await request(app).get('/api/artifacts').set('authorization', `Bearer ${process.env.API_TOKEN}`).expect(200);
});
