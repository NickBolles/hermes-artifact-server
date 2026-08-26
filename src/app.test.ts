import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';
import request from 'supertest';

const testBase = path.resolve('test-tmp', 'app');
await fs.rm(testBase, { recursive: true, force: true });
await fs.mkdir(testBase, { recursive: true });
const root = await fs.mkdtemp(path.join(testBase, 'artifact-server-'));
const token = 'test-api-token-at-least-32-characters';
process.env.ARTIFACT_ROOT = root;
process.env.STATE_DB_PATH = path.join(root, 'state.db');
process.env.API_TOKEN = token;
process.env.ADMIN_USERNAME = 'admin';
process.env.ADMIN_PASSWORD = 'password-password-password';
process.env.BASE_URL = 'http://example.test';
process.env.NODE_ENV = 'test';

const { createApp } = await import('./app.js');

test('creates an artifact, uploads index.html, and renders it through tokenized URL', async () => {
  const app = createApp();
  const create = await request(app)
    .post('/api/artifacts')
    .set('authorization', `Bearer ${token}`)
    .send({ slug: 'demo', title: 'Demo' })
    .expect(201);
  assert.equal(create.body.slug, 'demo');
  assert.match(create.body.publicUrl, /\/a\/demo\//);
  const publicPath = new URL(create.body.publicUrl).pathname;

  await request(app)
    .put('/api/artifacts/demo/files/index.html')
    .set('authorization', `Bearer ${token}`)
    .set('content-type', 'text/html')
    .send('<h1>Hello artifact</h1>')
    .expect(201);

  const rendered = await request(app).get(publicPath).expect(200);
  assert.match(rendered.text, /Hello artifact/);
});

test('rejects API calls without bearer token', async () => {
  const app = createApp();
  await request(app).post('/api/artifacts').send({ slug: 'nope' }).expect(401);
});

test('blocks path traversal during upload', async () => {
  const app = createApp();
  await request(app)
    .post('/api/artifacts')
    .set('authorization', `Bearer ${token}`)
    .send({ slug: 'traversal-demo' })
    .expect(201);

  const traversal = await request(app)
    .put('/api/artifacts/traversal-demo/files/../../owned.txt')
    .set('authorization', `Bearer ${token}`)
    .send('owned');
  assert.ok([400, 404].includes(traversal.status), `unexpected status ${traversal.status}`);
  await assert.rejects(() => fs.access(path.join(root, 'owned.txt')));
});

test('admin file browser requires basic auth', async () => {
  const app = createApp();
  await request(app).get('/admin/files/').expect(401);
  await request(app)
    .get('/admin/files/')
    .auth('admin', 'password-password-password')
    .expect(200);
});
