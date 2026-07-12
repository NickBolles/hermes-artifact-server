import fs from 'node:fs/promises';
import path from 'node:path';
import { Busboy } from '@fastify/busboy';
import type { BusboyFileStream, BusboyHeaders } from '@fastify/busboy';
import compression from 'compression';
import express from 'express';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import { pinoHttp } from 'pino-http';
import { z } from 'zod';
import { requireAdmin, requireApiToken } from './auth.js';
import { config } from './config.js';
import { adminUrl, artifactUrl, createArtifact, listArtifacts, readMeta, verifyArtifactToken } from './metadata.js';
import { ensureRoot, publicPathFromWildcard, safeResolve, safeSlug } from './paths.js';
import { renderDirectory, sendArtifactPath } from './render.js';

const createArtifactSchema = z.object({
  slug: z.string().min(1).max(100).optional(),
  title: z.string().min(1).max(200).optional(),
  expiresAt: z.string().datetime().optional(),
  allowDirectoryListing: z.boolean().optional(),
});

export function createApp() {
  const app = express();
  app.set('trust proxy', config.trustProxy);
  app.disable('x-powered-by');
  app.use(pinoHttp({ redact: ['req.headers.authorization', 'req.headers.cookie'] }));
  app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
  }));
  app.use(compression());
  app.use(rateLimit({ windowMs: 60_000, limit: 300, standardHeaders: true, legacyHeaders: false }));
  app.use(express.json({ limit: '1mb' }));

  app.get('/health', (_req, res) => res.json({ ok: true }));

  app.use('/api', requireApiToken);

  app.post('/api/artifacts', async (req, res, next) => {
    try {
      const parsed = createArtifactSchema.parse(req.body);
      const { meta, token, created } = await createArtifact(parsed);
      res.status(created ? 201 : 200).json({
        slug: meta.slug,
        title: meta.title,
        created,
        publicUrl: token ? artifactUrl(meta.slug, token) : undefined,
        adminUrl: adminUrl(meta.slug),
        meta: { ...meta, tokenHash: undefined },
      });
    } catch (error) { next(error); }
  });

  app.get('/api/artifacts', async (_req, res, next) => {
    try {
      const metas = await listArtifacts();
      res.json({ artifacts: metas.map((meta) => ({ ...meta, tokenHash: undefined, adminUrl: adminUrl(meta.slug) })) });
    } catch (error) { next(error); }
  });

  app.get('/api/artifacts/:slug', async (req, res, next) => {
    try {
      const meta = await readMeta(req.params.slug);
      if (!meta) return res.status(404).json({ error: 'Artifact not found' });
      return res.json({ artifact: { ...meta, tokenHash: undefined, adminUrl: adminUrl(meta.slug) } });
    } catch (error) { next(error); }
  });

  app.put('/api/artifacts/:slug/files{/*filePath}', express.raw({ type: '*/*', limit: config.maxUploadBytes }), async (req, res, next) => {
    try {
      const slug = safeSlug(req.params.slug);
      const meta = await readMeta(slug);
      if (!meta) return res.status(404).json({ error: 'Artifact not found' });
      const filePath = publicPathFromWildcard(req.params.filePath);
      if (!filePath) return res.status(400).json({ error: 'File path is required' });
      const dest = safeResolve(slug, filePath);
      await fs.mkdir(path.dirname(dest), { recursive: true });
      await fs.writeFile(dest, req.body);
      res.status(201).json({ ok: true, path: filePath });
    } catch (error) { next(error); }
  });

  app.post('/api/artifacts/:slug/files', async (req, res, next) => {
    try {
      const slug = safeSlug(req.params.slug);
      const meta = await readMeta(slug);
      if (!meta) return res.status(404).json({ error: 'Artifact not found' });

      const contentType = req.get('content-type');
      if (!contentType) return res.status(400).json({ error: 'Multipart content-type is required' });
      const headers = { ...req.headers, 'content-type': contentType } as BusboyHeaders;
      const busboy = Busboy({ headers, limits: { files: 1, fileSize: config.maxUploadBytes } });
      let targetPath = '';
      let uploaded = false;
      const writes: Promise<void>[] = [];

      busboy.on('field', (name: string, value: string) => {
        if (name === 'path') targetPath = value;
      });
      busboy.on('file', (_field: string, file: BusboyFileStream, filename: string) => {
        uploaded = true;
        const finalPath = targetPath || filename || 'upload.bin';
        const dest = safeResolve(slug, finalPath);
        writes.push(fs.mkdir(path.dirname(dest), { recursive: true }).then(() => new Promise<void>((resolve, reject) => {
          const chunks: Buffer[] = [];
          file.on('data', (chunk: Buffer) => chunks.push(Buffer.from(chunk)));
          file.on('limit', () => reject(new Error('Upload exceeded MAX_UPLOAD_BYTES')));
          file.on('end', () => fs.writeFile(dest, Buffer.concat(chunks)).then(resolve, reject));
          file.on('error', reject);
        })));
      });
      busboy.on('finish', async () => {
        if (!uploaded) return res.status(400).json({ error: 'No file uploaded' });
        await Promise.all(writes);
        return res.status(201).json({ ok: true });
      });
      busboy.on('error', next);
      req.pipe(busboy);
    } catch (error) { next(error); }
  });

  app.get('/a/:slug/:token{/*artifactPath}', async (req, res, next) => {
    try {
      const slug = safeSlug(req.params.slug);
      const meta = await readMeta(slug);
      if (!meta || !(await verifyArtifactToken(meta, req.params.token))) return res.status(404).send('Not found');
      const artifactPath = publicPathFromWildcard(req.params.artifactPath);
      await sendArtifactPath(req, res, {
        slug,
        requestPath: artifactPath,
        urlPrefix: `/a/${encodeURIComponent(slug)}/${encodeURIComponent(req.params.token)}/${artifactPath}`,
        allowDirectoryListing: meta.allowDirectoryListing,
      });
    } catch (error) { next(error); }
  });

  app.use('/admin', requireAdmin);
  app.get('/admin/files{/*adminPath}', async (req, res, next) => {
    try {
      const adminPath = publicPathFromWildcard(req.params.adminPath);
      const target = safeResolve(adminPath);
      const stat = await fs.stat(target);
      if (stat.isDirectory()) {
        await renderDirectory(res, { title: `Artifacts /${adminPath}`, dirPath: target, urlPrefix: `/admin/files/${adminPath}`, showHidden: true });
        return;
      }
      res.sendFile(target);
    } catch (error) { next(error); }
  });

  app.get('/', (_req, res) => res.redirect('/admin/files/'));

  app.use((error: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    const message = error instanceof z.ZodError ? 'Invalid request' : error instanceof Error ? error.message : 'Internal error';
    const status = error instanceof z.ZodError ? 400 : message.includes('escapes artifact root') ? 400 : 500;
    res.status(status).json({ error: message });
  });

  ensureRoot().catch((error) => {
    console.error(error);
  });
  return app;
}
