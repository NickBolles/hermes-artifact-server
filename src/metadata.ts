import fs from 'node:fs/promises';
import path from 'node:path';
import { nanoid } from 'nanoid';
import { z } from 'zod';
import { config } from './config.js';
import { META_FILE, safeResolve, safeSlug, slugify } from './paths.js';

export const artifactMetaSchema = z.object({
  slug: z.string(),
  title: z.string().optional(),
  tokenHash: z.string(),
  createdAt: z.string(),
  updatedAt: z.string(),
  expiresAt: z.string().optional(),
  allowDirectoryListing: z.boolean().default(true),
});

export type ArtifactMeta = z.infer<typeof artifactMetaSchema>;

export async function sha256(value: string): Promise<string> {
  const { createHash } = await import('node:crypto');
  return createHash('sha256').update(value).digest('hex');
}

export function artifactUrl(slug: string, token: string): string {
  return `${config.baseUrl}/a/${encodeURIComponent(slug)}/${encodeURIComponent(token)}/`;
}

export function adminUrl(slug: string): string {
  return `${config.baseUrl}/admin/files/${encodeURIComponent(slug)}/`;
}

export async function readMeta(slug: string): Promise<ArtifactMeta | null> {
  const file = safeResolve(safeSlug(slug), META_FILE);
  try {
    const raw = await fs.readFile(file, 'utf8');
    return artifactMetaSchema.parse(JSON.parse(raw));
  } catch (error: unknown) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw error;
  }
}

export async function writeMeta(meta: ArtifactMeta): Promise<void> {
  const dir = safeResolve(meta.slug);
  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(path.join(dir, META_FILE), `${JSON.stringify(meta, null, 2)}\n`, { mode: 0o600 });
}

export async function createArtifact(input: {
  slug?: string;
  title?: string;
  expiresAt?: string;
  allowDirectoryListing?: boolean;
}): Promise<{ meta: ArtifactMeta; token: string; created: boolean }> {
  const now = new Date().toISOString();
  const base = input.slug ? safeSlug(input.slug) : slugify(input.title ?? `artifact-${now}`);
  const slug = safeSlug(base || `artifact-${nanoid(8)}`);
  const existing = await readMeta(slug);
  if (existing) {
    return { meta: { ...existing, updatedAt: now }, token: '', created: false };
  }
  const token = nanoid(32);
  const meta: ArtifactMeta = {
    slug,
    title: input.title,
    tokenHash: await sha256(token),
    createdAt: now,
    updatedAt: now,
    expiresAt: input.expiresAt,
    allowDirectoryListing: input.allowDirectoryListing ?? true,
  };
  await writeMeta(meta);
  return { meta, token, created: true };
}

export async function listArtifacts(): Promise<ArtifactMeta[]> {
  await fs.mkdir(config.artifactRoot, { recursive: true });
  const entries = await fs.readdir(config.artifactRoot, { withFileTypes: true });
  const metas: ArtifactMeta[] = [];
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const meta = await readMeta(entry.name);
    if (meta) metas.push(meta);
  }
  return metas.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

export function isExpired(meta: ArtifactMeta): boolean {
  return Boolean(meta.expiresAt && Date.parse(meta.expiresAt) < Date.now());
}

export async function verifyArtifactToken(meta: ArtifactMeta, token: string): Promise<boolean> {
  if (isExpired(meta)) return false;
  return (await sha256(token)) === meta.tokenHash;
}
