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
  revokedAt: z.string().optional(),
  visibility: z.enum(['bearer', 'authenticated', 'restricted']).default('bearer'),
  allowedUserIds: z.array(z.string()).max(100).default([]),
  allowDirectoryListing: z.boolean().default(true),
});

export type ArtifactMeta = z.infer<typeof artifactMetaSchema>;

const metadataLocks = new Map<string, Promise<void>>();

async function withMetadataLock<T>(slug: string, operation: () => Promise<T>): Promise<T> {
  const previous = metadataLocks.get(slug) ?? Promise.resolve();
  let release!: () => void;
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const queued = previous.then(() => gate);
  metadataLocks.set(slug, queued);
  await previous;
  try { return await operation(); }
  finally {
    release();
    if (metadataLocks.get(slug) === queued) metadataLocks.delete(slug);
  }
}

function nextUpdatedAt(previous: string): string {
  const candidate = new Date().toISOString();
  return candidate > previous ? candidate : new Date(Date.parse(previous) + 1).toISOString();
}

export async function sha256(value: string): Promise<string> {
  const { createHash } = await import('node:crypto');
  return createHash('sha256').update(value).digest('hex');
}

export function artifactUrl(slug: string, token: string): string {
  return `${config.baseUrl}/a/${encodeURIComponent(slug)}/${encodeURIComponent(token)}/`;
}

export function artifactViewerUrl(slug: string): string {
  return `${config.baseUrl}/v/${encodeURIComponent(slug)}/`;
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
  const target = path.join(dir, META_FILE);
  const temporary = path.join(dir, `${META_FILE}.${process.pid}.${nanoid(8)}.tmp`);
  try {
    await fs.writeFile(temporary, `${JSON.stringify(meta, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
    await fs.rename(temporary, target);
  } finally { await fs.rm(temporary, { force: true }); }
}

export async function createArtifact(input: {
  slug?: string;
  title?: string;
  expiresAt?: string;
  allowDirectoryListing?: boolean;
  visibility?: ArtifactMeta['visibility'];
  allowedUserIds?: string[];
}): Promise<{ meta: ArtifactMeta; token: string; created: boolean }> {
  const now = new Date().toISOString();
  const base = input.slug ? safeSlug(input.slug) : slugify(input.title ?? `artifact-${now}`);
  const slug = safeSlug(base || `artifact-${nanoid(8)}`);
  return withMetadataLock(slug, async () => {
    const existing = await readMeta(slug);
    if (existing) {
      const requestedVisibility=input.visibility??'bearer';
      const requestedAllowed=[...new Set(input.allowedUserIds??[])].sort();
      const existingAllowed=[...existing.allowedUserIds].sort();
      if(existing.visibility!==requestedVisibility||JSON.stringify(existingAllowed)!==JSON.stringify(requestedVisibility==='restricted'?requestedAllowed:[]))throw new Error('Artifact already exists with different access policy');
      return { meta: existing, token: '', created: false };
    }
    const token = nanoid(32);
    const meta: ArtifactMeta = {
      slug,
      title: input.title,
      tokenHash: await sha256(token),
      createdAt: now,
      updatedAt: now,
      expiresAt: input.expiresAt,
      visibility: input.visibility ?? 'bearer',
      allowedUserIds: [...new Set(input.allowedUserIds ?? [])].slice(0, 100),
      allowDirectoryListing: input.allowDirectoryListing ?? true,
    };
    await writeMeta(meta);
    return { meta, token, created: true };
  });
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
  return Boolean(meta.revokedAt || (meta.expiresAt && Date.parse(meta.expiresAt) < Date.now()));
}

export async function revokeArtifact(slug: string): Promise<void> {
  await withMetadataLock(slug, async () => {
    const meta = await readMeta(slug);
    if (!meta) throw new Error('Artifact not found');
    const at = nextUpdatedAt(meta.updatedAt);
    await writeMeta({ ...meta, revokedAt: at, updatedAt: at });
  });
}

export async function updateArtifactAccess(slug: string, input: {
  visibility: ArtifactMeta['visibility'];
  allowedUserIds: string[];
  expectedUpdatedAt: string;
}): Promise<{ meta: ArtifactMeta; token?: string }> {
  return withMetadataLock(slug, async () => {
    const meta = await readMeta(slug);
    if (!meta) throw new Error('Artifact not found');
    if (isExpired(meta)) throw new Error('Artifact is revoked or expired');
    if (meta.updatedAt !== input.expectedUpdatedAt) throw new Error('Artifact access changed; reload and try again');
    const token = input.visibility === 'bearer' ? nanoid(32) : undefined;
    const updated: ArtifactMeta = {
      ...meta,
      tokenHash: token ? await sha256(token) : meta.tokenHash,
      visibility: input.visibility,
      allowedUserIds: input.visibility === 'restricted' ? [...new Set(input.allowedUserIds)].slice(0, 100) : [],
      updatedAt: nextUpdatedAt(meta.updatedAt),
    };
    await writeMeta(updated);
    return { meta: updated, token };
  });
}

export function canUserViewArtifact(meta: ArtifactMeta, user: { id: string; role: string }): boolean {
  if (isExpired(meta) || meta.visibility === 'bearer') return false;
  if (user.role === 'admin' || meta.visibility === 'authenticated') return true;
  return meta.allowedUserIds.includes(user.id);
}

export async function verifyArtifactToken(meta: ArtifactMeta, token: string): Promise<boolean> {
  if (isExpired(meta) || meta.visibility !== 'bearer') return false;
  return (await sha256(token)) === meta.tokenHash;
}
