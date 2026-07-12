import fs from 'node:fs/promises';
import path from 'node:path';
import { config } from './config.js';

export const META_FILE = '.artifact-meta.json';

export function slugify(input: string): string {
  return input
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9._-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 80);
}

export function safeSlug(input: string): string {
  const slug = slugify(input);
  if (!slug || slug === '.' || slug === '..') throw new Error('Invalid slug');
  return slug;
}

export function safeResolve(...segments: string[]): string {
  const root = config.artifactRoot;
  const resolved = path.resolve(root, ...segments);
  const rel = path.relative(root, resolved);
  if (rel.startsWith('..') || path.isAbsolute(rel)) {
    throw new Error('Path escapes artifact root');
  }
  return resolved;
}

export function publicPathFromWildcard(value: unknown): string {
  if (Array.isArray(value)) return value.join('/');
  if (typeof value === 'string') return value;
  return '';
}

export async function ensureRoot(): Promise<void> {
  await fs.mkdir(config.artifactRoot, { recursive: true });
}

export function isHiddenName(name: string): boolean {
  return name.startsWith('.') || name === META_FILE;
}
