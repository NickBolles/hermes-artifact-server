import fs from 'node:fs/promises';
import path from 'node:path';
import type { Request, Response } from 'express';
import mime from 'mime-types';
import { isHiddenName, safeResolve } from './paths.js';

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]!));
}

export async function renderDirectory(res: Response, opts: {
  title: string;
  dirPath: string;
  urlPrefix: string;
  showHidden?: boolean;
}): Promise<void> {
  const entries = await fs.readdir(opts.dirPath, { withFileTypes: true });
  const rows = entries
    .filter((entry) => opts.showHidden || !isHiddenName(entry.name))
    .sort((a, b) => Number(b.isDirectory()) - Number(a.isDirectory()) || a.name.localeCompare(b.name))
    .map((entry) => {
      const suffix = entry.isDirectory() ? '/' : '';
      const href = `${opts.urlPrefix.replace(/\/$/, '')}/${encodeURIComponent(entry.name)}${suffix}`;
      return `<li><a href="${href}">${escapeHtml(entry.name)}${suffix}</a></li>`;
    })
    .join('\n');
  res.type('html').send(`<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(opts.title)}</title>
<style>body{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem}a{color:#2563eb}li{line-height:1.8}.muted{color:#666}</style></head>
<body><h1>${escapeHtml(opts.title)}</h1><p class="muted">Directory listing</p><ul>${rows}</ul></body></html>`);
}

export async function sendArtifactPath(req: Request, res: Response, opts: {
  slug: string;
  requestPath: string;
  urlPrefix: string;
  allowDirectoryListing: boolean;
  showHidden?: boolean;
}): Promise<void> {
  const target = safeResolve(opts.slug, opts.requestPath);
  const stat = await fs.stat(target);
  if (stat.isDirectory()) {
    const indexPath = path.join(target, 'index.html');
    try {
      await fs.access(indexPath);
      res.sendFile(indexPath, { headers: { 'content-type': 'text/html; charset=utf-8' } });
      return;
    } catch {}
    if (!opts.allowDirectoryListing) {
      res.status(403).send('Directory listing disabled and no index.html exists');
      return;
    }
    await renderDirectory(res, { title: opts.slug, dirPath: target, urlPrefix: opts.urlPrefix, showHidden: opts.showHidden });
    return;
  }
  const contentType = mime.lookup(target) || 'application/octet-stream';
  res.sendFile(target, { headers: { 'content-type': contentType } });
}
