import { timingSafeEqual } from 'node:crypto';
import type { NextFunction, Request, Response } from 'express';
import { config } from './config.js';

function safeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

export function requireApiToken(req: Request, res: Response, next: NextFunction): void {
  const header = req.get('authorization') ?? '';
  const token = header.startsWith('Bearer ') ? header.slice('Bearer '.length) : req.get('x-api-token') ?? '';
  if (!config.apiToken || !safeEqual(token, config.apiToken)) {
    res.status(401).json({ error: 'Missing or invalid API token' });
    return;
  }
  next();
}

export function requireAdmin(req: Request, res: Response, next: NextFunction): void {
  const header = req.get('authorization') ?? '';
  if (!header.startsWith('Basic ')) {
    res.set('WWW-Authenticate', 'Basic realm="Hermes Artifacts", charset="UTF-8"');
    res.status(401).send('Authentication required');
    return;
  }
  const decoded = Buffer.from(header.slice('Basic '.length), 'base64').toString('utf8');
  const splitAt = decoded.indexOf(':');
  const username = decoded.slice(0, splitAt);
  const password = decoded.slice(splitAt + 1);
  if (!safeEqual(username, config.adminUsername) || !config.adminPassword || !safeEqual(password, config.adminPassword)) {
    res.set('WWW-Authenticate', 'Basic realm="Hermes Artifacts", charset="UTF-8"');
    res.status(401).send('Authentication required');
    return;
  }
  next();
}
