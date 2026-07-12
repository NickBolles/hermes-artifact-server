import path from 'node:path';

export const config = {
  port: Number(process.env.PORT ?? 3000),
  baseUrl: (process.env.BASE_URL ?? `http://localhost:${process.env.PORT ?? 3000}`).replace(/\/$/, ''),
  artifactRoot: path.resolve(process.env.ARTIFACT_ROOT ?? path.join(process.cwd(), 'artifacts')),
  apiToken: process.env.API_TOKEN ?? '',
  adminUsername: process.env.ADMIN_USERNAME ?? 'admin',
  adminPassword: process.env.ADMIN_PASSWORD ?? '',
  trustProxy: /^(1|true|yes)$/i.test(process.env.TRUST_PROXY ?? 'false'),
  maxUploadBytes: Number(process.env.MAX_UPLOAD_BYTES ?? 50 * 1024 * 1024),
};

export function assertProductionSecrets(): void {
  if (process.env.NODE_ENV === 'production') {
    const missing = [];
    if (!config.apiToken || config.apiToken.length < 32) missing.push('API_TOKEN >= 32 chars');
    if (!config.adminPassword || config.adminPassword.length < 16) missing.push('ADMIN_PASSWORD >= 16 chars');
    if (missing.length > 0) {
      throw new Error(`Refusing to start with weak/missing production secrets: ${missing.join(', ')}`);
    }
  }
}
