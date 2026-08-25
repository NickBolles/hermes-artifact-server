import path from 'node:path';

export function positiveInt(value:string|undefined,fallback:number,minimum=1):number { const parsed=Number(value); return Number.isFinite(parsed)&&parsed>=minimum?Math.floor(parsed):fallback; }
export function isCleanHttpsOrigin(value:URL):boolean { return value.protocol==='https:'&&!value.username&&!value.password&&!value.search&&!value.hash&&value.pathname==='/'; }

const port = positiveInt(process.env.PORT,3000);
const baseUrl = (process.env.BASE_URL ?? `http://localhost:${port}`).replace(/\/$/, '');
const parsedBaseUrl = new URL(baseUrl);
const appOrigin = (process.env.APP_ORIGIN ?? `http://app.localhost:${port}`).replace(/\/$/, '');
const parsedAppOrigin = new URL(appOrigin);
const webauthnOrigin = (process.env.WEBAUTHN_ORIGIN ?? appOrigin).replace(/\/$/, '');
const webauthnRpId = process.env.WEBAUTHN_RP_ID ?? parsedAppOrigin.hostname;
function optionalHttpUrl(value:string):string {
  if(!value)return '';
  const parsed=new URL(value);
  if(!['http:','https:'].includes(parsed.protocol)||parsed.username||parsed.password||parsed.search||parsed.hash)throw new Error('Hermes integration URLs must use http(s) without credentials, query, or fragment');
  return value.replace(/\/$/,'');
}
function trustProxyValue(value:string):boolean|number { if(/^\d+$/.test(value))return Number(value); return /^(true|yes)$/i.test(value); }

export const config = {
  port,
  baseUrl,
  artifactHostname: parsedBaseUrl.hostname.toLowerCase(),
  appOrigin,
  appHostname: parsedAppOrigin.hostname.toLowerCase(),
  artifactRoot: path.resolve(process.env.ARTIFACT_ROOT ?? path.join(process.cwd(), 'artifacts')),
  stateDbPath: path.resolve(process.env.STATE_DB_PATH ?? path.join(process.cwd(), 'data', 'artifact-app.db')),
  apiToken: process.env.API_TOKEN ?? '',
  adminUsername: process.env.ADMIN_USERNAME ?? 'admin',
  adminPassword: process.env.ADMIN_PASSWORD ?? '',
  trustProxy: trustProxyValue(process.env.TRUST_PROXY ?? 'false'),
  maxUploadBytes: positiveInt(process.env.MAX_UPLOAD_BYTES,50 * 1024 * 1024),
  webauthnOrigin,
  webauthnRpId,
  actionLimitPerMinute: positiveInt(process.env.ACTION_LIMIT_PER_MINUTE,10),
  actionLimitPerDay: positiveInt(process.env.ACTION_LIMIT_PER_DAY,100),
  sessionIdleMs: positiveInt(process.env.SESSION_IDLE_MINUTES,1_440,5) * 60_000,
  recoveryMaxConcurrent: positiveInt(process.env.RECOVERY_MAX_CONCURRENT,2),
  hermesRunMaxMs: positiveInt(process.env.HERMES_RUN_MAX_MINUTES,30,5) * 60_000,
  hermesWebhookUrl: optionalHttpUrl(process.env.HERMES_WEBHOOK_URL ?? ''),
  hermesWebhookSecret: process.env.HERMES_WEBHOOK_SECRET ?? '',
  hermesApiUrl: optionalHttpUrl(process.env.HERMES_API_URL ?? ''),
  hermesApiKey: process.env.HERMES_API_KEY ?? '',
};

export function assertProductionSecrets(): void {
  if (process.env.NODE_ENV === 'production') {
    const missing = [];
    if (!config.apiToken || config.apiToken.length < 32) missing.push('API_TOKEN >= 32 chars');
    if (!isCleanHttpsOrigin(parsedBaseUrl)) missing.push('BASE_URL must be a clean root HTTPS origin');
    if (!isCleanHttpsOrigin(parsedAppOrigin)) missing.push('APP_ORIGIN must be a clean root HTTPS origin');
    if (config.artifactHostname === config.appHostname) missing.push('APP_ORIGIN must use a different hostname from BASE_URL');
    if (config.webauthnOrigin !== config.appOrigin) missing.push('WEBAUTHN_ORIGIN must exactly match APP_ORIGIN');
    if (config.webauthnRpId !== config.appHostname) missing.push('WEBAUTHN_RP_ID must exactly match the app hostname');
    if (missing.length > 0) throw new Error(`Refusing to start with unsafe production configuration: ${missing.join(', ')}`);
  }
}
