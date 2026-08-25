import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync, type SQLInputValue } from 'node:sqlite';

export type UserRole = 'admin' | 'member' | 'viewer';
export type UserStatus = 'pending' | 'active' | 'suspended';
export type SessionKind = 'full' | 'recovery';

export interface UserRow {
  id: string;
  username: string;
  role: UserRole;
  status: UserStatus;
  scopes: string[];
  recoveryPasswordHash: string;
  requiresPasskeyEnrollment: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface SessionRow {
  id: string;
  userId: string;
  tokenHash: string;
  csrfToken: string;
  kind: SessionKind;
  createdAt: string;
  lastUsedAt: string;
  expiresAt: string;
  revokedAt: string | null;
  userAgent: string | null;
}

export interface ActionRow {
  id: string;
  actorId: string;
  appId: string;
  action: string;
  clientActionId: string;
  requestHash: string;
  state: string;
  payload: unknown;
  result: unknown;
  error: string | null;
  hermesRunId: string | null;
  createdAt: string;
  updatedAt: string;
}

function now(): string { return new Date().toISOString(); }
function asString(value: unknown): string { return String(value ?? ''); }
function asNullableString(value: unknown): string | null { return value == null ? null : String(value); }
function parseJson<T>(value: unknown, fallback: T): T {
  try { return JSON.parse(String(value)) as T; } catch { return fallback; }
}

function mapUser(row: Record<string, unknown> | undefined): UserRow | null {
  if (!row) return null;
  return {
    id: asString(row.id), username: asString(row.username), role: asString(row.role) as UserRole,
    status: asString(row.status) as UserStatus, scopes: parseJson<string[]>(row.scopes, []),
    recoveryPasswordHash: asString(row.recovery_password_hash), requiresPasskeyEnrollment: Boolean(row.requires_passkey_enrollment),
    createdAt: asString(row.created_at), updatedAt: asString(row.updated_at),
  };
}

function mapSession(row: Record<string, unknown>): SessionRow {
  return {
    id: asString(row.id), userId: asString(row.user_id), tokenHash: asString(row.token_hash), csrfToken: asString(row.csrf_token),
    kind: asString(row.kind) as SessionKind, createdAt: asString(row.created_at), lastUsedAt: asString(row.last_used_at),
    expiresAt: asString(row.expires_at), revokedAt: asNullableString(row.revoked_at), userAgent: asNullableString(row.user_agent),
  };
}

function mapAction(row: Record<string, unknown> | undefined): ActionRow | null {
  if (!row) return null;
  return {
    id: asString(row.id), actorId: asString(row.actor_id), appId: asString(row.app_id), action: asString(row.action),
    clientActionId: asString(row.client_action_id), requestHash: asString(row.request_hash), state: asString(row.state),
    payload: parseJson(row.payload_json, null), result: parseJson(row.result_json, null), error: asNullableString(row.error),
    hermesRunId: asNullableString(row.hermes_run_id), createdAt: asString(row.created_at), updatedAt: asString(row.updated_at),
  };
}

export class StateStore {
  readonly db: DatabaseSync;
  readonly filePath: string;

  constructor(filePath: string) {
    this.filePath = path.resolve(filePath);
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true, mode: 0o700 });
    try { fs.chmodSync(path.dirname(this.filePath), 0o700); } catch {}
    this.db = new DatabaseSync(this.filePath);
    this.db.exec('PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;');
    this.migrate();
    for (const candidate of [this.filePath, `${this.filePath}-wal`, `${this.filePath}-shm`]) { try { if (fs.existsSync(candidate)) fs.chmodSync(candidate, 0o600); } catch {} }
  }

  private migrate(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
        role TEXT NOT NULL CHECK(role IN ('admin','member','viewer')),
        status TEXT NOT NULL CHECK(status IN ('pending','active','suspended')),
        scopes TEXT NOT NULL DEFAULT '[]', recovery_password_hash TEXT NOT NULL,
        requires_passkey_enrollment INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS passkeys (
        id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        credential_id TEXT NOT NULL UNIQUE, public_key TEXT NOT NULL, counter INTEGER NOT NULL DEFAULT 0,
        transports TEXT NOT NULL DEFAULT '[]', device_type TEXT, backed_up INTEGER NOT NULL DEFAULT 0,
        label TEXT NOT NULL, created_at TEXT NOT NULL, last_used_at TEXT
      );
      CREATE TABLE IF NOT EXISTS auth_challenges (
        id TEXT PRIMARY KEY, user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
        kind TEXT NOT NULL, challenge TEXT NOT NULL, binding_hash TEXT, label TEXT, expires_at TEXT NOT NULL,
        consumed_at TEXT, created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token_hash TEXT NOT NULL UNIQUE, csrf_token TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('full','recovery')),
        created_at TEXT NOT NULL, last_used_at TEXT NOT NULL, expires_at TEXT NOT NULL,
        revoked_at TEXT, user_agent TEXT
      );
      CREATE TABLE IF NOT EXISTS invitations (
        id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE, username TEXT NOT NULL COLLATE NOCASE,
        role TEXT NOT NULL, scopes TEXT NOT NULL, expires_at TEXT NOT NULL, consumed_at TEXT,
        created_by TEXT NOT NULL REFERENCES users(id), created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS audit_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT, actor_id TEXT, event TEXT NOT NULL,
        target_type TEXT, target_id TEXT, metadata_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS apps (
        id TEXT PRIMARY KEY, name TEXT NOT NULL, allowed_actions TEXT NOT NULL, created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS actions (
        id TEXT PRIMARY KEY, actor_id TEXT NOT NULL REFERENCES users(id), app_id TEXT NOT NULL REFERENCES apps(id),
        action TEXT NOT NULL, client_action_id TEXT NOT NULL, request_hash TEXT NOT NULL, state TEXT NOT NULL,
        payload_json TEXT NOT NULL, result_json TEXT NOT NULL DEFAULT 'null', error TEXT,
        hermes_run_id TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
        UNIQUE(actor_id, client_action_id)
      );
      CREATE INDEX IF NOT EXISTS actions_actor_time ON actions(actor_id, created_at);
      CREATE TABLE IF NOT EXISTS action_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT, action_id TEXT NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
        sequence INTEGER NOT NULL, event TEXT NOT NULL, payload_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL,
        UNIQUE(action_id, sequence)
      );
      CREATE TABLE IF NOT EXISTS outbox (
        id TEXT PRIMARY KEY, action_id TEXT NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
        kind TEXT NOT NULL, payload_json TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'queued',
        attempts INTEGER NOT NULL DEFAULT 0, available_at TEXT NOT NULL, last_error TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS job_feedback (
        id TEXT PRIMARY KEY, actor_id TEXT NOT NULL REFERENCES users(id), job_id TEXT NOT NULL,
        disposition TEXT NOT NULL, note TEXT, created_at TEXT NOT NULL,
        UNIQUE(actor_id, job_id)
      );
      CREATE TABLE IF NOT EXISTS artifact_viewer_handoffs (
        id TEXT PRIMARY KEY, artifact_slug TEXT NOT NULL, return_path TEXT NOT NULL,
        user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
        app_session_id TEXT REFERENCES sessions(id) ON DELETE CASCADE, exchange_hash TEXT UNIQUE,
        expires_at TEXT NOT NULL, consumed_at TEXT, created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS artifact_viewer_sessions (
        id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        source_session_id TEXT REFERENCES sessions(id) ON DELETE CASCADE,
        token_hash TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL, last_used_at TEXT NOT NULL,
        expires_at TEXT NOT NULL, revoked_at TEXT
      );
      CREATE INDEX IF NOT EXISTS viewer_sessions_user ON artifact_viewer_sessions(user_id);
    `);
    try { this.db.exec('ALTER TABLE auth_challenges ADD COLUMN binding_hash TEXT'); } catch {}
    try { this.db.exec('ALTER TABLE artifact_viewer_handoffs ADD COLUMN app_session_id TEXT REFERENCES sessions(id) ON DELETE CASCADE'); } catch {}
    try { this.db.exec('ALTER TABLE artifact_viewer_sessions ADD COLUMN source_session_id TEXT REFERENCES sessions(id) ON DELETE CASCADE'); } catch {}
    this.db.prepare(`INSERT OR IGNORE INTO apps(id,name,allowed_actions,created_at) VALUES(?,?,?,?)`)
      .run('jobs', 'Jobs', JSON.stringify(['job.feedback.submit', 'report.question.ask']), now());
  }

  close(): void { this.db.close(); }
  transaction<T>(fn: () => T): T {
    this.db.exec('BEGIN IMMEDIATE');
    try { const value = fn(); this.db.exec('COMMIT'); return value; }
    catch (error) { try { this.db.exec('ROLLBACK'); } catch {} throw error; }
  }

  countUsers(): number { return Number((this.db.prepare('SELECT COUNT(*) n FROM users').get() as Record<string, unknown>).n); }
  createUser(input: Omit<UserRow, 'createdAt'|'updatedAt'>): void {
    const at = now();
    this.db.prepare(`INSERT INTO users(id,username,role,status,scopes,recovery_password_hash,requires_passkey_enrollment,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`)
      .run(input.id, input.username, input.role, input.status, JSON.stringify(input.scopes), input.recoveryPasswordHash, input.requiresPasskeyEnrollment ? 1 : 0, at, at);
  }
  getUserById(id: string): UserRow | null { return mapUser(this.db.prepare('SELECT * FROM users WHERE id=?').get(id) as Record<string, unknown>|undefined); }
  getUserByUsername(username: string): UserRow | null { return mapUser(this.db.prepare('SELECT * FROM users WHERE username=? COLLATE NOCASE').get(username) as Record<string, unknown>|undefined); }
  listUsers(): UserRow[] { return (this.db.prepare('SELECT * FROM users ORDER BY username').all() as Record<string, unknown>[]).map((row) => mapUser(row)!); }
  updateUserStatus(id: string, status: UserStatus): void { this.db.prepare('UPDATE users SET status=?,updated_at=? WHERE id=?').run(status, now(), id); }
  markPasskeyEnrolled(id: string): void { this.db.prepare('UPDATE users SET requires_passkey_enrollment=0,status=\'active\',updated_at=? WHERE id=?').run(now(), id); }
  requirePasskeyEnrollment(id: string): void { this.db.prepare('UPDATE users SET requires_passkey_enrollment=1,updated_at=? WHERE id=?').run(now(), id); }

  insertPasskey(input: {id:string;userId:string;credentialId:string;publicKey:string;counter:number;transports:string[];deviceType?:string;backedUp:boolean;label:string}): void {
    this.db.prepare(`INSERT INTO passkeys(id,user_id,credential_id,public_key,counter,transports,device_type,backed_up,label,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)`)
      .run(input.id,input.userId,input.credentialId,input.publicKey,input.counter,JSON.stringify(input.transports),input.deviceType ?? null,input.backedUp?1:0,input.label,now());
  }
  getPasskeyByCredentialId(id: string): Record<string, unknown>|null { return (this.db.prepare('SELECT * FROM passkeys WHERE credential_id=?').get(id) as Record<string, unknown>|undefined) ?? null; }
  listPasskeys(userId: string): Record<string, unknown>[] { return this.db.prepare('SELECT id,label,created_at,last_used_at FROM passkeys WHERE user_id=? ORDER BY created_at').all(userId) as Record<string, unknown>[]; }
  listAllPasskeys(): Record<string, unknown>[] { return this.db.prepare('SELECT id,user_id,label,created_at,last_used_at FROM passkeys ORDER BY created_at').all() as Record<string, unknown>[]; }
  deletePasskey(id:string):string|null { const row=this.db.prepare('SELECT user_id FROM passkeys WHERE id=?').get(id) as Record<string,unknown>|undefined; if(!row)return null; this.db.prepare('DELETE FROM passkeys WHERE id=?').run(id); return String(row.user_id); }
  updatePasskeyCounter(id:string,counter:number):void { this.db.prepare('UPDATE passkeys SET counter=?,last_used_at=? WHERE credential_id=?').run(counter,now(),id); }

  createChallenge(input:{id:string;userId?:string;kind:string;challenge:string;bindingHash?:string;label?:string;expiresAt:string}):void {
    this.db.prepare('DELETE FROM auth_challenges WHERE expires_at<? OR consumed_at IS NOT NULL').run(now());
    this.db.prepare('INSERT INTO auth_challenges(id,user_id,kind,challenge,binding_hash,label,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?)')
      .run(input.id,input.userId ?? null,input.kind,input.challenge,input.bindingHash??null,input.label ?? null,input.expiresAt,now());
  }
  consumeChallenge(id:string,kind:string,bindingHash?:string):Record<string,unknown>|null {
    return this.transaction(() => {
      const row=this.db.prepare('SELECT * FROM auth_challenges WHERE id=? AND kind=? AND consumed_at IS NULL AND expires_at>?').get(id,kind,now()) as Record<string,unknown>|undefined;
      if(!row || (row.binding_hash && row.binding_hash!==bindingHash)) return null;
      this.db.prepare('UPDATE auth_challenges SET consumed_at=? WHERE id=? AND consumed_at IS NULL').run(now(),id);
      return row;
    });
  }
  getActiveChallenge(id:string,kind:string,bindingHash?:string):Record<string,unknown>|null {
    const row=this.db.prepare('SELECT * FROM auth_challenges WHERE id=? AND kind=? AND consumed_at IS NULL AND expires_at>?').get(id,kind,now()) as Record<string,unknown>|undefined;
    if(!row||(row.binding_hash&&row.binding_hash!==bindingHash))return null;
    return row;
  }
  claimChallenge(id:string):boolean { return Number(this.db.prepare('UPDATE auth_challenges SET consumed_at=? WHERE id=? AND consumed_at IS NULL AND expires_at>?').run(now(),id,now()).changes)===1; }

  insertSession(row: SessionRow): void {
    this.db.prepare(`INSERT INTO sessions(id,user_id,token_hash,csrf_token,kind,created_at,last_used_at,expires_at,revoked_at,user_agent) VALUES(?,?,?,?,?,?,?,?,?,?)`)
      .run(row.id,row.userId,row.tokenHash,row.csrfToken,row.kind,row.createdAt,row.lastUsedAt,row.expiresAt,row.revokedAt,row.userAgent);
  }
  getSessionByHash(hash:string):SessionRow|null { const row=this.db.prepare('SELECT * FROM sessions WHERE token_hash=?').get(hash) as Record<string,unknown>|undefined; return row?mapSession(row):null; }
  touchSession(id:string):void { this.db.prepare('UPDATE sessions SET last_used_at=? WHERE id=?').run(now(),id); }
  listSessions(userId?:string):SessionRow[] { const rows=(userId?this.db.prepare('SELECT * FROM sessions WHERE user_id=? ORDER BY created_at DESC').all(userId):this.db.prepare('SELECT * FROM sessions ORDER BY created_at DESC').all()) as Record<string,unknown>[]; return rows.map(mapSession); }
  revokeSession(id:string):void { const at=now(); this.db.prepare('UPDATE sessions SET revoked_at=? WHERE id=? AND revoked_at IS NULL').run(at,id); this.db.prepare('UPDATE artifact_viewer_sessions SET revoked_at=? WHERE source_session_id=? AND revoked_at IS NULL').run(at,id); }
  revokeAllSessions(userId:string):void { const at=now(); this.db.prepare('UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL').run(at,userId); this.db.prepare('UPDATE artifact_viewer_sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL').run(at,userId); }

  createViewerHandoff(input:{id:string;artifactSlug:string;returnPath:string;expiresAt:string}):void {
    this.db.prepare('DELETE FROM artifact_viewer_handoffs WHERE expires_at<? OR consumed_at IS NOT NULL').run(now());
    this.db.prepare('INSERT INTO artifact_viewer_handoffs(id,artifact_slug,return_path,expires_at,created_at) VALUES(?,?,?,?,?)')
      .run(input.id,input.artifactSlug,input.returnPath,input.expiresAt,now());
  }
  getViewerHandoff(id:string):Record<string,unknown>|null {
    return (this.db.prepare('SELECT * FROM artifact_viewer_handoffs WHERE id=? AND consumed_at IS NULL AND expires_at>?').get(id,now()) as Record<string,unknown>|undefined)??null;
  }
  authorizeViewerHandoff(id:string,userId:string,appSessionId:string,exchangeHash:string):boolean {
    const at=now();
    return Number(this.db.prepare('UPDATE artifact_viewer_handoffs SET user_id=?,app_session_id=?,exchange_hash=? WHERE id=? AND user_id IS NULL AND consumed_at IS NULL AND expires_at>? AND EXISTS (SELECT 1 FROM sessions s WHERE s.id=? AND s.user_id=? AND s.revoked_at IS NULL AND s.expires_at>?)').run(userId,appSessionId,exchangeHash,id,at,appSessionId,userId,at).changes)===1;
  }
  consumeViewerHandoff(exchangeHash:string,viewer:{id:string;tokenHash:string;createdAt:string;expiresAt:string}):Record<string,unknown>|null {
    return this.transaction(()=>{
      const at=now();
      const handoff=this.db.prepare('SELECT h.*,s.expires_at source_expires_at FROM artifact_viewer_handoffs h JOIN sessions s ON s.id=h.app_session_id WHERE h.exchange_hash=? AND h.user_id IS NOT NULL AND h.consumed_at IS NULL AND h.expires_at>? AND s.revoked_at IS NULL AND s.expires_at>?').get(exchangeHash,at,at) as Record<string,unknown>|undefined;
      if(!handoff)return null;
      const consumed=this.db.prepare('UPDATE artifact_viewer_handoffs SET consumed_at=? WHERE id=? AND consumed_at IS NULL').run(now(),handoff.id as SQLInputValue);
      if(Number(consumed.changes)!==1)return null;
      const expiresAt=viewer.expiresAt<String(handoff.source_expires_at)?viewer.expiresAt:String(handoff.source_expires_at);
      this.db.prepare('INSERT INTO artifact_viewer_sessions(id,user_id,source_session_id,token_hash,created_at,last_used_at,expires_at) VALUES(?,?,?,?,?,?,?)')
        .run(viewer.id,handoff.user_id as SQLInputValue,handoff.app_session_id as SQLInputValue,viewer.tokenHash,viewer.createdAt,viewer.createdAt,expiresAt);
      return handoff;
    });
  }
  getViewerSessionByHash(hash:string):Record<string,unknown>|null {
    return (this.db.prepare('SELECT v.*,s.revoked_at source_revoked_at,s.expires_at source_expires_at,s.last_used_at source_last_used_at FROM artifact_viewer_sessions v JOIN sessions s ON s.id=v.source_session_id WHERE v.token_hash=?').get(hash) as Record<string,unknown>|undefined)??null;
  }
  listViewerSessions(userId?:string):Record<string,unknown>[] {
    const sql='SELECT id,user_id,source_session_id,created_at,last_used_at,expires_at,revoked_at FROM artifact_viewer_sessions';
    return (userId?this.db.prepare(`${sql} WHERE user_id=? ORDER BY created_at DESC`).all(userId):this.db.prepare(`${sql} ORDER BY created_at DESC`).all()) as Record<string,unknown>[];
  }
  touchViewerSession(id:string):void { this.db.prepare('UPDATE artifact_viewer_sessions SET last_used_at=? WHERE id=?').run(now(),id); }
  revokeViewerSession(id:string):void { this.db.prepare('UPDATE artifact_viewer_sessions SET revoked_at=? WHERE id=? AND revoked_at IS NULL').run(now(),id); }
  revokeAllViewerSessions(userId:string):void { this.db.prepare('UPDATE artifact_viewer_sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL').run(now(),userId); }

  createInvitation(input:{id:string;tokenHash:string;username:string;role:UserRole;scopes:string[];expiresAt:string;createdBy:string}):void {
    this.db.prepare('INSERT INTO invitations(id,token_hash,username,role,scopes,expires_at,created_by,created_at) VALUES(?,?,?,?,?,?,?,?)')
      .run(input.id,input.tokenHash,input.username,input.role,JSON.stringify(input.scopes),input.expiresAt,input.createdBy,now());
  }
  consumeInvitation(tokenHash:string):Record<string,unknown>|null { return this.transaction(()=>{ const row=this.db.prepare('SELECT * FROM invitations WHERE token_hash=? AND consumed_at IS NULL AND expires_at>?').get(tokenHash,now()) as Record<string,unknown>|undefined; if(!row)return null; this.db.prepare('UPDATE invitations SET consumed_at=? WHERE id=? AND consumed_at IS NULL').run(now(),row.id as SQLInputValue); return row; }); }
  acceptInvitation(tokenHash:string,input:{id:string;recoveryPasswordHash:string;requiresPasskeyEnrollment:boolean;status:UserStatus}):UserRow|null {
    return this.transaction(()=>{
      const invite=this.db.prepare('SELECT * FROM invitations WHERE token_hash=? AND consumed_at IS NULL AND expires_at>?').get(tokenHash,now()) as Record<string,unknown>|undefined;
      if(!invite)return null;
      this.createUser({id:input.id,username:String(invite.username),role:String(invite.role) as UserRole,status:input.status,scopes:parseJson<string[]>(invite.scopes,[]),recoveryPasswordHash:input.recoveryPasswordHash,requiresPasskeyEnrollment:input.requiresPasskeyEnrollment});
      this.db.prepare('UPDATE invitations SET consumed_at=? WHERE id=? AND consumed_at IS NULL').run(now(),invite.id as SQLInputValue);
      return this.getUserById(input.id);
    });
  }
  listInvitations():Record<string,unknown>[] { return this.db.prepare('SELECT id,username,role,scopes,expires_at,consumed_at,created_at FROM invitations ORDER BY created_at DESC').all() as Record<string,unknown>[]; }

  audit(actorId:string|null,event:string,targetType?:string,targetId?:string,metadata:Record<string,unknown>={}):void {
    this.db.prepare('INSERT INTO audit_events(actor_id,event,target_type,target_id,metadata_json,created_at) VALUES(?,?,?,?,?,?)').run(actorId,event,targetType??null,targetId??null,JSON.stringify(metadata),now());
  }
  listAudit(limit=100):Record<string,unknown>[] { return this.db.prepare('SELECT * FROM audit_events ORDER BY id DESC LIMIT ?').all(limit) as Record<string,unknown>[]; }

  getApp(id:string):Record<string,unknown>|null { return (this.db.prepare('SELECT * FROM apps WHERE id=?').get(id) as Record<string,unknown>|undefined)??null; }
  findAction(actorId:string,clientActionId:string):ActionRow|null { return mapAction(this.db.prepare('SELECT * FROM actions WHERE actor_id=? AND client_action_id=?').get(actorId,clientActionId) as Record<string,unknown>|undefined); }
  insertAction(row:ActionRow):void { this.db.prepare(`INSERT INTO actions(id,actor_id,app_id,action,client_action_id,request_hash,state,payload_json,result_json,error,hermes_run_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(row.id,row.actorId,row.appId,row.action,row.clientActionId,row.requestHash,row.state,JSON.stringify(row.payload),JSON.stringify(row.result),row.error,row.hermesRunId,row.createdAt,row.updatedAt); }
  updateAction(id:string,fields:{state:string;result?:unknown;error?:string|null;hermesRunId?:string|null}):void { this.db.prepare('UPDATE actions SET state=?,result_json=COALESCE(?,result_json),error=?,hermes_run_id=COALESCE(?,hermes_run_id),updated_at=? WHERE id=?').run(fields.state,fields.result===undefined?null:JSON.stringify(fields.result),fields.error??null,fields.hermesRunId??null,now(),id); }
  getAction(id:string):ActionRow|null { return mapAction(this.db.prepare('SELECT * FROM actions WHERE id=?').get(id) as Record<string,unknown>|undefined); }
  listActions(limit=100):ActionRow[] { return (this.db.prepare('SELECT * FROM actions ORDER BY created_at DESC LIMIT ?').all(limit) as Record<string,unknown>[]).map((r)=>mapAction(r)!); }
  nextRunningHermesAction():ActionRow|null { return mapAction(this.db.prepare("SELECT * FROM actions WHERE state='running' AND hermes_run_id IS NOT NULL ORDER BY updated_at LIMIT 1").get() as Record<string,unknown>|undefined); }
  touchAction(id:string):void { this.db.prepare('UPDATE actions SET updated_at=? WHERE id=?').run(now(),id); }
  countRecentActions(actorId:string,action:string,since:string):number { return Number((this.db.prepare('SELECT COUNT(*) n FROM actions WHERE actor_id=? AND action=? AND created_at>=?').get(actorId,action,since) as Record<string,unknown>).n); }
  appendActionEvent(actionId:string,event:string,payload:unknown={}):void { const row=this.db.prepare('SELECT COALESCE(MAX(sequence),0)+1 n FROM action_events WHERE action_id=?').get(actionId) as Record<string,unknown>; this.db.prepare('INSERT INTO action_events(action_id,sequence,event,payload_json,created_at) VALUES(?,?,?,?,?)').run(actionId,row.n as SQLInputValue,event,JSON.stringify(payload),now()); }
  insertOutbox(input:{id:string;actionId:string;kind:string;payload:unknown}):void { const at=now(); this.db.prepare('INSERT INTO outbox(id,action_id,kind,payload_json,state,available_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)').run(input.id,input.actionId,input.kind,JSON.stringify(input.payload),'queued',at,at,at); }
  listOutbox(limit=100):Record<string,unknown>[] { return this.db.prepare('SELECT * FROM outbox ORDER BY created_at DESC LIMIT ?').all(limit) as Record<string,unknown>[]; }
  claimNextOutbox(leaseMs=60_000):Record<string,unknown>|null { return this.transaction(()=>{ const at=now(); const row=this.db.prepare("SELECT * FROM outbox WHERE (state='queued' AND available_at<=?) OR (state='running' AND available_at<=?) ORDER BY created_at LIMIT 1").get(at,at) as Record<string,unknown>|undefined; if(!row)return null; const leaseUntil=new Date(Date.now()+leaseMs).toISOString(); const changed=this.db.prepare("UPDATE outbox SET state='running',available_at=?,updated_at=? WHERE id=? AND (state='queued' OR (state='running' AND available_at<=?))").run(leaseUntil,at,row.id as SQLInputValue,at); if(Number(changed.changes)!==1)return null; return {...row,state:'running',available_at:leaseUntil}; }); }
  markOutboxSucceeded(id:string):void { this.db.prepare("UPDATE outbox SET state='succeeded',updated_at=? WHERE id=?").run(now(),id); }
  markOutboxFailed(id:string,error:string,retryAt:string):void { this.db.prepare("UPDATE outbox SET state='queued',attempts=attempts+1,last_error=?,available_at=?,updated_at=? WHERE id=?").run(error.slice(0,300),retryAt,now(),id); }
  markOutboxDead(id:string,error:string):void { this.db.prepare("UPDATE outbox SET state='dead',attempts=attempts+1,last_error=?,updated_at=? WHERE id=?").run(error.slice(0,300),now(),id); }
  completeOutboxDispatch(id:string,actionId:string,runId?:string):void { this.transaction(()=>{ if(runId){ this.updateAction(actionId,{state:'running',hermesRunId:runId}); this.appendActionEvent(actionId,'action.started',{runId}); } this.markOutboxSucceeded(id); }); }
  deadLetterOutbox(id:string,actionId:string,error:string,failAction:boolean):void { this.transaction(()=>{ this.markOutboxDead(id,error); if(failAction){ this.updateAction(actionId,{state:'failed',error:'Agent dispatch failed'}); this.appendActionEvent(actionId,'action.failed',{retryable:false}); } else { this.appendActionEvent(actionId,'agent_event.failed',{retryable:false}); } }); }
  failHermesPolling(actionId:string):void { this.transaction(()=>{ this.updateAction(actionId,{state:'failed',error:'Hermes run status could not be reconciled'}); this.appendActionEvent(actionId,'action.failed',{retryable:false,reason:'poll_unrecoverable'}); }); }
  saveJobFeedback(input:{id:string;actorId:string;jobId:string;disposition:string;note?:string}):void { this.db.prepare('INSERT INTO job_feedback(id,actor_id,job_id,disposition,note,created_at) VALUES(?,?,?,?,?,?) ON CONFLICT(actor_id,job_id) DO UPDATE SET disposition=excluded.disposition,note=excluded.note,created_at=excluded.created_at').run(input.id,input.actorId,input.jobId,input.disposition,input.note??null,now()); }
  listJobFeedback(actorId:string):Record<string,unknown>[] { return this.db.prepare('SELECT * FROM job_feedback WHERE actor_id=? ORDER BY created_at').all(actorId) as Record<string,unknown>[]; }
}

export function createStateStore(filePath: string): StateStore { return new StateStore(filePath); }
