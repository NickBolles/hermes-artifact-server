import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import type { Request, Response } from 'express';
import { Algorithm, hash, verify } from '@node-rs/argon2';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type RegistrationResponseJSON,
} from '@simplewebauthn/server';
import { config } from './config.js';
import type { SessionKind, SessionRow, StateStore, UserRole, UserStatus } from './state.js';

export const SESSION_COOKIE = process.env.NODE_ENV==='production'?'__Host-artifact_app_session':'artifact_app_session';
export const VIEWER_SESSION_COOKIE = process.env.NODE_ENV==='production'?'__Host-artifact_viewer_session':'artifact_viewer_session';
export const AUTH_FLOW_COOKIE = process.env.NODE_ENV==='production'?'__Host-artifact_auth_flow':'artifact_auth_flow';
const ARGON_OPTIONS = { algorithm: Algorithm.Argon2id, memoryCost: 19_456, timeCost: 2, parallelism: 1, outputLen: 32 } as const;

function token(bytes = 32): string { return randomBytes(bytes).toString('base64url'); }
export function sha256(value: string | Buffer): string { return createHash('sha256').update(value).digest('hex'); }
function normalizeUsername(value: string): string { return value.trim().toLowerCase(); }
function validatedUsername(value:string):string { const username=normalizeUsername(value); if(!/^[a-z0-9][a-z0-9._-]{1,63}$/.test(username))throw new Error('Invalid username'); return username; }
function addMinutes(minutes: number): string { return new Date(Date.now() + minutes * 60_000).toISOString(); }
function addHours(hours: number): string { return new Date(Date.now() + hours * 3_600_000).toISOString(); }
function equalText(a:string,b:string):boolean { const x=Buffer.from(a); const y=Buffer.from(b); return x.length===y.length && timingSafeEqual(x,y); }

export interface ActiveSession {
  row: SessionRow;
  user: NonNullable<ReturnType<StateStore['getUserById']>>;
}

export interface ActiveViewerSession {
  row: Record<string, unknown>;
  user: NonNullable<ReturnType<StateStore['getUserById']>>;
}

export interface IssuedSession { token: string; csrfToken: string; row: SessionRow; }

export class AuthService {
  private recoveryInflight=0;
  constructor(readonly state: StateStore) {}

  async hashRecoveryPassword(password: string): Promise<string> {
    if (password.length < 14 || password.length > 256) throw new Error('Recovery password must be 14-256 characters');
    return hash(password, ARGON_OPTIONS);
  }

  async bootstrapAdmin(input: {username:string;recoveryPassword:string}): Promise<string> {
    if (this.state.countUsers() > 0) throw new Error('Bootstrap refused: users already exist');
    const id=randomUUID(); const username=validatedUsername(input.username);
    this.state.createUser({id,username,role:'admin',status:'active',scopes:['*'],recoveryPasswordHash:await this.hashRecoveryPassword(input.recoveryPassword),requiresPasskeyEnrollment:true});
    this.state.audit(id,'admin.bootstrapped','user',id);
    return id;
  }

  createInvitation(actorId:string,input:{username:string;role:UserRole;scopes:string[];expiresInMinutes?:number}):{id:string;token:string;expiresAt:string} {
    const username=validatedUsername(input.username);
    if(this.state.getUserByUsername(username)) throw new Error('Username already exists');
    const raw=token(); const id=randomUUID(); const expiresAt=addMinutes(input.expiresInMinutes??60);
    this.state.createInvitation({id,tokenHash:sha256(raw),username,role:input.role,scopes:[...new Set(input.scopes)].slice(0,32),expiresAt,createdBy:actorId});
    this.state.audit(actorId,'invitation.created','invitation',id,{username,role:input.role});
    return {id,token:raw,expiresAt};
  }

  async acceptInvitationForTests(rawToken:string,input:{recoveryPassword:string}):Promise<string> {
    if(process.env.NODE_ENV!=='test') throw new Error('Test helper unavailable');
    const id=randomUUID();
    const user=this.state.acceptInvitation(sha256(rawToken),{id,recoveryPasswordHash:await this.hashRecoveryPassword(input.recoveryPassword),requiresPasskeyEnrollment:false,status:'active'});
    if(!user) throw new Error('Invalid invitation');
    return id;
  }

  async beginInvitation(rawToken:string,input:{recoveryPassword:string}):Promise<{userId:string}> {
    const id=randomUUID();
    const user=this.state.acceptInvitation(sha256(rawToken),{id,recoveryPasswordHash:await this.hashRecoveryPassword(input.recoveryPassword),requiresPasskeyEnrollment:true,status:'pending'});
    if(!user) throw new Error('Invalid or expired invitation');
    this.state.audit(id,'invitation.accepted','user',id);
    return {userId:id};
  }

  issueSession(userId:string,kind:SessionKind,userAgent?:string):IssuedSession {
    const raw=token(); const csrfToken=token(24); const at=new Date().toISOString();
    const row:SessionRow={id:randomUUID(),userId,tokenHash:sha256(raw),csrfToken,kind,createdAt:at,lastUsedAt:at,expiresAt:kind==='recovery'?addMinutes(15):addHours(24*7),revokedAt:null,userAgent:userAgent?.slice(0,300)??null};
    this.state.insertSession(row); return {token:raw,csrfToken,row};
  }

  cookieOptions(): {httpOnly:true;secure:boolean;sameSite:'lax';path:string;maxAge:number} {
    return {httpOnly:true,secure:process.env.NODE_ENV==='production',sameSite:'lax',path:'/',maxAge:7*24*60*60*1000};
  }
  setSessionCookie(res:Response,issued:IssuedSession):void { res.cookie(SESSION_COOKIE,issued.token,this.cookieOptions()); }
  clearSessionCookie(res:Response):void { res.clearCookie(SESSION_COOKIE,{...this.cookieOptions(),maxAge:0}); }
  setViewerSessionCookie(res:Response,raw:string):void { res.cookie(VIEWER_SESSION_COOKIE,raw,{...this.cookieOptions(),maxAge:15*60*1000}); }
  clearViewerSessionCookie(res:Response):void { res.clearCookie(VIEWER_SESSION_COOKIE,{...this.cookieOptions(),maxAge:0}); }
  issueAuthFlow(res:Response):{raw:string;hash:string} { const raw=token(); res.cookie(AUTH_FLOW_COOKIE,raw,{httpOnly:true,secure:process.env.NODE_ENV==='production',sameSite:'lax',path:'/',maxAge:5*60*1000}); return {raw,hash:sha256(raw)}; }
  clearAuthFlow(res:Response):void { res.clearCookie(AUTH_FLOW_COOKIE,{httpOnly:true,secure:process.env.NODE_ENV==='production',sameSite:'lax',path:'/'}); }

  rawCookie(req:Request):string {
    return this.namedCookie(req,SESSION_COOKIE);
  }
  namedCookie(req:Request,nameToFind:string):string {
    const header=req.get('cookie')??'';
    for(const part of header.split(';')) { const [name,...rest]=part.trim().split('='); if(name===nameToFind) return decodeURIComponent(rest.join('=')); }
    return '';
  }

  getRequestSession(req:Request):ActiveSession|null {
    const raw=this.rawCookie(req); if(!raw)return null;
    const row=this.state.getSessionByHash(sha256(raw));
    if(!row||row.revokedAt||Date.parse(row.expiresAt)<=Date.now()||Date.now()-Date.parse(row.lastUsedAt)>config.sessionIdleMs)return null;
    const user=this.state.getUserById(row.userId);
    if(!user||user.status==='suspended'||(user.status==='pending'&&row.kind!=='recovery'))return null;
    this.state.touchSession(row.id);
    return {row,user};
  }

  getRequestViewerSession(req:Request):ActiveViewerSession|null {
    const raw=this.namedCookie(req,VIEWER_SESSION_COOKIE); if(!raw)return null;
    const row=this.state.getViewerSessionByHash(sha256(raw)); if(!row)return null;
    if(row.revoked_at||row.source_revoked_at||Date.parse(String(row.expires_at))<=Date.now()||Date.parse(String(row.source_expires_at))<=Date.now()||Date.now()-Date.parse(String(row.last_used_at))>config.sessionIdleMs||Date.now()-Date.parse(String(row.source_last_used_at))>config.sessionIdleMs)return null;
    const user=this.state.getUserById(String(row.user_id));
    if(!user||user.status!=='active'||user.requiresPasskeyEnrollment)return null;
    this.state.touchViewerSession(String(row.id));
    return {row,user};
  }

  beginViewerHandoff(artifactSlug:string,returnPath:string):string {
    const expectedPrefix=`/v/${encodeURIComponent(artifactSlug)}/`;
    if(!returnPath.startsWith(expectedPrefix)||returnPath.length>2_048)throw new Error('Invalid artifact return path');
    const id=randomUUID();
    this.state.createViewerHandoff({id,artifactSlug,returnPath,expiresAt:addMinutes(5)});
    return id;
  }

  authorizeViewerHandoff(id:string,userId:string,appSessionId:string):string|null {
    const raw=token();
    return this.state.authorizeViewerHandoff(id,userId,appSessionId,sha256(raw))?raw:null;
  }

  finishViewerHandoff(rawExchange:string):{sessionToken:string;returnPath:string}|null {
    const sessionToken=token(); const createdAt=new Date().toISOString();
    const handoff=this.state.consumeViewerHandoff(sha256(rawExchange),{id:randomUUID(),tokenHash:sha256(sessionToken),createdAt,expiresAt:addMinutes(15)});
    if(!handoff)return null;
    return {sessionToken,returnPath:String(handoff.return_path)};
  }

  requireCsrf(req:Request,session:ActiveSession):boolean {
    const supplied=req.get('x-csrf-token')??'';
    const origin=req.get('origin')??'';
    return equalText(origin,config.webauthnOrigin)&&equalText(supplied,session.row.csrfToken);
  }

  async recover(username:string,password:string,userAgent?:string):Promise<IssuedSession|null> {
    if(this.recoveryInflight>=config.recoveryMaxConcurrent)return null;
    this.recoveryInflight++;
    try {
      const user=this.state.getUserByUsername(normalizeUsername(username));
      if(!user||user.status==='suspended') { await hash('timing-equalizer-password',ARGON_OPTIONS); return null; }
      if(!(await verify(user.recoveryPasswordHash,password,ARGON_OPTIONS)))return null;
      this.state.revokeAllSessions(user.id);
      this.state.requirePasskeyEnrollment(user.id);
      this.state.audit(user.id,'recovery.authenticated','user',user.id);
      return this.issueSession(user.id,'recovery',userAgent);
    } finally { this.recoveryInflight--; }
  }

  revokeAllSessions(userId:string,actorId:string):void { this.state.revokeAllSessions(userId); this.state.audit(actorId,'sessions.revoked','user',userId); }
  setUserStatus(userId:string,status:UserStatus,actorId:string):void { this.state.updateUserStatus(userId,status); if(status!=='active')this.state.revokeAllSessions(userId); this.state.audit(actorId,'user.status_changed','user',userId,{status}); }

  async registrationOptions(userId:string,label:string):Promise<Record<string,unknown>> {
    const user=this.state.getUserById(userId); if(!user)throw new Error('User not found');
    const options=await generateRegistrationOptions({rpName:'Hermes Artifact Apps',rpID:config.webauthnRpId,userName:user.username,userID:new TextEncoder().encode(user.id),attestationType:'none',authenticatorSelection:{residentKey:'required',userVerification:'required'}});
    const flowId=randomUUID(); this.state.createChallenge({id:flowId,userId,kind:'registration',challenge:options.challenge,label:label.trim().slice(0,80)||'Passkey',expiresAt:addMinutes(5)});
    return {...options,flowId};
  }

  async finishRegistration(session:ActiveSession,flowId:string,response:RegistrationResponseJSON):Promise<IssuedSession> {
    const challenge=this.state.getActiveChallenge(flowId,'registration');
    if(!challenge||String(challenge.user_id)!==session.user.id)throw new Error('Invalid or expired challenge');
    const verification=await verifyRegistrationResponse({response,expectedChallenge:String(challenge.challenge),expectedOrigin:config.webauthnOrigin,expectedRPID:config.webauthnRpId,requireUserVerification:true});
    if(!verification.verified||!verification.registrationInfo)throw new Error('Passkey verification failed');
    const info=verification.registrationInfo;
    return this.state.transaction(()=>{
      if(!this.state.claimChallenge(flowId))throw new Error('Invalid or expired challenge');
      this.state.insertPasskey({id:randomUUID(),userId:session.user.id,credentialId:info.credential.id,publicKey:Buffer.from(info.credential.publicKey).toString('base64'),counter:info.credential.counter,transports:response.response.transports??[],deviceType:info.credentialDeviceType,backedUp:info.credentialBackedUp,label:String(challenge.label??'Passkey')});
      this.state.markPasskeyEnrolled(session.user.id); this.state.revokeAllSessions(session.user.id);
      this.state.audit(session.user.id,'passkey.registered','user',session.user.id);
      return this.issueSession(session.user.id,'full');
    });
  }

  async authenticationOptions(bindingHash:string):Promise<Record<string,unknown>> {
    const options=await generateAuthenticationOptions({rpID:config.webauthnRpId,userVerification:'required',allowCredentials:[]});
    const flowId=randomUUID(); this.state.createChallenge({id:flowId,kind:'authentication',challenge:options.challenge,bindingHash,expiresAt:addMinutes(5)});
    return {...options,flowId};
  }

  async finishAuthentication(flowId:string,response:AuthenticationResponseJSON,bindingHash:string,userAgent?:string):Promise<IssuedSession> {
    const challenge=this.state.getActiveChallenge(flowId,'authentication',bindingHash); if(!challenge)throw new Error('Invalid or expired challenge');
    const passkey=this.state.getPasskeyByCredentialId(response.id); if(!passkey)throw new Error('Authentication failed');
    const verification=await verifyAuthenticationResponse({response,expectedChallenge:String(challenge.challenge),expectedOrigin:config.webauthnOrigin,expectedRPID:config.webauthnRpId,requireUserVerification:true,credential:{id:String(passkey.credential_id),publicKey:Buffer.from(String(passkey.public_key),'base64'),counter:Number(passkey.counter),transports:JSON.parse(String(passkey.transports))}});
    if(!verification.verified)throw new Error('Authentication failed');
    const user=this.state.getUserById(String(passkey.user_id)); if(!user||user.status!=='active'||user.requiresPasskeyEnrollment)throw new Error('Authentication failed');
    return this.state.transaction(()=>{
      if(!this.state.claimChallenge(flowId))throw new Error('Authentication failed');
      this.state.updatePasskeyCounter(response.id,verification.authenticationInfo.newCounter);
      this.state.audit(user.id,'passkey.authenticated','user',user.id);
      return this.issueSession(user.id,'full',userAgent);
    });
  }
}

export function createAuthService(state:StateStore):AuthService { return new AuthService(state); }
