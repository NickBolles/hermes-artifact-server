import fs from 'node:fs/promises';
import path from 'node:path';
import { Busboy } from '@fastify/busboy';
import type { BusboyFileStream, BusboyHeaders } from '@fastify/busboy';
import compression from 'compression';
import express, { type NextFunction, type Request, type Response } from 'express';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import { pinoHttp } from 'pino-http';
import { z } from 'zod';
import { requireAdmin, requireApiToken } from './auth.js';
import { AUTH_FLOW_COOKIE, createAuthService, sha256, type ActiveSession, type AuthService } from './app-auth.js';
import { browserScript, renderAdmin, renderInvite, renderJobs, renderLogin, renderRecovery } from './app-ui.js';
import { ActionError, createActionService } from './actions.js';
import { config } from './config.js';
import { adminUrl, artifactUrl, createArtifact, listArtifacts, readMeta, revokeArtifact, verifyArtifactToken } from './metadata.js';
import { ensureRoot, publicPathFromWildcard, safeResolve, safeSlug } from './paths.js';
import { renderDirectory, sendArtifactPath } from './render.js';
import { createStateStore, type StateStore, type UserRole } from './state.js';
import { startOutboxWorker } from './worker.js';

const createArtifactSchema = z.object({slug:z.string().min(1).max(100).optional(),title:z.string().min(1).max(200).optional(),expiresAt:z.string().datetime().optional(),allowDirectoryListing:z.boolean().optional()}).strict();
const invitationSchema=z.object({username:z.string().min(2).max(64),role:z.enum(['admin','member','viewer']).default('member'),scopes:z.array(z.string().min(1).max(80)).max(32).default([])}).strict();
const recoverySchema=z.object({username:z.string().min(2).max(64),password:z.string().min(14).max(256)}).strict();
const labelSchema=z.object({label:z.string().trim().min(1).max(80)}).strict();

let defaultState:StateStore|undefined;
let defaultAuth:AuthService|undefined;
function defaults():{state:StateStore;auth:AuthService} { defaultState??=createStateStore(config.stateDbPath); defaultAuth??=createAuthService(defaultState); return {state:defaultState,auth:defaultAuth}; }

function appHeaders(res:Response):void {
  res.set({
    'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    'Referrer-Policy':'no-referrer',
    'Cache-Control':'no-store',
  });
}
function artifactHeaders(res:Response):void {
  res.set({
    'Content-Security-Policy': "default-src 'self' data: https:; script-src 'self' 'unsafe-inline' https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https:; connect-src 'self' https:; frame-ancestors 'none'; base-uri 'none'",
    'Referrer-Policy':'no-referrer',
    'Cache-Control':'private, no-store',
  });
}
function errorMessage(error:unknown):string { return error instanceof z.ZodError?'Invalid request':error instanceof Error?error.message:'Internal error'; }
function routeParam(value:string|string[]|undefined):string { return Array.isArray(value)?value[0]??'':value??''; }
export function sanitizeRequestUrl(value:string):string { return value.replace(/(\/a\/[^/]+\/)[^/?#]+/,'$1[REDACTED]').replace(/(\/invite\/)[^/?#]+/,'$1[REDACTED]'); }
function sessionJson(session:ActiveSession) { return {id:session.row.id,kind:session.row.kind,csrfToken:session.row.csrfToken,requiresPasskeyEnrollment:session.user.requiresPasskeyEnrollment,user:{id:session.user.id,username:session.user.username,role:session.user.role,scopes:session.user.scopes}}; }

export function createApp(options:{state?:StateStore;auth?:AuthService;startWorkers?:boolean}={}) {
  const fallback=options.state&&options.auth?{state:options.state,auth:options.auth}:defaults();
  const state=options.state??fallback.state; const auth=options.auth??fallback.auth; const actions=createActionService(state);
  if(options.startWorkers!==false) startOutboxWorker(state,actions);
  const app=express();
  app.set('trust proxy',config.trustProxy); app.disable('x-powered-by');
  app.use(pinoHttp({redact:['req.headers.authorization','req.headers.cookie','req.headers.x-csrf-token'],serializers:{req:(req)=>({id:req.id,method:req.method,url:sanitizeRequestUrl(req.url),query:req.query,params:req.params,headers:req.headers,remoteAddress:req.remoteAddress,remotePort:req.remotePort})}}));
  app.use(helmet({contentSecurityPolicy:false,crossOriginEmbedderPolicy:false,referrerPolicy:{policy:'no-referrer'}}));
  app.use(compression());
  app.use(rateLimit({windowMs:60_000,limit:300,standardHeaders:true,legacyHeaders:false}));
  app.use(express.json({limit:'1mb'}));
  app.use((req,res,next)=>{
    if(req.path==='/health'||req.path==='/')return next();
    const host=req.hostname.toLowerCase();
    if(process.env.NODE_ENV==='test'&&(host==='127.0.0.1'||host==='localhost'))return next();
    const artifactSurface=req.path.startsWith('/a/')||req.path==='/api'||req.path.startsWith('/api/')||req.path==='/admin/files'||req.path.startsWith('/admin/files/');
    const appSurface=req.path==='/assets/app.js'||req.path==='/login'||req.path==='/recovery'||req.path.startsWith('/invite/')||req.path==='/auth'||req.path.startsWith('/auth/')||req.path==='/app'||req.path.startsWith('/app/')||req.path==='/admin'||req.path.startsWith('/admin/api/');
    if(artifactSurface&&host!==config.artifactHostname)return res.status(404).send('Not found');
    if(appSurface&&host!==config.appHostname)return res.status(404).send('Not found');
    next();
  });

  const recoveryLimiter=rateLimit({windowMs:15*60_000,limit:5,standardHeaders:true,legacyHeaders:false,message:{error:'Recovery temporarily unavailable'}});
  const passkeyLimiter=rateLimit({windowMs:15*60_000,limit:30,standardHeaders:true,legacyHeaders:false,message:{error:'Authentication temporarily unavailable'}});
  const mutationSession=(req:Request,res:Response,next:NextFunction)=>{const current=auth.getRequestSession(req);if(!current)return res.status(401).json({error:'Authentication required'});if(!auth.requireCsrf(req,current))return res.status(403).json({error:'Request verification failed'});res.locals.session=current;next();};
  const fullSession=(req:Request,res:Response,next:NextFunction)=>{const current=auth.getRequestSession(req);if(!current)return res.status(401).json({error:'Authentication required'});if(current.row.kind!=='full'||current.user.requiresPasskeyEnrollment)return res.status(403).json({error:'Passkey enrollment required'});res.locals.session=current;next();};
  const fullMutation=(req:Request,res:Response,next:NextFunction)=>mutationSession(req,res,()=>fullSession(req,res,next));
  const adminSession=(req:Request,res:Response,next:NextFunction)=>fullSession(req,res,()=>{const current=res.locals.session as ActiveSession;if(current.user.role!=='admin')return res.status(403).json({error:'Admin role required'});next();});
  const adminMutation=(req:Request,res:Response,next:NextFunction)=>fullMutation(req,res,()=>{const current=res.locals.session as ActiveSession;if(current.user.role!=='admin')return res.status(403).json({error:'Admin role required'});if(Date.now()-Date.parse(current.row.createdAt)>15*60_000)return res.status(403).json({error:'Passkey reauthentication required'});next();});

  app.get('/health',(_req,res)=>res.json({ok:true}));
  app.get('/assets/app.js',(_req,res)=>{res.set({'content-type':'text/javascript; charset=utf-8','cache-control':'public, max-age=300'}).send(browserScript)});
  app.get('/login',(_req,res)=>{appHeaders(res);res.send(renderLogin())});
  app.get('/recovery',(_req,res)=>{appHeaders(res);res.send(renderRecovery())});
  app.get('/invite/:token',(req,res)=>{appHeaders(res);res.send(renderInvite(routeParam(req.params.token)))});

  app.post('/auth/recovery',recoveryLimiter,async(req,res,next)=>{try{if(req.get('origin')!==config.webauthnOrigin)return res.status(403).json({error:'Recovery failed'});const parsed=recoverySchema.parse(req.body);const issued=await auth.recover(parsed.username,parsed.password,req.get('user-agent'));if(!issued)return res.status(401).json({error:'Recovery failed'});auth.setSessionCookie(res,issued);return res.json({session:{kind:'recovery',csrfToken:issued.csrfToken,requiresPasskeyEnrollment:true}})}catch(error){next(error)}});
  app.get('/auth/session',(req,res)=>{const current=auth.getRequestSession(req);if(!current)return res.status(401).json({error:'Authentication required'});return res.json({session:sessionJson(current)})});
  app.post('/auth/logout',mutationSession,(req,res)=>{const current=res.locals.session as ActiveSession;state.revokeSession(current.row.id);auth.clearSessionCookie(res);res.json({ok:true})});

  app.post('/auth/passkeys/register/options',mutationSession,async(req,res,next)=>{try{const current=res.locals.session as ActiveSession;const parsed=labelSchema.parse(req.body);res.json(await auth.registrationOptions(current.user.id,parsed.label))}catch(error){next(error)}});
  app.post('/auth/passkeys/register/verify',mutationSession,async(req,res,next)=>{try{const current=res.locals.session as ActiveSession;const flowId=String(req.body?.flowId??'');if(!flowId||!req.body?.response)return res.status(400).json({error:'Invalid registration response'});const issued=await auth.finishRegistration(current,flowId,req.body.response);auth.setSessionCookie(res,issued);res.json({verified:true})}catch(error){next(error)}});
  app.post('/auth/passkeys/authenticate/options',passkeyLimiter,async(req,res,next)=>{try{if(req.get('origin')!==config.webauthnOrigin)return res.status(403).json({error:'Authentication failed'});const flow=auth.issueAuthFlow(res);res.json(await auth.authenticationOptions(flow.hash))}catch(error){next(error)}});
  app.post('/auth/passkeys/authenticate/verify',passkeyLimiter,async(req,res,next)=>{try{if(req.get('origin')!==config.webauthnOrigin)return res.status(403).json({error:'Authentication failed'});const flowToken=auth.namedCookie(req,AUTH_FLOW_COOKIE);if(!flowToken)return res.status(401).json({error:'Authentication failed'});const issued=await auth.finishAuthentication(String(req.body?.flowId??''),req.body?.response,sha256(flowToken),req.get('user-agent'));auth.clearAuthFlow(res);auth.setSessionCookie(res,issued);res.json({verified:true})}catch{auth.clearAuthFlow(res);res.status(401).json({error:'Authentication failed'})}});
  app.post('/auth/invitations/:token/begin',recoveryLimiter,async(req,res,next)=>{try{if(req.get('origin')!==config.webauthnOrigin)return res.status(403).json({error:'Invitation failed'});const parsed=z.object({password:z.string().min(14).max(256)}).strict().parse(req.body);const accepted=await auth.beginInvitation(routeParam(req.params.token),{recoveryPassword:parsed.password});const issued=auth.issueSession(accepted.userId,'recovery',req.get('user-agent'));auth.setSessionCookie(res,issued);res.json({session:{kind:'recovery',csrfToken:issued.csrfToken,requiresPasskeyEnrollment:true}})}catch(error){next(error)}});

  app.get('/app/jobs',fullSession,(req,res)=>{const current=res.locals.session as ActiveSession;appHeaders(res);res.send(renderJobs(current.user,current.row.csrfToken))});
  app.post('/app/:appId/actions/:action',fullMutation,(req,res,next)=>{try{const current=res.locals.session as ActiveSession;const idempotencyKey=req.get('idempotency-key')??'';const outcome=actions.submit({actor:current.user,appId:routeParam(req.params.appId),action:routeParam(req.params.action),body:req.body,idempotencyKey});res.status(outcome.duplicate?200:202).json({action:outcome.action})}catch(error){next(error)}});
  app.get('/app/:appId/actions/:id',fullSession,(req,res)=>{const current=res.locals.session as ActiveSession;const action=state.getAction(routeParam(req.params.id));if(!action||action.actorId!==current.user.id||action.appId!==routeParam(req.params.appId))return res.status(404).json({error:'Action not found'});res.json({action})});

  app.get('/admin',adminSession,async(req,res,next)=>{try{const current=res.locals.session as ActiveSession;appHeaders(res);res.send(renderAdmin({user:current.user,csrf:current.row.csrfToken,users:state.listUsers(),passkeys:state.listAllPasskeys(),sessions:state.listSessions(),actions:state.listActions(),outbox:state.listOutbox(),artifacts:(await listArtifacts()).map(({tokenHash:_,...meta})=>meta),audit:state.listAudit()}))}catch(error){next(error)}});
  app.post('/admin/api/invitations',adminMutation,(req,res,next)=>{try{const current=res.locals.session as ActiveSession;const parsed=invitationSchema.parse(req.body);const invitation=auth.createInvitation(current.user.id,{username:parsed.username,role:parsed.role as UserRole,scopes:parsed.scopes,expiresInMinutes:60});res.status(201).json({invitationUrl:`${config.appOrigin}/invite/${invitation.token}`,expiresAt:invitation.expiresAt})}catch(error){next(error)}});
  app.post('/admin/api/users/:id/status',adminMutation,(req,res,next)=>{try{const current=res.locals.session as ActiveSession;const parsed=z.object({status:z.enum(['active','suspended'])}).strict().parse(req.body);const target=routeParam(req.params.id);if(target===current.user.id&&parsed.status==='suspended')return res.status(400).json({error:'Cannot suspend the current admin'});auth.setUserStatus(target,parsed.status,current.user.id);res.json({ok:true})}catch(error){next(error)}});
  app.post('/admin/api/users/:id/revoke-sessions',adminMutation,(req,res)=>{const current=res.locals.session as ActiveSession;auth.revokeAllSessions(routeParam(req.params.id),current.user.id);res.json({ok:true})});
  app.post('/admin/api/sessions/:id/revoke',adminMutation,(req,res)=>{const current=res.locals.session as ActiveSession;const id=routeParam(req.params.id);state.revokeSession(id);state.audit(current.user.id,'session.revoked','session',id);res.json({ok:true})});
  app.delete('/admin/api/passkeys/:id',adminMutation,(req,res)=>{const current=res.locals.session as ActiveSession;const id=routeParam(req.params.id);const userId=state.deletePasskey(id);if(!userId)return res.status(404).json({error:'Passkey not found'});state.revokeAllSessions(userId);state.audit(current.user.id,'passkey.deleted','passkey',id,{userId});res.json({ok:true})});
  app.post('/admin/api/artifacts/:slug/revoke',adminMutation,async(req,res,next)=>{try{const current=res.locals.session as ActiveSession;const slug=safeSlug(routeParam(req.params.slug));await revokeArtifact(slug);state.audit(current.user.id,'artifact.revoked','artifact',slug);res.json({ok:true})}catch(error){next(error)}});

  app.use('/api',requireApiToken);
  app.post('/api/artifacts',async(req,res,next)=>{try{const parsed=createArtifactSchema.parse(req.body);const {meta,token,created}=await createArtifact(parsed);res.status(created?201:200).json({slug:meta.slug,title:meta.title,created,publicUrl:token?artifactUrl(meta.slug,token):undefined,adminUrl:adminUrl(meta.slug),meta:{...meta,tokenHash:undefined}})}catch(error){next(error)}});
  app.get('/api/artifacts',async(_req,res,next)=>{try{const metas=await listArtifacts();res.json({artifacts:metas.map((meta)=>({...meta,tokenHash:undefined,adminUrl:adminUrl(meta.slug)}))})}catch(error){next(error)}});
  app.get('/api/artifacts/:slug',async(req,res,next)=>{try{const meta=await readMeta(routeParam(req.params.slug));if(!meta)return res.status(404).json({error:'Artifact not found'});return res.json({artifact:{...meta,tokenHash:undefined,adminUrl:adminUrl(meta.slug)}})}catch(error){next(error)}});
  app.put('/api/artifacts/:slug/files{/*filePath}',express.raw({type:'*/*',limit:config.maxUploadBytes}),async(req,res,next)=>{try{const slug=safeSlug(routeParam(req.params.slug));if(!(await readMeta(slug)))return res.status(404).json({error:'Artifact not found'});const filePath=publicPathFromWildcard(req.params.filePath);if(!filePath)return res.status(400).json({error:'File path is required'});const dest=safeResolve(slug,filePath);await fs.mkdir(path.dirname(dest),{recursive:true});await fs.writeFile(dest,req.body);res.status(201).json({ok:true,path:filePath})}catch(error){next(error)}});
  app.post('/api/artifacts/:slug/files',async(req,res,next)=>{try{const slug=safeSlug(routeParam(req.params.slug));if(!(await readMeta(slug)))return res.status(404).json({error:'Artifact not found'});const contentType=req.get('content-type');if(!contentType)return res.status(400).json({error:'Multipart content-type is required'});const headers={...req.headers,'content-type':contentType} as BusboyHeaders;const busboy=Busboy({headers,limits:{files:1,fileSize:config.maxUploadBytes}});let targetPath='';let uploaded=false;const writes:Promise<void>[]=[];busboy.on('field',(name:string,value:string)=>{if(name==='path')targetPath=value});busboy.on('file',(_field:string,file:BusboyFileStream,filename:string)=>{uploaded=true;const dest=safeResolve(slug,targetPath||filename||'upload.bin');writes.push(fs.mkdir(path.dirname(dest),{recursive:true}).then(()=>new Promise<void>((resolve,reject)=>{const chunks:Buffer[]=[];file.on('data',(chunk:Buffer)=>chunks.push(Buffer.from(chunk)));file.on('limit',()=>reject(new Error('Upload exceeded MAX_UPLOAD_BYTES')));file.on('end',()=>fs.writeFile(dest,Buffer.concat(chunks)).then(resolve,reject));file.on('error',reject)})))});busboy.on('finish',async()=>{if(!uploaded)return res.status(400).json({error:'No file uploaded'});await Promise.all(writes);return res.status(201).json({ok:true})});busboy.on('error',next);req.pipe(busboy)}catch(error){next(error)}});

  app.get('/a/:slug/:token{/*artifactPath}',async(req,res,next)=>{try{artifactHeaders(res);const slug=safeSlug(routeParam(req.params.slug));const meta=await readMeta(slug);if(!meta||!(await verifyArtifactToken(meta,routeParam(req.params.token))))return res.status(404).send('Not found');const artifactPath=publicPathFromWildcard(req.params.artifactPath);await sendArtifactPath(req,res,{slug,requestPath:artifactPath,urlPrefix:`/a/${encodeURIComponent(slug)}/${encodeURIComponent(routeParam(req.params.token))}/${artifactPath}`,allowDirectoryListing:meta.allowDirectoryListing})}catch(error){next(error)}});
  app.use('/admin/files',requireAdmin);
  app.get('/admin/files{/*adminPath}',async(req,res,next)=>{try{const adminPath=publicPathFromWildcard(req.params.adminPath);const target=safeResolve(adminPath);const stat=await fs.stat(target);if(stat.isDirectory()){await renderDirectory(res,{title:`Artifacts /${adminPath}`,dirPath:target,urlPrefix:`/admin/files/${adminPath}`,showHidden:true});return}res.sendFile(target)}catch(error){next(error)}});
  app.get('/',(req,res)=>{if(req.hostname.toLowerCase()===config.artifactHostname)return res.redirect('/admin/files/');if(req.hostname.toLowerCase()!==config.appHostname)return res.status(404).send('Not found');const current=auth.getRequestSession(req);if(current?.row.kind==='full')return res.redirect(current.user.role==='admin'?'/admin':'/app/jobs');res.redirect('/login')});

  app.use((error:unknown,_req:Request,res:Response,_next:NextFunction)=>{const message=errorMessage(error);const status=error instanceof ActionError?error.status:error instanceof z.ZodError?400:message.includes('escapes artifact root')?400:message.includes('already exists')?409:500;if(error instanceof ActionError&&error.retryAfter)res.set('Retry-After',String(error.retryAfter));res.status(status).json({error:status>=500?'Internal error':message})});
  ensureRoot().catch(console.error);
  return app;
}
