import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import type { Actor, Context, Scope } from './contracts.ts';
import { canonical, invariant, nonempty, requireScope, validTime } from './contracts.ts';
export const ACTIONS=['read','investigate','process','draft','manage_agents','contact','release','admin'] as const;
export type Action=(typeof ACTIONS)[number];
const roleActions:Record<string,readonly Action[]>={viewer:['read'],researcher:['read','investigate','process','draft'],operator:['read','investigate','process','draft','manage_agents'],owner:ACTIONS};
export interface Identity extends Scope {actor:Actor;tokenHash:string;disabled:boolean;epoch:number;}
function object(value:unknown):value is Record<string,unknown>{return value!==null&&typeof value==='object'&&!Array.isArray(value);}
function identifier(value:unknown):value is string{return typeof value==='string'&&value.trim().length>0&&value.length<=128;}
function scoped(value:unknown):boolean{return object(value)&&identifier(value.tenantId)&&identifier(value.projectId);}
function scopedActor(value:unknown):boolean{
 if(!scoped(value)||!object(value)||!object(value.actor))return false;
 const actor=value.actor;
 return identifier(actor.id)&&['human','agent','service'].includes(actor.kind as string)&&Array.isArray(actor.roles)&&actor.roles.length<=32&&actor.roles.every(identifier);
}
export function tokenHash(token:string):string{return createHash('sha256').update(token).digest('hex');}
export function authenticate(token:string,identities:readonly Identity[]):Identity{
 invariant(typeof token==='string'&&token.length>=32&&token.length<=512&&Array.isArray(identities),'unauthenticated','Valid credentials required');const hash=Buffer.from(tokenHash(token),'hex');
 const matches=identities.filter(i=>object(i)&&i.disabled===false&&typeof i.tokenHash==='string'&&/^[a-f0-9]{64}$/.test(i.tokenHash)&&timingSafeEqual(hash,Buffer.from(i.tokenHash,'hex')));
 const id=matches[0];
 invariant(matches.length===1&&id&&scopedActor(id)&&Number.isSafeInteger(id.epoch)&&id.epoch>=0,'unauthenticated','Valid credentials required');return structuredClone(id);
}
export function authorize(ctx:Context, action:Action, resource:Scope=ctx):void {
 invariant(scopedActor(ctx),'invalid_identity','A valid scoped actor is required');invariant(scoped(resource),'invalid_scope','A valid resource scope is required');
 requireScope(ctx,resource);nonempty(ctx.purpose,'purpose',200);
 invariant(ctx.actor.roles.some(r=>Object.hasOwn(roleActions,r)&&roleActions[r]!.includes(action)),'forbidden','This action requires an authorized role');
 if(action==='release'||action==='admin') invariant(ctx.actor.kind==='human','human_authority_required','A human identity is required');
}
export type Capability = Scope & {id:string;actorId:string;action:Action;purpose:string;resourceIds:string[];policyRevision:number;actorEpoch:number;notBefore:string;expiresAt:string;};
export function issueCapability(ctx:Context,cap:Capability,secret:Uint8Array):string{
 authorize(ctx,'admin',cap);invariant(secret.length>=32,'invalid_key','Signing key must be at least32bytes');
 invariant(validTime(cap.expiresAt)>validTime(cap.notBefore)&&validTime(cap.expiresAt)-validTime(cap.notBefore)<=3600000,'invalid_expiry','Capability duration is at most1hour');
 const payload=Buffer.from(canonical(cap)).toString('base64url');return payload+'.'+createHmac('sha256',secret).update(payload).digest('base64url');
}
export function verifyCapability(token:string,ctx:Context,expected:{action:Action;resourceId:string;policyRevision:number;actorEpoch:number;revokedIds:readonly string[]},secret:Uint8Array):Capability{
 invariant(secret.length>=32&&token.length<10000,'invalid_capability','Invalid capability');const [payload,signature,...extra]=token.split('.');invariant(payload&&signature&&extra.length===0,'invalid_capability','Malformed capability');
 const got=Buffer.from(signature,'base64url');const want=createHmac('sha256',secret).update(payload).digest();invariant(got.length===want.length&&timingSafeEqual(got,want),'invalid_capability','Signature mismatch');
 let cap:Capability;try{cap=JSON.parse(Buffer.from(payload,'base64url').toString()) as Capability;}catch{throw new Error('Invalid capability encoding');}
 requireScope(ctx,cap);const now=validTime(ctx.now);
 invariant(cap.actorId===ctx.actor.id&&cap.action===expected.action&&cap.purpose===ctx.purpose,'invalid_capability','Capability audience or purpose mismatch');
 invariant(cap.policyRevision===expected.policyRevision&&cap.actorEpoch===expected.actorEpoch&&!expected.revokedIds.includes(cap.id),'revoked_capability','Capability revoked or stale');
 invariant(now>=validTime(cap.notBefore)&&now<validTime(cap.expiresAt),'expired_capability','Capability outside validity window');
 invariant(Array.isArray(cap.resourceIds)&&cap.resourceIds.includes(expected.resourceId),'invalid_capability','Resource outside capability scope');return cap;
}
