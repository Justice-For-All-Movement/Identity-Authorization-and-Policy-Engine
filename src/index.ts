import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import type { Actor, Context, Scope } from './contracts.ts';
import { canonical, invariant, nonempty, requireScope, validTime } from './contracts.ts';
export const ACTIONS=['read','investigate','process','draft','manage_agents','contact','release','admin'] as const;
export type Action=(typeof ACTIONS)[number];
const roleActions:Record<string,readonly Action[]>={viewer:['read'],researcher:['read','investigate','process','draft'],operator:['read','investigate','process','draft','manage_agents'],owner:ACTIONS};
export interface Identity extends Scope {actor:Actor;tokenHash:string;disabled:boolean;epoch:number;}
function object(value:unknown):value is Record<string,unknown>{return value!==null&&typeof value==='object'&&!Array.isArray(value);}
function identifier(value:unknown):value is string{return typeof value==='string'&&value.trim().length>0&&value.length<=128;}
function positiveInteger(value:unknown):value is number{return Number.isSafeInteger(value)&&(value as number)>0;}
function nonnegativeInteger(value:unknown):value is number{return Number.isSafeInteger(value)&&(value as number)>=0;}
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
const CAPABILITY_FIELDS=['tenantId','projectId','id','actorId','action','purpose','resourceIds','policyRevision','actorEpoch','notBefore','expiresAt'] as const;
const EXPECTED_FIELDS=['action','resourceId','policyRevision','actorEpoch','revokedIds'] as const;
function validateCapability(value:unknown,code='invalid_capability'):asserts value is Capability{
 invariant(object(value)&&Object.keys(value).every(key=>(CAPABILITY_FIELDS as readonly string[]).includes(key))&&Object.keys(value).length===CAPABILITY_FIELDS.length,code,'Capability schema is invalid');
 invariant(identifier(value.tenantId)&&identifier(value.projectId)&&identifier(value.id)&&identifier(value.actorId),code,'Capability identifiers are invalid');
 invariant((ACTIONS as readonly unknown[]).includes(value.action)&&identifier(value.purpose),code,'Capability action or purpose is invalid');
 invariant(Array.isArray(value.resourceIds)&&value.resourceIds.length>0&&value.resourceIds.length<=256&&value.resourceIds.every(identifier)&&new Set(value.resourceIds).size===value.resourceIds.length,code,'Capability resources are invalid');
 invariant(positiveInteger(value.policyRevision)&&nonnegativeInteger(value.actorEpoch),code,'Capability revisions are invalid');
 const notBeforeValue=value.notBefore,expiresAtValue=value.expiresAt;
 invariant(identifier(notBeforeValue)&&identifier(expiresAtValue),code,'Capability validity timestamps are invalid');
 const notBefore=validTime(notBeforeValue),expiresAt=validTime(expiresAtValue);
 invariant(expiresAt>notBefore&&expiresAt-notBefore<=3600000,code,'Capability duration is at most 1 hour');
}
function validateExpected(value:unknown):asserts value is {action:Action;resourceId:string;policyRevision:number;actorEpoch:number;revokedIds:readonly string[]}{
 invariant(object(value)&&Object.keys(value).every(key=>(EXPECTED_FIELDS as readonly string[]).includes(key))&&Object.keys(value).length===EXPECTED_FIELDS.length,'invalid_capability','Expected capability schema is invalid');
 invariant((ACTIONS as readonly unknown[]).includes(value.action)&&identifier(value.resourceId),'invalid_capability','Expected capability scope is invalid');
 invariant(positiveInteger(value.policyRevision)&&nonnegativeInteger(value.actorEpoch),'invalid_capability','Expected capability revisions are invalid');
 invariant(Array.isArray(value.revokedIds)&&value.revokedIds.length<=10000&&value.revokedIds.every(identifier),'invalid_capability','Capability revocations are invalid');
}
function validateKey(secret:unknown):asserts secret is Uint8Array{
 invariant(secret instanceof Uint8Array&&secret.length>=32,'invalid_key','Signing key must be at least 32 bytes');
}
export function issueCapability(ctx:Context,cap:Capability,secret:Uint8Array):string{
 validateCapability(cap,'invalid_capability');validateKey(secret);authorize(ctx,'admin',cap);
 const payload=Buffer.from(canonical(cap)).toString('base64url');return payload+'.'+createHmac('sha256',secret).update(payload).digest('base64url');
}
export function verifyCapability(token:string,ctx:Context,expected:{action:Action;resourceId:string;policyRevision:number;actorEpoch:number;revokedIds:readonly string[]},secret:Uint8Array):Capability{
 validateKey(secret);validateExpected(expected);invariant(typeof token==='string'&&token.length>0&&token.length<10000,'invalid_capability','Invalid capability');const [payload,signature,...extra]=token.split('.');invariant(payload&&signature&&extra.length===0&&/^[A-Za-z0-9_-]{43}$/.test(signature),'invalid_capability','Malformed capability');
 const got=Buffer.from(signature,'base64url');const want=createHmac('sha256',secret).update(payload).digest();invariant(got.length===want.length&&timingSafeEqual(got,want),'invalid_capability','Signature mismatch');
 let parsed:unknown;try{parsed=JSON.parse(Buffer.from(payload,'base64url').toString('utf8'));}catch{invariant(false,'invalid_capability','Invalid capability encoding');}
 validateCapability(parsed);const cap=parsed;invariant(Buffer.from(canonical(cap)).toString('base64url')===payload,'invalid_capability','Capability encoding is not canonical');
 requireScope(ctx,cap);const now=validTime(ctx.now);
 invariant(cap.actorId===ctx.actor.id&&cap.action===expected.action&&cap.purpose===ctx.purpose,'invalid_capability','Capability audience or purpose mismatch');
 invariant(cap.policyRevision===expected.policyRevision&&cap.actorEpoch===expected.actorEpoch&&!expected.revokedIds.includes(cap.id),'revoked_capability','Capability revoked or stale');
 invariant(now>=validTime(cap.notBefore)&&now<validTime(cap.expiresAt),'expired_capability','Capability outside validity window');
 invariant(cap.resourceIds.includes(expected.resourceId),'invalid_capability','Resource outside capability scope');return structuredClone(cap);
}

