import test from 'node:test';
import assert from 'node:assert/strict';
import {authenticate, authorize, tokenHash} from '../src/index.ts';
import type {Identity} from '../src/index.ts';
import type {Context} from '../src/contracts.ts';

const context: Context = {tenantId:'alpha', projectId:'study', actor:{id:'operator', kind:'human', roles:['owner']}, purpose:'research', requestId:'request', now:'2026-01-01T00:00:00Z'};
const token = 'synthetic-token-with-at-least-thirty-two-characters';
const identity: Identity = {tenantId:'alpha', projectId:'study', actor:context.actor, tokenHash:tokenHash(token), disabled:false, epoch:0};

test('role authorization rejects unknown actor kinds and empty scoped identifiers at runtime', () => {
  const malformed: unknown[] = [
    {...context, tenantId:''}, {...context, projectId:' '},
    {...context, actor:{...context.actor, id:''}},
    {...context, actor:{...context.actor, kind:'robot'}},
    {...context, actor:{...context.actor, roles:'owner'}},
    {...context, actor:{...context.actor, roles:['owner', 7]}},
    {...context, actor:{...context.actor, roles:Array(33).fill('owner')}},
  ];
  for (const value of malformed) assert.throws(() => authorize(value as Context, 'read'));
  authorize({...context, actor:{id:'service', kind:'service', roles:['viewer']}}, 'read');
  authorize({...context, actor:{id:'agent', kind:'agent', roles:['operator']}}, 'manage_agents');
  assert.throws(() => authorize({...context, actor:{id:'agent', kind:'agent', roles:['owner']}}, 'admin'), {code:'human_authority_required'});
});

test('credential authentication requires explicitly enabled well-formed scoped identities', () => {
  const malformed: unknown[] = [
    {...identity, tenantId:''}, {...identity, projectId:' '},
    {...identity, actor:{...identity.actor, id:''}},
    {...identity, actor:{...identity.actor, kind:'robot'}},
    {...identity, actor:{...identity.actor, roles:'owner'}},
    {...identity, epoch:-1}, {...identity, epoch:0.5},
    {...identity, epoch:Number.MAX_SAFE_INTEGER + 1},
    {...identity, disabled:undefined}, {...identity, disabled:0},
  ];
  for (const value of malformed) assert.throws(() => authenticate(token, [value as Identity]), {code:'unauthenticated'});
  const result = authenticate(token, [identity]);
  assert.equal(result.epoch, 0);
  assert.deepEqual(result.actor, identity.actor);
  assert.notEqual(result.actor, identity.actor);
});

test('one credential cannot ambiguously select among enabled identities across scopes or principals', () => {
  for (const other of [identity, {...identity, tenantId:'other'}, {...identity, actor:{...identity.actor, id:'other'}}]) {
    assert.throws(() => authenticate(token, [identity, other]), {code:'unauthenticated'});
    assert.throws(() => authenticate(token, [other, identity]), {code:'unauthenticated'});
  }
  assert.deepEqual(authenticate(token, [identity, {...identity, disabled:true}]), identity);
});
