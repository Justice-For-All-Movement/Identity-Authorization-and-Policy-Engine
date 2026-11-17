// Deployment acceptance against the standalone server over real sockets: the opt-in live-verification script
// (public and signed-in checks), the new HTTP routes, and password-reset delivery through the signed webhook.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import { withDisposableDatabase } from '../src/service-kit.ts';
import { start } from '../src/engine/serve.ts';
import { ADMIN_URL, PASSWORD, needsPg } from './engine-fixture.ts';

const SCRIPT = fileURLToPath(new URL('../scripts/live-verify.mjs', import.meta.url));
const runScript = (env: Record<string, string>): Promise<{ code: number; out: string }> => new Promise((resolve) => {
  execFile(process.execPath, [SCRIPT], { env: { PATH: process.env.PATH ?? '', ...env }, timeout: 120000 }, (error, stdout) => resolve({ code: error === null ? 0 : Number((error as { code?: number }).code ?? 1), out: stdout }));
});

test('live-verification script skips without a target and passes against a fresh deployment', needsPg, async () => {
  const skipped = await runScript({});
  assert.equal(skipped.code, 0); assert.equal(JSON.parse(skipped.out).skipped, true);
  const mail: { body: string }[] = [];
  const mailer = createServer((req, res) => { let body = ''; req.on('data', (c) => { body += c; }); req.on('end', () => { mail.push({ body }); res.writeHead(202).end(); }); });
  await new Promise<void>((r) => mailer.listen(0, '127.0.0.1', r));
  try {
  await withDisposableDatabase(pg, ADMIN_URL, async (url) => {
    const served = await start({ DATABASE_URL: url, PORT: '0', IDENTITY_KEY_ENCRYPTION_KEY: 'deploy-fixture-key-encryption-key-0123456789', IDENTITY_BOOTSTRAP_TOKEN: 'deploy-bootstrap-token', IDENTITY_ISSUER: 'identity.deploy.test',
      IDENTITY_PASSWORD_RESET_WEBHOOK_URL: `http://127.0.0.1:${(mailer.address() as AddressInfo).port}/mail`, IDENTITY_PASSWORD_RESET_WEBHOOK_SECRET: 'deploy-fixture-webhook-secret-0123456789' });
    const base = `http://127.0.0.1:${served.port}`;
    const call = async (method: string, path: string, body?: unknown, token?: string): Promise<{ status: number; json: any }> => {
      const res = await fetch(`${base}${path}`, { method, headers: { ...(body === undefined ? {} : { 'content-type': 'application/json' }), ...(token === undefined ? {} : { authorization: `Bearer ${token}` }) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
      const text = await res.text(); let json: unknown = null; try { json = JSON.parse(text); } catch { /* not JSON */ }
      return { status: res.status, json };
    };
    try {
      const env = { IDENTITY_LIVE_BASE_URL: base, IDENTITY_LIVE_ALLOW_HTTP: 'true', IDENTITY_LIVE_EXPECT_ISSUER: 'identity.deploy.test' };
      // Before bootstrap the deployment is not accepted.
      const early = await runScript(env);
      assert.equal(early.code, 1);
      assert.ok(JSON.parse(early.out).checks.some((c: { name: string; ok: boolean }) => c.name === 'deployment is bootstrapped' && !c.ok));
      assert.equal((await call('POST', '/v1/bootstrap', { login: 'ada@example.org', password: PASSWORD, displayName: 'Ada Example', bootstrapToken: 'deploy-bootstrap-token', organization: { id: 'org-a', name: 'Alder Collective', project: { id: 'main', name: 'Main' } } })).status, 200);
      // HTTPS is required unless explicitly allowed for a loopback target.
      assert.equal((await runScript({ IDENTITY_LIVE_BASE_URL: base })).code, 1);
      const full = await runScript({ ...env, IDENTITY_LIVE_LOGIN: 'ada@example.org', IDENTITY_LIVE_PASSWORD: PASSWORD });
      const report = JSON.parse(full.out);
      assert.equal(full.code, 0, JSON.stringify(report.checks.filter((c: { ok: boolean }) => !c.ok)));
      assert.ok(report.passed >= 30, `passed ${report.passed}`);
      assert.doesNotMatch(full.out, /eyJ|refreshToken|correct horse/);
      for (const name of ['token verifies offline against the published keys', 'revoked token is refused within the cache window', 'who-can-access view answers', 'ended session cannot issue tokens'])
        assert.ok(report.checks.some((c: { name: string; ok: boolean }) => c.name === name && c.ok), name);
      assert.equal((await runScript({ ...env, IDENTITY_LIVE_LOGIN: 'ada@example.org', IDENTITY_LIVE_PASSWORD: 'wrong password entirely' })).code, 1);

      // New routes over HTTP: invitations (admin → public accept), rate limits, revocation impact, password reset.
      const session = (await call('POST', '/v1/sessions', { login: 'ada@example.org', password: PASSWORD })).json;
      const admin = (await call('POST', '/v1/tokens', { refreshToken: session.refreshToken, tenantId: 'org-a', projectId: 'main', purpose: 'administration' })).json.token as string;
      assert.equal((await call('POST', '/v1/invitations', { roles: ['investigator'] })).status, 401);
      const inv = await call('POST', '/v1/invitations', { roles: ['investigator'], displayName: 'Nia Example' }, admin);
      assert.equal(inv.status, 200);
      assert.equal((await call('GET', '/v1/invitations', undefined, admin)).json.length, 1);
      const accepted = await call('POST', '/v1/invitations/accept', { token: inv.json.token, login: 'nia@example.org', password: PASSWORD });
      assert.equal(accepted.status, 200); assert.deepEqual(accepted.json.roles, ['investigator']);
      assert.equal((await call('POST', '/v1/invitations/accept', { token: inv.json.token, login: 'nia2@example.org', password: PASSWORD })).status, 401);
      const impact = await call('GET', `/v1/access/revocation-impact?actorId=${accepted.json.actorId as string}`, undefined, admin);
      assert.equal(impact.status, 200); assert.equal(impact.json.activeSessions, 1);
      const metered = await call('POST', '/v1/rate-limits/consume', { key: 'probe', limit: 1, windowSeconds: 60 }, admin);
      assert.equal(metered.json.allowed, true);
      assert.equal((await call('POST', '/v1/rate-limits/consume', { key: 'probe', limit: 1, windowSeconds: 60 }, admin)).json.allowed, false);
      assert.equal((await call('GET', '/v1/rate-limits?key=probe', undefined, admin)).json.used, 1);
      assert.deepEqual((await call('POST', '/v1/password-resets', { login: 'nia@example.org' })).json, { accepted: true });
      const until = Date.now() + 5000;
      while (mail.length === 0 && Date.now() < until) await new Promise((r) => setTimeout(r, 20));
      const delivered = JSON.parse(mail[0]?.body ?? '{}');
      assert.equal(delivered.login, 'nia@example.org');
      assert.equal((await call('POST', '/v1/password-resets/complete', { token: delivered.token, newPassword: 'a brand new long passphrase' })).status, 200);
      assert.equal((await call('POST', '/v1/sessions', { login: 'nia@example.org', password: 'a brand new long passphrase' })).status, 200);
      assert.equal((await call('GET', '/v1/manifest')).json.version, '1.1.0');
    } finally { await served.close(); }
  });
  } finally { mailer.closeAllConnections(); await new Promise<void>((r) => mailer.close(() => r())); }
});
