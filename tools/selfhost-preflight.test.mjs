import test from 'node:test';
import assert from 'node:assert/strict';
import { inspectEnv, isNonLocalBind, parseEnv } from './selfhost-preflight.mjs';
test('parses quoted values and ignores comment lines', () => {
  assert.deepEqual(parseEnv('# comment\nAPI_HOST="0.0.0.0"\nACCESS_TOKEN=demo'), { API_HOST:'0.0.0.0', ACCESS_TOKEN:'demo' });
});
test('detects publicly bound unauthenticated API', () => {
  assert(inspectEnv('API_HOST=0.0.0.0\nAUTH_MODE=single').some(x=>x.code==='PUBLIC_API_NO_AUTH'));
});
test('treats every non-loopback explicit bind as externally reachable', () => {
  for (const host of ['0.0.0.0', '::', '[::]', '192.168.1.10']) assert.equal(isNonLocalBind(host), true);
  for (const host of ['', 'localhost', '127.0.0.1', '::1', '[::1]']) assert.equal(isNonLocalBind(host), false);
});
test('allows authenticated public API', () => {
  assert(!inspectEnv('API_HOST=0.0.0.0\nACCESS_TOKEN=long-unique-secret').some(x=>x.code==='PUBLIC_API_NO_AUTH'));
});
test('detects unsafe placeholders', () => {
  assert(inspectEnv('JWT_SECRET=changeme').some(x=>x.code==='PLACEHOLDER_SECRET'));
});
test('detects configured secrets that are too short without leaking values', () => {
  const findings=inspectEnv('JWT_SECRET=jellyfish42\nACCESS_TOKEN=beetle8');
  assert.equal(findings.filter(x=>x.code==='WEAK_SECRET').length, 2);
  assert(!JSON.stringify(findings).includes('jellyfish42'));
  assert(!JSON.stringify(findings).includes('beetle8'));
});
test('checks multi-user JWT', () => {
  assert(inspectEnv('AUTH_MODE=multi').some(x=>x.code==='MISSING_JWT_SECRET'));
});
test('flags wildcard CORS while allowing explicit local origins', () => {
  assert(inspectEnv('CORS_ORIGINS=*').some(x=>x.code==='WILDCARD_CORS'));
  assert(!inspectEnv('CORS_ORIGINS=http://localhost:3000,https://brain.example').some(x=>x.code==='WILDCARD_CORS'));
});
test('requires a credentials encryption key in production', () => {
  const findings=inspectEnv('NODE_ENV=production\nDATABASE_URL=postgres://local');
  assert(findings.some(x=>x.code==='MISSING_CREDENTIALS_KEY'));
  assert(!inspectEnv('NODE_ENV=production\nDATABASE_URL=postgres://local\nCREDENTIALS_KEY='+'x'.repeat(32)).some(x=>x.code==='MISSING_CREDENTIALS_KEY'));
});
test('does not log or include secret values', () => {
  assert(!JSON.stringify(inspectEnv('ACCESS_TOKEN=supersecretvalue')).includes('supersecretvalue'));
});
