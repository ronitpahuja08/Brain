import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { inspectComposeDockerSocketMounts, inspectComposeHostIpcMode, inspectComposeHostPidMode, inspectComposeNetworkMode, inspectComposePorts, inspectComposePrivileges, inspectEnv, isNonLocalBind, parseEnv, sortFindings } from './selfhost-preflight.mjs';
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
test('rejects unknown authentication modes before deployment', () => {
  assert(inspectEnv('AUTH_MODE=maybe').some(x=>x.code==='INVALID_AUTH_MODE'));
  assert(!inspectEnv('AUTH_MODE=single').some(x=>x.code==='INVALID_AUTH_MODE'));
});
test('flags wildcard CORS while allowing explicit local origins', () => {
  assert(inspectEnv('CORS_ORIGINS=*').some(x=>x.code==='WILDCARD_CORS'));
  assert(!inspectEnv('CORS_ORIGINS=http://localhost:3000,https://brain.example').some(x=>x.code==='WILDCARD_CORS'));
});
test('flags non-local HTTP CORS origins in production', () => {
  assert(inspectEnv('NODE_ENV=production\nCORS_ORIGINS=http://brain.example').some(x=>x.code==='INSECURE_CORS_ORIGIN'));
  assert(!inspectEnv('NODE_ENV=production\nCORS_ORIGINS=https://brain.example,http://localhost:3000').some(x=>x.code==='INSECURE_CORS_ORIGIN'));
});
test('requires a credentials encryption key in production', () => {
  const findings=inspectEnv('NODE_ENV=production\nDATABASE_URL=postgres://local');
  assert(findings.some(x=>x.code==='MISSING_CREDENTIALS_KEY'));
  assert(!inspectEnv('NODE_ENV=production\nDATABASE_URL=postgres://local\nCREDENTIALS_KEY='+'x'.repeat(32)).some(x=>x.code==='MISSING_CREDENTIALS_KEY'));
});
test('flags compose ports that are not bound to loopback', () => {
  assert.equal(inspectComposePorts('ports:\n  - "127.0.0.1:3000:3000"').length, 0);
  assert.equal(inspectComposePorts('ports:\n  - "3000:3000"\n  - "0.0.0.0:3333:3333"').filter(x=>x.code==='PUBLIC_CONTAINER_PORT').length, 2);
});
test('flags privileged Compose services', () => {
  const findings=inspectComposePrivileges('services:\n  worker:\n    privileged: true\n');
  assert.equal(findings[0]?.code, 'PRIVILEGED_CONTAINER');
  assert.equal(inspectComposePrivileges('privileged: false').length, 0);
});
test('flags Compose host networking', () => {
  assert.equal(inspectComposeNetworkMode('network_mode: host')[0]?.code, 'HOST_NETWORKING');
  assert.equal(inspectComposeNetworkMode('network_mode: bridge').length, 0);
});
test('flags Docker socket mounts in Compose', () => {
  assert.equal(inspectComposeDockerSocketMounts('volumes:\n  - /var/run/docker.sock:/var/run/docker.sock')[0]?.code, 'DOCKER_SOCKET_MOUNT');
  assert.equal(inspectComposeDockerSocketMounts('volumes:\n  - ./data:/data').length, 0);
});
test('flags Compose services that share the host PID namespace', () => {
  assert.equal(inspectComposeHostPidMode('pid: host')[0]?.code, 'HOST_PID_NAMESPACE');
  assert.equal(inspectComposeHostPidMode('pid: container:sidecar').length, 0);
});
test('flags Compose services that share the host IPC namespace', () => {
  assert.equal(inspectComposeHostIpcMode('ipc: host')[0]?.code, 'HOST_IPC_NAMESPACE');
  assert.equal(inspectComposeHostIpcMode('ipc: private').length, 0);
});
test('CLI combines private environment and Compose preflight findings', () => {
  const directory=mkdtempSync(join(tmpdir(), 'companybrain-preflight-'));
  try {
    const envPath=join(directory, '.env');
    const composePath=join(directory, 'compose.yml');
    writeFileSync(envPath, 'API_HOST=127.0.0.1\n');
    writeFileSync(composePath, 'ports:\n  - "3000:3000"\n');
    const result=spawnSync(process.execPath, ['tools/selfhost-preflight.mjs', envPath, '--compose', composePath], { encoding:'utf8' });
    assert.equal(result.status, 1);
    assert.match(result.stdout, /PUBLIC_CONTAINER_PORT/);
  } finally {
    rmSync(directory, { recursive:true, force:true });
  }
});
test('sorts findings by severity and then stable code', () => {
  const sorted=sortFindings([{ level:'high', code:'Z' }, { level:'critical', code:'B' }, { level:'high', code:'A' }]);
  assert.deepEqual(sorted.map(x=>x.code), ['B','A','Z']);
});
test('does not log or include secret values', () => {
  assert(!JSON.stringify(inspectEnv('ACCESS_TOKEN=supersecretvalue')).includes('supersecretvalue'));
});
