#!/usr/bin/env node
/**
 * Read-only security preflight for a self-hosted CompanyBrain deployment.
 * No keys are printed or transmitted.
 */
import { readFileSync } from 'node:fs';

export function parseEnv(text) {
  const env = {};
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const split = trimmed.indexOf('=');
    if (split < 1) continue;
    const key = trimmed.slice(0, split).trim();
    const value = trimmed.slice(split + 1).trim().replace(/^["']|["']$/g, '');
    env[key] = value;
  }
  return env;
}
export function isNonLocalBind(host) {
  return !['', '127.0.0.1', 'localhost', '::1', '[::1]'].includes((host || '').trim().toLowerCase());
}
export function inspectEnv(text) {
  const env = parseEnv(text);
  const findings = [];
  if (env.AUTH_MODE && !['single','multi'].includes(env.AUTH_MODE)) {
    findings.push({ level:'high', code:'INVALID_AUTH_MODE', message:'AUTH_MODE must be single or multi' });
  }
  if (isNonLocalBind(env.API_HOST || '127.0.0.1') && !env.ACCESS_TOKEN && (env.AUTH_MODE || 'single') !== 'multi') {
    findings.push({ level:'critical', code:'PUBLIC_API_NO_AUTH', message:'Public API binding without access token or multi-user authentication' });
  }
  const secretMinimumLengths = { JWT_SECRET:32, CREDENTIALS_KEY:32, ACCESS_TOKEN:16 };
  for (const key of ['JWT_SECRET','DATABASE_URL','ACCESS_TOKEN','CREDENTIALS_KEY']) {
    const value=env[key];
    if (value && /^(change.?me|your.?secret|example|placeholder|default|123456)$/i.test(value)) {
      findings.push({ level:'high', code:'PLACEHOLDER_SECRET', message:key+' uses a recognizable placeholder' });
    } else if (value && secretMinimumLengths[key] && value.length < secretMinimumLengths[key]) {
      findings.push({ level:'high', code:'WEAK_SECRET', message:key+' is shorter than the recommended minimum length' });
    }
  }
  if ((env.AUTH_MODE || 'single') === 'multi' && !env.JWT_SECRET) {
    findings.push({ level:'high', code:'MISSING_JWT_SECRET', message:'Multi-user mode requires a server-side JWT secret' });
  }
  if ((env.CORS_ORIGINS || '').split(',').map(origin=>origin.trim()).includes('*')) {
    findings.push({ level:'high', code:'WILDCARD_CORS', message:'CORS_ORIGINS permits every website; use explicit trusted origins' });
  }
  if (env.NODE_ENV === 'production' && (env.CORS_ORIGINS || '').split(',').some(origin=>origin.trim().startsWith('http://') && !origin.trim().includes('localhost'))) {
    findings.push({ level:'medium', code:'INSECURE_CORS_ORIGIN', message:'Production CORS origin uses HTTP; use HTTPS for non-local browser clients' });
  }
  if (env.NODE_ENV === 'production' && !env.DATABASE_URL) {
    findings.push({ level:'high', code:'MISSING_DATABASE_URL', message:'Production deployment requires a database URL' });
  }
  if (env.NODE_ENV === 'production' && !env.CREDENTIALS_KEY) {
    findings.push({ level:'high', code:'MISSING_CREDENTIALS_KEY', message:'Production deployment requires a credentials encryption key' });
  }
  return findings;
}
export function inspectComposePorts(text) {
  const findings=[];
  for (const line of text.split(/\r?\n/)) {
    const match=line.match(/^\s*-\s*["']?([^"'#]+)["']?\s*(?:#.*)?$/);
    if (!match) continue;
    const binding=match[1].trim();
    if (!/\d/.test(binding) || !binding.includes(':')) continue;
    if (binding.startsWith('127.0.0.1:') || binding.startsWith('localhost:') || binding.startsWith('[::1]:')) continue;
    findings.push({ level:'high', code:'PUBLIC_CONTAINER_PORT', message:'Container port is published without a loopback host binding' });
  }
  return findings;
}
export function inspectComposePrivileges(text) {
  const findings=[];
  for (const line of text.split(/\r?\n/)) {
    if (/^\s*privileged\s*:\s*true\s*(?:#.*)?$/i.test(line)) {
      findings.push({ level:'critical', code:'PRIVILEGED_CONTAINER', message:'Compose enables privileged container mode; remove it unless a documented host-level capability is required' });
    }
  }
  return findings;
}
export function inspectComposeNetworkMode(text) {
  const findings=[];
  for (const line of text.split(/\r?\n/)) {
    if (/^\s*network_mode\s*:\s*["']?host["']?\s*(?:#.*)?$/i.test(line)) {
      findings.push({ level:'high', code:'HOST_NETWORKING', message:'Compose service uses host networking and bypasses normal container network isolation' });
    }
  }
  return findings;
}
export function inspectComposeDockerSocketMounts(text) {
  const findings=[];
  for (const line of text.split(/\r?\n/)) {
    if (/^\s*-\s*["']?\/var\/run\/docker\.sock(?::|["']?\s*(?:#.*)?$)/i.test(line)) {
      findings.push({ level:'critical', code:'DOCKER_SOCKET_MOUNT', message:'Compose mounts the Docker socket, which grants the container effective host control' });
    }
  }
  return findings;
}
export function inspectComposeHostPidMode(text) {
  const findings=[];
  for (const line of text.split(/\r?\n/)) {
    if (/^\s*pid\s*:\s*["']?host["']?\s*(?:#.*)?$/i.test(line)) {
      findings.push({ level:'high', code:'HOST_PID_NAMESPACE', message:'Compose service shares the host PID namespace and can inspect host processes' });
    }
  }
  return findings;
}
export function inspectComposeHostIpcMode(text) {
  const findings=[];
  for (const line of text.split(/\r?\n/)) {
    if (/^\s*ipc\s*:\s*["']?host["']?\s*(?:#.*)?$/i.test(line)) {
      findings.push({ level:'high', code:'HOST_IPC_NAMESPACE', message:'Compose service shares the host IPC namespace and can access host inter-process communication resources' });
    }
  }
  return findings;
}
export function sortFindings(findings) {
  const priority={ critical:0, high:1, medium:2, low:3 };
  return [...findings].sort((left,right)=>(priority[left.level] ?? 9)-(priority[right.level] ?? 9) || left.code.localeCompare(right.code));
}
if (process.argv[1] && import.meta.url === new URL('file://' + process.argv[1]).href) {
  const [file, ...options]=process.argv.slice(2);
  if (!file) {
    console.error('Usage: node tools/selfhost-preflight.mjs /path/to/private/.env [--compose /path/to/docker-compose.yml]');
    process.exit(2);
  }
  try {
    let findings=inspectEnv(readFileSync(file,'utf8'));
    if (options.length) {
      if (options.length !== 2 || options[0] !== '--compose') throw new Error('invalid options');
      const composeText=readFileSync(options[1],'utf8');
      findings=findings.concat(inspectComposePorts(composeText), inspectComposePrivileges(composeText), inspectComposeNetworkMode(composeText), inspectComposeDockerSocketMounts(composeText), inspectComposeHostPidMode(composeText), inspectComposeHostIpcMode(composeText));
    }
    findings=sortFindings(findings);
    console.log(JSON.stringify({ result:findings.length ? 'review_required' : 'no_findings', findings },null,2));
    process.exitCode=findings.length ? 1 : 0;
  } catch {
    console.error('Unable to read local configuration. No credentials were displayed.');
    process.exitCode=2;
  }
}
