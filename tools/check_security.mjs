// Bounded negative tests. Run against an isolated production-mode replica.
// Token files and certificate fixture are local operator inputs; never printed.
import {readFile, writeFile} from 'node:fs/promises';
const origin = new URL(process.env.GATEWAY_SECURITY_URL || 'http://127.0.0.1:18083');
if (!['127.0.0.1', '[::1]', 'localhost'].includes(origin.hostname) || origin.protocol !== 'http:' || origin.username || origin.password || origin.pathname !== '/' || origin.search || origin.hash) throw Error('Use an isolated loopback HTTP origin');
const secret = async name => (await readFile(process.env[name], 'utf8')).trim();
const operator = await secret('GATEWAY_TEST_TOKEN_FILE');
const relay = await secret('GATEWAY_RELAY_TOKEN_FILE');
const retired = await secret('GATEWAY_RETIRED_TOKEN_FILE');
const {certificate} = JSON.parse(await readFile(process.env.GATEWAY_CANARY_FILE, 'utf8'));
const results = [];
async function check(name, path, {token, method = 'GET', body, expected, verify} = {}) {
  const headers = {'Content-Type': 'application/json'};
  if (token) headers.Authorization = `Bearer ${token}`;
  const response = await fetch(new URL(path, origin), {method, headers, body: typeof body === 'string' ? body : body === undefined ? undefined : JSON.stringify(body), redirect: 'error', signal: AbortSignal.timeout(10000)});
  const text = await response.text();
  const pass = response.status === expected && ![operator, relay, retired].some(s => text.includes(s)) && (!verify || verify(text, response));
  results.push({name, status: response.status, expected, pass});
}
await check('protected networks require authentication', '/v1/networks', {expected: 401});
await check('retired credential rejected', '/v1/networks', {token: retired, expected: 401});
await check('invalid credential rejected', '/v1/networks', {token: 'invalid-security-probe', expected: 401});
await check('operator access retained', '/v1/networks', {token: operator, expected: 200});
await check('relay cannot read metrics', '/metrics', {token: relay, expected: 403});
await check('production key generation unavailable', '/keygen', {token: operator, method: 'POST', body: {}, expected: 404});
await check('production issuance unavailable', '/issue', {token: operator, method: 'POST', body: {}, expected: 404});
await check('wrong verification method', '/verify', {token: operator, expected: 405});
await check('malformed JSON rejected', '/verify', {token: operator, method: 'POST', body: '{', expected: 400});
await check('oversized body rejected', '/verify', {token: operator, method: 'POST', body: ' '.repeat(1048577), expected: 413});
await check('empty batch rejected', '/verify/batch', {token: operator, method: 'POST', body: {certificates: []}, expected: 400});
await check('caller trust anchor override rejected', '/verify', {token: operator, method: 'POST', body: {certificate, anchors: {'attacker': certificate.node_public_key}}, expected: 400});
await check('cross-network verification rejected', '/verify', {token: operator, method: 'POST', body: {certificate: {...certificate, network_name: 'not-authorized'}}, expected: 403});
await check('revocation survives restored state', '/verify', {token: operator, method: 'POST', body: {certificate}, expected: 200, verify: text => { const d = JSON.parse(text); return d.trusted === false && JSON.stringify(d.reasons).includes('Revoked'); }});
await check('forged signature rejected', '/verify', {token: operator, method: 'POST', body: {certificate: {...certificate, cert_id: 'security-forgery', signatures: certificate.signatures.map(s => ({...s, sig: Buffer.alloc(64).toString('base64')}))}}, expected: 200, verify: text => JSON.parse(text).trusted === false});
await check('unknown proxy operation rejected', '/v1/networks/authority-a/services/https%3A%2F%2Fexample.com', {token: operator, expected: 404});
await check('browser defense headers', '/', {expected: 200, verify: (_, r) => r.headers.get('x-content-type-options') === 'nosniff' && r.headers.get('cache-control') === 'no-store' && r.headers.get('cross-origin-embedder-policy') === 'require-corp' && r.headers.has('permissions-policy') && r.headers.get('content-security-policy')?.includes("frame-ancestors 'none'")});
const report = {checked_at: new Date().toISOString(), origin: origin.origin, results};
if (process.env.GATEWAY_SECURITY_REPORT) await writeFile(process.env.GATEWAY_SECURITY_REPORT, JSON.stringify(report, null, 2));
console.log(JSON.stringify(report, null, 2));
if (results.some(r => !r.pass)) process.exitCode = 1;
