// Read-only authenticated gateway probe. Credentials are read from a local file.
import {readFile} from 'node:fs/promises';
import {performance} from 'node:perf_hooks';
const urls = (process.env.GATEWAY_TEST_URLS || 'http://127.0.0.1:8080').split(',').map(s => new URL(s));
if (urls.some(u => !['http:', 'https:'].includes(u.protocol) || u.username || u.password || u.search || u.hash || u.pathname !== '/')) throw Error('Use gateway origins without credentials');
const token = (await readFile(process.env.GATEWAY_TEST_TOKEN_FILE, 'utf8')).trim();
const count = Number(process.env.GATEWAY_TEST_REQUESTS || 100);
const concurrency = Number(process.env.GATEWAY_TEST_CONCURRENCY || 4);
const budget = Number(process.env.GATEWAY_TEST_P99_MS || 500);
if (![count, concurrency, budget].every(Number.isFinite) || count < 1 || count > 10000 || concurrency < 1 || concurrency > 32) throw Error('Invalid workload bounds');
let cursor = 0;
const samples = [], status = {};
for (const origin of urls) {
  const response = await fetch(new URL('/ready', origin), {signal: AbortSignal.timeout(5000)});
  if (!response.ok) throw Error('A replica is not ready before the run');
}
await Promise.all(Array.from({length: concurrency}, async () => {
  while (cursor < count) {
    const index = cursor++;
    const start = performance.now();
    let code = 'transport_error';
    try {
      const response = await fetch(new URL('/v1/networks', urls[index % urls.length]), {headers: {Authorization: 'Bearer ' + token}, redirect: 'error', signal: AbortSignal.timeout(10000)});
      const body = await response.json();
      code = String(response.status);
      if (response.ok && (!Array.isArray(body.networks) || !body.networks.every(n => n.ready))) code = 'invalid_snapshot';
    } catch { /* Count failures without printing credentials or server bodies. */ }
    status[code] = (status[code] || 0) + 1;
    samples.push(performance.now() - start);
  }
}));
samples.sort((a,b) => a-b);
const percentile = n => Math.round(samples[Math.min(samples.length-1, Math.ceil(samples.length*n)-1)] * 100) / 100;
const result = {replicas: urls.length, requests: count, concurrency, status, p50_ms: percentile(.5), p95_ms: percentile(.95), p99_ms: percentile(.99), budget_ms: budget};
console.log(JSON.stringify(result, null, 2));
if (status['200'] !== count || result.p99_ms > budget) process.exitCode = 1;
