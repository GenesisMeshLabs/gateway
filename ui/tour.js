// Demo access and guided scenarios (v0.65). Everything here runs with the
// public demo token, which the gateway limits to read and verify operations.
const $ = id => document.getElementById(id);
const el = (tag, text, cls) => { const n = document.createElement(tag); if (text !== undefined) n.textContent = text; if (cls) n.className = cls; return n; };
let demo = null, catalog = null, network = null;

async function getJson(path, options = {}) {
  const response = await fetch(path, { cache: 'no-store', credentials: 'omit', redirect: 'error', signal: AbortSignal.timeout(20000), ...options });
  const text = await response.text();
  let data; try { data = JSON.parse(text); } catch { data = text; }
  if (!response.ok) throw new Error((data && (data.error?.message || data.error || data.message)) || 'HTTP ' + response.status);
  return data;
}

async function demoAccess() {
  if (demo) return demo;
  const data = await getJson('/v1/demo');
  if (!data.available || !data.clients.length) throw new Error('Demo access is not enabled on this gateway.');
  demo = data.clients[0];
  return demo;
}

async function operation(method, upstreamPath) {
  catalog ??= (await getJson('/v1/services')).operations;
  const op = catalog.find(o => o.method === method && o.upstream_path === upstreamPath);
  if (!op) throw new Error('Operation not in this gateway catalog: ' + method + ' ' + upstreamPath);
  return op;
}

async function service(net, method, upstreamPath, { query = {}, body } = {}) {
  const access = await demoAccess();
  const op = await operation(method, upstreamPath);
  const params = new URLSearchParams(query);
  const path = '/v1/networks/' + encodeURIComponent(net) + '/services/' + op.id + (params.size ? '?' + params : '');
  const headers = { Authorization: 'Bearer ' + access.token };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  return getJson(path, { method, headers, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
}

async function demoData(name) {
  return getJson('/demo-data/' + name);
}

async function context() {
  network ??= await demoData('network.json');
  return network;
}

// ── Canonical JSON (Python json.dumps(sort_keys=True, separators=(",", ":"))) ──
// Parsed with number lexemes preserved so floats re-serialize as Python writes them.
function parsePreserving(text) {
  let i = 0;
  const ws = () => { while (' \t\n\r'.includes(text[i])) i++; };
  function value() {
    ws();
    const c = text[i];
    if (c === '{') { i++; const out = {}; ws(); if (text[i] === '}') { i++; return out; }
      for (;;) { ws(); const k = string(); ws(); i++; out[k] = value(); ws(); if (text[i++] === '}') return out; } }
    if (c === '[') { i++; const out = []; ws(); if (text[i] === ']') { i++; return out; }
      for (;;) { out.push(value()); ws(); if (text[i++] === ']') return out; } }
    if (c === '"') return string();
    if (text.startsWith('true', i)) { i += 4; return true; }
    if (text.startsWith('false', i)) { i += 5; return false; }
    if (text.startsWith('null', i)) { i += 4; return null; }
    const m = /^-?\d+(\.\d+)?([eE][+-]?\d+)?/.exec(text.slice(i));
    if (!m) throw new Error('invalid JSON at ' + i);
    i += m[0].length;
    return m[1] || m[2] ? { float: Number(m[0]) } : { int: m[0] };
  }
  function string() { const start = i; i++; while (text[i] !== '"') i += text[i] === '\\' ? 2 : 1; i++; return JSON.parse(text.slice(start, i)); }
  const result = value(); ws();
  if (i !== text.length) throw new Error('trailing data');
  return result;
}

function pythonFloat(v) {
  if (!Number.isFinite(v)) throw new Error('non-finite number');
  if (Object.is(v, -0)) return '-0.0';
  if (Number.isInteger(v) && Math.abs(v) < 1e16) return v.toFixed(1);
  const [mantissa, exp] = v.toExponential().split('e');
  const e = Number(exp);
  if (e < -4 || e >= 16) return mantissa + 'e' + (e < 0 ? '-' : '+') + String(Math.abs(e)).padStart(2, '0');
  return String(v);
}

function canonical(v) {
  if (v === null || typeof v === 'boolean') return JSON.stringify(v);
  if (typeof v === 'string') return JSON.stringify(v).replace(/[\u007f-￿]/g, c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
  if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
  if ('int' in v && Object.keys(v).length === 1) return v.int;
  if ('float' in v && Object.keys(v).length === 1) return pythonFloat(v.float);
  const keys = Object.keys(v).sort((a, b) => { const x = Array.from(a, c => c.codePointAt(0)), y = Array.from(b, c => c.codePointAt(0));
    for (let k = 0; k < Math.min(x.length, y.length); k++) if (x[k] !== y[k]) return x[k] - y[k]; return x.length - y.length; });
  return '{' + keys.map(k => canonical(k) + ':' + canonical(v[k])).join(',') + '}';
}

function without(model, always, whenNull = []) {
  const out = {};
  for (const [k, v] of Object.entries(model)) {
    if (always.includes(k) || (whenNull.includes(k) && v === null)) continue;
    out[k] = v;
  }
  return out;
}

const RESOURCE_FIELDS = ['resource_id', 'resource_action', 'resource_sequence', 'prev_resource_digest'];
const plain = v => (v && typeof v === 'object' && !Array.isArray(v) && ('int' in v) && Object.keys(v).length === 1) ? Number(v.int) : v;
const bytes = s => new TextEncoder().encode(s);
const b64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

async function sha256(text) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes(text)));
  return Array.from(digest, b => b.toString(16).padStart(2, '0')).join('');
}

async function signedBy(canonicalText, signature, publicKey) {
  if (!signature || typeof signature.sig !== 'string') return false;
  try {
    const key = await crypto.subtle.importKey('raw', b64(publicKey), { name: 'Ed25519' }, false, ['verify']);
    return await crypto.subtle.verify('Ed25519', key, b64(signature.sig), bytes(canonicalText));
  } catch { return false; }
}

// ── Rendering helpers ─────────────────────────────────────────────────────────
function result(id) { const box = $(id); box.replaceChildren(); box.hidden = false; return box; }
function step(box, ok, title, detail) {
  const row = el('div', undefined, 'tour-step ' + (ok === true ? 'ok' : ok === false ? 'fail' : 'info'));
  row.append(el('strong', (ok === true ? '✓ ' : ok === false ? '✕ ' : '• ') + title));
  if (detail) row.append(el('span', detail));
  box.append(row);
}
function proof(box, label, value) {
  const d = el('details'); d.append(el('summary', label), el('pre', JSON.stringify(value, null, 2))); box.append(d);
}
async function run(button, box, task) {
  button.disabled = true; const label = button.textContent; button.textContent = 'Running...';
  try { await task(result(box)); }
  catch (error) { step($(box), false, 'Could not complete', error.message); }
  finally { button.disabled = false; button.textContent = label; }
}

// ── Scenarios ─────────────────────────────────────────────────────────────────
async function exploreMesh(box) {
  const mesh = await getJson('/v1/mesh');
  step(box, true, mesh.networks.length + ' trust domains behind this gateway', mesh.networks.map(n => n.id + (n.trust_ready ? ' (fresh revocation list)' : ' (stale revocation list)')).join(', '));
  const external = mesh.external_sovereigns || [];
  step(box, true, mesh.links.length + ' active recognition treaties', external.length + ' of them recognize sovereigns outside this gateway.');
  for (const s of mesh.synchronization || []) step(box, s.status === 'current' ? true : null, s.consumer + ' imports ' + s.publisher + "'s revocation feed", s.status.replaceAll('_', ' ') + ' (published ' + (s.published_sequence ?? '?') + ', imported ' + (s.imported_sequence ?? '?') + ')');
  step(box, null, 'Open the live graph below', 'Select a domain, a treaty or a membership to inspect it.');
  $('mesh').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

async function verifyTreaty(box) {
  const ctx = await context();
  const listing = await service(ctx.reference.sovereign_id, 'GET', '/recognition-treaties');
  const rows = [...(listing.external_treaties || []), ...(listing.treaties || [])];
  const treaty = (rows.find(r => r.treaty.subject_sovereign_id === ctx.sovereign_id) || rows[0])?.treaty;
  if (!treaty) throw new Error('The reference published no treaties.');
  step(box, null, 'Read from ' + ctx.reference.sovereign_id + ' through the gateway', treaty.issuer_sovereign_id + ' recognizes ' + treaty.subject_sovereign_id + ' for ' + treaty.scope.allowed_roles.join(', ') + ' until ' + new Date(treaty.expires_at).toLocaleDateString());
  const keys = [ctx.reference.public_key];
  const good = await service(ctx.sovereign_id, 'POST', '/recognition-treaties/verify', { body: { treaty, issuer_public_keys: keys } });
  step(box, good.accepted, 'Verified by ' + ctx.sovereign_id + ' against the pinned key of ' + ctx.reference.sovereign_id, 'reason: ' + good.reason);
  const tampered = structuredClone(treaty); tampered.scope.allowed_roles = ['role:operator'];
  const bad = await service(ctx.sovereign_id, 'POST', '/recognition-treaties/verify', { body: { treaty: tampered, issuer_public_keys: keys } });
  step(box, !bad.accepted, 'A copy with its scope changed to role:operator is rejected', 'reason: ' + bad.reason);
  proof(box, 'Signed treaty', treaty);
}

async function crossSovereign(box) {
  const ctx = await context();
  const records = await demoData('attestations.json');
  const active = records.active[records.active.length - 1];
  if (active) {
    const r = await service(ctx.sovereign_id, 'POST', '/attestations/verify', { body: { attestation: active } });
    step(box, r.accepted, 'Membership ' + active.subject_id + ' issued by ' + active.issuer_sovereign_id, 'accepted: ' + r.accepted + ' (' + r.reason + ')');
  }
  const revoked = records.revoked[records.revoked.length - 1];
  if (revoked) {
    const r = await service(ctx.sovereign_id, 'POST', '/attestations/verify', { body: { attestation: revoked } });
    step(box, !r.accepted, 'After revocation, ' + revoked.subject_id + ' is refused', 'reason: ' + r.reason);
    const feed = await service(ctx.sovereign_id, 'GET', '/sovereign-revocation-feed');
    step(box, (feed.revoked_attestation_ids || []).includes(revoked.attestation_id), 'Its ID is in the signed revocation feed of ' + ctx.sovereign_id, 'feed sequence ' + feed.sequence + ', ' + (feed.revoked_attestation_ids || []).length + ' revoked IDs');
  }
  const treaty = ctx.treaties_received?.[0];
  if (treaty) {
    const r = await service(ctx.sovereign_id, 'POST', '/attestations/verify-with-treaty', { body: { attestation: records.controller, treaty, treaty_issuer_public_keys: [ctx.reference.public_key] } });
    step(box, r.accepted, 'Across sovereigns: ' + treaty.issuer_sovereign_id + "'s treaty accepts " + records.controller.subject_id + ' from ' + records.controller.issuer_sovereign_id, 'accepted: ' + r.accepted + ' (' + r.reason + ')');
  } else {
    step(box, null, 'The reverse treaty from ' + ctx.reference.sovereign_id + ' is not published yet', 'It appears after the reference next signs its external treaties.');
  }
  proof(box, 'Signed attestations', records);
}

async function evidenceChain(box) {
  const ctx = await context();
  const [text, keyList, status] = await Promise.all([
    fetch('/demo-data/evidence.ndjson', { cache: 'no-store', credentials: 'omit' }).then(r => { if (!r.ok) throw new Error('evidence export unavailable'); return r.text(); }),
    demoData('executor-keys.json'), demoData('status.json'),
  ]);
  const events = text.split('\n').filter(l => l.trim()).map(parsePreserving);
  const { failures, decisions, executions, linked, last } = await checkEvents(events, ctx.na_public_key, keyList.executor_keys, ctx.resource_id);
  report(box, ctx, status, events, failures, decisions, executions, linked, last);
}

/** Verify a run of `gm.evidence.event` records: digests, store links, signatures and one resource chain. */
async function checkEvents(events, naPublicKey, executorKeyList, resourceId) {
  const executorKeys = new Map(executorKeyList.map(k => [k.key_id, k]));
  let failures = [], decisions = 0, executions = 0, linked = 0, prev = null, last = null;
  for (const event of events) {
    const seq = plain(event.entry.store_sequence);
    if (await sha256(canonical(event.entry)) !== event.entry_digest) failures.push(seq + ': envelope digest');
    if (await sha256(canonical(event.payload)) !== event.entry.payload_digest) failures.push(seq + ': payload digest');
    if (prev && plain(prev.store_sequence) + 1 === seq && event.entry.prev_entry_digest !== await sha256(canonical(prev))) failures.push(seq + ': store chain');
    prev = event.entry;
    if (event.entry.entry_kind === 'decision') {
      decisions++;
      const d = event.payload.decision;
      if (!await signedBy(canonical(without(d, ['signature'], ['policy_binding', 'attestation_binding'])), d.signature, naPublicKey)) failures.push(seq + ': decision signature');
    } else if (event.entry.entry_kind === 'execution') {
      executions++;
      const r = event.payload, key = executorKeys.get(r.signature?.key_id);
      const body = without(r, ['signature'], RESOURCE_FIELDS);
      if (!key || key.executor_sovereign_id !== r.executor_sovereign_id || !await signedBy(canonical(body), r.signature, key.public_key)) failures.push(seq + ': execution signature');
      if (r.resource_id === resourceId) {
        if (last && plain(r.resource_sequence) === plain(last.record.resource_sequence) + 1) {
          if (r.prev_resource_digest !== last.digest) failures.push(seq + ': resource chain'); else linked++;
        }
        last = { record: r, digest: await sha256(canonical(body)) };
      }
    }
  }
  return { failures, decisions, executions, linked, last };
}

function report(box, ctx, status, events, failures, decisions, executions, linked, last) {
  step(box, failures.length === 0, 'Checked ' + events.length + ' signed events in this browser', decisions + ' decisions and ' + executions + ' executions: every signature, digest and store link' + (failures.length ? '. Failures: ' + failures.slice(0, 5).join('; ') : ''));
  if (last) {
    const head = ctx.resource_head;
    step(box, linked > 0, 'Resource ' + ctx.resource_id + ': ' + (linked + 1) + ' consecutive records linked by digest', 'latest is ' + plain(last.record.resource_action) + ' ' + JSON.stringify(last.record.execution_parameters));
    if (head) step(box, head.record_digest === last.digest || plain(head.resource_sequence) > plain(last.record.resource_sequence), 'Matches the head the authority reports', 'sequence ' + head.resource_sequence + ', digest ' + head.record_digest.slice(0, 16) + '…');
  }
  const actions = status.last_actions || [];
  for (const a of actions) step(box, null, a.authorized ? 'Last governed action: allowed and recorded' : 'Last governed action: denied by policy', a.authorized ? 'resource sequence ' + a.resource_sequence + ' (' + a.status + ')' : a.denial_reason);
  step(box, null, 'Updated ' + new Date(status.updated_at).toLocaleString(), 'The demo controller acts every ' + Math.round(status.interval_seconds / 60) + ' minutes.');
}

// ── Wiring ────────────────────────────────────────────────────────────────────
async function tryDemo() {
  const state = $('demo-state');
  try {
    const access = await demoAccess();
    for (const id of ['token', 'network-token']) { $(id).value = access.token; }
    $('token').dispatchEvent(new Event('input'));
    $('connect').click();
    state.textContent = 'Connected with demo access (' + access.client_id + '): read and verify only, ' + access.requests_per_minute + ' requests per minute.';
    $('tour').scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (error) { state.textContent = error.message; }
}

if (typeof document !== 'undefined') {
const scenarios = [
  ['run-explore', 'explore-result', exploreMesh],
  ['run-treaty', 'treaty-result', verifyTreaty],
  ['run-cross', 'cross-result', crossSovereign],
  ['run-evidence', 'evidence-result', evidenceChain],
];
for (const [button, box, task] of scenarios) $(button)?.addEventListener('click', () => run($(button), box, task));
for (const id of ['try-demo', 'try-demo-hero']) $(id)?.addEventListener('click', tryDemo);
getJson('/v1/demo').then(d => { if (!d.available) for (const id of ['try-demo', 'try-demo-hero']) { if ($(id)) $(id).hidden = true; } }).catch(() => {});
}

export { canonical, checkEvents, parsePreserving, pythonFloat };
