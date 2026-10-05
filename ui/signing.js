// Operator keys remain in browser memory. Only signed headers are transmitted.
export function canonical(value) {
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new Error('Browser signing supports safe integers. Use SDK-generated headers for fractional or large numeric values.');
    return String(value);
  }
  if (typeof value === 'string') return JSON.stringify(value).replace(/[\u007f-\uffff]/g, c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (typeof value === 'object') return '{' + Object.keys(value).sort((a,b) => {
    const x=Array.from(a,c=>c.codePointAt(0)), y=Array.from(b,c=>c.codePointAt(0));
    for(let i=0;i<Math.min(x.length,y.length);i++) if(x[i]!==y[i]) return x[i]-y[i];
    return x.length-y.length;
  }).map(k => canonical(k) + ':' + canonical(value[k])).join(',') + '}';
  throw new Error('Unsupported JSON value');
}

// Path parameters that may span several segments (`kv:vault/secret`), as in
// the gateway's services.rs; every other parameter is exactly one segment.
const MULTI_SEGMENT = ['resource_id'];

/**
 * What the Network Authority will see for a catalog operation forwarded by
 * the gateway: the decoded upstream path with its parameters filled in, and
 * the query parameters the gateway forwards (`{name: [value]}`).
 */
export function adminRequestFor(operation, params, audience, body) {
  const segments = [];
  for (const segment of operation.upstream_path.replace(/^\//, '').split('/')) {
    const name = segment.match(/^\{(.+)\}$/)?.[1];
    if (!name) { segments.push(segment); continue; }
    const value = params[name];
    if (!value) throw new Error('Enter ' + name + '.');
    segments.push(...(MULTI_SEGMENT.includes(name) ? value.split('/') : [value]));
  }
  const query = {};
  for (const name of operation.query || []) if (params[name]) query[name] = [String(params[name])];
  return {method: operation.method, path: '/' + segments.join('/'), query, audience, body};
}

/** The canonical bytes an operator signs (signature version 2, Genesis Mesh 1.0.2). */
export function adminSigningPayload(request, keyId, timestamp, nonce) {
  if (!request.path.startsWith('/')) throw new Error('Admin request path must start with /.');
  return canonical({
    v: 2,
    method: request.method.toUpperCase(),
    path: request.path,
    query: request.query || {},
    audience: request.audience,
    body: request.body ?? {},
    key_id: keyId,
    timestamp,
    nonce,
  });
}

/**
 * The four admin headers for one request. The signature binds the method,
 * path, query, the authority's public key and the body, so it is valid only
 * for this request at this authority.
 */
export async function operatorHeaders(request, seedBase64, keyId, fixed = {}) {
  if (!keyId || !/^[\x21-\x7e]{1,256}$/.test(keyId)) throw new Error('Enter a valid operator key ID.');
  if (!request?.audience) throw new Error('The authority public key is unknown.');
  let seed;
  try { seed = Uint8Array.from(atob(seedBase64.trim()), c => c.charCodeAt(0)); }
  catch { throw new Error('Operator seed must be base64.'); }
  if (seed.length !== 32) throw new Error('Operator seed must contain 32 bytes.');
  const encoded = new Uint8Array(48);
  encoded.set([0x30,0x2e,0x02,0x01,0x00,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x04,0x22,0x04,0x20]);
  encoded.set(seed,16);
  try {
    const key = await crypto.subtle.importKey('pkcs8', encoded, 'Ed25519', false, ['sign']);
    const timestamp = fixed.timestamp || new Date().toISOString(), nonce = fixed.nonce || crypto.randomUUID();
    const payload = adminSigningPayload(request, keyId, timestamp, nonce);
    const signature = new Uint8Array(await crypto.subtle.sign('Ed25519',key,new TextEncoder().encode(payload)));
    return {'X-Admin-Key-Id':keyId,'X-Admin-Timestamp':timestamp,'X-Admin-Nonce':nonce,'X-Admin-Signature':btoa(String.fromCharCode(...signature))};
  } finally { seed.fill(0); encoded.fill(0); }
}
