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

export async function operatorHeaders(body, seedBase64, keyId) {
  if (!keyId || !/^[\x21-\x7e]{1,256}$/.test(keyId)) throw new Error('Enter a valid operator key ID.');
  let seed;
  try { seed = Uint8Array.from(atob(seedBase64.trim()), c => c.charCodeAt(0)); }
  catch { throw new Error('Operator seed must be base64.'); }
  if (seed.length !== 32) throw new Error('Operator seed must contain 32 bytes.');
  const encoded = new Uint8Array(48);
  encoded.set([0x30,0x2e,0x02,0x01,0x00,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x04,0x22,0x04,0x20]);
  encoded.set(seed,16);
  try {
    const key = await crypto.subtle.importKey('pkcs8', encoded, 'Ed25519', false, ['sign']);
    const timestamp = new Date().toISOString(), nonce = crypto.randomUUID();
    const payload = canonical({body, key_id:keyId, timestamp, nonce});
    const signature = new Uint8Array(await crypto.subtle.sign('Ed25519',key,new TextEncoder().encode(payload)));
    return {'X-Admin-Key-Id':keyId,'X-Admin-Timestamp':timestamp,'X-Admin-Nonce':nonce,'X-Admin-Signature':btoa(String.fromCharCode(...signature))};
  } finally { seed.fill(0); encoded.fill(0); }
}
