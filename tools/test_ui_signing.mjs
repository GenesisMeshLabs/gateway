import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createPrivateKey, createPublicKey, verify} from 'node:crypto';
import {execFileSync} from 'node:child_process';
const source=readFileSync(new URL('../ui/signing.js',import.meta.url),'utf8');
const {adminRequestFor,adminSigningPayload,canonical,operatorHeaders}=await import('data:text/javascript;base64,'+Buffer.from(source).toString('base64'));
const pythonCanonical=value=>execFileSync('python',['-X','utf8','-c','import sys,json; print(json.dumps(json.load(sys.stdin),sort_keys=True,separators=(",",":")))'],{input:JSON.stringify(value),encoding:'utf8'}).trim();
const body={subject_id:'gateway-å-😀',roles:['member'],nested:{'😀':true,'':null},count:12};
assert.equal(canonical(body),pythonCanonical(body));
for(const n of [1.5,Number.MAX_SAFE_INTEGER+1,NaN,Infinity])assert.throws(()=>canonical({n}));

// Signature version 2: method, decoded path, query, audience and body are signed.
const seed=Buffer.alloc(32,7), keyId='test-operator';
const request={method:'POST',path:'/admin/attestations',query:{},audience:'USG',body};
const headers=await operatorHeaders(request,seed.toString('base64'),keyId);
const envelope={v:2,method:'POST',path:'/admin/attestations',query:{},audience:'USG',body,key_id:keyId,timestamp:headers['X-Admin-Timestamp'],nonce:headers['X-Admin-Nonce']};
const key=createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),seed]),format:'der',type:'pkcs8'});
const signature=Buffer.from(headers['X-Admin-Signature'],'base64');
assert(verify(null,Buffer.from(pythonCanonical(envelope)),createPublicKey(key),signature));
for(const other of [{...envelope,method:'PUT'},{...envelope,path:'/admin/revoke'},{...envelope,query:{limit:['1']}},{...envelope,audience:'OTHER'}])
  assert(!verify(null,Buffer.from(pythonCanonical(other)),createPublicKey(key),signature));
await assert.rejects(()=>operatorHeaders(request,'invalid','test'));
await assert.rejects(()=>operatorHeaders({...request,audience:''},seed.toString('base64'),keyId));
assert(!JSON.stringify(headers).includes(seed.toString('base64')));

// The shared reference vectors (genesismesh conformance/vectors/admin_auth.json), copied unchanged.
const suite=JSON.parse(readFileSync(new URL('../tests/reference/admin_auth.json',import.meta.url),'utf8'));
const seedA=Buffer.from(Array.from({length:32},(_,i)=>i)).toString('base64');
for(const v of suite.vectors){
  const i=v.input, req={method:i.method,path:i.path,query:i.query,audience:i.audience,body:i.body};
  assert.equal(adminSigningPayload(req,i.key_id,i.timestamp,i.nonce),v.expected.payload,v.id);
  const h=await operatorHeaders(req,seedA,i.key_id,{timestamp:i.timestamp,nonce:i.nonce});
  assert.equal(h['X-Admin-Signature'],v.expected.signature_b64,v.id);
}

// The console signs the upstream request the gateway forwards (services.rs).
assert.equal(adminRequestFor({method:'POST',upstream_path:'/admin/recognition-treaties/{treaty_id}/revoke',query:[]},{treaty_id:'t-1'},'USG',{}).path,'/admin/recognition-treaties/t-1/revoke');
assert.equal(adminRequestFor({method:'GET',upstream_path:'/admin/evidence/resources/{resource_id}',query:[]},{resource_id:'kv:vault/secret'},'USG',{}).path,'/admin/evidence/resources/kv:vault/secret');
assert.deepEqual(adminRequestFor({method:'GET',upstream_path:'/admin/evidence/export',query:['limit','since_sequence']},{limit:'10',other:'x'},'USG',{}).query,{limit:['10']});
assert.throws(()=>adminRequestFor({method:'POST',upstream_path:'/admin/operator-keys/{key_id}/revoke',query:[]},{},'USG',{}));
console.log('Browser signing (version 2) matches Python canonical JSON, the shared vectors and Ed25519 verification; the upstream request is reconstructed as the gateway forwards it.');
