import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const source=readFileSync(new URL('../ui/errors.js',import.meta.url),'utf8');
const {errorCode,explainFailure,fromGateway,requestIds}=await import('data:text/javascript;base64,'+Buffer.from(source).toString('base64'));

// The authority's envelope, relayed by the gateway, and the gateway's own body.
const authority=(code,message='refused')=>({error:{code,message,request_id:'r'}});
const gateway=(error,code)=>({error,code});
const headers=values=>new Headers(values);

assert.equal(errorCode(authority('admin_auth_throttled')),'admin_auth_throttled');
assert.equal(errorCode(gateway('client quota exhausted','rate_limited')),'rate_limited');
assert.equal(errorCode('not json'),'');
assert.equal(fromGateway(gateway('x','forbidden')),true);
assert.equal(fromGateway(authority('forbidden')),false);

// 429: the client quota (on any route), the authority's throttling of failed signatures, its rate limit.
let text=explainFailure(429,gateway('client quota exhausted','rate_limited'),headers({'retry-after':'1'}));
assert.match(text,/quota/);
assert.match(text,/Wait 1 second before/);
text=explainFailure(429,authority('admin_auth_throttled','Too many failed admin requests for this key from this address.'),headers({'retry-after':'42'}));
assert.match(text,/from this gateway after too many failed signatures \(Too many failed admin requests for this key/);
assert.match(text,/Wait 42 seconds/);
assert.match(text,/clock/);
text=explainFailure(429,authority('rate_limit_exceeded'),headers({}));
assert.match(text,/authority is limiting/);
assert.match(text,/Wait before retrying/);

// 401: the gateway (the service token, or missing operator headers), or the authority's refusal of the signature.
assert.match(explainFailure(401,gateway('missing or invalid bearer token','unauthorized'),headers({})),/service token was refused/);
assert.equal(explainFailure(401,gateway('operator-signed headers required for this operation','unauthorized'),headers({})),
  'The gateway refused the request: operator-signed headers required for this operation');
text=explainFailure(401,authority('admin_auth_failed'),headers({}));
assert.match(text,/refused the operator signature \(admin_auth_failed\)/);

// 403: the gateway's scope, an operator key below the route's tier, any other authority refusal.
assert.match(explainFailure(403,gateway('service operation not authorized','forbidden'),headers({})),/does not have access/);
text=explainFailure(403,authority('insufficient_operator_tier','This operation requires the privileged operator tier.'),headers({}));
assert.match(text,/tier does not allow/);
assert.match(text,/privileged operator tier/);
assert.equal(explainFailure(403,authority('node_key_revoked','The node key is revoked.'),headers({})),
  'The authority refused the request (node_key_revoked): The node key is revoked.');

// Anything else keeps the status and the message.
assert.equal(explainFailure(404,authority('resource_not_found','no head'),headers({})),'Request rejected (404): no head');
assert.equal(explainFailure(500,'oops',headers({})),'Request rejected (500): oops');

// Both request IDs, for reporting a failure.
assert.equal(requestIds(headers({'x-request-id':'gw-1','x-upstream-request-id':'na-2'})),'Request ID: gw-1 | Authority request ID: na-2');
assert.equal(requestIds(headers({'x-request-id':'gw-1'})),'Request ID: gw-1');
console.log('console error explanations: ok');
