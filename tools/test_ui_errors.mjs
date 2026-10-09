import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const source=readFileSync(new URL('../ui/errors.js',import.meta.url),'utf8');
const {errorCode,explainFailure,requestIds}=await import('data:text/javascript;base64,'+Buffer.from(source).toString('base64'));

const authority=code=>({error:{code,message:'This operation requires the privileged operator tier.'}});
const gateway=(error,code)=>({error,code});
const headers=values=>new Headers(values);

// Both body shapes.
assert.equal(errorCode(authority('admin_auth_throttled')),'admin_auth_throttled');
assert.equal(errorCode(gateway('client quota exhausted','rate_limited')),'rate_limited');
assert.equal(errorCode('not json'),'');

// 429: the authority's throttling of failed signatures, the client quota, the authority's rate limit.
let text=explainFailure(429,authority('admin_auth_throttled'),headers({'retry-after':'42'}),true);
assert.match(text,/failed operator signatures/);
assert.match(text,/Wait 42 seconds/);
assert.match(text,/clock/);
text=explainFailure(429,gateway('client quota exhausted','rate_limited'),headers({'retry-after':'1'}));
assert.match(text,/quota/);
assert.match(text,/Wait 1 second before/);
text=explainFailure(429,authority('rate_limit_exceeded'),headers({}),true);
assert.match(text,/authority is limiting/);
assert.match(text,/Wait before retrying/);

// 401: the gateway's bearer token, or the authority's refusal of the operator signature.
assert.match(explainFailure(401,gateway('missing or invalid bearer token','unauthorized'),headers({})),/service token was refused/);
text=explainFailure(401,authority('admin_auth_failed'),headers({}),true);
assert.match(text,/refused the operator signature \(admin_auth_failed\)/);
assert.match(text,/clock/);

// 403: an operator key below the route's tier, or a token without access.
text=explainFailure(403,authority('insufficient_operator_tier'),headers({}),true);
assert.match(text,/tier does not allow/);
assert.match(text,/privileged operator tier/);
assert.match(explainFailure(403,gateway('service operation not authorized','forbidden'),headers({})),/does not have access/);

// Anything else keeps the status and the message.
assert.equal(explainFailure(404,authority('resource_not_found'),headers({}),true),'Request rejected (404): This operation requires the privileged operator tier.');
assert.equal(explainFailure(500,'oops',headers({})),'Request rejected (500): oops');

// Both request IDs, for reporting a failure.
assert.equal(requestIds(headers({'x-request-id':'gw-1','x-upstream-request-id':'na-2'})),'Request ID: gw-1 | Authority request ID: na-2');
assert.equal(requestIds(headers({'x-request-id':'gw-1'})),'Request ID: gw-1');
console.log('console error explanations: ok');
