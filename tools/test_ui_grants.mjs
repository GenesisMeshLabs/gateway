// The console's grant views (Genesis Mesh 1.6.0): the grant list, one grant
// with its use chain, remaining budget, envelope and revocation, its uses
// (admitted or quarantined), the uses and revocation actions, an issued or
// revoked grant, a time token, a grant use as its
// resource's head, grant uses in a resource's changes and judgements governed
// by a grant. Their input is authority data, rendered as text only.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const load=async name=>import('data:text/javascript;base64,'+Buffer.from(readFileSync(new URL('../ui/'+name,import.meta.url),'utf8')).toString('base64'));
const {GRANT_FILTERS,REVOCATION_REASONS,governedBy,grantChangeDetails,grantStatusView,grantUseView,grantUsesView,grantView,grantsView,
  issuedView,judgementView,resourceHeadView,revocationReason,revocationView,timeTokenView}=await load('grants.js');
const {explainFailure}=await load('errors.js');

const strings=view=>{for(const t of view.tables)for(const r of t.rows){assert.equal(r.length,t.headers.length);for(const c of r)assert.equal(typeof c,'string');}};

// A summary as GET /admin/grants writes it.
const active={grant_id:'g-1',status:'active',bearer_key_id:'site-7-device',bearer_sovereign_id:'sovereign-b',
  capabilities:['secret.rotate','secret.disable'],basis_kind:'attestation',basis_id:'att-1',
  valid_from:'2026-06-01T08:00:00Z',valid_until:'2026-06-01T12:00:00Z',max_uses:3,uses:1,issued_at:'2026-06-01T07:59:00.123456Z',
  issued_by_operator:'operator-1',store_sequence:41,revoked_at:null,revocation_reason:null};
const revoked={...active,grant_id:'<img src=x onerror=alert(1)>',status:'revoked',uses:3,revoked_at:'2026-06-01T09:00:00Z',
  revocation_reason:'attestation_revoked'};

assert.deepEqual(GRANT_FILTERS,['active','expired','revoked']);
let view=grantsView({grants:[active,revoked,'not a grant'],next_before:null});
assert.deepEqual(view.tables.map(t=>t.caption),['Grants (2)']);
assert.deepEqual(view.tables[0].headers,['Grant','Status','Bearer key','Capabilities','Basis','Valid','Uses','Issued','Revoked']);
assert.deepEqual(view.tables[0].rows[0],['g-1','active','site-7-device','secret.rotate, secret.disable','attestation att-1',
  '2026-06-01 08:00:00 UTC to 2026-06-01 12:00:00 UTC','1 of 3','2026-06-01 07:59:00 UTC by operator-1','']);
assert.deepEqual(view.tables[0].rows[1].slice(0,2),['<img src=x onerror=alert(1)>','revoked']);
assert.equal(view.tables[0].rows[1][8],'2026-06-01 09:00:00 UTC (its attestation was revoked)');
assert.equal(view.note,'');
strings(view);
// The list's cursor is the ID of the page's last grant (ordered by issued_at, then grant_id).
view=grantsView({grants:[active],next_before:'g-1'});
assert.equal(view.note,'More on the next page: send again with before = g-1');
assert.deepEqual(grantsView({grants:[],next_before:null}),{tables:[],note:'No grants match.'});

// GET /admin/grants/<id>: the grant, its uses and remaining budget, its envelope, the policies it was checked against.
const grant={grant_id:'g-1',bearer_key_id:'site-7-device',max_uses:3,max_uses_per_time_token:2,parameter_envelope:{
  region:{required:true,one_of:['eu-west',1,true,null]},
  lifetime_days:{required:true,number_range:{number_type:'integer',minimum:1,maximum:60,exclusive_minimum:false,exclusive_maximum:true}},
  scopes:{required:false,subset_of:['read','write']},
  ratio:{required:true,number_range:{number_type:'number',minimum:0.5,exclusive_minimum:true,exclusive_maximum:false}}}};
const detail={...active,remaining_uses:2,chain_length:2,grant,policy_versions:[{policy_id:'rotation',version:3}],revocation:null};
view=grantView(detail);
assert.deepEqual(view.tables.map(t=>t.caption),['Grant g-1','Parameter envelope (4)']);
const [summary,envelope]=view.tables;
assert.deepEqual(summary.rows,[['Status','active'],['Bearer','site-7-device (sovereign-b)'],['Capabilities','secret.rotate, secret.disable'],
  ['Basis','attestation att-1'],['Valid','2026-06-01 08:00:00 UTC to 2026-06-01 12:00:00 UTC'],['Uses admitted','1 of 3'],['Remaining uses','2'],
  ['Use chain','2 (1 quarantined)'],['Uses per time token','2'],['Issued','2026-06-01 07:59:00 UTC by operator-1'],['Store position','41'],['Checked against','rotation v3']]);
// Envelope values keep their types apart: "eu-west" is text, 1 and true are not.
assert.deepEqual(envelope.rows,[['lifetime_days','yes','integer >= 1 and < 60'],['ratio','yes','number > 0.5'],
  ['region','yes','one of: eu-west, 1, true, null'],['scopes','no','any of: read, write']]);
assert.match(view.note,/admitted or quarantined; the budget counts admitted uses only\.$/);
// A grant offers its uses and, unless revoked, its revocation, prepared for review: an operation and its parameters, nothing sent.
assert.deepEqual(view.actions,[{operation:'grants-list-grant-uses',parameters:{grant_id:'g-1'},label:'Prepare the list of its uses'},
  {operation:'grants-revoke-grant',parameters:{grant_id:'g-1'},label:'Prepare revocation of this grant'}]);
// A chain without quarantined uses, or an older authority without chain_length.
assert.equal(grantView({...detail,chain_length:1}).tables[0].rows[7][1],'1');
assert.equal(grantView({...detail,chain_length:undefined}).tables[0].rows[7][1],'');
strings(view);

const revocation={revocation_id:'rv-1',grant_id:'g-1',grant_digest:'d'.repeat(64),reason:'operator',detail:'The device was lost',
  revoked_by:'operator-2',revoked_at:'2026-06-01T09:00:00Z',issuer_sovereign_id:'sovereign-c',issued_by:'na-key',signature:{key_id:'na-key',sig:'S'}};
view=grantView({...detail,status:'revoked',revoked_at:revocation.revoked_at,revocation_reason:'operator',remaining_uses:0,revocation});
assert.deepEqual(view.tables.map(t=>t.caption),['Grant g-1','Parameter envelope (4)','Revocation']);
assert.deepEqual(view.tables[2].rows,[['Revoked at','2026-06-01 09:00:00 UTC'],['Reason','operator: by an operator'],['Detail','The device was lost'],
  ['Revoked by','operator-2'],['Revocation','rv-1']]);
assert.deepEqual(view.actions.map(a=>a.operation),['grants-list-grant-uses']);
assert.match(view.note,/Uses executed from the revocation on are refused\./);
// A grant without an envelope shows no envelope table.
assert.deepEqual(grantView({...detail,grant:{...grant,parameter_envelope:{}}}).tables.map(t=>t.caption),['Grant g-1']);

// POST /admin/grants/<id>/revoke.
view=revocationView({grant_id:'g-1',status:'revoked',revocation,entry:{store_sequence:57},entry_digest:'e'.repeat(64)});
assert.deepEqual(view.tables[0].caption,'Revoked grant g-1');
assert.deepEqual(view.tables[0].rows.at(-1),['Store position','57']);
assert.match(view.note,/^Uses executed from 2026-06-01 09:00:00 UTC on are refused\. .*revoked_grant_ids/);
strings(view);

// POST /admin/grants: the signed grant and its first time token (no use before it, so no head digest).
const token={time_token_id:'t-0',grant_id:'g-1',use_sequence:0,issued_at:'2026-06-01T07:59:00Z',issuer_sovereign_id:'sovereign-c',issued_by:'na-key'};
view=issuedView({grant:{...grant,...active,bearer_sovereign_id:'sovereign-b'},time_token:token,entry:{store_sequence:41}});
assert.deepEqual(view.tables.map(t=>t.caption),['Issued grant g-1','Parameter envelope (4)','First time token']);
assert.deepEqual(view.tables[0].rows.slice(4,8),[['Budget','3 uses'],['Uses per time token','2'],['Issued','2026-06-01 07:59:00 UTC'],['Store position','41']]);
assert.deepEqual(view.tables[2].rows,[['Time token','t-0'],['Grant','g-1'],['Uses before it','0'],['Last use digest',''],['Issued','2026-06-01 07:59:00 UTC']]);
strings(view);
// POST /grants/time-tokens: a token bound to the holder's chain head.
view=timeTokenView({time_token:{...token,time_token_id:'t-2',use_sequence:2,use_head_digest:'f'.repeat(64)}});
assert.deepEqual(view.tables[0].rows.slice(2,4),[['Uses before it','2'],['Last use digest','f'.repeat(64)]]);

// POST /evidence/grant-executions: a use with a resource becomes the resource's head.
const use={use_id:'u-2',grant_id:'g-1',use_sequence:2,capability:'secret.rotate',resource_id:'kv:vault/zoë',resource_action:'rotate',
  executed_at:'2026-06-01T08:30:00Z',outcome:'success'};
view=grantUseView({entry:{store_sequence:60,resource_sequence:7},entry_digest:'a'.repeat(64),payload:use,status:'recorded',resource_sequence:7});
assert.deepEqual(view.tables[0].caption,'Grant use u-2');
assert.deepEqual(view.tables[0].rows,[['Grant','g-1'],['Use','2'],['Capability','secret.rotate'],['Resource','kv:vault/zoë'],['Action','rotate'],
  ['Executed','2026-06-01 08:30:00 UTC'],['Outcome','success'],['Status','recorded'],['Resource position','7'],['Store position','60']]);
assert.match(view.note,/^The use is the head of kv:vault\/zoë at position 7 .*links to it\.$/);
// The same use again: the authority's duplicate answer names the position in the entry.
view=grantUseView({entry:{store_sequence:60,resource_sequence:7},payload:use,status:'duplicate'});
assert.deepEqual(view.tables[0].rows.slice(7,9),[['Status','duplicate'],['Resource position','7']]);
// A use without a resource takes no place in a chain.
view=grantUseView({entry:{store_sequence:61},payload:{...use,resource_id:undefined,resource_action:undefined},status:'recorded',resource_sequence:null});
assert.equal(view.note,'The use names no resource, so it takes no place in a resource\'s chain.');

// Revocation reasons, agreement_untrusted (a treaty revocation left the agreement untrusted) among them.
assert.deepEqual(Object.keys(REVOCATION_REASONS),['operator','attestation_revoked','policy_deactivated','policy_activated',
  'bearer_key_retired','agreement_untrusted']);
assert.equal(revocationReason('agreement_untrusted'),'its agreement is no longer trusted');
assert.equal(revocationReason('a_later_reason'),'a later reason');
view=grantsView({grants:[{...revoked,revocation_reason:'agreement_untrusted',basis_kind:'agreement'}],next_before:null});
assert.equal(view.tables[0].rows[0][8],'2026-06-01 09:00:00 UTC (its agreement is no longer trusted)');
assert.deepEqual(revocationView({grant_id:'g-1',revocation:{...revocation,reason:'agreement_untrusted',revoked_by:null,detail:null}})
  .tables[0].rows[1],['Reason','agreement_untrusted: its agreement is no longer trusted']);

// GET /admin/grants/<id>/uses: the use chain, newest first, admitted or quarantined, with the next page's use_sequence.
const uses={grant_id:'g-1',uses:[
  {use_id:'00000000-0000-4000-8000-000000000003',use_sequence:3,state:'quarantined',rejection_code:'grant_use_out_of_scope',
    executed_at:'2026-06-01T08:40:00Z',recorded_at:'2026-06-01T09:10:00.000000+00:00',store_sequence:70,resource_id:'kv:other/x',
    resource_sequence:null,outcome:'success'},
  {use_id:'00000000-0000-4000-8000-000000000002',use_sequence:2,state:'admitted',rejection_code:null,
    executed_at:'2026-06-01T08:30:00Z',recorded_at:'2026-06-01T09:10:00Z',store_sequence:60,resource_id:'kv:vault/zoë',
    resource_sequence:7,outcome:'success'},'not a use'],next_before:2};
view=grantUsesView(uses);
assert.equal(view.tables[0].caption,'Uses of grant g-1 (2)');
assert.deepEqual(view.tables[0].headers,['#','Use','State','Refused as','Executed','Recorded','Resource','Resource position','Store position','Outcome']);
assert.deepEqual(view.tables[0].rows[0],['3','00000000-0000-4000-8000-000000000003','quarantined','grant_use_out_of_scope',
  '2026-06-01 08:40:00 UTC','2026-06-01 09:10:00 UTC','kv:other/x','','70','success']);
assert.deepEqual(view.tables[0].rows[1].slice(2,4),['admitted','']);
assert.deepEqual(view.tables[0].rows[1].slice(7,9),['7','60']);
assert.match(view.note,/^A quarantined use was refused but continued the chain: .*budget\. More on the next page: send again with before = 2$/);
strings(view);
assert.deepEqual(grantUsesView({grant_id:'g-1',uses:[],next_before:null}),{tables:[],note:'No uses yet.'});
assert.equal(grantUsesView({...uses,uses:[uses.uses[1]],next_before:null}).note,'');

// GET /admin/evidence/resource-heads/<id>: what the head is (1.6.0: entry_kind and record_id).
view=resourceHeadView({resource_id:'kv:vault/zoë',resource_sequence:7,record_digest:'a'.repeat(64),entry_kind:'grant_execution',
  record_id:'00000000-0000-4000-8000-000000000002'});
assert.deepEqual(view.tables[0].rows,[['Position','7'],['Record digest','a'.repeat(64)],['Record','a grant use 00000000-0000-4000-8000-000000000002']]);
assert.match(view.note,/The head is a grant use, at the position the authority gave it/);
view=resourceHeadView({resource_id:'r',resource_sequence:3,record_digest:'b'.repeat(64),entry_kind:'execution',record_id:'ev-3'});
assert.deepEqual(view.tables[0].rows[2],['Record','execution evidence ev-3']);
assert.equal(view.note,'The next record of this resource links to this digest.');
view=resourceHeadView({resource_id:'r',resource_sequence:9,record_digest:'c'.repeat(64),entry_kind:'retention_checkpoint',record_id:null});
assert.deepEqual(view.tables[0].rows[2],['Record','the latest retention checkpoint']);
assert.match(view.note,/Retention removed/);
// An authority before 1.6.0 names neither: no Record row.
assert.equal(resourceHeadView({resource_id:'r',resource_sequence:1,record_digest:'d'.repeat(64)}).tables[0].rows.length,2);

// A resource's changes: a grant use names its grant and use; an observation it matched says so; a refused use too.
assert.equal(grantChangeDetails({kind:'grant_execution',governed_by:'grant',grant_id:'g-1',use_sequence:2,state:'recorded'}),'grant g-1, use 2');
assert.equal(grantChangeDetails({kind:'observation',governed_by:'grant',state:'matched'}),'matched a grant use');
assert.equal(grantChangeDetails({kind:'quarantine',record_kind:'grant_execution',rejection_code:'grant_revoked'}),'a grant use');
assert.equal(grantChangeDetails({kind:'execution',governed_by:'prior_decision'}),'');

// Judgements: governed_by grant (1.6.0) beside the earlier two.
assert.equal(governedBy({governed_by:'grant',matched_evidence_id:'u-2'}),'a grant (use u-2)');
assert.equal(governedBy({governed_by:'prior_decision',matched_decision_id:'d-1'}),'a prior decision (d-1)');
assert.equal(governedBy({governed_by:'after_the_fact'}),'judged after the fact');
assert.equal(governedBy({governed_by:'some_later_kind'}),'some later kind');
const judgement={judgement_id:'j-1',subject_kind:'break_glass',subject_id:'bg_1',resource_id:'kv:vault/zoë',action:'rotate',
  capability:'secret.rotate',governed_by:'grant',verdict:'allow',evaluated_as_of:'2026-06-01T08:30:00Z',matched_evidence_id:'u-2',
  judged_at:'2026-06-01T08:31:00Z'};
view=judgementView({entry:{},payload:judgement,status:'existing'});
assert.equal(view.tables[0].caption,'Judgement j-1 (existing)');
assert.deepEqual(view.tables[0].rows.slice(0,6),[['Subject','break glass bg_1'],['Resource','kv:vault/zoë'],['Action','rotate'],
  ['Capability','secret.rotate'],['Governed by','a grant (use u-2)'],['Verdict','allow']]);
assert.match(view.note,/governed by the grant, not judged again/);
assert.equal(judgementView({payload:{...judgement,governed_by:'after_the_fact'}}).note,'');
strings(view);

// /admin/evidence/status: grant counts with grants on, a note with them off, nothing from an older authority.
assert.deepEqual(grantStatusView({evidence_grants:true,grants_issued:4,grants_active:2,grants_revoked:1,grant_uses:9}).tables[0].rows,
  [['Issued','4'],['Active','2'],['Revoked','1'],['Uses admitted','9']]);
assert.match(grantStatusView({evidence_grants:false}).note,/off on this authority/);
assert.deepEqual(grantStatusView({evidence_store:'on'}),{tables:[],note:''});

// Anything else shows nothing.
for(const data of [undefined,null,'text',[],{error:{code:'grants_disabled'}},{grants:'none'}]){
  for(const f of [grantsView,grantView,grantUsesView,issuedView,revocationView,timeTokenView,grantUseView,resourceHeadView,judgementView])
    assert.deepEqual(f(data),{tables:[],note:''},f.name);
}

// Grants off: every grant route answers 404 grants_disabled, explained.
assert.match(explainFailure(404,{error:{code:'grants_disabled',message:'grants are off'}},{}),/^Pre-issued grants are off on this authority/);
// The codes the review fixes added: a conflict to retry, a grant that no longer verifies, a use outside the key's scope.
assert.match(explainFailure(409,{error:{code:'grant_issuance_conflict',message:'retry'}},{}),/Send the issuance again\.$/);
assert.match(explainFailure(503,{error:{code:'grant_store_integrity_failed',message:'x'}},{'retry-after':'30'}),
  /no longer verifies under its signature.*Wait 30 seconds before retrying\.$/);
assert.equal(explainFailure(422,{error:{code:'grant_use_out_of_scope',message:'x',details:{quarantine_id:'q-1'}}},{}),
  'The bearer key\'s role or resource prefix does not cover the use\'s resource; the authority kept the use in quarantine q-1.');

// The catalog: grant operations are evidence-store operations; the authority checks each operator route's tier.
const ops=JSON.parse(readFileSync(new URL('../ui/services.json',import.meta.url),'utf8'));
const rows=Object.fromEntries(ops.filter(o=>o.id.startsWith('grants-')).map(o=>[o.id,[o.group,o.admin,o.method,o.upstream_path]]));
assert.deepEqual(rows,{
  'grants-issue-grant':['evidence_store',true,'POST','/admin/grants'],
  'grants-list-grants':['evidence_store',true,'GET','/admin/grants'],
  'grants-get-grant':['evidence_store',true,'GET','/admin/grants/{grant_id}'],
  'grants-list-grant-uses':['evidence_store',true,'GET','/admin/grants/{grant_id}/uses'],
  'grants-revoke-grant':['evidence_store',true,'POST','/admin/grants/{grant_id}/revoke'],
  'grants-time-token':['evidence_store',false,'POST','/grants/time-tokens'],
  'grants-submit-grant-execution':['evidence_store',false,'POST','/evidence/grant-executions'],
});
assert.deepEqual(ops.find(o=>o.id==='grants-list-grants').query,['bearer_key_id','before','limit','status']);
assert.deepEqual(ops.find(o=>o.id==='grants-list-grant-uses').query,['before','limit']);
assert.ok(ops.find(o=>o.id==='evidence_store-search').query.includes('grant_id'));

// Authority text never reaches markup, and app.js routes each answer to its view.
for(const name of ['app.js','grants.js','errors.js']){
  const source=readFileSync(new URL('../ui/'+name,import.meta.url),'utf8');
  assert.doesNotMatch(source,/innerHTML|outerHTML|insertAdjacentHTML|document\.write/,name);
}
const app=readFileSync(new URL('../ui/app.js',import.meta.url),'utf8');
for(const route of ["'grants-list-grants':grantsView","'grants-get-grant':grantView","'grants-list-grant-uses':grantUsesView","'grants-revoke-grant':revocationView",
  "'grants-submit-grant-execution':grantUseView","'evidence_store-resource-head':resourceHeadView","'out_of_band-judge-observation':judgementView",
  "grantChangeDetails(c)","'grants-list-grants':{status:GRANT_FILTERS}"])
  assert.ok(app.includes(route),route);
console.log('Console grant views: grants, a grant with its uses, budget and revocation, uses as resource heads and judgements are text tables.');
