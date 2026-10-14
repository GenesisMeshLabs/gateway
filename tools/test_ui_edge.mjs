// The console's edge node views (Genesis Mesh 1.7.0): the edge node list
// with its status filter and paging, and the revocation of an edge node.
// Their input is authority data, rendered as text only. The node-scoped
// routes an edge agent signs are not in the catalog.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const load=async name=>import('data:text/javascript;base64,'+Buffer.from(readFileSync(new URL('../ui/'+name,import.meta.url),'utf8')).toString('base64'));
const {EDGE_FILTERS,edgeNodesView,edgeRevocationView}=await load('edge.js');
const {explainFailure}=await load('errors.js');

const strings=view=>{for(const t of view.tables)for(const r of t.rows){assert.equal(r.length,t.headers.length);for(const c of r)assert.equal(typeof c,'string');}};

// An edge node as GET /admin/edge-nodes writes it (the core writes times as isoformat, +00:00).
const online={node_public_key:'nodeKeyA+/=',node_sovereign_id:'site7-17',executor_key_id:'edge-3f1c0d4e9a7b2c6d8e0f1a2b3c4d5e6f',
  resource_prefix:'edge:site7-17/',roles:['role:client'],status:'online',enrolled_at:'2026-10-14T09:00:00.000000+00:00',
  cert_id:'c-1',cert_expires_at:'2026-10-21T09:00:00.000000+00:00',last_seen_at:'2026-10-14T09:29:40.123456+00:00',remote_addr:'203.0.113.17',
  agent:{version:'1.7.0',snapshot_age_seconds:7500,pending_uploads:12,dead_letters:3,reported_at:'2026-10-14T09:29:40.000000+00:00'},
  grants:{usable:2,admitted_uses:7},break_glass:{records:1,last_executed_at:'2026-10-13T22:10:05Z'},revoked_at:null,revocation_reason:null};
// A revoked node whose authority text tries to be markup, with grants and the store off and no heartbeat yet.
const revoked={...online,node_public_key:'<img src=x onerror=alert(1)>',node_sovereign_id:'<b>site</b>',status:'revoked',
  last_seen_at:null,remote_addr:null,agent:null,grants:null,break_glass:null,
  revoked_at:'2026-10-14T10:00:00+00:00',revocation_reason:'key_compromise'};

assert.deepEqual(EDGE_FILTERS,['online','offline','revoked']);
// The views read the time now from their caller: half a minute after the heartbeat.
const NOW=Date.parse('2026-10-14T09:30:10Z');
let view=edgeNodesView({count:3,next_before:null,edge_nodes:[online,revoked,'not a node']},NOW);
assert.deepEqual(view.tables.map(t=>t.caption),['Edge nodes (2)']);
assert.deepEqual(view.tables[0].headers,['Node','Sovereign','Executor key','Resource prefix','Status','Certificate','Last seen',
  'Snapshot age','Pending uploads','Grants in use','Break-glass uses','Agent']);
assert.deepEqual(view.tables[0].rows[0],['nodeKeyA+/=','site7-17','edge-3f1c0d4e9a7b2c6d8e0f1a2b3c4d5e6f','edge:site7-17/','online',
  'c-1 (expires 2026-10-21 09:00:00 UTC)','2026-10-14 09:29:40 UTC from 203.0.113.17',
  '2 h 5 min (reported 2026-10-14 09:29:40 UTC)','12 (3 dead letters)','2 usable, 7 uses','1 (last 2026-10-13 22:10:05 UTC)','1.7.0']);
// Authority text stays text; null agent and null counts are empty cells.
assert.deepEqual(view.tables[0].rows[1],['<img src=x onerror=alert(1)>','<b>site</b>','edge-3f1c0d4e9a7b2c6d8e0f1a2b3c4d5e6f','edge:site7-17/',
  'revoked 2026-10-14 10:00:00 UTC (key compromise)','c-1 (expires 2026-10-21 09:00:00 UTC)','','','','','','']);
assert.equal(view.note,'');
strings(view);

// Durations, singular counts, no dead letters, an agent without a snapshot yet, zero counts.
const row=(n,now=NOW)=>edgeNodesView({edge_nodes:[n],next_before:null},now).tables[0].rows[0];
for(const [age,shown] of [[0,'0 s'],[42,'42 s'],[125,'2 min 5 s'],[3600,'1 h'],[90061,'1 d 1 h']])
  assert.equal(row({...online,agent:{...online.agent,snapshot_age_seconds:age}})[7],shown+' (reported 2026-10-14 09:29:40 UTC)');
let r=row({...online,agent:{version:'1.7.0',snapshot_age_seconds:null,pending_uploads:0,dead_letters:0,reported_at:'2026-10-14T09:29:40Z'},
  grants:{usable:1,admitted_uses:1},break_glass:{records:0,last_executed_at:null}});
assert.deepEqual(r.slice(7),['no snapshot (reported 2026-10-14 09:29:40 UTC)','0','1 usable, 1 use','0','1.7.0']);
assert.equal(row({...online,agent:{...online.agent,dead_letters:1}})[8],'12 (1 dead letter)');
// An agent block with dropped or badly typed values leaves those cells empty.
r=row({...online,agent:{version:null,snapshot_age_seconds:'42',pending_uploads:-1,reported_at:null},grants:{usable:null,admitted_uses:3}});
assert.deepEqual(r.slice(7,12),['no snapshot','','','1 (last 2026-10-13 22:10:05 UTC)','']);
// An offline node keeps its last heartbeat.
assert.deepEqual(row({...online,status:'offline'}).slice(4,7),['offline','c-1 (expires 2026-10-21 09:00:00 UTC)',
  '2026-10-14 09:29:40 UTC from 203.0.113.17']);
// A node whose newest certificate expired is not merely offline: it must enrol again. Z and +00:00 both read.
const lapsed={...online,status:'offline',cert_expires_at:'2026-10-14T09:00:00.000000+00:00'};
view=edgeNodesView({edge_nodes:[lapsed],next_before:null},NOW);
assert.deepEqual(view.tables[0].rows[0].slice(4,6),['certificate expired','c-1 (expired 2026-10-14 09:00:00 UTC)']);
assert.match(view.note,/^A node whose certificate expired is refused at heartbeats and renewals until it enrols again;/);
assert.equal(row({...lapsed,cert_expires_at:'2026-10-14T09:30:10Z'})[4],'certificate expired');
assert.equal(row({...lapsed,cert_expires_at:'2026-10-14T09:30:11Z'})[4],'offline');
// A revoked node stays revoked; its certificate says it expired.
assert.deepEqual(row({...revoked,cert_expires_at:lapsed.cert_expires_at}).slice(4,6),
  ['revoked 2026-10-14 10:00:00 UTC (key compromise)','c-1 (expired 2026-10-14 09:00:00 UTC)']);
// No certificate (not yet issued) or an unreadable expiry: no expiry claimed.
assert.deepEqual(row({...online,cert_id:null,cert_expires_at:null}).slice(4,6),['online','']);
assert.deepEqual(row({...online,cert_expires_at:'next week'}).slice(4,6),['online','c-1 (expires next week)']);
// Without a time from its caller, the view reads the clock.
assert.equal(edgeNodesView({edge_nodes:[lapsed],next_before:null}).tables[0].rows[0][4],'certificate expired');

// Paging: next_before is the node_public_key of the page's last node.
view=edgeNodesView({count:1,next_before:'nodeKeyA+/=',edge_nodes:[online]},NOW);
assert.equal(view.note,'More on the next page: send again with before = nodeKeyA+/=');
assert.deepEqual(edgeNodesView({count:0,next_before:null,edge_nodes:[]}),{tables:[],note:'No edge nodes match.'});

// POST /admin/revoke of an edge node's certificate: every certificate, the executor key and its grants.
const revocation={crl_sequence:12,revoked_count:3,edge_node:{node_public_key:'nodeKeyA+/=',executor_key_id:online.executor_key_id,
  revoked_cert_ids:['c-1','c-2'],executor_key_retired:true,grants_revoked:2}};
view=edgeRevocationView(revocation);
assert.deepEqual(view.tables.map(t=>t.caption),['Revoked edge node nodeKeyA+/=']);
assert.deepEqual(view.tables[0].rows,[['CRL sequence','12'],['Certificates revoked','2: c-1, c-2'],['Executor key',online.executor_key_id],
  ['Executor key retired','yes'],['Grants revoked','2']]);
assert.match(view.note,/revocation feed lists them \(revoked_grant_ids\)\.$/);
strings(view);
// Idempotent: a second call revokes nothing more.
view=edgeRevocationView({...revocation,edge_node:{...revocation.edge_node,revoked_cert_ids:[],grants_revoked:0}});
assert.deepEqual(view.tables[0].rows.slice(1,2),[['Certificates revoked','0']]);
assert.equal(view.note,'The node was already revoked: nothing changed.');
// The key could not be retired: the certificates stay revoked, the authority retires the key when it next starts.
view=edgeRevocationView({...revocation,edge_node:{...revocation.edge_node,executor_key_retired:false,grants_revoked:0}});
assert.deepEqual(view.tables[0].rows[3],['Executor key retired','no']);
assert.match(view.note,/could not retire the executor key yet: it retires it when it next starts\./);
// Any other certificate's revocation has no edge_node: no table, as before 1.7.0.
assert.deepEqual(edgeRevocationView({crl_sequence:12,revoked_count:1}),{tables:[],note:''});

// Anything else shows nothing.
for(const data of [undefined,null,'text',[],{error:{code:'invalid_edge_status'}},{edge_nodes:'none'},{edge_node:'x'}]){
  for(const f of [edgeNodesView,edgeRevocationView])assert.deepEqual(f(data),{tables:[],note:''},f.name);
}

// Refusals of edge invites, enrolment and the list, explained.
const authority=(code)=>({error:{code,message:'x'}});
assert.match(explainFailure(400,authority('invalid_edge_invite'),{}),/needs both node_sovereign_id and executor_resource_prefix/);
assert.match(explainFailure(400,authority('invalid_node_sovereign_id'),{}),/^node_sovereign_id must be 1 to 64 characters/);
assert.match(explainFailure(409,authority('edge_requires_evidence_store'),{}),/EVIDENCE_STORE=on and EVIDENCE_OUT_OF_BAND=on\.$/);
assert.match(explainFailure(409,authority('node_sovereign_in_use'),{}),
  /^This node_sovereign_id is in use: by an active edge node, an outstanding edge invite, another executor key or the subject of an attestation/);
assert.match(explainFailure(400,authority('invalid_resource_prefix'),{}),/1 to 256 characters\. .*ends with \/ or :, for example edge:site7-17\/\.$/);
assert.match(explainFailure(409,authority('resource_prefix_overlap'),{}),/^The resource prefix overlaps the prefix of an active executor key or an outstanding edge invite/);
// Retiring an edge node's key directly is refused: the node is revoked instead.
assert.match(explainFailure(409,authority('executor_key_is_edge_node'),{}),/belongs to an active edge node\. Revoke the node with Revoke certificate/);
// A revoked edge node at /renew or /heartbeat (403): explained, not the generic refusal.
assert.match(explainFailure(403,authority('edge_node_retired'),{}),/^The authority revoked this edge node: its node key is refused whatever certificate it presents\./);
assert.match(explainFailure(400,authority('invalid_edge_status'),{}),/online, offline or revoked/);
// An edge invite needs the privileged tier: the existing tier explanation.
assert.match(explainFailure(403,authority('insufficient_operator_tier'),{}),/tier does not allow/);

// The catalog: the operator list is a network operation read like the node roster; the node-signed routes are not forwarded.
const ops=JSON.parse(readFileSync(new URL('../ui/services.json',import.meta.url),'utf8'));
const edge=ops.filter(o=>o.id.startsWith('edge-'));
assert.deepEqual(edge.map(o=>[o.id,o.group,o.admin,o.method,o.upstream_path,o.query,o.body]),
  [['edge-list-edge-nodes','network',true,'GET','/admin/edge-nodes',['before','limit','node_sovereign_id','status'],null]]);
assert.equal(ops.find(o=>o.id==='health-list-nodes').group,'network');
for(const path of ['/node/boundary/evaluate','/node/state','/node/evidence/resource-head'])
  assert.ok(ops.every(o=>o.upstream_path!==path&&!o.upstream_path.startsWith('/node/')),path);
const spec=readFileSync(new URL('../ui/openapi.json',import.meta.url),'utf8');
assert.ok(spec.includes('/services/edge-list-edge-nodes'));
assert.doesNotMatch(spec,/Upstream: \/node\//);

// Authority text never reaches markup, and app.js routes each answer to its view.
for(const name of ['app.js','edge.js','errors.js']){
  const source=readFileSync(new URL('../ui/'+name,import.meta.url),'utf8');
  assert.doesNotMatch(source,/innerHTML|outerHTML|insertAdjacentHTML|document\.write/,name);
}
const app=readFileSync(new URL('../ui/app.js',import.meta.url),'utf8');
for(const route of ["from './edge.js'","'edge-list-edge-nodes':edgeNodesView","'admin-revoke-certificate':edgeRevocationView",
  "'edge-list-edge-nodes':{status:EDGE_FILTERS}"])
  assert.ok(app.includes(route),route);
// The public mesh view stays unchanged: it knows nothing of edge nodes.
assert.doesNotMatch(readFileSync(new URL('../ui/mesh.js',import.meta.url),'utf8'),/edge.node|edge-nodes/i);
console.log('Console edge node views: the edge node list, its filter and paging, and an edge node\'s revocation are text tables.');
