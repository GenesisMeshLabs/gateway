// The console's Stage 3 views (Genesis Mesh 1.4.0): the due queue, overdue
// items, pending reviews, waived items, status counts, a change's remediation
// and the tour step. Their input is authority data, rendered as text only.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const load=async name=>import('data:text/javascript;base64,'+Buffer.from(readFileSync(new URL('../ui/'+name,import.meta.url),'utf8')).toString('base64'));
const {QUEUE_FILTERS,STORED_STATES,changesNote,plan,queueView,remediationSummary,stateView,statusView,time}=await load('remediation.js');
const {afterTheFactSteps}=await load('tour.js');

const at='2026-11-02T10:16:00.000000+00:00';
const base={subject_kind:'judgement',change_kind:'observation',change_id:'o-1',change_version_id:null,resource_id:'kv:vault/zoë',
  capability:'secrets.rotate',actor:'alice@example.org',actor_holder:'Alice',verdict:'deny',mode:'cancel',steps:'rotate_forward_then_disable',
  fallback:null,grace_seconds:3600,guidance_source:'gate',remediation_due_at:at,lifetime_ends_at:null,waived_until:null,review_id:null,
  remediation_id:null,notified_at:null,notified_by:null,overdue_since:null,created_at:at,updated_at:at,review_pending:false};
const request={review_id:'r-1',opened_for:'requested',requested_by:'operator-2',requester_holder:'Bob',
  justification:'<img src=x onerror=alert(1)> was planned',requested_at:at,decided_at:null,verdict:null};
const due={...base,subject_id:'j-due',state:'remediation_due',notified_at:'2026-11-02T10:20:00.000000+00:00',notified_by:'operator-1'};
// A pending review is a flag beside any state: here an overdue item and an allowed emergency change.
const overdue={...base,subject_id:'j-over',state:'overdue',mode:'alert_only',steps:'none',fallback:'not_rotatable',
  overdue_since:'2026-11-02T11:16:00.000000+00:00',review_pending:true,review_id:'r-1',review:{...request,subject_id:'j-over'}};
const allowed={...base,subject_id:'j-ok',state:'judged_allowed',verdict:'allow',mode:null,steps:null,remediation_due_at:null,
  lifetime_ends_at:'2026-11-03T10:16:00.000000+00:00',review_pending:true,review_id:'r-2',
  review:{...request,review_id:'r-2',subject_id:'j-ok',opened_for:'review_required',requested_by:null,requester_holder:null,justification:null}};
const waived={...base,subject_id:'j-wai',state:'waived',review_id:'r-0',waived_until:'2026-11-09T00:00:00.000000+00:00'};

assert.deepEqual(STORED_STATES,['judged_allowed','matched','recorded','remediation_due','overdue','remediated','upheld','waived']);
assert.deepEqual(QUEUE_FILTERS,[...STORED_STATES,'review_pending']);
assert.equal(time(at),'2026-11-02 10:16:00 UTC');
assert.equal(time('2026-11-02T10:16:00Z'),'2026-11-02 10:16:00 UTC');
assert.equal(time('not a time'),'not a time');
assert.equal(time(null),'');
assert.equal(plan(due),'cancel / rotate forward then disable');
assert.equal(plan(overdue),'alert only / fallback: not rotatable');
assert.equal(plan({mode:'alert_only',steps:'none',fallback:'not_executed'}),'alert only / fallback: not executed');

// The default queue: one table per open state in the console's order, each item's review flag beside
// its state; other states together; then every pending review again, with its request.
let view=queueView({state:null,count:4,remediations:[waived,allowed,overdue,due],next_after:null});
assert.deepEqual(view.tables.map(t=>t.caption),['Remediation due (1)','Overdue (1)','Waived (1)','Judged allowed (1)','Pending reviews (2)']);
assert.equal(view.note,'');
const [dueT,overT,waiT,otherT,revT]=view.tables;
assert.deepEqual(dueT.headers,['Subject','Due','Plan','Actor','Resource','Notified','Review']);
assert.deepEqual(dueT.rows[0],['judgement j-due','2026-11-02 10:16:00 UTC','cancel / rotate forward then disable','alice@example.org (Alice)','kv:vault/zoë','2026-11-02 10:20:00 UTC by operator-1','']);
assert.deepEqual(overT.headers.slice(0,2),['Subject','Overdue since']);
assert.equal(overT.rows[0][1],'2026-11-02 11:16:00 UTC');
assert.equal(overT.rows[0][6],'not yet');
assert.equal(overT.rows[0][7],'pending: requested');
assert.deepEqual(waiT.rows[0].slice(0,2),['judgement j-wai','2026-11-09 00:00:00 UTC']);
assert.equal(waiT.rows[0][5],'decided (r-0)');
assert.deepEqual(otherT.rows[0].slice(1,3),['judged_allowed','pending: review required']);
assert.deepEqual(revT.headers,['Subject','State','Opened for','Requester','Justification','Lifetime ends','Actor','Resource','Review']);
assert.deepEqual(revT.rows[0].slice(1,6),['judged_allowed','review required','the authority','','2026-11-03 10:16:00 UTC']);
assert.deepEqual(revT.rows[1].slice(1,5),['overdue','requested','operator-2 (Bob)','<img src=x onerror=alert(1)> was planned']);
// Every cell is a string: app.js puts them in text nodes.
for(const t of view.tables)for(const r of t.rows){assert.equal(r.length,t.headers.length);for(const c of r)assert.equal(typeof c,'string');}

// state=review_pending filters on the flag: the reviews table only, whatever the states.
view=queueView({state:'review_pending',count:2,remediations:[overdue,allowed],next_after:null});
assert.deepEqual(view.tables.map(t=>t.caption),['Pending reviews (2)']);
// A state filter shows that state, flagged or not, and no reviews table.
view=queueView({state:'overdue',count:1,remediations:[overdue],next_after:'2026-11-02T10:16:00.000000Z|j-over'});
assert.deepEqual(view.tables.map(t=>t.caption),['Overdue (1)']);
assert.match(view.note,/after = 2026-11-02T10:16:00.000000Z\|j-over$/);
assert.equal(queueView({state:'waived',count:0,remediations:[],next_after:null}).note,'Nothing in waived.');
assert.equal(queueView({state:'review_pending',remediations:[]}).note,'Nothing in pending reviews.');
assert.match(queueView({state:null,remediations:[]}).note,/the open states/);
view=queueView({state:'remediated',remediations:[{...base,subject_id:'j-done',state:'remediated',remediation_id:'m-1'}]});
assert.equal(view.tables[0].caption,'Remediated (1)');
assert.equal(view.tables[0].rows[0][view.tables[0].headers.indexOf('State')],'remediated');
assert.equal(view.tables[0].rows[0][view.tables[0].headers.indexOf('Remediation')],'m-1');
assert.deepEqual(queueView({error:{code:'remediation_disabled'}}).tables,[]);

// One subject's state (get, notice, request and decide answer with it), and the detail's truncation.
view=stateView({...overdue,reviews:[request],reviews_truncated:false,records:[],records_truncated:false});
assert.deepEqual(view.tables.map(t=>t.caption),['Overdue (1)','Pending reviews (1)']);
assert.equal(view.note,'1 review (see the JSON below).');
view=stateView({...due,reviews:Array(100).fill(request),reviews_truncated:true,records:Array(100).fill({}),records_truncated:true});
assert.equal(view.note,'The newest 100 reviews; older ones are not shown. The newest 100 records; older ones are not shown.');
assert.deepEqual(stateView({review_id:'r-1'}).tables,[]);

// Status counts (with pending reviews), the switch off, and an older authority.
view=statusView({evidence_remediation:true,remediation:{judged_allowed:5,matched:0,recorded:2,remediation_due:2,overdue:1,remediated:4,upheld:0,waived:1,review_pending:3}});
assert.deepEqual(view.tables[0].headers,['State','Count']);
assert.deepEqual(view.tables[0].rows,[['Judged allowed','5'],['Matched','0'],['Recorded','2'],['Remediation due','2'],['Overdue','1'],
  ['Remediated','4'],['Upheld','0'],['Waived','1'],['Pending reviews','3']]);
assert.match(view.note,/counted twice/);
assert.match(statusView({evidence_remediation:false}).note,/EVIDENCE_REMEDIATION/);
assert.deepEqual(statusView({evidence_store:true}),{tables:[],note:''});

// A change's remediation in the changes table, and its paging.
assert.equal(remediationSummary(due),'cancel / rotate forward then disable; due 2026-11-02 10:16:00 UTC; notified 2026-11-02 10:20:00 UTC');
assert.equal(remediationSummary({...base,state:'remediated',remediation_id:'m-1'}),'remediation m-1');
assert.equal(remediationSummary(overdue),'alert only / fallback: not rotatable; due 2026-11-02 10:16:00 UTC; overdue since 2026-11-02 11:16:00 UTC; review pending: requested');
assert.equal(remediationSummary(allowed),'review pending: review required; lifetime ends 2026-11-03 10:16:00 UTC');
assert.equal(remediationSummary(undefined),'');
assert.equal(changesNote({truncated:true,next_after_sequence:1042}),'More on the next page: send again with after_sequence = 1042');
assert.equal(changesNote({truncated:true}),'The resource has more changes than one response holds.');
assert.equal(changesNote({truncated:false,next_after_sequence:null}),'');

// The tour step: counts when the records are on, a note when off, and the gateway's operations.
const ops=JSON.parse(readFileSync(new URL('../ui/services.json',import.meta.url),'utf8'));
let steps=afterTheFactSteps({evidence_remediation:true,remediation:{remediation_due:2,overdue:1,review_pending:1,waived:0,remediated:3,upheld:1}},ops,'gm-demo');
assert.equal(steps.length,4);
assert.deepEqual(steps[1],[true,'Remediation records are on at gm-demo','2 due, 1 overdue, 1 pending review, 0 waived, 3 remediated, 1 upheld']);
assert.deepEqual(steps[2].slice(0,2),[true,'This gateway forwards 7 of 7 remediation and review operations']);
steps=afterTheFactSteps({evidence_remediation:false},ops.filter(o=>o.id!=='remediation-decide-review'));
assert.deepEqual(steps[1].slice(0,2),[null,'Remediation records are off']);
assert.deepEqual(steps[2].slice(0,2),[false,'This gateway forwards 6 of 7 remediation and review operations']);
assert.equal(afterTheFactSteps(undefined,ops)[1][1],'This deployment publishes no authority status');

// The catalog: the remediation operations are evidence-store operations; the queue and the
// changes view take their paging query.
for(const o of ops.filter(o=>o.id.startsWith('remediation-')))assert.equal(o.group,'evidence_store',o.id);
assert.deepEqual(ops.find(o=>o.id==='remediation-due-queue').query,['after','limit','state']);
assert.deepEqual(ops.find(o=>o.id==='out_of_band-resource-changes').query,['after_sequence','limit']);

// Authority text never reaches markup.
for(const name of ['app.js','remediation.js','tour.js']){
  const source=readFileSync(new URL('../ui/'+name,import.meta.url),'utf8');
  assert.doesNotMatch(source,/innerHTML|outerHTML|insertAdjacentHTML|document\.write/,name);
}
console.log('Console remediation views: queue, overdue, reviews, waivers, counts, changes and the tour step are text tables.');
