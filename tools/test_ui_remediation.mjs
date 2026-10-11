// The console's Stage 3 views (Genesis Mesh 1.4.0): the due queue, overdue
// items, pending reviews, waived items, status counts, a change's remediation
// and the tour step. Their input is authority data, rendered as text only.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const load=async name=>import('data:text/javascript;base64,'+Buffer.from(readFileSync(new URL('../ui/'+name,import.meta.url),'utf8')).toString('base64'));
const {QUEUE_STATES,STAGE3_STATES,plan,queueView,remediationSummary,stateView,statusView,time}=await load('remediation.js');
const {afterTheFactSteps}=await load('tour.js');

const at='2026-11-02T10:16:00.000000+00:00';
const base={subject_kind:'judgement',change_kind:'observation',change_id:'o-1',resource_id:'kv:vault/zoë',capability:'secrets.rotate',
  actor:'alice@example.org',verdict:'deny',mode:'cancel',steps:'rotate_forward_then_disable',fallback:null,grace_seconds:3600,
  guidance_source:'gate',remediation_due_at:at,lifetime_ends_at:null,waived_until:null,review_id:null,remediation_id:null,
  notified_at:null,notified_by:null,overdue_since:null,created_at:at,updated_at:at};
const due={...base,subject_id:'j-due',state:'remediation_due',notified_at:'2026-11-02T10:20:00.000000+00:00',notified_by:'operator-1'};
const overdue={...base,subject_id:'j-over',state:'overdue',mode:'alert_only',steps:'none',fallback:'not_rotatable',overdue_since:'2026-11-02T11:16:00.000000+00:00'};
const pending={...base,subject_id:'j-rev',state:'review_pending',review_id:'r-1',lifetime_ends_at:'2026-11-03T10:16:00.000000+00:00',
  review:{review_id:'r-1',subject_id:'j-rev',opened_for:'requested',requested_by:'operator-2',requester_holder:'Bob',
    justification:'<img src=x onerror=alert(1)> was planned',requested_at:at,decided_at:null,verdict:null}};
const flagged={...pending,subject_id:'j-flag',review:{...pending.review,opened_for:'flagged_for_review',requested_by:null,requester_holder:null,justification:null}};
const waived={...base,subject_id:'j-wai',state:'waived',review_id:'r-0',waived_until:'2026-11-09T00:00:00.000000+00:00'};

assert.deepEqual(QUEUE_STATES,['remediation_due','overdue','review_pending','waived']);
assert.equal(STAGE3_STATES.length,7);
assert.equal(time(at),'2026-11-02 10:16:00 UTC');
assert.equal(time('2026-11-02T10:16:00Z'),'2026-11-02 10:16:00 UTC');
assert.equal(time('not a time'),'not a time');
assert.equal(time(null),'');
assert.equal(plan(due),'cancel / rotate forward then disable');
assert.equal(plan(overdue),'alert only / fallback: not rotatable');

// The default queue: one captioned table per open state, in the console's order, whatever the authority's.
let view=queueView({state:null,count:5,remediations:[waived,pending,overdue,due,flagged],next_after:null});
assert.deepEqual(view.tables.map(t=>t.caption),['Remediation due (1)','Overdue (1)','Pending reviews (2)','Waived (1)']);
assert.equal(view.note,'');
const [dueT,overT,revT,waiT]=view.tables;
assert.deepEqual(dueT.headers,['Subject','Due','Plan','Actor','Resource','Notified']);
assert.deepEqual(dueT.rows[0],['judgement j-due','2026-11-02 10:16:00 UTC','cancel / rotate forward then disable','alice@example.org','kv:vault/zoë','2026-11-02 10:20:00 UTC by operator-1']);
assert.deepEqual(overT.headers.slice(0,2),['Subject','Overdue since']);
assert.equal(overT.rows[0][1],'2026-11-02 11:16:00 UTC');
assert.equal(overT.rows[0][6],'not yet');
assert.deepEqual(revT.headers,['Subject','Opened for','Requester','Justification','Lifetime ends','Actor','Resource','Review']);
assert.deepEqual(revT.rows[0].slice(1,5),['requested','operator-2 (Bob)','<img src=x onerror=alert(1)> was planned','2026-11-03 10:16:00 UTC']);
assert.deepEqual(revT.rows[1].slice(1,4),['flagged for review','the authority','']);
assert.deepEqual(waiT.rows[0].slice(0,2),['judgement j-wai','2026-11-09 00:00:00 UTC']);
// Every cell is a string: app.js puts them in text nodes.
for(const t of view.tables)for(const r of t.rows){assert.equal(r.length,t.headers.length);for(const c of r)assert.equal(typeof c,'string');}

// A filtered page with more to come; an empty one; other states in one table with their state.
view=queueView({state:'overdue',count:1,remediations:[overdue],next_after:'2026-11-02T10:16:00.000000Z|j-over'});
assert.match(view.note,/after = 2026-11-02T10:16:00.000000Z\|j-over$/);
assert.equal(queueView({state:'waived',count:0,remediations:[],next_after:null}).note,'Nothing in waived.');
assert.match(queueView({state:null,remediations:[]}).note,/the open states/);
view=queueView({state:'remediated',remediations:[{...base,subject_id:'j-done',state:'remediated',remediation_id:'m-1'}]});
assert.equal(view.tables[0].caption,'Remediated (1)');
assert.equal(view.tables[0].rows[0][view.tables[0].headers.indexOf('State')],'remediated');
assert.equal(view.tables[0].rows[0][view.tables[0].headers.indexOf('Remediation')],'m-1');
assert.deepEqual(queueView({error:{code:'remediation_disabled'}}).tables,[]);

// One subject's state (get, notice, request and decide answer with it).
view=stateView({...pending,reviews:[pending.review],records:[]});
assert.equal(view.tables[0].caption,'Pending reviews (1)');
assert.equal(view.note,'1 review (see the JSON below).');
assert.deepEqual(stateView({review_id:'r-1'}).tables,[]);

// Status counts, the switch off, and an older authority.
view=statusView({evidence_remediation:true,remediation:{remediation_due:2,overdue:1,remediated:4,review_pending:0,upheld:0,waived:1}});
assert.deepEqual(view.tables[0].headers,['State','Count']);
assert.deepEqual(view.tables[0].rows,[['Remediation due','2'],['Overdue','1'],['Pending reviews','0'],['Waived','1'],['Remediated','4'],['Upheld','0']]);
assert.match(statusView({evidence_remediation:false}).note,/EVIDENCE_REMEDIATION/);
assert.deepEqual(statusView({evidence_store:true}),{tables:[],note:''});

// A change's remediation in the changes table.
assert.equal(remediationSummary(due),'cancel / rotate forward then disable; due 2026-11-02 10:16:00 UTC; notified 2026-11-02 10:20:00 UTC');
assert.equal(remediationSummary({...base,state:'remediated',remediation_id:'m-1'}),'remediation m-1');
assert.equal(remediationSummary(pending),'cancel / rotate forward then disable; due 2026-11-02 10:16:00 UTC; review requested; lifetime ends 2026-11-03 10:16:00 UTC');
assert.equal(remediationSummary(undefined),'');

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

// The catalog's remediation operations are evidence-store operations.
for(const o of ops.filter(o=>o.id.startsWith('remediation-')))assert.equal(o.group,'evidence_store',o.id);

// Authority text never reaches markup.
for(const name of ['app.js','remediation.js','tour.js']){
  const source=readFileSync(new URL('../ui/'+name,import.meta.url),'utf8');
  assert.doesNotMatch(source,/innerHTML|outerHTML|insertAdjacentHTML|document\.write/,name);
}
console.log('Console remediation views: queue, overdue, reviews, waivers, counts, changes and the tour step are text tables.');
