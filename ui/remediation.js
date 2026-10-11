// Changes governed after the fact (Genesis Mesh 1.4.0, Stage 3) in the
// console: the due queue, overdue items, pending reviews, waived items, the
// status counts and a change's remediation. Pure functions of the authority's
// JSON that return tables of plain strings, so tools/test_ui_remediation.mjs
// can check them without a browser; app.js renders them as text nodes.

/** The states the queue lists by default, in the order the console shows them. */
export const QUEUE_STATES=['remediation_due','overdue','review_pending','waived'];
/** Every Stage 3 state (`?state=` accepts each). */
export const STAGE3_STATES=[...QUEUE_STATES,'remediated','upheld','review_denied'];
const TITLES={remediation_due:'Remediation due',overdue:'Overdue',review_pending:'Pending reviews',waived:'Waived',
  remediated:'Remediated',upheld:'Upheld',review_denied:'Review denied'};

const text=v=>v==null?'':String(v);
const words=v=>text(v).replaceAll('_',' ');
const isObject=v=>Boolean(v)&&typeof v==='object'&&!Array.isArray(v);

/** A UTC time as the authority writes it, shortened: `2026-11-02 10:16:00 UTC`. */
export function time(value){
  if(typeof value!=='string'||!value)return '';
  const m=/^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(?:\.\d+)?(?:Z|\+00:00)$/.exec(value);
  return m?m[1]+' '+m[2]+' UTC':value;
}

/** The plan: mode, steps and why a cancel fell back to an alert. */
export function plan(s){
  return [words(s.mode),s.steps&&s.steps!=='none'?words(s.steps):'',s.fallback?'fallback: '+words(s.fallback):'']
    .filter(Boolean).join(' / ');
}

function subject(s){return [s.subject_kind,s.subject_id].filter(v=>v!=null&&v!=='').map(String).join(' ');}
function notified(s){return s.notified_at?time(s.notified_at)+(s.notified_by?' by '+s.notified_by:''):'not yet';}
function requester(review){
  if(!review?.requested_by)return 'the authority';
  return review.requested_by+(review.requester_holder?' ('+review.requester_holder+')':'');
}

// Each state's columns: what an operator acts on for it.
const COLUMNS={
  remediation_due:[['Subject',subject],['Due',s=>time(s.remediation_due_at)],['Plan',plan],['Actor',s=>text(s.actor)],
    ['Resource',s=>text(s.resource_id)],['Notified',notified]],
  overdue:[['Subject',subject],['Overdue since',s=>time(s.overdue_since)],['Due',s=>time(s.remediation_due_at)],['Plan',plan],
    ['Actor',s=>text(s.actor)],['Resource',s=>text(s.resource_id)],['Notified',notified]],
  review_pending:[['Subject',subject],['Opened for',s=>words(s.review?.opened_for)],['Requester',s=>requester(s.review)],
    ['Justification',s=>text(s.review?.justification)],['Lifetime ends',s=>time(s.lifetime_ends_at)],['Actor',s=>text(s.actor)],
    ['Resource',s=>text(s.resource_id)],['Review',s=>text(s.review?.review_id??s.review_id)]],
  waived:[['Subject',subject],['Waived until',s=>time(s.waived_until)],['Then',plan],['Actor',s=>text(s.actor)],
    ['Resource',s=>text(s.resource_id)],['Review',s=>text(s.review_id)]],
};
const OTHER=[['Subject',subject],['State',s=>text(s.state)],['Plan',plan],['Actor',s=>text(s.actor)],['Resource',s=>text(s.resource_id)],
  ['Remediation',s=>text(s.remediation_id)],['Review',s=>text(s.review_id)],['Updated',s=>time(s.updated_at)]];

/** One table per state for remediation states: `{state, caption, headers, rows}`. */
export function stateTables(states){
  const groups=new Map();
  for(const s of states.filter(isObject)){
    const key=COLUMNS[s.state]?s.state:'other';
    if(!groups.has(key))groups.set(key,[]);
    groups.get(key).push(s);
  }
  const order=[...QUEUE_STATES,'other'].filter(k=>groups.has(k));
  return order.map(state=>{
    const columns=COLUMNS[state]||OTHER, rows=groups.get(state);
    const title=TITLES[state]||(new Set(rows.map(r=>r.state)).size===1?TITLES[rows[0].state]||words(rows[0].state):'Other states');
    return {state,caption:title+' ('+rows.length+')',headers:columns.map(c=>c[0]),rows:rows.map(r=>columns.map(c=>c[1](r)))};
  });
}

/** The due queue (`GET /admin/evidence/remediations`): its tables and a note. */
export function queueView(data){
  const states=Array.isArray(data?.remediations)?data.remediations:[];
  const scope=data?.state?(TITLES[data.state]||words(data.state)).toLowerCase():'the open states (due, overdue, pending review, waived)';
  let note=states.length?'':'Nothing in '+scope+'.';
  if(data?.next_after)note='More on the next page: send again with after = '+data.next_after;
  return {tables:stateTables(states),note};
}

/** One remediation state (the answer of get, notice, request and decide). */
export function stateView(data){
  if(!isObject(data)||typeof data.subject_id!=='string'||typeof data.state!=='string')return {tables:[],note:''};
  const reviews=Array.isArray(data.reviews)?data.reviews.length:0;
  return {tables:stateTables([data]),note:reviews?reviews+' review'+(reviews===1?'':'s')+' (see the JSON below).':''};
}

/** `/admin/evidence/status`: the number of remediation states by state. */
export function statusView(data){
  if(!isObject(data))return {tables:[],note:''};
  if(!isObject(data.remediation))
    return {tables:[],note:data.evidence_remediation===false?'Remediation records are off on this authority (EVIDENCE_REMEDIATION).':''};
  const known=STAGE3_STATES.filter(s=>s in data.remediation), extra=Object.keys(data.remediation).filter(s=>!STAGE3_STATES.includes(s));
  const rows=[...known,...extra].map(s=>[TITLES[s]||words(s),text(data.remediation[s])]);
  return {tables:[{state:'status',caption:'Remediation states',headers:['State','Count'],rows}],note:''};
}

/** A change's remediation, in a few words, for the changes table. */
export function remediationSummary(r){
  if(!isObject(r))return '';
  const parts=[];
  if(['remediation_due','overdue','waived'].includes(r.state)||(r.state==='review_pending'&&r.mode))parts.push(plan(r));
  if(r.remediation_due_at&&r.state!=='remediated')parts.push('due '+time(r.remediation_due_at));
  if(r.overdue_since)parts.push('overdue since '+time(r.overdue_since));
  if(r.review?.opened_for)parts.push('review '+words(r.review.opened_for));
  if(r.waived_until)parts.push('waived until '+time(r.waived_until));
  if(r.lifetime_ends_at)parts.push('lifetime ends '+time(r.lifetime_ends_at));
  if(r.remediation_id)parts.push('remediation '+r.remediation_id);
  if(r.notified_at)parts.push('notified '+time(r.notified_at));
  return parts.filter(Boolean).join('; ');
}
