// Changes governed after the fact (Genesis Mesh 1.4.0, Stage 3) in the
// console: the due queue, overdue items, pending reviews, waived items, the
// status counts and a change's remediation. Pure functions of the authority's
// JSON that return tables of plain strings, so tools/test_ui_remediation.mjs
// can check them without a browser; app.js renders them as text nodes.

/** The states a remediation state can hold. A pending review is a flag beside any of them. */
export const STORED_STATES=['judged_allowed','matched','recorded','remediation_due','overdue','remediated','upheld','waived'];
/** Values of the queue's `state` filter: a state, or `review_pending` (the flag, whatever the state). */
export const QUEUE_FILTERS=[...STORED_STATES,'review_pending'];
// The states the default queue lists, in the order the console shows them.
const OPEN_STATES=['remediation_due','overdue','waived'];
const TITLES={judged_allowed:'Judged allowed',matched:'Matched',recorded:'Recorded',remediation_due:'Remediation due',
  overdue:'Overdue',remediated:'Remediated',upheld:'Upheld',waived:'Waived',review_pending:'Pending reviews'};

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
function actor(s){return text(s.actor)+(s.actor_holder?' ('+s.actor_holder+')':'');}
function requester(review){
  if(!review?.requested_by)return 'the authority';
  return review.requested_by+(review.requester_holder?' ('+review.requester_holder+')':'');
}
/** The review flag beside a state: pending (and why), or the latest decided review. */
function review(s){
  if(s.review_pending===true)return 'pending'+(s.review?.opened_for?': '+words(s.review.opened_for):'');
  return s.review_id?'decided ('+s.review_id+')':'';
}

// Each open state's columns: what an operator acts on for it.
const COLUMNS={
  remediation_due:[['Subject',subject],['Due',s=>time(s.remediation_due_at)],['Plan',plan],['Actor',actor],
    ['Resource',s=>text(s.resource_id)],['Notified',notified],['Review',review]],
  overdue:[['Subject',subject],['Overdue since',s=>time(s.overdue_since)],['Due',s=>time(s.remediation_due_at)],['Plan',plan],
    ['Actor',actor],['Resource',s=>text(s.resource_id)],['Notified',notified],['Review',review]],
  waived:[['Subject',subject],['Waived until',s=>time(s.waived_until)],['Then',plan],['Actor',actor],
    ['Resource',s=>text(s.resource_id)],['Review',review]],
};
const OTHER=[['Subject',subject],['State',s=>text(s.state)],['Review',review],['Plan',plan],['Actor',actor],
  ['Resource',s=>text(s.resource_id)],['Remediation',s=>text(s.remediation_id)],['Updated',s=>time(s.updated_at)]];
const REVIEWS=[['Subject',subject],['State',s=>text(s.state)],['Opened for',s=>words(s.review?.opened_for)],['Requester',s=>requester(s.review)],
  ['Justification',s=>text(s.review?.justification)],['Lifetime ends',s=>time(s.lifetime_ends_at)],['Actor',actor],
  ['Resource',s=>text(s.resource_id)],['Review',s=>text(s.review?.review_id??s.review_id)]];

function table(state,caption,columns,rows){
  return {state,caption:caption+' ('+rows.length+')',headers:columns.map(c=>c[0]),rows:rows.map(r=>columns.map(c=>c[1](r)))};
}

/** One table per state, each item's review flag beside its state: `{state, caption, headers, rows}`. */
export function stateTables(states){
  const groups=new Map();
  for(const s of states.filter(isObject)){
    const key=COLUMNS[s.state]?s.state:'other';
    if(!groups.has(key))groups.set(key,[]);
    groups.get(key).push(s);
  }
  return [...OPEN_STATES,'other'].filter(k=>groups.has(k)).map(state=>{
    const rows=groups.get(state);
    const title=TITLES[state]||(new Set(rows.map(r=>r.state)).size===1?TITLES[rows[0].state]||words(rows[0].state):'Other states');
    return table(state,title,COLUMNS[state]||OTHER,rows);
  });
}

/** The items with a pending review, whatever their state, with the request. */
export function reviewTable(states){
  const rows=states.filter(s=>isObject(s)&&s.review_pending===true);
  return rows.length?[table('review_pending',TITLES.review_pending,REVIEWS,rows)]:[];
}

/**
 * The due queue (`GET /admin/evidence/remediations`): its tables and a note.
 * `state=review_pending` filters on the flag, so it shows the reviews table
 * only; the default queue (due, overdue, waived, and any item with a pending
 * review) shows the state tables, then the pending reviews again with their requests.
 */
export function queueView(data){
  const states=Array.isArray(data?.remediations)?data.remediations.filter(isObject):[];
  const scope=data?.state?(TITLES[data.state]||words(data.state)).toLowerCase():'the open states (due, overdue, waived) or under review';
  let note=states.length?'':'Nothing in '+scope+'.';
  if(data?.next_after)note='More on the next page: send again with after = '+data.next_after;
  if(data?.state==='review_pending')return {tables:reviewTable(states),note};
  return {tables:[...stateTables(states),...(data?.state?[]:reviewTable(states))],note};
}

/** One remediation state (the answer of get, notice, request and decide). */
export function stateView(data){
  if(!isObject(data)||typeof data.subject_id!=='string'||typeof data.state!=='string')return {tables:[],note:''};
  const notes=[];
  for(const [field,truncated,name] of [['reviews','reviews_truncated','review'],['records','records_truncated','record']]){
    const n=Array.isArray(data[field])?data[field].length:0;
    if(data[truncated]===true)notes.push('The newest '+n+' '+name+'s; older ones are not shown.');
    else if(n)notes.push(n+' '+name+(n===1?'':'s')+' (see the JSON below).');
  }
  return {tables:[...stateTables([data]),...reviewTable([data])],note:notes.join(' ')};
}

/** `/admin/evidence/status`: the number of remediation states by state, and of pending reviews. */
export function statusView(data){
  if(!isObject(data))return {tables:[],note:''};
  if(!isObject(data.remediation))
    return {tables:[],note:data.evidence_remediation===false?'Remediation records are off on this authority (EVIDENCE_REMEDIATION).':''};
  const known=QUEUE_FILTERS.filter(s=>s in data.remediation), extra=Object.keys(data.remediation).filter(s=>!QUEUE_FILTERS.includes(s));
  const rows=[...known,...extra].map(s=>[TITLES[s]||words(s),text(data.remediation[s])]);
  return {tables:[{state:'status',caption:'Remediation states',headers:['State','Count'],rows}],
    note:'A pending review sits beside a state, so it is counted twice: under its state and under pending reviews.'};
}

/** A change's remediation, in a few words, for the changes table. */
export function remediationSummary(r){
  if(!isObject(r))return '';
  const parts=[];
  if(OPEN_STATES.includes(r.state))parts.push(plan(r));
  if(r.remediation_due_at&&r.state!=='remediated')parts.push('due '+time(r.remediation_due_at));
  if(r.overdue_since)parts.push('overdue since '+time(r.overdue_since));
  if(r.review_pending===true)parts.push('review '+review(r));
  if(r.waived_until)parts.push('waived until '+time(r.waived_until));
  if(r.lifetime_ends_at)parts.push('lifetime ends '+time(r.lifetime_ends_at));
  if(r.remediation_id)parts.push('remediation '+r.remediation_id);
  if(r.notified_at)parts.push('notified '+time(r.notified_at));
  return parts.filter(Boolean).join('; ');
}

/** The note under a page of a resource's changes (paged from 1.4.0). */
export function changesNote(data){
  if(!data?.truncated)return '';
  const next=data.next_after_sequence;
  return Number.isSafeInteger(next)?'More on the next page: send again with after_sequence = '+next:'The resource has more changes than one response holds.';
}
