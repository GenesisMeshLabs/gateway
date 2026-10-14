// Pre-issued grants (Genesis Mesh 1.6.0, Stage 5) in the console: the grants
// an authority issued, one grant with its uses, remaining budget and
// revocation, an issued or revoked grant, a time token, a grant use and the
// resource head it becomes, and judgements of changes a grant governed. Pure
// functions of the authority's JSON that return tables of plain strings, so
// tools/test_ui_grants.mjs can check them without a browser; app.js renders
// them as text nodes. The console shows grants; it does not verify them.

const text=v=>v==null?'':String(v);
const words=v=>text(v).replaceAll('_',' ');
const isObject=v=>Boolean(v)&&typeof v==='object'&&!Array.isArray(v);

/** A UTC time as the authority writes it, shortened: `2026-11-02 10:16:00 UTC`. */
function time(value){
  if(typeof value!=='string'||!value)return '';
  const m=/^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(?:\.\d+)?(?:Z|\+00:00)$/.exec(value);
  return m?m[1]+' '+m[2]+' UTC':value;
}

/** Values of the grant list's `status` filter. */
export const GRANT_FILTERS=['active','expired','revoked'];

/** A list of strings, comma separated (anything else in it is left out). */
function list(v){return Array.isArray(v)?v.filter(s=>typeof s==='string').join(', '):'';}
/** An envelope value as JSON shows it, so `"1"`, `1` and `true` stay apart; a string as itself. */
function scalar(v){return typeof v==='string'?v:JSON.stringify(v)??'';}
function count(v){return Number.isSafeInteger(v)?String(v):'';}

function basis(g){return [g.basis_kind,g.basis_id].filter(v=>typeof v==='string'&&v).join(' ');}
function validity(g){return g.valid_from||g.valid_until?time(g.valid_from)+' to '+time(g.valid_until):'';}
function uses(g){return Number.isSafeInteger(g.uses)&&Number.isSafeInteger(g.max_uses)?g.uses+' of '+g.max_uses:'';}
function issued(g){return time(g.issued_at)+(g.issued_by_operator?' by '+g.issued_by_operator:'');}
function revoked(g){return g.revoked_at?time(g.revoked_at)+(g.revocation_reason?' ('+words(g.revocation_reason)+')':''):'';}

const SUMMARY=[['Grant',g=>text(g.grant_id)],['Status',g=>text(g.status)],['Bearer key',g=>text(g.bearer_key_id)],
  ['Capabilities',g=>list(g.capabilities)],['Basis',basis],['Valid',validity],['Uses',uses],['Issued',issued],['Revoked',revoked]];

/** `GET /admin/grants`: one row per grant, newest first, and the next page. */
export function grantsView(data){
  if(!isObject(data)||!Array.isArray(data.grants))return {tables:[],note:''};
  const grants=data.grants.filter(isObject);
  const tables=grants.length?[{state:'grants',caption:'Grants ('+grants.length+')',headers:SUMMARY.map(c=>c[0]),
    rows:grants.map(g=>SUMMARY.map(c=>c[1](g)))}]:[];
  let note=grants.length?'':'No grants match.';
  if(typeof data.next_before==='string'&&data.next_before)note='More on the next page: send again with before = '+data.next_before;
  return {tables,note};
}

/** A number range: its type and bounds, `>`/`<` when exclusive. */
function range(r){
  const parts=[];
  if(r.minimum!=null)parts.push((r.exclusive_minimum===true?'> ':'>= ')+scalar(r.minimum));
  if(r.maximum!=null)parts.push((r.exclusive_maximum===true?'< ':'<= ')+scalar(r.maximum));
  return [text(r.number_type),parts.join(' and ')].filter(Boolean).join(' ');
}
function allowed(spec){
  if(Array.isArray(spec.one_of))return 'one of: '+spec.one_of.map(scalar).join(', ');
  if(Array.isArray(spec.subset_of))return 'any of: '+spec.subset_of.map(scalar).join(', ');
  if(isObject(spec.number_range))return range(spec.number_range);
  return '';
}

/** The parameter envelope as a table: every request parameter a use may carry. */
function envelopeTable(grant){
  const envelope=isObject(grant?.parameter_envelope)?grant.parameter_envelope:{};
  const names=Object.keys(envelope).filter(n=>isObject(envelope[n])).sort();
  if(!names.length)return [];
  return [{state:'envelope',caption:'Parameter envelope ('+names.length+')',headers:['Parameter','Required','Allowed values'],
    rows:names.map(n=>[n,envelope[n].required===false?'no':'yes',allowed(envelope[n])])}];
}

function revocationRows(r,store){
  return [['Revoked at',time(r.revoked_at)],['Reason',words(r.reason)],['Detail',text(r.detail)],['Revoked by',text(r.revoked_by)],
    ['Revocation',text(r.revocation_id)],...(store!=null?[['Store position',count(store)]]:[])];
}

/** The action a grant's detail offers: revoking it, prepared for the operator to review, sign and send. */
function revokeAction(grantId){
  return {operation:'grants-revoke-grant',parameters:{grant_id:grantId},label:'Prepare revocation of this grant'};
}

/**
 * `GET /admin/grants/<id>`: the grant, its uses and remaining budget, its
 * envelope and its revocation, and (unless revoked) the revocation action.
 */
export function grantView(data){
  if(!isObject(data)||typeof data.grant_id!=='string')return {tables:[],note:''};
  const grant=isObject(data.grant)?data.grant:{};
  const policies=Array.isArray(data.policy_versions)?data.policy_versions.filter(isObject)
    .map(p=>text(p.policy_id)+' v'+text(p.version)).join(', '):'';
  const rows=[['Status',text(data.status)],['Bearer',text(data.bearer_key_id)+(data.bearer_sovereign_id?' ('+data.bearer_sovereign_id+')':'')],
    ['Capabilities',list(data.capabilities)],['Basis',basis(data)],['Valid',validity(data)],['Uses',uses(data)],
    ['Remaining uses',count(data.remaining_uses)],['Uses per time token',count(grant.max_uses_per_time_token)],
    ['Issued',issued(data)],['Store position',count(data.store_sequence)],['Checked against',policies]];
  const tables=[{state:'grant',caption:'Grant '+data.grant_id,headers:['Field','Value'],rows},...envelopeTable(grant)];
  if(isObject(data.revocation))tables.push({state:'revocation',caption:'Revocation',headers:['Field','Value'],rows:revocationRows(data.revocation)});
  const notes=['Each admitted use is a grant_execution entry in the evidence store; a resource\'s changes list the uses that changed it.'];
  if(data.status==='revoked')notes.push('Uses executed from the revocation on are refused.');
  return {tables,note:notes.join(' '),...(data.status==='revoked'?{}:{action:revokeAction(data.grant_id)})};
}

/** `POST /admin/grants`: the signed grant and the first time token the holder keeps with it. */
export function issuedView(data){
  if(!isObject(data)||!isObject(data.grant)||typeof data.grant.grant_id!=='string')return {tables:[],note:''};
  const g=data.grant, token=isObject(data.time_token)?data.time_token:null;
  const rows=[['Bearer',text(g.bearer_key_id)+(g.bearer_sovereign_id?' ('+g.bearer_sovereign_id+')':'')],
    ['Capabilities',list(g.capabilities)],['Basis',basis(g)],['Valid',validity(g)],['Budget',count(g.max_uses)+' uses'],
    ['Uses per time token',count(g.max_uses_per_time_token)],['Issued',time(g.issued_at)],['Store position',count(data.entry?.store_sequence)]];
  const tables=[{state:'grant',caption:'Issued grant '+g.grant_id,headers:['Field','Value'],rows},...envelopeTable(g)];
  if(token)tables.push(timeTokenTable(token,'First time token'));
  return {tables,note:'The holder keeps the grant and its time token, and acts within them while the authority is unreachable.'};
}

/** `POST /admin/grants/<id>/revoke`: the revocation the authority signed. */
export function revocationView(data){
  if(!isObject(data)||!isObject(data.revocation))return {tables:[],note:''};
  return {tables:[{state:'revocation',caption:'Revoked grant '+text(data.grant_id),headers:['Field','Value'],
    rows:revocationRows(data.revocation,data.entry?.store_sequence??null)}],
    note:'Uses executed from '+time(data.revocation.revoked_at)+' on are refused. Holders stop using the grant once their '+
      'revocation feed lists it (revoked_grant_ids).'};
}

function timeTokenTable(t,caption){
  return {state:'time_token',caption,headers:['Field','Value'],rows:[['Time token',text(t.time_token_id)],['Grant',text(t.grant_id)],
    ['Uses before it',count(t.use_sequence)],['Last use digest',text(t.use_head_digest)],['Issued',time(t.issued_at)]]};
}

/** `POST /grants/time-tokens`: the token the authority signed for the holder's chain head. */
export function timeTokenView(data){
  if(!isObject(data)||!isObject(data.time_token))return {tables:[],note:''};
  return {tables:[timeTokenTable(data.time_token,'Time token')],note:''};
}

/**
 * `POST /evidence/grant-executions`: the use, and the place in its resource's
 * chain the authority gave it. A use with a resource becomes that resource's
 * head: the next execution evidence for it links to the use.
 */
export function grantUseView(data){
  if(!isObject(data)||!isObject(data.payload))return {tables:[],note:''};
  const u=data.payload, entry=isObject(data.entry)?data.entry:{};
  const position=Number.isSafeInteger(data.resource_sequence)?data.resource_sequence:entry.resource_sequence;
  const rows=[['Grant',text(u.grant_id)],['Use',count(u.use_sequence)],['Capability',text(u.capability)],
    ['Resource',text(u.resource_id)],['Action',text(u.resource_action)],['Executed',time(u.executed_at)],['Outcome',text(u.outcome)],
    ['Status',text(data.status)],['Resource position',count(position)],['Store position',count(entry.store_sequence)]];
  let note='The use names no resource, so it takes no place in a resource\'s chain.';
  if(typeof u.resource_id==='string'&&Number.isSafeInteger(position))
    note='The use is the head of '+u.resource_id+' at position '+position+' unless a later record followed it: the next '+
      'execution evidence for the resource links to it.';
  return {tables:[{state:'grant_use',caption:'Grant use '+text(u.use_id),headers:['Field','Value'],rows}],note};
}

/** `GET /admin/evidence/resource-heads/<id>`: the record the next record of a resource links to. */
export function resourceHeadView(data){
  if(!isObject(data)||typeof data.resource_id!=='string')return {tables:[],note:''};
  return {tables:[{state:'head',caption:'Head of '+data.resource_id,headers:['Field','Value'],
    rows:[['Position',count(data.resource_sequence)],['Record digest',text(data.record_digest)]]}],
    note:'The next record of this resource links to this digest. From Genesis Mesh 1.6.0 the head may be a grant use, '+
      'at the position the authority gave it when it admitted the use; the resource\'s changes show which record it is.'};
}

/** Extra details of a change in a resource's changes: the grant a use was made under, or a grant use refused. */
export function grantChangeDetails(c){
  if(!isObject(c))return '';
  if(c.kind==='grant_execution')return 'grant '+text(c.grant_id)+(Number.isSafeInteger(c.use_sequence)?', use '+c.use_sequence:'');
  if(c.kind==='quarantine'&&c.record_kind==='grant_execution')return 'a grant use';
  if(c.governed_by==='grant')return 'matched a grant use';
  return '';
}

/** How a judged change was governed, in words: by a prior decision, a grant (1.6.0) or a judgement afterwards. */
export function governedBy(j){
  if(!isObject(j))return '';
  if(j.governed_by==='grant')return 'a grant'+(j.matched_evidence_id?' (use '+j.matched_evidence_id+')':'');
  if(j.governed_by==='prior_decision')return 'a prior decision'+(j.matched_decision_id?' ('+j.matched_decision_id+')':'');
  if(j.governed_by==='after_the_fact')return 'judged after the fact';
  return words(j.governed_by);
}

/** The answer of judging an observation or a break-glass record: its judgement. */
export function judgementView(data){
  const j=isObject(data)&&isObject(data.payload)?data.payload:null;
  if(!j||typeof j.judgement_id!=='string')return {tables:[],note:''};
  const rows=[['Subject',[words(j.subject_kind),text(j.subject_id)].filter(Boolean).join(' ')],['Resource',text(j.resource_id)],
    ['Action',text(j.action)],['Capability',text(j.capability)],['Governed by',governedBy(j)],['Verdict',text(j.verdict)],
    ['Current verdict',text(j.current_verdict)],['Evaluated as of',time(j.evaluated_as_of)],['Judged',time(j.judged_at)]];
  const note=j.governed_by==='grant'?'The change was made under a grant the authority signed in advance: it is governed '+
    'by the grant, not judged again.':'';
  return {tables:[{state:'judgement',caption:'Judgement '+j.judgement_id+(data.status?' ('+data.status+')':''),headers:['Field','Value'],rows}],note};
}

/** `/admin/evidence/status`: grants by state and their uses, when the authority has grants on. */
export function grantStatusView(data){
  if(!isObject(data)||!('evidence_grants' in data))return {tables:[],note:''};
  if(data.evidence_grants!==true)return {tables:[],note:'Pre-issued grants are off on this authority (EVIDENCE_GRANTS).'};
  const rows=[['Issued','grants_issued'],['Active','grants_active'],['Revoked','grants_revoked'],['Uses admitted','grant_uses']]
    .filter(([,k])=>k in data).map(([title,k])=>[title,text(data[k])]);
  return {tables:rows.length?[{state:'grant_status',caption:'Grants',headers:['State','Count'],rows}]:[],note:''};
}
