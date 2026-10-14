// Edge nodes (Genesis Mesh 1.7.0, Stage 6) in the console: the edge nodes an
// authority enrolled, with their status, last heartbeat, what their agent
// last reported, the grants their executor key bears and their break-glass
// records, and the revocation of an edge node. Pure functions of the
// authority's JSON that return tables of plain strings, so
// tools/test_ui_edge.mjs can check them without a browser; app.js renders
// them as text nodes. Edge nodes are operator data: the public mesh view
// does not show them.

const text=v=>v==null?'':String(v);
const words=v=>text(v).replaceAll('_',' ');
const isObject=v=>Boolean(v)&&typeof v==='object'&&!Array.isArray(v);
const count=v=>Number.isSafeInteger(v)&&v>=0?String(v):'';
const plural=(n,one,many)=>n+' '+(n===1?one:many);

/** A UTC time as the authority writes it (`Z` or `+00:00`), shortened: `2026-10-14 09:29:40 UTC`. */
function time(value){
  if(typeof value!=='string'||!value)return '';
  const m=/^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(?:\.\d+)?(?:Z|\+00:00)$/.exec(value);
  return m?m[1]+' '+m[2]+' UTC':value;
}

/** A number of seconds in its two largest units: `42 s`, `2 min 5 s`, `2 h 5 min`, `3 d 4 h`. */
function duration(seconds){
  if(!Number.isSafeInteger(seconds)||seconds<0)return '';
  const units=[['d',86400],['h',3600],['min',60],['s',1]];
  const first=units.findIndex(([,size])=>seconds>=size);
  if(first<0)return '0 s';
  return units.slice(first,first+2).map(([unit,size],i)=>{
    const value=i===0?Math.floor(seconds/size):Math.floor(seconds%units[first][1]/size);
    return value?value+' '+unit:'';
  }).filter(Boolean).join(' ');
}

/** Values of the edge node list's `status` filter. */
export const EDGE_FILTERS=['online','offline','revoked'];

function agentOf(n){return isObject(n.agent)?n.agent:null;}
function status(n){
  if(n.status!=='revoked'||!n.revoked_at)return text(n.status);
  return 'revoked '+time(n.revoked_at)+(n.revocation_reason?' ('+words(n.revocation_reason)+')':'');
}
function lastSeen(n){return time(n.last_seen_at)+(n.last_seen_at&&n.remote_addr?' from '+n.remote_addr:'');}
function snapshotAge(n){
  const agent=agentOf(n);
  if(!agent)return '';
  const age=Number.isSafeInteger(agent.snapshot_age_seconds)?duration(agent.snapshot_age_seconds):'no snapshot';
  return age+(agent.reported_at?' (reported '+time(agent.reported_at)+')':'');
}
function pending(n){
  const agent=agentOf(n);
  if(!agent||!count(agent.pending_uploads))return '';
  const dead=Number.isSafeInteger(agent.dead_letters)&&agent.dead_letters>0?' ('+plural(agent.dead_letters,'dead letter','dead letters')+')':'';
  return agent.pending_uploads+dead;
}
function grants(n){
  const g=isObject(n.grants)?n.grants:null;
  if(!g||!count(g.usable)||!count(g.admitted_uses))return '';
  return g.usable+' usable, '+plural(g.admitted_uses,'use','uses');
}
function breakGlass(n){
  const b=isObject(n.break_glass)?n.break_glass:null;
  if(!b||!count(b.records))return '';
  return b.records+(b.last_executed_at?' (last '+time(b.last_executed_at)+')':'');
}

const NODES=[['Node',n=>text(n.node_public_key)],['Sovereign',n=>text(n.node_sovereign_id)],['Status',status],['Last seen',lastSeen],
  ['Snapshot age',snapshotAge],['Pending uploads',pending],['Grants in use',grants],['Break-glass uses',breakGlass],
  ['Agent',n=>text(agentOf(n)?.version)]];

/** `GET /admin/edge-nodes`: one row per edge node, newest enrolment first, and the next page. */
export function edgeNodesView(data){
  if(!isObject(data)||!Array.isArray(data.edge_nodes))return {tables:[],note:''};
  const nodes=data.edge_nodes.filter(isObject);
  const tables=nodes.length?[{state:'edge_nodes',caption:'Edge nodes ('+nodes.length+')',headers:NODES.map(c=>c[0]),
    rows:nodes.map(n=>NODES.map(c=>c[1](n)))}]:[];
  let note=nodes.length?'':'No edge nodes match.';
  if(typeof data.next_before==='string'&&data.next_before)note='More on the next page: send again with before = '+data.next_before;
  return {tables,note};
}

/**
 * `POST /admin/revoke` of an edge node's certificate: every certificate of
 * the node revoked in one CRL, its executor key retired and the grants that
 * key bore revoked. Nothing for any other certificate.
 */
export function edgeRevocationView(data){
  if(!isObject(data)||!isObject(data.edge_node))return {tables:[],note:''};
  const e=data.edge_node;
  const certs=Array.isArray(e.revoked_cert_ids)?e.revoked_cert_ids.filter(c=>typeof c==='string'):[];
  const retired=e.executor_key_retired===true?'yes':e.executor_key_retired===false?'no':'';
  const rows=[['CRL sequence',count(data.crl_sequence)],['Certificates revoked',certs.length?certs.length+': '+certs.join(', '):'0'],
    ['Executor key',text(e.executor_key_id)],['Executor key retired',retired],['Grants revoked',count(e.grants_revoked)]];
  const notes=[];
  if(!certs.length&&e.grants_revoked===0)notes.push('The node was already revoked: nothing changed.');
  if(e.executor_key_retired===false)notes.push('The certificates are revoked, but the authority could not retire the executor key yet: '+
    'it retires it when it next starts. Until then the grants the key bears are not revoked.');
  else if(Number.isSafeInteger(e.grants_revoked)&&e.grants_revoked>0)
    notes.push('Holders stop using the revoked grants once their revocation feed lists them (revoked_grant_ids).');
  return {tables:[{state:'edge_revocation',caption:'Revoked edge node '+text(e.node_public_key),headers:['Field','Value'],rows}],
    note:notes.join(' ')};
}
