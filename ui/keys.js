// The Network Authority's key history (Genesis Mesh 1.5.0, Stage 4) in the
// console: which NA key signs when, from the genesis block's key through each
// key succession. Pure functions of the authority's JSON that return tables of
// plain strings, so tools/test_ui_keys.mjs can check them without a browser;
// app.js renders them as text nodes. The console shows the history; it does
// not verify it.

const text=v=>v==null?'':String(v);
const isObject=v=>Boolean(v)&&typeof v==='object'&&!Array.isArray(v);

/** A UTC time as the authority writes it, shortened: `2026-11-02 10:16:00 UTC`. */
function time(value){
  if(typeof value!=='string'||!value)return '';
  const m=/^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(?:\.\d+)?(?:Z|\+00:00)$/.exec(value);
  return m?m[1]+' '+m[2]+' UTC':value;
}

/** Where a key stands, from the key the authority says signs now (the console reads no clock). */
function standing(key,signing){
  const parts=[];
  if(Number.isSafeInteger(signing)&&Number.isSafeInteger(key.key_sequence)){
    if(key.key_sequence===signing)parts.push('signs now');
    else if(key.key_sequence>signing)parts.push('takes effect '+time(key.valid_from));
    else parts.push('succeeded');
  }else if(key.succeeded_at)parts.push('succeeded');
  if(key.current===true)parts.push('this instance');
  return parts.join('; ');
}

function validTo(key){
  if(!key.valid_to)return '';
  return time(key.valid_to)+(key.valid_to_enforced===false?' (not enforced)':'');
}

const KEYS=[['#',k=>text(k.key_sequence)],['Key ID',k=>text(k.key_id)],['Public key',k=>text(k.public_key)],
  ['Valid from',k=>k.valid_from?time(k.valid_from):'start of the network'],['Succeeded at',k=>time(k.succeeded_at)],
  ['Valid to',validTo]];
const SUCCESSIONS=[['#',s=>text(s.key_sequence)],['Succession',s=>text(s.succession_id)],['From key',s=>text(s.previous_key_id)],
  ['To key',s=>text(s.new_key_id)],['Effective',s=>time(s.effective_at)],['New key valid to',s=>time(s.new_valid_to)],
  ['Issued',s=>time(s.issued_at)]];

/**
 * `GET /na/key-history`: the keys (with where each stands) and the
 * successions as tables, and a note on the root key and the hand-over.
 */
export function keyHistoryView(data){
  if(!isObject(data)||!Array.isArray(data.keys))return {tables:[],note:''};
  const keys=data.keys.filter(isObject), successions=Array.isArray(data.successions)?data.successions.filter(isObject):[];
  const signing=data.signing_key_sequence;
  const tables=[{state:'keys',caption:'NA keys'+(data.sovereign_id?' of '+data.sovereign_id:'')+' ('+keys.length+')',
    headers:[...KEYS.map(c=>c[0]),'Standing'],rows:keys.map(k=>[...KEYS.map(c=>c[1](k)),standing(k,signing)])}];
  if(successions.length)tables.push({state:'successions',caption:'Successions ('+successions.length+')',
    headers:SUCCESSIONS.map(c=>c[0]),rows:successions.map(s=>SUCCESSIONS.map(c=>c[1](s)))});
  const notes=[];
  if(signing==null)notes.push('No key of this history may sign now.');
  if(Number.isSafeInteger(data.handover_seconds))
    notes.push('A succeeded key is still accepted for records dated up to '+data.handover_seconds+' seconds after the next key takes effect.');
  notes.push('The console shows this history and does not check it: a verifier checks it from the root key it already holds'+
    (data.root_public_key?' (the authority names '+data.root_public_key+')':'')+'.');
  return {tables,note:notes.join(' ')};
}

/** `POST /admin/na/succession`: the recorded succession's key history. */
export function successionView(data){
  return keyHistoryView(isObject(data)?data.key_history:undefined);
}
