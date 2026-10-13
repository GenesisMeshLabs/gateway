// The console's NA key history view (Genesis Mesh 1.5.0): the keys with where
// each stands, the successions and the note. Its input is authority data,
// rendered as text only.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const load=async name=>import('data:text/javascript;base64,'+Buffer.from(readFileSync(new URL('../ui/'+name,import.meta.url),'utf8')).toString('base64'));
const {keyHistoryView,successionView}=await load('keys.js');

// GET /na/key-history as the authority answers it: the genesis key, a succeeded
// key signed by the root and the outgoing key, and a pending succession.
const history={
  sovereign_id:'gm-demo',root_public_key:'ROOTKEY0000000000000000000000000000000000000=',handover_seconds:300,
  genesis:{network_name:'gm-demo'},
  successions:[
    {succession_id:'s-2',sovereign_id:'gm-demo',key_sequence:2,previous_key_id:'na-2026',new_key_id:'na-2027',
      effective_at:'2026-11-01T09:00:00Z',new_valid_to:'2027-11-01T09:00:00Z',issued_at:'2026-10-20T08:00:00Z',signatures:[]},
    {succession_id:'s-3',sovereign_id:'gm-demo',key_sequence:3,previous_key_id:'na-2027',new_key_id:'<b>na-2028</b>',
      effective_at:'2027-10-01T09:00:00Z',new_valid_to:'2028-10-01T09:00:00Z',issued_at:'2027-09-20T08:00:00Z',signatures:[]},
  ],
  keys:[
    {key_sequence:1,key_id:'na-2026',public_key:'KEY1',valid_from:null,succeeded_at:'2026-11-01T09:00:00Z',
      valid_to:'2026-12-01T00:00:00Z',valid_to_enforced:false,current:false},
    {key_sequence:2,key_id:'na-2027',public_key:'KEY2',valid_from:'2026-11-01T09:00:00Z',succeeded_at:'2027-10-01T09:00:00Z',
      valid_to:'2027-11-01T09:00:00Z',valid_to_enforced:true,current:true},
    {key_sequence:3,key_id:'<b>na-2028</b>',public_key:'KEY3',valid_from:'2027-10-01T09:00:00Z',succeeded_at:null,
      valid_to:'2028-10-01T09:00:00Z',valid_to_enforced:true,current:false},
  ],
  signing_key_sequence:2,
};

let view=keyHistoryView(history);
assert.deepEqual(view.tables.map(t=>t.caption),['NA keys of gm-demo (3)','Successions (2)']);
const [keys,successions]=view.tables;
assert.deepEqual(keys.headers,['#','Key ID','Public key','Valid from','Succeeded at','Valid to','Standing']);
// The genesis key's valid_to is shown, not enforced; a succession's key has its own end.
assert.deepEqual(keys.rows[0],['1','na-2026','KEY1','start of the network','2026-11-01 09:00:00 UTC','2026-12-01 00:00:00 UTC (not enforced)','succeeded']);
assert.deepEqual(keys.rows[1],['2','na-2027','KEY2','2026-11-01 09:00:00 UTC','2027-10-01 09:00:00 UTC','2027-11-01 09:00:00 UTC','signs now; this instance']);
assert.deepEqual(keys.rows[2],['3','<b>na-2028</b>','KEY3','2027-10-01 09:00:00 UTC','','2028-10-01 09:00:00 UTC','takes effect 2027-10-01 09:00:00 UTC']);
assert.deepEqual(successions.headers,['#','Succession','From key','To key','Effective','New key valid to','Issued']);
assert.deepEqual(successions.rows[0],['2','s-2','na-2026','na-2027','2026-11-01 09:00:00 UTC','2027-11-01 09:00:00 UTC','2026-10-20 08:00:00 UTC']);
assert.match(view.note,/up to 300 seconds after the next key takes effect/);
assert.match(view.note,/does not check it: a verifier checks it from the root key it already holds \(the authority names ROOTKEY0+=\)\.$/);
// Every cell is a string: app.js puts them in text nodes.
for(const t of view.tables)for(const r of t.rows){assert.equal(r.length,t.headers.length);for(const c of r)assert.equal(typeof c,'string');}

// A network that never succeeded its key: the genesis key alone, no successions table.
view=keyHistoryView({...history,successions:[],keys:[{...history.keys[0],succeeded_at:null,current:true}],signing_key_sequence:1});
assert.deepEqual(view.tables.map(t=>t.caption),['NA keys of gm-demo (1)']);
assert.equal(view.tables[0].rows[0][6],'signs now; this instance');
// No key may sign now (a succeeded-to key past its end): said in the note.
view=keyHistoryView({...history,signing_key_sequence:null});
assert.match(view.note,/^No key of this history may sign now\./);
assert.deepEqual(view.tables[0].rows.map(r=>r[6]),['succeeded','succeeded; this instance','']);

// A succession's answer carries the key history; anything else shows nothing.
assert.deepEqual(successionView({status:'recorded',succession:history.successions[1],key_history:history}),keyHistoryView(history));
for(const data of [undefined,null,'text',[],{error:{code:'succession_pending'}},{keys:'none'}]){
  assert.deepEqual(keyHistoryView(data),{tables:[],note:''});
  assert.deepEqual(successionView(data),{tables:[],note:''});
}

// The catalog: the key history is a network read anyone with the network group may send;
// recording a succession is an operator operation for administration clients.
const ops=JSON.parse(readFileSync(new URL('../ui/services.json',import.meta.url),'utf8'));
const read=ops.find(o=>o.id==='key_history-key-history'), succeed=ops.find(o=>o.id==='key_history-succession');
assert.deepEqual([read.group,read.admin,read.method,read.upstream_path],['network',false,'GET','/na/key-history']);
assert.deepEqual([succeed.group,succeed.admin,succeed.method,succeed.upstream_path],['administration',true,'POST','/admin/na/succession']);
assert.equal(ops.some(o=>o.upstream_path==='/admin/evidence/audit-pack'),false);

// Authority text never reaches markup.
for(const name of ['app.js','keys.js']){
  const source=readFileSync(new URL('../ui/'+name,import.meta.url),'utf8');
  assert.doesNotMatch(source,/innerHTML|outerHTML|insertAdjacentHTML|document\.write/,name);
}
assert.match(readFileSync(new URL('../ui/app.js',import.meta.url),'utf8'),/'key_history-key-history':keyHistoryView/);
console.log('Console key history view: keys, where each stands, successions and the note are text tables.');
