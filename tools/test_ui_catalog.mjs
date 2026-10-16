// The console's operation tables point at the catalog: every VIEWS and
// CHOICES key in app.js is an operation ID in ui/services.json, and every
// CHOICES parameter is one that operation takes. A renamed or removed
// operation otherwise leaves a view that silently never renders.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

const read=name=>readFileSync(new URL('../ui/'+name,import.meta.url),'utf8');
const operations=new Map(JSON.parse(read('services.json')).map(o=>[o.id,o]));
const app=read('app.js');

// The keys of the object literal assigned to `const <name>={...}`: quoted or
// bare keys at depth 1, and for each its own keys at depth 2.
function literalKeys(source,name){
  const start=source.indexOf('const '+name+'={');
  assert.notEqual(start,-1,`app.js has no const ${name}={`);
  const keys=new Map();
  let depth=0, i=source.indexOf('{',start), current=null, token='', quote=null;
  for(;i<source.length;i++){
    const c=source[i];
    if(quote){if(c===quote){quote=null;}else token+=c;continue;}
    if(c==="'"||c==='"'){quote=c;token='';continue;}
    if(c==='{'||c==='('||c==='['){depth++;token='';continue;}
    if(c==='}'||c===')'||c===']'){depth--;token='';if(depth===0)break;continue;}
    if(c===':'){
      const key=token.trim();
      if(key&&depth===1){current=key;keys.set(key,[]);}
      else if(key&&depth===2&&current)keys.get(current).push(key);
      token='';continue;
    }
    if(c===','){token='';continue;}
    token+=c;
  }
  assert.equal(depth,0,`const ${name} is not a closed object literal`);
  return keys;
}

// The parser itself: nested braces, calls and quoted keys.
assert.deepEqual([...literalKeys("const X={'a-b':f,'c':both(g,h),d:{p:[1,2],'q':Q}};",'X')],
  [['a-b',[]],['c',[]],['d',['p','q']]]);

const views=literalKeys(app,'VIEWS'), choices=literalKeys(app,'CHOICES');
// A parse that finds nothing would pass every check below.
assert.ok(views.size>=10,`only ${views.size} VIEWS keys parsed`);
assert.ok(choices.size>=1,`only ${choices.size} CHOICES keys parsed`);
for(const id of views.keys())assert.ok(operations.has(id),`VIEWS key ${id} is not a catalog operation`);
for(const [id,parameters] of choices){
  const operation=operations.get(id);
  assert.ok(operation,`CHOICES key ${id} is not a catalog operation`);
  assert.ok(parameters.length>0,`CHOICES ${id} names no parameter`);
  for(const p of parameters)assert.ok(operation.query.includes(p)||operation.parameters.includes(p),
    `CHOICES ${id} offers values for ${p}, which ${id} does not take`);
}
console.log(`console catalog keys: ${views.size} views, ${choices.size} choices, all in the catalog`);
