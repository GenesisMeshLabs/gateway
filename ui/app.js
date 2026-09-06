import './mesh.js';
import {operatorHeaders} from './signing.js';
const $ = id => document.getElementById(id);
const core = [
  {id:'mesh',method:'GET',path:'/v1/mesh',name:'Live mesh topology',description:'Published trust domains, active recognition treaties and explicitly public memberships.',public:true},
  {id:'health',method:'GET',path:'/health',name:'Liveness',description:'Check whether the gateway process is running.',public:true},
  {id:'ready',method:'GET',path:'/ready',name:'Trust readiness',description:'Check freshness of the gateway revocation snapshots.',public:true},
  {id:'api',method:'GET',path:'/api',name:'Service information',description:'Gateway version and service routes.',public:true},
  {id:'catalog',method:'GET',path:'/v1/services',name:'Service catalog',description:'All supported authority operations and their input templates.',public:true},
  {id:'networks',method:'GET',path:'/v1/networks',name:'Network data',description:'View your authorized networks and service permissions.'},
  {id:'verify',method:'POST',path:'/verify',name:'Verify certificate',description:'Evaluate a certificate using the gateway operator trust policy.',body:{certificate:{}}},
  {id:'batch',method:'POST',path:'/verify/batch',name:'Verify batch',description:'Evaluate certificates using a single policy snapshot.',body:{certificates:[]}},
  {id:'metrics',method:'GET',path:'/metrics',name:'Gateway metrics',description:'Prometheus metrics; requires metrics permission.'}
].map(e=>({...e,group:'gateway'}));
let endpoints=[...core], selected=core[0], lastResult, connectedToken='', session=null, busy=false, sessionGeneration=0;
const label = s => s.replaceAll('_',' ').replaceAll('-',' ').replace(/\b\w/g,c=>c.toUpperCase());
function node(tag,text,className){const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(className)n.className=className;return n;}
function example(body){
  const value=structuredClone(body);
  function visit(v){if(!v||typeof v!=='object')return;for(const k of Object.keys(v)){
    if(['valid_from','issued_at','registered_at','evaluated_at','signed_at','timestamp','traced_at','proof_issued_at'].includes(k))v[k]=new Date(Date.now()-60000).toISOString();
    else if(['valid_until','expires_at'].includes(k))v[k]=new Date(Date.now()+3600000).toISOString();
    else if(v[k]==='PASTE_AUTHORITY_PUBLIC_KEY'&&session){const n=session.networks.find(n=>n.name===$('network-select').value);v[k]=Object.values(n?.anchors||{})[0]||v[k];}
    else if(['local_sovereign_id','network_name','sovereign_id'].includes(k)&&v[k]==='authority-a'&&$('network-select').value)v[k]=$('network-select').value;
    else visit(v[k]);
  }}visit(value);return value;
}
function renderEndpoints(){
  const text=$('endpoint-search').value.toLowerCase(), group=$('service-group').value;
  const visible=endpoints.filter(e=>(!group||e.group===group)&&[e.name,e.path,e.upstream_path,e.group].join(' ').toLowerCase().includes(text));
  $('endpoints').replaceChildren();let previous;
  for(const e of visible){if(previous!==e.group){$('endpoints').append(node('div',label(e.group),'group-heading'));previous=e.group;}
    const b=node('button');b.type='button';b.dataset.id=e.id;b.classList.toggle('selected',e.id===selected.id);
    const title=node('span');title.append(node('code',e.upstream_path||e.path),node('small',e.name+(e.admin?' | Operator signed':'')));
    b.append(node('span',e.method,'method '+e.method.toLowerCase()),title);b.addEventListener('click',()=>choose(e));$('endpoints').append(b);
  }
  $('catalog-summary').textContent=visible.length+' operations shown | '+(endpoints.length-core.length)+' authority operations | '+(session?'Connected as '+session.client_id:'Connect with a service token to access your networks');
}
function destination(){return selected.authority?'/v1/networks/'+encodeURIComponent($('network-select').value||'{network}')+'/services/'+selected.id:selected.path;}
function choose(e){
  if(busy)return;
  selected=e;$('method').textContent=e.method;$('method').className='method '+e.method.toLowerCase();$('path').textContent=destination();
  $('description').textContent=e.description+(e.authority?' Authority endpoint: '+e.upstream_path:'');
  $('auth-label').textContent=e.public?'Public':e.admin?'Bearer + operator signature':'Bearer token';
  $('body-field').hidden=!e.body;$('operator-panel').hidden=!e.admin;
  $('parameters').replaceChildren();
  for(const p of [...(e.parameters||[]),...(e.query||[])]){const wrapper=node('div',undefined,'parameter-field');const l=node('label',label(p)+(e.parameters.includes(p)?' (required)':' (optional)'));l.htmlFor='param-'+p;const input=node('input');input.id='param-'+p;input.dataset.parameter=p;input.autocomplete='off';wrapper.append(l,input);$('parameters').append(wrapper);}
  if(e.body){$('request-body').value=JSON.stringify(example(e.body),null,2);updateInsertFields();}
  $('send').textContent=e.admin?'Send signed request':'Send request';renderEndpoints();
}
function updateInsertFields(){
  $('insert-field').replaceChildren();try{for(const k of Object.keys(JSON.parse($('request-body').value)))$('insert-field').append(new Option('Into '+k,k));}catch{}
}
async function request(path,options={}){
  const response=await fetch(path,{...options,cache:'no-store',credentials:'omit',redirect:'error',signal:AbortSignal.timeout(20000)});
  const raw=await response.text();let data;try{data=JSON.parse(raw);}catch{data=raw;}return {response,data};
}
function resetSession(){
  sessionGeneration++;session=null;connectedToken='';lastResult=undefined;
  $('network-select').replaceChildren(new Option('Connect to load networks',''));
  $('network-data').replaceChildren(node('p','Enter a service token and select Load networks.'));
  $('network-state').textContent='Enter your token here, then select Load networks. The public mesh above needs no token.';
  $('response').textContent='Session data cleared.';$('request-id').textContent='';
  $('operator-seed').value='';$('signed-headers').value='';renderEndpoints();
}
async function connect(){
  const token=$('token').value.trim();if(!token)throw new Error('Enter a service token first.');
  const generation=sessionGeneration;
  const {response,data}=await request('/v1/networks',{headers:{Authorization:'Bearer '+token}});
  if(generation!==sessionGeneration||token!==$('token').value.trim())throw new Error('Credentials changed. Connect again.');
  if(!response.ok)throw new Error((typeof data.error==='string'?data.error:data.error?.message)||'Connection rejected ('+response.status+')');
  session=data;connectedToken=token;
  $('network-select').replaceChildren(...data.networks.map(n=>new Option(n.name+(n.services_configured?'':' (services unavailable)'),n.name)));
  renderNetworks(data);$('path').textContent=destination();renderEndpoints();
  $('request-state').textContent='Connected as '+data.client_id;
  $('network-state').textContent='Loaded '+data.networks.length+' networks. Connected as '+data.client_id+'.';
}
function renderNetworks(data){
  const container=$('network-data');container.replaceChildren();container.className='network-list';
  for(const n of data.networks){const card=node('article');card.append(node('h3',n.name),node('span',n.ready?'Ready':'Stale revocation data','pill'),node('p',n.services_configured?'Authority services configured':'Authority services not configured','connection-note'),node('pre',JSON.stringify({authorities:n.anchors,required_roles:n.required_roles,revocation:n.revocation},null,2)));container.append(card);}
}
async function send(){
  if(busy)return;busy=true;$('send').disabled=true;$('network-select').disabled=true;const e=selected, generation=sessionGeneration;
  try{
    const token=$('token').value.trim();if(!e.public&&!token)throw new Error('Enter a service token for this endpoint.');
    if(e.authority&&connectedToken!==token)await connect();
    if(e.authority){
      if(!session?.service_groups?.includes(e.group))throw new Error('Your service identity does not have access to this service area.');
      if(e.admin&&!session.authority_admin)throw new Error('Your service identity does not have operator access.');
      if(!session.networks.find(n=>n.name===$('network-select').value)?.services_configured)throw new Error('Select a network with authority services configured.');
    }
    let path=destination();const query=new URLSearchParams();
    for(const input of $('parameters').querySelectorAll('input')){
      if(e.parameters.includes(input.dataset.parameter)&&!input.value.trim())throw new Error('Enter '+input.dataset.parameter+'.');
      if(input.value.trim())query.set(input.dataset.parameter,input.value.trim());
    }
    if(query.size)path+='?'+query;
    const headers={};if(!e.public)headers.Authorization='Bearer '+token;
    const value=e.body?JSON.parse($('request-body').value):{};
    if(e.body&&(value===null||Array.isArray(value)||typeof value!=='object'))throw new Error('Request body must be a JSON object.');
    if(e.body)headers['Content-Type']='application/json';
    if(e.admin){
      if($('signed-headers').value.trim()){
        const signed=JSON.parse($('signed-headers').value);
        for(const name of ['X-Admin-Key-Id','X-Admin-Timestamp','X-Admin-Nonce','X-Admin-Signature']){
          if(typeof signed[name]!=='string'||!signed[name])throw new Error('Signed headers must include '+name);
          headers[name]=signed[name];
        }
      }else Object.assign(headers,await operatorHeaders(value,$('operator-seed').value,$('operator-id').value.trim()));
    }
    if(generation!==sessionGeneration)return;
    $('request-state').textContent='Sending...';const start=performance.now();
    const {response,data}=await request(path,{method:e.method,headers,...(e.body?{body:JSON.stringify(value)}:{})});
    if(generation!==sessionGeneration)return;
    $('response').textContent=typeof data==='string'?data:JSON.stringify(data,null,2);
    $('response-meta').textContent=response.status+' | '+Math.round(performance.now()-start)+' ms';
    $('request-state').textContent=response.ok?'Request completed':'Request rejected ('+response.status+')';
    $('request-id').textContent='Request ID: '+(response.headers.get('x-request-id')||'unavailable');
    if(response.ok)lastResult=data;
    if(e.id==='networks'&&response.ok)renderNetworks(data);
  }catch(error){if(generation===sessionGeneration)$('request-state').textContent=error.message||'Request could not be completed.';}
  finally{busy=false;$('send').disabled=false;$('network-select').disabled=false;}
}
$('endpoint-search').addEventListener('input',renderEndpoints);$('service-group').addEventListener('change',renderEndpoints);
$('network-select').addEventListener('change',()=>{$('operator-seed').value='';$('signed-headers').value='';$('path').textContent=destination();});
for(const id of ['token','network-token'])$(id).addEventListener('input',()=>{const value=$(id).value;$('token').value=value;$('network-token').value=value;resetSession();});
$('send').addEventListener('click',send);
let connecting=false;
async function connectWithFeedback(field){
  if(connecting)return;
  if(!$(field).value.trim()){
    $('network-state').textContent='A bearer token is required for protected network details. Paste it in the Network access token field.';
    $('request-state').textContent='Enter a service token first.';
    $(field).focus();return;
  }
  connecting=true;$('load-networks').disabled=true;$('connect').disabled=true;
  $('load-networks').textContent='Loading networks...';$('network-state').textContent='Loading your authorized networks...';
  const generation=sessionGeneration;
  try{await connect();}
  catch(error){if(generation===sessionGeneration){$('network-state').textContent='Could not load networks: '+error.message;$('request-state').textContent=error.message;}}
  finally{connecting=false;$('load-networks').disabled=false;$('connect').disabled=false;$('load-networks').textContent='Load networks';}
}
$('connect').addEventListener('click',()=>connectWithFeedback('token'));
$('load-networks').addEventListener('click',()=>connectWithFeedback('network-token'));
for(const id of ['token','network-token'])$(id).addEventListener('keydown',event=>{if(event.key==='Enter'){event.preventDefault();connectWithFeedback(id);}});
for(const id of ['clear-token','clear-network-token'])$(id).addEventListener('click',()=>{$('token').value='';$('network-token').value='';resetSession();});
$('reset-body').addEventListener('click',()=>{$('request-body').value=JSON.stringify(example(selected.body),null,2);updateInsertFields();});
$('request-body').addEventListener('input',updateInsertFields);
$('reuse-response').addEventListener('click',()=>{try{if(lastResult===undefined)throw new Error('Send a successful request first.');const body=JSON.parse($('request-body').value), field=$('insert-field').value;if(!field)throw new Error('Choose a destination field.');body[field]=structuredClone(lastResult);$('request-body').value=JSON.stringify(body,null,2);}catch(e){$('request-state').textContent=e.message;}});
$('copy-response').addEventListener('click',()=>navigator.clipboard.writeText($('response').textContent).then(()=>$('request-state').textContent='Response copied.').catch(()=>$('request-state').textContent='Select and copy the response text.'));
async function refresh(){try{const [health,ready,api]=await Promise.all(['/health','/ready','/api'].map(p=>request(p)));$('health-value').textContent=health.response.ok?'Operational':'Unavailable';$('ready-value').textContent=ready.response.ok?'Ready':'Not ready';$('health-detail').textContent='Checked '+new Date().toLocaleTimeString();$('connection').textContent=health.response.ok?'Gateway connected':'Gateway unavailable';$('connection-dot').classList.toggle('bad',!health.response.ok);$('version').textContent='v'+(api.data.version||'?');}catch{$('health-value').textContent='Unavailable';$('ready-value').textContent='Unknown';$('connection').textContent='Connection unavailable';}}
choose(core[0]);refresh();
request('/v1/services').then(({response,data})=>{if(!response.ok)throw new Error('Service catalog unavailable');endpoints=[...core,...data.operations.map(e=>({...e,authority:true})).sort((a,b)=>a.group.localeCompare(b.group))];for(const g of [...new Set(endpoints.map(e=>e.group))])$('service-group').append(new Option(label(g),g));renderEndpoints();}).catch(e=>$('catalog-summary').textContent=e.message);
setInterval(()=>{if(!document.hidden)refresh();},30000);
