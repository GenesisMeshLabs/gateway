const ns='http://www.w3.org/2000/svg';
const el=(tag,text,cls)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n;};
const svg=(tag,attrs,text)=>{const n=document.createElementNS(ns,tag);for(const [k,v] of Object.entries(attrs))n.setAttribute(k,String(v));if(text!==undefined)n.textContent=text;return n;};
let snapshot, pending=false, chosen;
function inspect(record,type){
  chosen={id:record.id,type};
  const panel=document.getElementById('mesh-detail');panel.replaceChildren();
  panel.append(el('span',type==='network'?'TRUST DOMAIN':type==='link'?'RECOGNITION TREATY':'SIGNED MEMBERSHIP','eyebrow'));
  panel.append(el('h3',type==='network'?record.id:type==='link'?record.from+' recognizes '+record.to:record.subject));
  const fields=type==='network'?{'Authority':record.available?'Responding':'Unavailable','Revocation snapshot':record.trust_ready?'Fresh':'Stale','CRL sequence':record.crl_sequence}:type==='link'?{'Treaty ID':record.id,'Allowed roles':(record.roles||[]).join(', '),'Expires':record.expires_at}:{'Network':record.network,'Attestation ID':record.id,'Roles':(record.roles||[]).join(', '),'Expires':record.expires_at,'Purpose':record.demo?'Demonstration participant':'Published participant'};
  const list=el('dl');for(const [key,value] of Object.entries(fields)){list.append(el('dt',key),el('dd',String(value)));}panel.append(list);
  panel.append(el('p','Read from the authority. Open the API explorer to inspect signatures and perform verification.','field-note'));
  document.querySelectorAll('.mesh-node').forEach(n=>n.classList.toggle('selected',n.dataset.record===record.id));
}
function render(data){
  snapshot=data;const root=document.getElementById('mesh-view');root.replaceChildren();
  const stats=document.getElementById('mesh-stats');stats.replaceChildren();
  const pairs=new Set(data.links.map(l=>[l.from,l.to].sort().join('|')));
  for(const [value,label] of [[data.networks.length,'TRUST DOMAINS'],[pairs.size,'CONNECTED PAIRS'],[data.links.length,'ACTIVE TREATIES'],[data.members.length,'PUBLIC MEMBERSHIPS']]){const item=el('div');item.append(el('strong',String(value)),el('span',label));stats.append(item);}
  if(!data.networks.length){root.append(el('p','No networks have been published yet. Operators can enable a read-only overview for approved networks.'));return;}
  const graph=svg('svg',{viewBox:'0 0 1200 '+(Math.ceil(data.networks.length/2)*320+150),role:'group','aria-label':'Live mesh of trust domains, recognition treaties and signed memberships'});
  const defs=svg('defs',{}),marker=svg('marker',{id:'mesh-arrow',viewBox:'0 0 10 10',refX:9,refY:5,markerWidth:6,markerHeight:6,orient:'auto-start-reverse'});marker.append(svg('path',{d:'M 0 0 L 10 5 L 0 10 z',fill:'#baff45'}));defs.append(marker);graph.append(defs);
  const positions=new Map();
  data.networks.forEach((n,i)=>positions.set(n.id,{x:i%2===0?330:870,y:230+Math.floor(i/2)*320}));
  const routes=svg('g',{'aria-hidden':'true'});
  for(const [id,p] of positions){routes.append(svg('path',{d:`M 600 58 L ${p.x} ${p.y-42}`,class:'mesh-route'}));}
  graph.append(routes,svg('rect',{x:521,y:26,width:158,height:48,rx:12,class:'mesh-gateway'}),svg('text',{x:600,y:55,'text-anchor':'middle',class:'mesh-gateway-label'},'RUST GATEWAY'));
  for(const l of data.links){const a=positions.get(l.from),b=positions.get(l.to);if(!a||!b||l.from===l.to)continue;
    const dx=b.x-a.x,dy=b.y-a.y,length=Math.hypot(dx,dy),ux=dx/length,uy=dy/length;
    const x1=a.x+ux*48,y1=a.y+uy*48,x2=b.x-ux*48,y2=b.y-uy*48;
    const curve=`M ${x1} ${y1} Q ${(a.x+b.x)/2-uy*85} ${(a.y+b.y)/2+ux*85} ${x2} ${y2}`;
    const path=svg('path',{d:curve,class:'mesh-link',fill:'none','marker-end':'url(#mesh-arrow)',tabindex:0,role:'button','aria-label':l.from+' recognizes '+l.to});
    path.append(svg('title',{},l.from+' recognizes '+l.to));path.addEventListener('click',()=>inspect(l,'link'));path.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();inspect(l,'link');}});graph.append(path);
  }
  function addNode(record,type,x,y,r,label,subtitle){
    const g=svg('g',{class:'mesh-node '+type,tabindex:0,role:'button','aria-label':label+', '+subtitle,'data-record':record.id});
    g.append(svg('circle',{cx:x,cy:y,r:r+7,class:'mesh-halo'}),svg('circle',{cx:x,cy:y,r}),svg('text',{x,y:y+5,'text-anchor':'middle',class:'mesh-glyph'},type==='network'?'NA':'M'),svg('text',{x,y:y+r+26,'text-anchor':'middle',class:'mesh-label'},label),svg('text',{x,y:y+r+44,'text-anchor':'middle',class:'mesh-subtitle'},subtitle));
    g.addEventListener('click',()=>inspect(record,type));g.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();inspect(record,type);}});graph.append(g);
  }
  for(const n of data.networks){const p=positions.get(n.id);const members=data.members.filter(m=>m.network===n.id).slice(0,6);
    members.forEach((m,i)=>{const side=p.x<600?-1:1;const angle=(i-(members.length-1)/2)*0.8;const x=p.x+side*Math.cos(angle)*175,y=p.y+Math.sin(angle)*165;
      graph.append(svg('line',{x1:p.x,y1:p.y,x2:x,y2:y,class:'mesh-membership-line'}));addNode(m,'member',x,y,17,m.subject.replace(/^demo:/,''),m.demo?'Demo membership':'Membership');});
    addNode(n,'network',p.x,p.y,35,n.id,n.available?(n.trust_ready?'Online / fresh CRL':'Online / stale CRL'):'Authority unavailable');
  }
  root.append(graph);
  const records=document.getElementById('mesh-records');records.replaceChildren();
  for(const l of data.links){const button=el('button',l.from+' → '+l.to,'mesh-record');button.type='button';button.append(el('small','Recognition treaty / expires '+new Date(l.expires_at).toLocaleDateString()));button.addEventListener('click',()=>inspect(l,'link'));records.append(button);}
  if(!data.links.length)records.append(el('p','No active recognition treaties between the published networks.'));
  const note=document.getElementById('mesh-status');const unavailable=data.networks.filter(n=>!n.available).length;
  note.textContent=(unavailable?unavailable+' authority unavailable. ':'Live authority data. ')+'Updated '+new Date(data.observed_at).toLocaleTimeString()+'. Refreshes every 30 seconds.';
  const selected=chosen&&(chosen.type==='network'?data.networks:chosen.type==='link'?data.links:data.members).find(n=>n.id===chosen.id);
  inspect(selected||data.networks[0],selected?chosen.type:'network');
}
export async function refreshMesh(){
  if(pending)return;pending=true;const button=document.getElementById('refresh-mesh');button.disabled=true;
  try{const response=await fetch('/v1/mesh',{cache:'no-store',credentials:'omit',redirect:'error',signal:AbortSignal.timeout(10000)});if(!response.ok)throw new Error('Mesh data unavailable');render(await response.json());}
  catch{document.getElementById('mesh-status').textContent='Mesh refresh failed. '+(snapshot?'The displayed snapshot may be stale.':'Retry to load live authority data.');}
  finally{pending=false;button.disabled=false;}
}
document.getElementById('refresh-mesh').addEventListener('click',refreshMesh);
refreshMesh();setInterval(()=>{if(!document.hidden)refreshMesh();},30000);
