document.querySelectorAll('form.file-upload').forEach(function(form){form.addEventListener('submit',function(event){var input=form.querySelector('input[type=file]');if(!input||!input.files.length)return;event.preventDefault();var file=input.files[0];fetch(form.action,{method:'POST',headers:{'Content-Type':'application/octet-stream','X-Filename':file.name,'X-CSRF-Token':sessionStorage.getItem('osint_csrf')||''},body:file}).then(function(r){if(r.redirected)location.href=r.url;else location.reload()}).catch(function(){location.reload()});});});
var graph=document.getElementById('case-graph');if(graph){var d=JSON.parse(graph.dataset.graph), ns=d.nodes, es=d.edges, w=760,h=360;graph.setAttribute('viewBox','0 0 '+w+' '+h);var pos={};ns.forEach(function(n,i){pos[n.id]={x:40+(i%4)*180,y:60+Math.floor(i/4)*110};});es.forEach(function(e){var a=pos[e.source],b=pos[e.target];if(!a||!b)return;var line=document.createElementNS('http://www.w3.org/2000/svg','line');line.setAttribute('x1',a.x);line.setAttribute('y1',a.y);line.setAttribute('x2',b.x);line.setAttribute('y2',b.y);line.setAttribute('stroke','#718096');graph.appendChild(line);});ns.forEach(function(n){var g=document.createElementNS('http://www.w3.org/2000/svg','g');g.setAttribute('tabindex','0');g.setAttribute('role','link');g.setAttribute('aria-label',n.type+': '+n.value);var c=document.createElementNS('http://www.w3.org/2000/svg','circle');c.setAttribute('cx',pos[n.id].x);c.setAttribute('cy',pos[n.id].y);c.setAttribute('r','24');c.setAttribute('fill','#155eef');var t=document.createElementNS('http://www.w3.org/2000/svg','text');t.setAttribute('x',pos[n.id].x);t.setAttribute('y',pos[n.id].y+42);t.setAttribute('text-anchor','middle');t.setAttribute('fill','#17202a');t.textContent=n.type+': '+n.value;g.appendChild(c);g.appendChild(t);g.addEventListener('click',function(){location.href=n.url;});g.addEventListener('keydown',function(e){if(e.key==='Enter'||e.key===' '){e.preventDefault();location.href=n.url;}});graph.appendChild(g);});}
// The API login supplies the existing session-bound CSRF token. It stays in
// this tab's sessionStorage and is sent only in the X-CSRF-Token header.
document.querySelectorAll('form[method="post"]:not(.file-upload)').forEach(function(form){
  form.addEventListener('submit',async function(event){
    event.preventDefault();
    var login=form.getAttribute('action')==='/ui/login';
    var body={},data=new FormData(form);
    data.forEach(function(value,key){body[key]=['principal_id','owner_user_id','user_id'].includes(key)?Number(value):key==='enabled'?value==='true':value;});
    var headers={'Content-Type':form.classList.contains('api-form')||login?'application/json':'application/x-www-form-urlencoded','X-CSRF-Token':sessionStorage.getItem('osint_csrf')||''};
    try {
      var r=await fetch(login?'/api/v1/auth/login':form.action,{method:form.dataset.method||'POST',headers:headers,body:form.classList.contains('api-form')||login?JSON.stringify(body):new URLSearchParams(data)});
      if(login){var auth=await r.json();if(!r.ok)throw new Error('Sign in failed');sessionStorage.setItem('osint_csrf',auth.result.csrf_token);location.href='/cases';}
      else if(r.ok){if(r.redirected)location.href=r.url;else location.reload();}
      else {var output=form.querySelector('output');if(output)output.textContent='Request rejected ('+r.status+').';else alert('Request rejected ('+r.status+').');}
    }catch(e){var output=form.querySelector('output');if(output)output.textContent='Request failed.';else alert('Request failed.');}
  });
});
