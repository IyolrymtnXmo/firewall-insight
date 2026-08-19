const S=document.getElementById('status'), L=document.getElementById('layer'), P=document.getElementById('pkg');
let browserData=null,accessData=null,natData=null,mapData=null;

function renderDataQuality(id,dq){
  const el=document.getElementById(id);
  if(el) el.innerHTML=dataQualityBanner(dq);
}

function primeEmptyStates(){
  const pkgHint='Pick a Policy Package at the top of the page, then run the analysis. Nothing is fetched until you ask.';
  const put=(id,html)=>{const el=document.getElementById(id); if(el&&!el.innerHTML.trim()) el.innerHTML=html;};
  put('browserResults',emptyState('\u25a4','No policy loaded yet',pkgHint,'Load Policy','onclick="loadPolicyBrowser()"'));
  put('accessFindings',emptyState('\u25c7','No analysis yet',pkgHint,'Run Analysis','onclick="runAccess()"'));
  put('traceResult',emptyState('\u279c','No trace yet','Enter a source, a destination and a port or service, then run the trace. This is a configuration-based simulation \u2014 it never sends a packet, so the hosts do not need to exist.',null,null));
}

function esc(v){return String(v??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]))}

/* ============================================================
   v4.11 UX runtime.

   The problem this replaces: every long call ran silently and the only
   feedback was one line of text, so "working", "finished" and "crashed"
   looked identical and you had to open DevTools to tell them apart.

   Design rules:
     - every request is tracked, so activity is always visible
     - every failure surfaces in the UI, never only in the console
     - anything slow reports elapsed time, so it never looks frozen
     - a partial result is labelled partial, never shown as complete
   ============================================================ */

const UX_LONG_MS = 6000;      // when to explain that slowness is expected
const UX_TIMEOUT_MS = 240000; // hard ceiling; hydration on a big policy is slow

/* ---------- status bar ---------- */
const STATUS_ICONS = {info:'•', busy:'', success:'✓', warn:'!', error:'✕'};

function setStatus(msg, kind='info'){
  const bar = document.getElementById('statusBar');
  const icon = document.getElementById('statusIcon');
  const time = document.getElementById('statusTime');
  if(S) S.textContent = msg;
  if(bar) bar.className = 'statusbar' + (kind !== 'info' ? ' ' + kind : '');
  if(icon) icon.innerHTML = kind === 'busy'
    ? '<span class="spinner sm"></span>'
    : (STATUS_ICONS[kind] || '•');
  if(time) time.textContent = new Date().toLocaleTimeString();
  const live = document.getElementById('srLive');
  if(live && kind !== 'busy') live.textContent = msg;
}

/* ---------- toasts ---------- */
const TOAST_ICONS = {success:'✓', info:'i', warn:'!', error:'✕'};
const TOAST_LIFE = {success:4200, info:5200, warn:9000, error:0}; // 0 = sticky

function notify(kind, title, message='', opts={}){
  const host = document.getElementById('toasts');
  if(!host) return;
  const el = document.createElement('div');
  el.className = 'toast ' + kind;
  el.setAttribute('role', kind === 'error' ? 'alert' : 'status');

  const life = opts.duration !== undefined ? opts.duration : TOAST_LIFE[kind];
  el.innerHTML =
    `<div class="ic">${TOAST_ICONS[kind] || 'i'}</div>` +
    `<div class="body"><div class="t">${esc(title)}</div>` +
    (message ? `<div class="m">${esc(message)}</div>` : '') +
    (opts.actionLabel ? `<button class="act">${esc(opts.actionLabel)}</button>` : '') +
    `</div><button class="x" aria-label="Dismiss">×</button>` +
    (life ? `<div class="life"></div>` : '');

  host.appendChild(el);
  requestAnimationFrame(() => el.classList.add('in'));

  const close = () => {
    if(el.dataset.closing) return;
    el.dataset.closing = '1';
    el.classList.add('out');
    setTimeout(() => el.remove(), 400);
  };
  el.querySelector('.x').onclick = close;
  const act = el.querySelector('.act');
  if(act && opts.onAction) act.onclick = () => { close(); opts.onAction(); };

  if(life){
    const bar = el.querySelector('.life');
    bar.style.transition = `transform ${life}ms linear`;
    requestAnimationFrame(() => { bar.style.transform = 'scaleX(0)'; });
    setTimeout(close, life);
  }
  return close;
}

/* ---------- global request tracking ---------- */
let uxInFlight = 0;

function uxRequestStart(){
  uxInFlight++;
  const p = document.getElementById('topProgress');
  if(p) p.classList.add('on');
  document.body.setAttribute('aria-busy', 'true');
}
function uxRequestEnd(){
  uxInFlight = Math.max(0, uxInFlight - 1);
  if(uxInFlight === 0){
    const p = document.getElementById('topProgress');
    if(p) p.classList.remove('on');
    document.body.removeAttribute('aria-busy');
  }
}

/* ---------- blocking overlay ---------- */
let uxBusyTimer = null, uxBusyStart = 0, uxBusyDepth = 0;

function busyShow(title, sub='', steps=[]){
  uxBusyDepth++;
  const ov = document.getElementById('busyOverlay');
  if(!ov) return;
  document.getElementById('busyTitle').textContent = title;
  document.getElementById('busySub').innerHTML =
    esc(sub) + ' <span class="busy-elapsed" id="busyElapsed">0.0s</span>';
  const hint = document.getElementById('busyHint');
  hint.classList.remove('on');
  const stepBox = document.getElementById('busySteps');
  stepBox.innerHTML = steps.map((s, i) =>
    `<div class="busy-step${i === 0 ? ' active' : ''}" data-step="${i}">` +
    `<span class="dot"></span><span>${esc(s)}</span></div>`).join('');

  ov.classList.add('on');
  uxBusyStart = Date.now();
  clearInterval(uxBusyTimer);
  uxBusyTimer = setInterval(() => {
    const ms = Date.now() - uxBusyStart;
    const e = document.getElementById('busyElapsed');
    if(e) e.textContent = (ms / 1000).toFixed(1) + 's';
    if(ms > UX_LONG_MS && !hint.classList.contains('on')){
      hint.classList.add('on');
      hint.textContent = 'Still working. The first load of a package fetches '
        + 'full object detail one object at a time, paced to stay under the '
        + 'Management API rate limit, so 10–20s is normal. Results are '
        + 'then cached for 5 minutes.';
    }
  }, 100);
}

function busyStep(index){
  document.querySelectorAll('#busySteps .busy-step').forEach(el => {
    const i = Number(el.dataset.step);
    el.classList.toggle('active', i === index);
    el.classList.toggle('done', i < index);
  });
}

function busyDetail(text){
  const el = document.getElementById('busyDetail');
  if(!el) return;
  el.textContent = text || '';
  el.classList.toggle('on', !!text);
}

/* Real progress, polled from the server.

   The browser issues ONE request for a trace or an analysis, so it cannot see
   server-side phases. Driving the step list from a client-side guess would
   make it decoration that lies — exactly the failure mode this project keeps
   fixing elsewhere. The backend records its phase against a request id and
   this polls it. */
let uxRid = 0;
function newRid(){ return 'r' + (++uxRid) + '-' + Date.now().toString(36); }

function trackProgress(rid){
  let stopped = false;
  const tick = async () => {
    if(stopped) return;
    try{
      const r = await fetch('/api/progress?rid=' + encodeURIComponent(rid));
      if(r.ok){
        const p = await r.json();
        if(p.done){ busyStep(999); busyDetail(''); }
        else if(typeof p.phase === 'number'){
          busyStep(p.phase);
          busyDetail(p.detail || '');
        }
      }
    }catch(_){ /* progress is best-effort; never fail the real request for it */ }
    if(!stopped) setTimeout(tick, 500);
  };
  tick();
  return () => { stopped = true; };
}

function busyHide(){
  uxBusyDepth = Math.max(0, uxBusyDepth - 1);
  if(uxBusyDepth > 0) return;
  clearInterval(uxBusyTimer);
  const ov = document.getElementById('busyOverlay');
  if(ov) ov.classList.remove('on');
}

/* ---------- error normalisation ---------- */
function describeError(e){
  const raw = String((e && e.message) || e || 'Unknown error');
  if(e && e.name === 'AbortError')
    return {title:'Request timed out', hint:'The Management API did not answer in time. It may be busy loading a large policy — try again, or raise CHECKPOINT_TIMEOUT.'};
  if(/failed to fetch|networkerror|load failed/i.test(raw))
    return {title:'Cannot reach Firewall Insight', hint:'The uvicorn server looks like it stopped. Check the terminal running it, then retry.'};
  if(/^HTTP 429|rate limit|too many requests/i.test(raw))
    return {title:'Management API rate limit', hint:'Retry/backoff was exhausted. Wait a moment and retry, or raise CHECKPOINT_MIN_REQUEST_INTERVAL in .env.'};
  if(/^HTTP 502|unable to connect/i.test(raw))
    return {title:'Management Server unreachable', hint:'Check CHECKPOINT_MGMT in .env, that the server is up, and that the Management API accepts this client.'};
  if(/^HTTP 400/i.test(raw))
    return {title:'Request rejected', hint:raw.replace(/^HTTP 400:\s*/i, '')};
  if(/login|authentication|credential/i.test(raw))
    return {title:'Authentication failed', hint:'Check CHECKPOINT_USER and CHECKPOINT_PASSWORD in .env.'};
  return {title:'Request failed', hint:raw};
}

function fail(e, context=''){
  const d = describeError(e);
  const raw = String((e && e.message) || e || '');
  setStatus((context ? context + ': ' : '') + d.title + ' — ' + d.hint, 'error');
  notify('error', d.title, d.hint, {
    actionLabel: 'Copy details',
    onAction: () => {
      const text = (context ? context + '\n' : '') + raw;
      if(navigator.clipboard) navigator.clipboard.writeText(text);
      notify('info', 'Copied', 'Error details are on your clipboard.');
    }
  });
  console.error('[Firewall Insight]', context, e);
  return d;
}

/* ---------- the task wrapper ---------- */
const uxRunning = new Set();

async function task(key, label, fn, opts={}){
  if(uxRunning.has(key)){
    notify('info', 'Already running', label + ' is still in progress.');
    return;
  }
  uxRunning.add(key);
  const btn = opts.button || null;
  if(btn){ btn.dataset.busy = '1'; btn.disabled = true; }
  setStatus(label + '…', 'busy');
  if(opts.blocking !== false) busyShow(label, opts.sub || 'Elapsed', opts.steps || []);

  try{
    const out = await fn();
    if(opts.successMessage !== null){
      setStatus(opts.successMessage || (label + ' complete.'), 'success');
      if(opts.toast !== false)
        notify('success', opts.successTitle || label + ' complete', opts.successMessage || '');
    }
    return out;
  }catch(e){
    fail(e, label);
    throw e;
  }finally{
    uxRunning.delete(key);
    if(btn){ delete btn.dataset.busy; btn.disabled = false; }
    if(opts.blocking !== false) busyHide();
  }
}

/* ---------- skeletons / states ---------- */
function skeletonTable(cols=7, rows=8){
  return '<div class="table-wrap" style="padding:4px 14px 14px">'
    + `<div class="skel-row">${'<div class="skel"></div>'.repeat(cols)}</div>`.repeat(rows + 1)
    + '</div>';
}
function skeletonCards(n=5){
  return `<div class="cards">${
    '<div class="skel-card"><div class="skel skel-line" style="width:52%"></div>'
    + '<div class="skel skel-line" style="height:26px;width:38%"></div>'
    + '<div class="skel skel-line" style="width:72%"></div></div>'}`.repeat(1)
    + '</div>';
}
function emptyState(icon, title, hint, actionLabel, actionAttr){
  return `<div class="state"><div class="ic">${icon}</div><h4>${esc(title)}</h4>`
    + `<p>${esc(hint)}</p>`
    + (actionLabel ? `<button class="primary" ${actionAttr}>${esc(actionLabel)}</button>` : '')
    + `</div>`;
}
function errorState(e, retryAttr){
  const d = describeError(e);
  return `<div class="state err"><div class="ic">✕</div><h4>${esc(d.title)}</h4>`
    + `<p>${esc(d.hint)}</p>`
    + (retryAttr ? `<button class="primary" ${retryAttr}>Retry</button>` : '')
    + `<pre>${esc(String((e && e.message) || e || ''))}</pre></div>`;
}

/* ---------- data-quality banner ---------- */
function dataQualityBanner(dq){
  if(!dq || !dq.warnings || !dq.warnings.length) return '';
  return `<div class="dq"><div class="ic">!</div><div><h4>This result is incomplete</h4>`
    + `<ul>${dq.warnings.map(w => `<li>${esc(w)}</li>`).join('')}</ul></div></div>`;
}
function reportDataQuality(dq, context){
  if(!dq || dq.complete !== false) return;
  (dq.warnings || []).forEach(w =>
    notify('warn', context + ': incomplete result', w, {duration: 12000}));
}

/* ---------- connection badge ---------- */
function setConn(state, text){
  const el = document.getElementById('conn');
  if(!el) return;
  el.className = 'badge conn' + (state ? ' ' + state : '');
  el.innerHTML = `<span class="dot"></span><span>${esc(text)}</span>`;
}

/* ---------- mobile nav ---------- */
function toggleRail(force){
  const on = force !== undefined ? force : !document.body.classList.contains('rail');
  document.body.classList.toggle('rail', on);
  try{ localStorage.setItem('fw-rail', on ? '1' : '0'); }catch(_){}
  const b = document.getElementById('railToggle');
  if(b) b.innerHTML = on ? '&#8677;' : '&#8676; <span>Collapse</span>';
}

function toggleNav(force){
  const open = force !== undefined ? force : !document.body.classList.contains('nav-open');
  document.body.classList.toggle('nav-open', open);
}

/* ---------- global safety nets ---------- */
window.addEventListener('error', ev => {
  notify('error', 'Unexpected interface error',
    (ev.message || 'Script error') + (ev.lineno ? ' (line ' + ev.lineno + ')' : ''));
});
window.addEventListener('unhandledrejection', ev => {
  const r = ev.reason;
  if(r && r.__uxHandled) return;
  const d = describeError(r);
  notify('error', d.title, d.hint);
});
window.addEventListener('offline', () => {
  document.getElementById('offlineBar')?.classList.add('on');
  setStatus('Browser is offline. Requests will fail until the connection returns.', 'error');
});
window.addEventListener('online', () => {
  document.getElementById('offlineBar')?.classList.remove('on');
  setStatus('Connection restored.', 'success');
});
document.addEventListener('keydown', ev => {
  if((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === 'b'){
    ev.preventDefault();
    toggleRail();
  }
  if(ev.key === 'Escape'){
    document.querySelectorAll('#toasts .toast .x').forEach(b => b.click());
    toggleNav(false);
  }
});

async function api(u){
  uxRequestStart();
  const ctl=new AbortController();
  const to=setTimeout(()=>ctl.abort(),UX_TIMEOUT_MS);
  try{
    const r=await fetch(u,{signal:ctl.signal});
    const t=await r.text();
    let d;
    try{d=JSON.parse(t)}catch{throw new Error('HTTP '+r.status+': '+t.slice(0,300))}
    if(!r.ok)throw new Error('HTTP '+r.status+': '+(d.detail||JSON.stringify(d)));
    return d;
  }finally{
    clearTimeout(to);
    uxRequestEnd();
  }
}

function showPage(id,b){
  document.querySelectorAll('.page').forEach(x=>x.classList.remove('active'));
  const pg=document.getElementById(id); if(pg)pg.classList.add('active');
  document.querySelectorAll('.menu button').forEach(x=>x.classList.remove('active'));
  if(b)b.classList.add('active');
  if(typeof layerControl!=='undefined') layerControl.style.display=(id==='traffic')?'inline-block':'none';
  if(typeof packageControl!=='undefined') packageControl.style.display=(id==='dashboard'||id==='browser'||id==='access'||id==='nat'||id==='traffic')?'inline-block':'none';
}

function goTo(id){
  const b=document.querySelector(`.menu button[data-page="${id}"]`);
  showPage(id,b);
}
async function dashboardRefresh(){
  if(!P.value){
    setStatus('Select a Policy Package on the Dashboard first.','warn');notify('warn','No Policy Package selected','Pick a package in the selector at the top, then run the analysis again.');
    return;
  }
  const btn=document.querySelector('#dashboard button.primary');
  return task('dashboard','Analyzing selected policies',async()=>{
    const completed=[];
    // These ARE three separate requests, so the step list is real here.
    busyStep(0);
    await runAccess();
    busyStep(1);
    await loadPolicyBrowser();
    completed.push('Access');
    busyStep(2);
    await runNat();
    completed.push('NAT');
    busyStep(3);

    // browserData / accessData / natData remain in the browser session, so
    // opening Access Policy, Analyze or NAT Policy immediately shows results.
    showPage('dashboard',document.querySelector('.menu button[data-page="dashboard"]'));
    const msg=completed.join(' + ')+' analysis complete. Results are available in all related pages, including Access Policy.';
    setStatus(msg,'success');
    notify('success','Analysis complete',msg);
    return msg;
  },{
    button:btn,
    sub:'Package: '+P.value+' · elapsed',
    steps:['Analyze Access Control policy','Load configured rulebase','Analyze NAT rulebase','Render dashboard'],
    successMessage:null
  }).catch(()=>{});
}


let pendingAnalysisTab=null;
let pendingNatTab=null;
function drillTo(page,tab=null){
  const b=document.querySelector(`.menu button[data-page="${page}"]`);
  showPage(page,b);
  if(page==='access'){
    pendingAnalysisTab=tab;
    if(accessData){renderAccess(tab||'shadow');pendingAnalysisTab=null;}
  }
  if(page==='nat'){
    pendingNatTab=tab;
    if(natData){renderNat(tab||'rulebase');pendingNatTab=null;}
  }
  if(page==='browser' && typeof browserData!=='undefined' && browserData){
    renderPolicyBrowser(browserData.rules);
  }
}
window.addEventListener('DOMContentLoaded',()=>{
  try{ if(localStorage.getItem('fw-rail')==='1') toggleRail(true); }catch(_){}
  primeEmptyStates();
  setStatus('Ready. No API calls are made automatically \u2014 pick a Policy Package and run an analysis.','info');
  notify('info','Read-only tool',
    'Firewall Insight only issues show-* Management API calls. It never publishes or installs policy.',
    {duration:7000});
});

function toggleTheme(){document.body.classList.toggle('light');localStorage.setItem('fw-theme',document.body.classList.contains('light')?'light':'dark')}
if(localStorage.getItem('fw-theme')==='light')document.body.classList.add('light');

async function testConn(ev){
  setConn('testing','Testing…');
  return task('conn','Testing Management API',async()=>{
    const d=await api('/api/checkpoint/test');
    setConn('ok','Connected · API '+(d.api_server_version||'?'));
    const m='Connected. Persistent read-only API session is ready.';
    setStatus(m,'success');
    notify('success','Management API reachable','API '+(d.api_server_version||'?')+' · read-only session established.');
    return d;
  },{
    blocking:false,
    button:ev&&ev.currentTarget,
    successMessage:null
  }).catch(()=>{setConn('bad','Connection failed')});
}
async function loadMetadata(force=false,ev){
  return task('meta','Loading policy metadata',async()=>{
    const d=await api('/api/bootstrap?force='+(force?'true':'false'));
    L.innerHTML='<option value="">Select Access Layer...</option>'+d.layers.map(x=>`<option>${esc(x.name)}</option>`).join('');
    P.innerHTML='<option value="">Select Policy Package...</option>'+d.packages.map(x=>`<option>${esc(x.name)}</option>`).join('');
    const m=`Loaded ${d.layers.length} Access Layers and ${d.packages.length} packages`+(d.cached?' (from cache)':'')+'.';
    setStatus(m,'success');
    if(!d.layers.length||!d.packages.length)
      notify('warn','Nothing to select','The Management API returned no '+(!d.packages.length?'policy packages':'access layers')+'. Check that this API user has read permission.');
    else notify('success','Metadata loaded',m);
    return d;
  },{blocking:false,button:ev&&ev.currentTarget,successMessage:null}).catch(()=>{});
}

function isAlertMetric(label){
  return [
    'Shadow / Redundant','Duplicate Groups','Any / Any / Any',
    'Duplicate NAT','Broad Any/Any/Any','Disabled NAT','Possible No-Translation'
  ].includes(String(label||''));
}
function alertValue(label,value){
  const n=Number(value);
  if(isAlertMetric(label) && Number.isFinite(n) && n>0){
    return `<span class="alert-count" title="Finding requires review">${esc(value)}</span>`;
  }
  return esc(value);
}
function setDashboardMetric(el,value,isFinding=false){
  if(!el)return;
  const n=Number(value);
  el.classList.toggle('num',isNumericValue(value));
  el.innerHTML=(isFinding && Number.isFinite(n) && n>0)
    ? `<span class="alert-count" title="Finding requires review">${esc(value)}</span>`
    : esc(value);
}
function isNumericValue(v){
  if(typeof v==='number')return true;
  return typeof v==='string' && /^[\d.,%+\-\s]+$/.test(v.trim()) && /\d/.test(v);
}
function metricCards(el,items){
  el.classList.remove('hidden');
  el.innerHTML=items.map(x=>`<div class="card"><div class="metric-label">${esc(x[0])}</div><div class="metric${isNumericValue(x[1])?' num':''}">${alertValue(x[0],x[1])}</div></div>`).join('');
}


async function loadPolicyBrowser(){
  if(!P.value){setStatus('Select a Policy Package first.','warn');notify('warn','No Policy Package selected','Choose a package from the selector at the top of the page.');return}
  browserBtn.disabled=true;
  browserBtn.dataset.busy='1';
  setStatus('Loading configured Access Policy without optimizer analysis…','busy');
  browserResults.innerHTML=skeletonTable(13,10);

  try{
    browserData=await api('/api/package-policy-browser?package='+encodeURIComponent(P.value));
    browserCount.textContent=browserData.total_rules+' access rules';
    metricCards(browserSummary,[
      ['Access Rules',browserData.total_rules],
      ['Policy Type','Access Control'],
      ['Top-Level Rules',browserData.top_level_rules],
      ['Inline Rules',browserData.inline_rules],
      ['Inline Layers',browserData.inline_layers],
      ['Policy Package',P.value]
    ]);
    renderPolicyBrowser(browserData.rules);
    renderDataQuality('browserDq',browserData.data_quality);
    reportDataQuality(browserData.data_quality,'Access Policy');
    if(!browserData.total_rules)
      browserResults.innerHTML=emptyState('▤','No rules returned',
        'The package resolved, but its Access layer contained no rules. Confirm in SmartConsole that this package has a policy.',
        'Reload','onclick="loadPolicyBrowser()"');
    setStatus('Policy Browser loaded — '+browserData.total_rules+' top-level + '+browserData.inline_rules+' inline rule(s). No optimizer analysis was performed.','success');
  }catch(e){
    browserResults.innerHTML=errorState(e,'onclick="loadPolicyBrowser()"');
    fail(e,'Access Policy');
    throw e;
  }finally{
    browserBtn.disabled=false;
    delete browserBtn.dataset.busy;
  }
}

function policyActionClass(action){
  const a=String(action||'').toLowerCase();
  if(a.includes('accept'))return 'good';
  if(a.includes('drop')||a.includes('reject'))return 'bad';
  return 'purple';
}


function hierarchyKey(layer,rule){
  return `${String(layer||'')}::${String(rule??'')}`;
}

function accessHierarchyRows(rows){
  const top=[];
  const childMap=new Map();
  const orphans=[];

  for(const r of rows||[]){
    if(Number(r.depth||0)===0){
      top.push(r);
      continue;
    }
    const key=hierarchyKey(r.parent_layer,r.parent_rule);
    if(!r.parent_rule && r.parent_rule!==0){
      orphans.push(r);
      continue;
    }
    if(!childMap.has(key))childMap.set(key,[]);
    childMap.get(key).push(r);
  }

  const output=[];
  for(const parent of top){
    const key=hierarchyKey(parent.layer,parent.rule);
    const children=childMap.get(key)||[];
    output.push({...parent,_row_kind:'parent',_inline_count:children.length});
    for(const child of children){
      output.push({...child,_row_kind:'inline'});
    }
    childMap.delete(key);
  }

  // Preserve data even when a parent cannot be matched.
  for(const children of childMap.values()){
    for(const child of children)orphans.push(child);
  }
  for(const child of orphans){
    output.push({...child,_row_kind:'inline'});
  }
  return output;
}

function renderInlineDashboardSummary(s){
  const box=document.getElementById('inlineAnalysisSummary');
  if(!box)return;
  if(!s || Number(s.inline_layers||0)<=0){
    box.style.display='none';
    return;
  }
  box.style.display='block';
  diLayers.textContent=s.inline_layers||0;
  diRules.textContent=s.inline_rules||0;
  setDashboardMetric(diShadow,s.inline_shadow_findings||0,true);
  setDashboardMetric(diDup,s.inline_duplicate_groups||0,true);
  setDashboardMetric(diAny,s.inline_any_any_any_rules||0,true);
}

function renderPolicyBrowser(rows){
  if(!rows)rows=[];
  rows=accessHierarchyRows(rows);
  browserResults.innerHTML=`
    <div class="section-title">
      <h3>Configured Rulebase</h3>
      <span class="hint">${browserData?.top_level_rules??0} top-level + ${browserData?.inline_rules??0} inline rule(s)</span>
    </div>
    <div class="table-wrap" style="margin-top:12px">
      <table>
        <thead>
          <tr>
            <th>Layer</th><th>Rule</th><th>Section</th><th>Name</th><th>Source</th>
            <th>Destination</th><th>VPN</th><th>Service</th><th>Action</th>
            <th>Track</th><th>Install On</th><th>Hits</th><th>Enabled</th>
          </tr>
        </thead>
        <tbody>
          ${rows.map(r=>`<tr class="${r._row_kind==='inline'?'inline-child-row':(r._inline_count?'inline-parent-row':'')}">
            <td>${r._row_kind==='inline'
              ? `<span class="inline-layer-name"><span class="pill inline">${esc(r.layer||'Inline Layer')}</span></span><br><span class="muted">${esc(r.layer_path||'')}</span>`
              : `<span class="pill good">${esc(r.layer||'Access Layer')}</span><br><span class="muted">${r._inline_count?`${esc(r._inline_count)} inline rule(s) attached`:'Top-level'}</span>`
            }</td>
            <td><span class="rule-no">${r._row_kind==='inline'?'↳ ':''}Rule ${esc(r.display_rule||r.rule)}</span>${r.parent_rule!=null?`<br><span class="muted">under Parent Rule ${esc(r.parent_rule)}</span>`:''}</td>
            <td>${esc(r.section||'—')}</td>
            <td>${esc(r.name||'—')}</td>
            <td>${esc(r.source||'—')}</td>
            <td>${esc(r.destination||'—')}</td>
            <td>${esc(r.vpn||'—')}</td>
            <td>${esc(r.service||'—')}</td>
            <td><span class="pill ${policyActionClass(r.action)}">${esc(r.action||'—')}</span></td>
            <td>${esc(r.track||'—')}</td>
            <td>${esc(r.install_on||'—')}</td>
            <td>${esc(r.hits??'—')}</td>
            <td>${r.enabled?'<span class="pill good">Enabled</span>':'<span class="pill bad">Disabled</span>'}</td>
          </tr>`).join('')}
        </tbody>
      </table>
    </div>`;
}

function filterPolicyBrowser(){
  if(!browserData)return;
  const q=String(policySearch.value||'').trim().toLowerCase();
  const af=String(actionFilter.value||'').toLowerCase();

  const rows=browserData.rules.filter(r=>{
    const text=[
      r.layer,r.layer_path,r.parent_rule,r.rule,r.section,r.name,r.source,r.destination,r.vpn,r.service,
      r.action,r.track,r.install_on,r.comments
    ].join(' ').toLowerCase();

    const qok=!q||text.includes(q);
    const aok=!af||String(r.action||'').toLowerCase().includes(af);
    return qok&&aok;
  });

  renderPolicyBrowser(rows);
}

function exportRawPolicy(){
  if(!P.value){setStatus('Select a Policy Package first.','warn');notify('warn','No Policy Package selected','Choose a package from the selector at the top of the page.');return}
  S.textContent='Package-level CSV export will be added after package/inline validation. The on-screen Access Policy view contains the complete package context.';
}


async function runAccess(){
 if(!P.value){setStatus('Select a Policy Package first.','warn');notify('warn','No Policy Package selected','Choose a package from the selector at the top of the page.');return}
 setStatus('Analyzing Access Policy Package…','busy');
 if(typeof accessCards!=='undefined'&&accessCards&&!accessData) accessCards.innerHTML=skeletonCards(8);
 try{
   const rid=newRid(); const stopP=trackProgress(rid);
   try{ accessData=await api('/api/package-analyze?package='+encodeURIComponent(P.value)+'&rid='+rid); }
   finally{ stopP(); }
   let s=accessData.summary;
   metricCards(accessCards,[['Access Rules',s.total_rules],['Inline Rules Analyzed',s.inline_rules],['Inline Layers',s.inline_layers],['Total Rules Inspected',s.analyzed_rules],['Shadow / Redundant',s.potential_shadowed_or_redundant],['Duplicate Groups',s.duplicate_groups],['Any / Any / Any',s.any_any_any_rules],['Optimizer Score',s.optimization_score+'%']]);
   setDashboardMetric(dAccess,s.total_rules,false);dAccessDetail.textContent=`SmartConsole: ${s.top_level_rules} parent/top-level rule(s) · ${s.inline_rules} inline rule(s) analyzed`;setDashboardMetric(dShadow,s.potential_shadowed_or_redundant,true);setDashboardMetric(dDup,s.duplicate_groups,true);renderInlineDashboardSummary(s);
   dashLayer.textContent=(accessData?.root_layers||[]).join(', ')||'Resolved from package';
   dashFindings.innerHTML=`<table style="min-width:650px"><thead><tr><th>Finding</th><th>Count</th><th>Meaning</th></tr></thead><tbody>
     <tr class="drill-row" onclick="drillTo('access','shadow')" title="Open Shadow / Redundant findings"><td>Shadow / Redundant</td><td>${s.potential_shadowed_or_redundant?`<span class="alert-count">${esc(s.potential_shadowed_or_redundant)}</span>`:esc(s.potential_shadowed_or_redundant)}</td><td>${esc(s.top_level_shadow_findings||0)} top-level + ${esc(s.inline_shadow_findings||0)} inline finding(s).</td></tr>
     <tr class="drill-row" onclick="drillTo('access','duplicates')" title="Open Duplicate Access findings"><td>Duplicate Access</td><td>${s.duplicate_groups?`<span class="alert-count">${esc(s.duplicate_groups)}</span>`:esc(s.duplicate_groups)}</td><td>${esc(s.top_level_duplicate_groups||0)} top-level + ${esc(s.inline_duplicate_groups||0)} inline group(s).</td></tr>
     <tr class="drill-row" onclick="drillTo('access','any')" title="Open Any / Any / Any findings"><td>Any / Any / Any</td><td>${s.any_any_any_rules?`<span class="alert-count">${esc(s.any_any_any_rules)}</span>`:esc(s.any_any_any_rules)}</td><td>${esc(s.top_level_any_any_any_rules||0)} top-level + ${esc(s.inline_any_any_any_rules||0)} inline rule(s).</td></tr>
     <tr><td>Optimizer Score</td><td>${esc(s.optimization_score)}%</td><td>Heuristic score from this analyzer, not Check Point Security Score.</td></tr>
   </tbody></table>`;
   renderAccess(pendingAnalysisTab||'shadow');pendingAnalysisTab=null;
   renderDataQuality('accessDq',accessData.data_quality);
   reportDataQuality(accessData.data_quality,'Analyze');
   const findings=(s.potential_shadowed_or_redundant||0)+(s.duplicate_groups||0)+(s.any_any_any_rules||0);
   setStatus('Access Policy analysis complete — '+s.analyzed_rules+' rule(s) inspected, '+findings+' finding(s), score '+s.optimization_score+'%.','success');
   if(findings) notify('warn',findings+' optimization finding(s)',
     (s.potential_shadowed_or_redundant||0)+' shadow/redundant · '+(s.duplicate_groups||0)+' duplicate group(s) · '+(s.any_any_any_rules||0)+' Any/Any/Any. Click a dashboard count to drill in.',
     {duration:10000});
   if(s.cleanup_rules) notify('info','Cleanup rules excluded',
     s.cleanup_rules+' trailing Any/Any/Any deny rule(s) were counted as cleanup rules, not findings.');
 }catch(e){
   if(typeof accessFindings!=='undefined'&&accessFindings) accessFindings.innerHTML=errorState(e,'onclick="runAccess()"');
   fail(e,'Analyze');
   throw e;
 }
}
function accessTabs(kind){let d=accessData;return `<div class="tabs"><button class="${kind==='shadow'?'active':''}" onclick="renderAccess('shadow')">Shadow / Redundant</button><button class="${kind==='duplicates'?'active':''}" onclick="renderAccess('duplicates')">Duplicate Rules (${d.findings.duplicates.length})</button><button class="${kind==='any'?'active':''}" onclick="renderAccess('any')">Any Rules (${(d.findings.any_any_any_rules||[]).length})</button></div>`}
function renderAccess(kind){
 if(!accessData)return;let d=accessData,t=accessTabs(kind);
 if(kind==='shadow'){
   let sh=d.findings.shadowing||[];
   accessFindings.innerHTML=t+'<div class="section-title"><h3>Shadow / Redundant Findings</h3><span class="hint">'+sh.length+' finding(s)</span></div>'+
   (sh.length?`<div class="table-wrap"><table><thead><tr><th>Layer</th><th>Rule</th><th>Covered By</th><th>Class</th><th>Action</th><th>Source Match</th><th>Destination Match</th><th>Service Match</th></tr></thead><tbody>${
     sh.map(x=>`<tr><td><span class="pill ${Number(x.depth||0)>0?'purple':'good'}">${esc(x.layer||'')}</span></td><td><span class="rule-no">Rule ${esc(x.display_rule||x.rule)}</span><br><span class="muted">${esc(x.rule_name)}</span></td><td><span class="rule-no">Rule ${esc(x.covered_by)}</span><br><span class="muted">${esc(x.covered_by_name)}</span></td><td><span class="pill ${x.risk==='High'?'bad':'warn'}">${esc(x.classification)} · ${esc(x.risk)}</span></td><td>${esc(x.earlier_action)} → ${esc(x.later_action)}</td><td>${friendly(x.source_reason)}</td><td>${friendly(x.destination_reason)}</td><td>${friendly(x.service_reason)}</td></tr>`).join('')
   }</tbody></table></div>`:'<p>No conservative findings.</p>');
 }else if(kind==='duplicates'){
   let gs=d.findings.duplicates||[];
   accessFindings.innerHTML=t+'<h3>Duplicate Rules</h3>'+(gs.length?gs.map(g=>`<div class="card" style="margin:12px 0"><div class="section-title"><b>Duplicate Group ${esc(g.group)} <span class="pill purple">Exact Duplicate</span></b><span class="hint">${esc(g.recommendation)}</span></div><div class="table-wrap"><table><tr><th>Layer</th><th>Rule</th><th>Name</th><th>Source</th><th>Destination</th><th>Service</th><th>Action</th></tr>${g.members.map(m=>`<tr><td><span class="pill purple">${esc(m.layer||g.layer||'')}</span></td><td><span class="rule-no">Rule ${esc(m.display_rule||m.rule)}</span></td><td>${esc(m.name)}</td><td>${esc(m.source)}</td><td>${esc(m.destination)}</td><td>${esc(m.service)}</td><td>${esc(m.action)}</td></tr>`).join('')}</table></div></div>`).join(''):'<p>No exact duplicate groups found.</p>');
 }else{
   let rs=d.findings.any_any_any_rules||[];
   accessFindings.innerHTML=t+'<h3>Any / Any / Any Rules</h3>'+(rs.length?`<div class="table-wrap"><table><tr><th>Layer</th><th>Rule</th><th>Name</th><th>Source</th><th>Destination</th><th>Service</th><th>Action</th><th>Hits</th></tr>${rs.map(r=>`<tr><td><span class="pill ${Number(r.depth||0)>0?'purple':'good'}">${esc(r.layer||'')}</span></td><td><span class="rule-no">Rule ${esc(r.display_rule||r.rule)}</span></td><td>${esc(r.name)}</td><td>${esc(r.source)}</td><td>${esc(r.destination)}</td><td>${esc(r.service)}</td><td>${esc(r.action)}</td><td>${esc(r.hits??'N/A')}</td></tr>`).join('')}</table></div>`:'<p>No Any / Any / Any rules found.</p>')+cleanupNote(d);
 }
}
function cleanupNote(d){
  let cs=(d.findings&&d.findings.cleanup_rules)||[];
  if(!cs.length)return '';
  return `<p class="muted" style="margin-top:14px">Excluded ${cs.length} cleanup rule(s) — `
    +cs.map(c=>`${esc(c.layer||'')} Rule ${esc(c.display_rule||c.rule)} (${esc(c.action||'')})`).join(', ')
    +`. A trailing Any/Any/Any deny rule is expected in every policy and is not an optimization finding.</p>`;
}
function friendly(v){v=String(v||'');return esc(v.replace('Exact object/group UID coverage','Exact Match').replace('Subnet/range coverage','Network Contains').replace('Protocol/port coverage','Port / Service Contains').replace(/^Any$/,'Covered by Any'))}

async function runNat(){
 if(!P.value){setStatus('Select a Policy Package first.','warn');notify('warn','No Policy Package selected','Choose a package from the selector at the top of the page.');return}
 setStatus('Loading and analyzing NAT rulebase…','busy');
 try{
   natData=await api('/api/nat-analyze?package='+encodeURIComponent(P.value)); renderNatSpecialViews(natData);let s=natData.summary;
   metricCards(natCards,[['Total NAT Rules',s.total_nat_rules],['Duplicate NAT',s.duplicate_nat_groups],['Broad Any/Any/Any',s.broad_original_any_any_any],['Disabled NAT',s.disabled_nat_rules],['Possible No-Translation',s.possible_no_translation_rules]]);
   setDashboardMetric(dNat,s.total_nat_rules,false);setDashboardMetric(dNatDup,s.duplicate_nat_groups,true);dashPackage.textContent=P.value||'Not selected';natTabs.style.display='flex';renderNat(pendingNatTab||'rulebase');pendingNatTab=null;
   const hits=s.nat_hits_available;
   setStatus('NAT analysis complete — '+s.total_nat_rules+' rule(s). Hit counts '+(hits?'available':'not supported by this Management API build')+'.',hits?'success':'warn');
   if(!hits) notify('info','NAT hit counts unavailable',
     'This Management API build rejected show-hits on show-nat-rulebase, so the Hits column stays empty. Access hit counts are unaffected.',
     {duration:9000});
 }catch(e){
   fail(e,'NAT Policy');
   throw e;
 }
}
function renderNat(kind,b){
 document.querySelectorAll('#natTabs button').forEach(x=>x.classList.remove('active'));if(b)b.classList.add('active');
 if(!natData)return;
 if(kind==='rulebase'){
   let rs=natData.rules||[];
   natResults.innerHTML='<h3>NAT Rulebase</h3>'+natTable(rs);
 }else if(kind==='duplicates'){
   let gs=natData.findings.duplicates||[];
   natResults.innerHTML='<h3>Duplicate NAT Rules</h3>'+(gs.length?gs.map(g=>`<div class="card" style="margin:12px 0"><div class="section-title"><b>Duplicate NAT Group ${esc(g.group)} <span class="pill purple">Exact NAT Duplicate</span></b><span class="hint">${esc(g.recommendation)}</span></div>${natTable(g.members)}</div>`).join(''):'<p>No exact duplicate NAT groups found.</p>');
 }else{
   let nums=new Set(natData.findings.broad_rule_numbers||[]),rs=natData.rules.filter(r=>nums.has(r.rule));
   natResults.innerHTML='<h3>Broad Original Any / Any / Any NAT Rules</h3>'+(rs.length?natTable(rs):'<p>No broad NAT rules found.</p>');
 }
}
function natTable(rs){return `<div class="table-wrap"><table><thead><tr><th>Rule</th><th>Name</th><th>Original Source</th><th>Original Destination</th><th>Original Service</th><th>Translated Source</th><th>Translated Destination</th><th>Translated Service</th><th>Install On</th><th>Method</th><th>Hits</th></tr></thead><tbody>${rs.map(r=>`<tr><td><span class="rule-no">Rule ${esc(r.display_rule||r.rule)}</span></td><td>${esc(r.name)}</td><td>${esc(r.original_source)}</td><td>${esc(r.original_destination)}</td><td>${esc(r.original_service)}</td><td>${esc(r.translated_source)}</td><td>${esc(r.translated_destination)}</td><td>${esc(r.translated_service)}</td><td>${esc(r.install_on)}</td><td>${esc(r.method)}</td><td>${esc(r.hits??'N/A')}</td></tr>`).join('')}</tbody></table></div>`}

async function trace(){
 if(!L.value){setStatus('Select an Access Layer first.','warn');notify('warn','No Access Layer selected','Traffic Path needs an Access Layer so it knows which rulebase to start from.');return}
 if(!src.value||!dst.value||port.value.trim()===''){setStatus('Enter Source, Destination and Port/Service.','warn');notify('warn','Missing input','Traffic Path needs a source, a destination and a port or service name. Source and destination accept an IP or an FQDN.');return}
 let q=new URLSearchParams({layer:L.value,src:src.value.trim(),dst:dst.value.trim(),protocol:proto.value,service:port.value.trim()});if(P.value)q.set('package',P.value);
 const traceBtn=document.querySelector('#traffic button.primary');
 if(traceBtn){traceBtn.dataset.busy='1';traceBtn.disabled=true}
 const rid=newRid(); q.set('rid',rid);
 setStatus('Analyzing traffic path through Access and Inline Layers…','busy');
 busyShow('Tracing traffic path',
   src.value.trim()+' \u2192 '+dst.value.trim()+' \u00b7 elapsed',
   ['Load package / inline layer tree','Resolve objects and service','Walk the ordered rulebase','Correlate NAT']);
 const stopProgress=trackProgress(rid);
 try{
   let d=await api('/api/traffic-path?'+q),w=d.access.winner,n=d.nat||[],path=d.access.path||[],possible=d.access.possible_winner;
   const confidence=d.access.confidence||'none';
   const actionClass=String(w?.action||'').toLowerCase().includes('accept')?'good':(String(w?.action||'').toLowerCase().includes('drop')||String(w?.action||'').toLowerCase().includes('reject')?'bad':'purple');

   const pathHtml=path.length?`
     <div class="card" style="margin-top:16px">
       <div class="section-title"><h3>Matched Policy Path</h3><span class="hint">Top-level → Inline Layer → Final Action</span></div>
       <div class="table-wrap" style="margin-top:12px">
         <table>
           <thead><tr><th>Step</th><th>Rule</th><th>Layer</th><th>Name</th><th>Action</th><th>Transition</th><th>Match Details</th></tr></thead>
           <tbody>${path.map((x,i)=>`<tr>
             <td>${i+1}</td>
             <td><span class="rule-no">Rule ${esc(x.display_rule||x.rule)}</span></td>
             <td><span class="pill ${Number(x.depth||0)>0?'inline':'good'}">${esc(x.layer||'—')}</span></td>
             <td>${esc(x.name||'—')}</td>
             <td><span class="pill ${String(x.action||'').toLowerCase().includes('accept')?'good':(String(x.action||'').toLowerCase().includes('drop')?'bad':'purple')}">${esc(x.action||'Inline')}</span></td>
             <td>${x.transition==='inline-layer'?`→ Inline Layer: <b>${esc(x.inline_layer||'')}</b>`:'Final rule'}</td>
             <td>Src: ${esc(x.source_match||'—')}<br>Dst: ${esc(x.destination_match||'—')}<br>Svc: ${esc(x.service_match||'—')}</td>
           </tr>`).join('')}</tbody>
         </table>
       </div>
     </div>`:'';

   traceResult.innerHTML=`<div class="flow">
     <div class="step"><span class="muted">Source</span><br><b>${esc(d.query.source)}</b></div>
     <div class="arrow">→</div>
     <div class="step"><span class="muted">${w?'Matched Access Rule':(possible?'Possible Earlier Rule':'Matched Access Rule')}</span><br>${w?`<b>Rule ${esc(w.display_rule||w.rule)}</b><br>${esc(w.name)}<br><span class="muted">${esc(w.layer||'')}</span>`:(possible?`<b>Rule ${esc(possible.display_rule||possible.rule)}</b><br>${esc(possible.name||'')}<br><span class="muted">Requires gateway context</span>`:'No matching rule')}</div>
     <div class="arrow">→</div>
     <div class="step"><span class="muted">Final Action</span><br><span class="pill ${confidence==='unknown'?'warn':actionClass}">${esc(w?.action||(confidence==='unknown'?'UNVERIFIED':'NO MATCH'))}</span><br><span class="muted">${esc(confidence.toUpperCase())}</span></div>
     <div class="arrow">→</div>
     <div class="step"><span class="muted">Destination</span><br><b>${esc(d.query.destination)}</b><br><span class="muted">${esc(d.query.service_display||((d.query.protocol||'').toUpperCase()+'/'+d.query.port))}</span></div>
   </div>
   <div class="table-wrap" style="margin-top:18px"><table>
     <tr><th>Item</th><th>Result</th><th>Details</th></tr>
     <tr><td>Source</td><td>${esc(d.query.source)}</td><td>${esc(w?.source_match||'—')}</td></tr>
     <tr><td>Destination</td><td>${esc(d.query.destination)}</td><td>${esc(w?.destination_match||'—')}</td></tr>
     <tr><td>Service</td><td>${esc(d.query.service_display||d.query.service_input||'—')}</td><td>${esc(w?.service_match||'—')} · resolved by ${esc(d.query.service_resolved_by||'—')}</td></tr>
     <tr><td>Access Rule</td><td>${w?'Rule '+esc(w.display_rule||w.rule):'No match'}</td><td>${w?`${esc(w.layer||'—')} · ${esc(w.name||'—')}`:esc(d.access.reason||'—')}</td></tr>
     <tr><td>Action</td><td>${esc(w?.action||(confidence==='unknown'?'UNVERIFIED':'—'))}</td><td>${esc(d.access.reason||'—')} · Confidence: ${esc(confidence)}</td></tr>
     <tr><td>NAT</td><td>${n.length?'Rule '+esc(n[0].rule):(P.value?'No match':'Not checked')}</td><td>${n.length?`Source → ${esc(n[0].translated_source)} · Destination → ${esc(n[0].translated_destination)}`:'—'}</td></tr>
   </table></div>
   ${pathHtml}
   <div class="hint" style="margin-top:12px">${(d.limitations||[]).map(esc).join(' · ')}</div>`;
   reportDataQuality(d.data_quality,'Traffic Path');
   if(d.nat_error) notify('warn','NAT correlation failed',d.nat_error+' The Access result above is unaffected.');
   if(d.access.matched){
     const msg=`Traffic path matched configured policy path (${confidence}).`;
     setStatus(msg,confidence==='exact'?'success':'warn');
     if(confidence==='exact')
       notify('success','Matched: '+String(w.action||''),
         'Rule '+(w.display_rule||w.rule)+' in '+(w.layer||'')+' \u2014 every condition was verified against the configuration.');
     else
       notify('warn','Matched, but inferred',
         'Rule '+(w.display_rule||w.rule)+' matched, however an earlier rule contains conditions this static simulator cannot evaluate. Treat the gateway log as authoritative.',
         {duration:12000});
   }else if(confidence==='unknown'){
     setStatus('Traffic path is unverified because an earlier rule requires gateway context.','warn');
     notify('warn','UNVERIFIED \u2014 deliberately not guessing',
       (d.access.reason||'An earlier rule could not be evaluated statically.')+' Reporting a confident answer here would risk being confidently wrong.',
       {duration:0});
   }else{
     setStatus('Traffic path analysis complete: no final matching rule found.','info');
     notify('info','No matching rule','No rule in the selected layer matched this flow.');
   }
 }catch(e){
   traceResult.innerHTML=errorState(e,'onclick="trace()"');
   fail(e,'Traffic Path');
 }finally{
   stopProgress();
   busyHide();
   if(traceBtn){delete traceBtn.dataset.busy;traceBtn.disabled=false}
 }
}

async function loadMap(ev){
  return task('map','Loading gateway topology',async()=>{
    mapData=await api('/api/network-map?force=true');
    inventory.innerHTML=mapData.nodes.map(n=>`<div class="node"><b>${esc(n.name)}</b><br><span class="muted">${esc(n.role||n.type)}</span><br>${esc(n.cidr||(n.ips||[]).join(', '))}</div>`).join('');
    renderTopology(mapData);
    mapNote.textContent=(mapData.limitations||[]).join(' · ');
    mapMode('topology');
    const m=`Loaded ${mapData.count} nodes and ${mapData.edges.length} relationships.`;
    setStatus(m,'success');
    if(!mapData.count) notify('warn','No topology objects',
      'show-gateways-and-servers returned nothing. Check that this API user can read gateway objects.');
    else notify('success','Topology loaded',m);
    return mapData;
  },{
    button:ev&&ev.currentTarget,
    sub:'Reading gateways and servers · elapsed',
    steps:['Fetch gateways and servers','Derive interfaces and subnets','Render graph'],
    successMessage:null
  }).catch(()=>{});
}
function mapMode(v){topology.classList.toggle('hidden',v!=='topology');inventory.classList.toggle('hidden',v!=='inventory')}

function topoIcon(role){
  if(role==='gateway'){
    return `<g transform="translate(10,11)">
      <rect x="0" y="2" width="27" height="19" rx="3" fill="none" stroke="#d8c6ff" stroke-width="1.5"/>
      <path d="M0 9h27M0 15h27M8 2v7M18 2v7M5 9v6M15 9v6M23 9v6" stroke="#d8c6ff" stroke-width="1.2"/>
      <path d="M31 5l7 3v6c0 5-3 8-7 10-4-2-7-5-7-10V8z" fill="#8b5cf6" stroke="#cbb7ff" stroke-width="1"/>
    </g>`;
  }
  if(role==='management'){
    return `<g transform="translate(10,10)">
      <rect x="0" y="0" width="31" height="23" rx="3" fill="none" stroke="#7ce8b7" stroke-width="1.5"/>
      <path d="M5 7h15M5 15h15" stroke="#7ce8b7" stroke-width="1.3"/>
      <circle cx="25" cy="7" r="2" fill="#38d996"/>
      <circle cx="25" cy="15" r="2" fill="#38d996"/>
      <path d="M7 23v4M24 23v4" stroke="#7ce8b7" stroke-width="1.3"/>
    </g>`;
  }
  return '';
}
function renderTopology(d){
 let ns=d.nodes||[],es=d.edges||[],pos={},dev=ns.filter(n=>['gateway','management','device'].includes(n.role)),ifs=ns.filter(n=>n.role==='interface'),nets=ns.filter(n=>n.role==='network');
 dev.forEach((n,i)=>pos[n.id]={x:70,y:80+i*170});
 ifs.forEach(n=>{let sib=ifs.filter(x=>x.parent===n.parent),idx=sib.findIndex(x=>x.id===n.id),p=pos[n.parent]||{x:70,y:80};pos[n.id]={x:430,y:p.y+(idx-(sib.length-1)/2)*90}});
 nets.forEach((n,i)=>{let e=es.find(e=>e.to===n.id),p=e?pos[e.from]:null;pos[n.id]={x:810,y:p?p.y:80+i*90}});
 let H=Math.max(590,dev.length*180,ifs.length*90+120),W=1250;
 let edge=es.map(e=>{let a=pos[e.from],b=pos[e.to];if(!a||!b)return'';let x1=a.x+200,y1=a.y+33,x2=b.x,y2=b.y+33,m=(x1+x2)/2;return `<path class="edge" d="M${x1},${y1} C${m},${y1} ${m},${y2} ${x2},${y2}"/><text class="edge-label" x="${m-36}" y="${(y1+y2)/2-5}">${esc(e.label)}</text>`}).join('');
 let nodes=ns.map(n=>{let p=pos[n.id];if(!p)return'';let sub=n.role==='interface'?(n.cidr||''):(n.ips||[]).join(', ');let icon=(n.role==='gateway'||n.role==='management')?topoIcon(n.role):'';let tx=icon?52:12;return `<g class="toponode ${esc(n.role||'device')}" transform="translate(${p.x},${p.y})"><rect width="200" height="66" rx="10"/>${icon}<text x="${tx}" y="27">${esc(n.name).slice(0,24)}</text><text class="sub" x="${tx}" y="47">${esc(sub).slice(0,27)}</text></g>`}).join('');
 topology.innerHTML=`<svg viewBox="0 0 ${W} ${H}" id="topoSvg"><g id="world">${edge}${nodes}</g></svg>`;panZoom();
}
function panZoom(){let svg=topoSvg,w=world,scale=1,tx=0,ty=0,drag=false,lx=0,ly=0;function a(){w.setAttribute('transform',`translate(${tx} ${ty}) scale(${scale})`)}svg.addEventListener('wheel',e=>{e.preventDefault();scale=Math.max(.45,Math.min(2.7,scale*(e.deltaY<0?1.1:.9)));a()},{passive:false});svg.addEventListener('mousedown',e=>{drag=true;lx=e.clientX;ly=e.clientY});window.addEventListener('mouseup',()=>drag=false);svg.addEventListener('mousemove',e=>{if(!drag)return;tx+=(e.clientX-lx)/scale;ty+=(e.clientY-ly)/scale;lx=e.clientX;ly=e.clientY;a()})}
function exportAccess(){if(!L.value){notify('warn','No Access Layer selected','Pick an Access Layer before exporting.');return}location.href='/api/export.csv?layer='+encodeURIComponent(L.value)}

function showAccessTab(tab,btn){
  ['all','shadow','duplicates','any'].forEach(x=>{
    const el=document.getElementById('access-'+x+'-view');
    if(el) el.style.display=(x===tab)?'block':'none';
  });
  document.querySelectorAll('#access-tabs button').forEach(b=>b.classList.remove('active'));
  if(btn) btn.classList.add('active');
}

function renderAccessAll(data){
  const body=document.getElementById('access-all-body');
  if(!body) return;
  const rules=(data && (data.rules || data.rulebase || data.all_rules)) || [];
  if(!rules.length){
    body.innerHTML='<tr><td colspan="13" class="muted">No rule rows returned.</td></tr>';
    return;
  }
  const desc=(v)=>{
    if(v==null) return '—';
    if(Array.isArray(v)) return v.map(desc).join(', ');
    if(typeof v==='object') return v.name || v.uid || '—';
    return String(v);
  };
  body.innerHTML=rules.map((r,i)=>`<tr>
    <td><strong>Rule ${esc(r.rule_number ?? r.rule ?? (i+1))}</strong></td>
    <td>${esc(r.name||'—')}</td>
    <td>${esc(desc(r.source))}</td>
    <td>${esc(desc(r.destination))}</td>
    <td>${esc(desc(r.service))}</td>
    <td>${esc(desc(r.action))}</td>
    <td>${esc(desc(r.track))}</td>
    <td>${r.enabled===false?'Disabled':'Enabled'}</td>
  </tr>`).join('');
}

function renderNatSpecialViews(data){
  const rules=(data && data.rules)||[];
  const findings=(data && data.findings)||{};

  const norm=v=>String(v??'').trim();
  const disabledNums=new Set((findings.disabled_rule_numbers||[]).map(norm));
  const noTransNums=new Set((findings.possible_no_translation_rule_numbers||[]).map(norm));

  const disabled=rules.filter(r=>disabledNums.has(norm(r.rule)));
  const noTrans=rules.filter(r=>noTransNums.has(norm(r.rule)));

  const db=document.getElementById('nat-disabled-body');
  if(db){
    db.innerHTML=disabled.length?disabled.map(r=>`<tr>
      <td><strong>Rule ${esc(r.rule)}</strong></td>
      <td>${esc(r.name||'—')}</td>
      <td>${esc(r.original_source)}</td>
      <td>${esc(r.original_destination)}</td>
      <td>${esc(r.original_service)}</td>
      <td>${esc(r.method)}</td>
    </tr>`).join(''):'<tr><td colspan="6" class="muted">No disabled NAT rules found.</td></tr>';
  }

  const nb=document.getElementById('nat-notrans-body');
  if(nb){
    nb.innerHTML=noTrans.length?noTrans.map(r=>`<tr>
      <td><strong>Rule ${esc(r.rule)}</strong></td>
      <td>${esc(r.name||'—')}</td>
      <td>${esc(r.original_source)}</td>
      <td>${esc(r.original_destination)}</td>
      <td>${esc(r.original_service)}</td>
      <td>${esc(r.translated_source)}</td>
      <td>${esc(r.translated_destination)}</td>
      <td>${esc(r.translated_service)}</td>
    </tr>`).join(''):'<tr><td colspan="13" class="muted">No possible no-translation NAT rules found.</td></tr>';
  }

  const dc=document.getElementById('nat-disabled-tab-count');
  if(dc)dc.textContent=`(${disabled.length})`;
  const nc=document.getElementById('nat-notrans-tab-count');
  if(nc)nc.textContent=`(${noTrans.length})`;
}

// Extend the existing NAT tab switcher without changing the current rulebase/duplicate/broad behavior.


function showNatTab(tab,btn){
  // Hide every NAT content area first.
  const ids=['nat-disabled-view','nat-notrans-view'];
  ids.forEach(id=>{const el=document.getElementById(id);if(el)el.style.display='none';});

  // renderNat() owns rulebase / duplicates / broad views.
  // Clear its container when entering the custom views.
  if(tab==='disabled' || tab==='notrans'){
    if(typeof natResults!=='undefined' && natResults) natResults.innerHTML='';

    const target=document.getElementById(tab==='disabled'?'nat-disabled-view':'nat-notrans-view');
    if(target) target.style.display='block';

    if(btn && btn.parentElement){
      btn.parentElement.querySelectorAll('button').forEach(b=>b.classList.remove('active'));
      btn.classList.add('active');
    }
    return;
  }

  // For standard tabs, hide special views and delegate to the original renderer.
  renderNat(tab,btn);
}
