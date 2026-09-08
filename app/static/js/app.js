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
  if(b){
    // The arrow is mirrored in CSS, so only the wording changes here.
    b.title = on ? 'Expand sidebar (Ctrl+B)' : 'Collapse sidebar (Ctrl+B)';
    b.setAttribute('aria-label', b.title);
  }
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
  if((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === 'j'){
    ev.preventDefault();
    toggleTheme();
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
  if(typeof packageControl!=='undefined') packageControl.style.display=(id==='dashboard'||id==='browser'||id==='access'||id==='nat'||id==='traffic'||id==='diff'||id==='compliance')?'inline-block':'none';
  // Both new pages are useless with an empty selector, and both lists are one
  // cheap local read - so fill them on arrival rather than making the first
  // thing a new user does be pressing Refresh.
  if(id==='diff' && !snapshotList.length) loadSnapshots();
  if(id==='health' && !healthBaseline.options.length) loadBaselines();
  if(id==='compliance'){
    if(!profileSel.options.length) loadProfiles();
    if(!snapshotList.length) loadSnapshots();
  }
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
  location.href='/api/package-policy-browser.csv?package='+encodeURIComponent(P.value);
  setStatus('Exporting the configured rulebase for '+P.value+' (top-level + inline).','success');
  notify('success','CSV export started','Inline rules are included, each with its display rule (7.1) and layer path.');
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
     <tr class="drill-row" onclick="drillTo('access','unused')" title="Open zero-hit and disabled rules"><td>Unused Rules</td><td>${deadRules(accessData).length?`<span class="alert-count">${esc(deadRules(accessData).length)}</span>`:0}</td><td>${esc(s.zero_hit_rules||0)} zero-hit + ${esc(s.disabled_rules||0)} disabled rule(s).</td></tr>
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
function accessTabs(kind){let d=accessData;return `<div class="tabs"><button class="${kind==='shadow'?'active':''}" onclick="renderAccess('shadow')">Shadow / Redundant</button><button class="${kind==='duplicates'?'active':''}" onclick="renderAccess('duplicates')">Duplicate Rules (${d.findings.duplicates.length})</button><button class="${kind==='any'?'active':''}" onclick="renderAccess('any')">Any Rules (${(d.findings.any_any_any_rules||[]).length})</button><button class="${kind==='unused'?'active':''}" onclick="renderAccess('unused')">Unused Rules (${deadRules(d).length})</button></div>`}

/* Zero-hit and disabled rules have been computed since v4.0 - with layer,
   display rule and hit counts - and were never rendered anywhere. They are the
   finding a policy review is usually commissioned to produce, because a rule
   that has not matched in months is the one an auditor asks about. */
function deadRules(d){
  if(!d||!d.findings)return [];
  const zero=(d.findings.zero_hit_rules||[]).map(x=>({...x,reason:'Zero hits'}));
  const off=(d.findings.disabled_rules||[]).map(x=>({...x,reason:'Disabled'}));
  const seen=new Set(),out=[];
  for(const r of [...off,...zero]){                 // disabled wins the label
    const key=(r.layer||'')+'::'+(r.rule??'');
    if(seen.has(key))continue;
    seen.add(key);out.push(r);
  }
  return out;
}
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
 }else if(kind==='unused'){
   const rows=deadRules(d);
   const byRule=new Map((d.rules||[]).map(r=>[(r.layer||'')+'::'+(r.rule??''),r]));
   accessFindings.innerHTML=t+
   '<div class="section-title"><h3>Unused Rules</h3><span class="hint">'+rows.length+' zero-hit or disabled rule(s)</span></div>'+
   (rows.length?`<div class="table-wrap" style="margin-top:12px"><table><thead><tr><th>Layer</th><th>Rule</th><th>Name</th><th>Why</th><th>Source</th><th>Destination</th><th>Service</th><th>Action</th><th>Hits</th><th>Last Hit</th></tr></thead><tbody>${
     rows.map(x=>{
       const f=byRule.get((x.layer||'')+'::'+(x.rule??''))||{};
       const last=(f.last_hit&&typeof f.last_hit==='object')?f.last_hit['iso-8601']:f.last_hit;
       return `<tr><td><span class="pill ${Number(f.depth||0)>0?'inline':'good'}">${esc(x.layer||'')}</span></td>`+
         `<td><span class="rule-no">Rule ${esc(x.display_rule||x.rule)}</span></td>`+
         `<td>${esc(f.name||'—')}</td>`+
         `<td><span class="pill ${x.reason==='Disabled'?'bad':'warn'}">${esc(x.reason)}</span></td>`+
         `<td>${esc(f.source||'—')}</td><td>${esc(f.destination||'—')}</td>`+
         `<td>${esc(f.service||'—')}</td><td>${esc(f.action||'—')}</td>`+
         `<td>${esc(f.hits??'—')}</td><td>${esc(last||'never')}</td></tr>`;
     }).join('')
   }</tbody></table></div>
   <p class="muted" style="margin-top:12px">A zero-hit rule is a candidate for review, not proof that it is safe to delete. Hit counters reset on policy install and on gateway restart, and a rule can protect a path that is simply idle. Confirm against the gateway before removing anything.</p>`
   :'<p>No zero-hit or disabled rules found.</p>');
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
   metricCards(natCards,[['Total NAT Rules',s.total_nat_rules],['Duplicate NAT',s.duplicate_nat_groups],['Broad Any/Any/Any',s.broad_original_any_any_any],['Disabled NAT',s.disabled_nat_rules],['Possible No-Translation',s.possible_no_translation_rules],['Install-On Not Found',s.install_on_checked?s.install_on_unknown_rules:'n/a']]);
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
   ['Load package / inline layer tree','Resolve objects and service','Walk the ordered rulebase','Correlate NAT','Place the path on the network map']);
 const stopProgress=trackProgress(rid);
 try{
   let d=await api('/api/traffic-path?'+q),w=d.access.winner,n=d.nat||[],path=d.access.path||[],possible=d.access.possible_winner;
   const confidence=d.access.confidence||'none';
   // NAT is first-match-wins, so an earlier rule this simulator cannot
   // evaluate is returned ahead of a later rule that does match. Showing the
   // later rule's translation as the answer would be the confident-and-wrong
   // failure the Access side already refuses to make.
   // An exact Check Point object name wins over the standard service list -
   // the rulebase is written in object names. When the object turns out to be
   // a different protocol or port from the one the person typed, say so here
   // rather than leaving it to be spotted in a small display string.
   const svcWarn=d.query.service_warnings||[];
   const svcWarnHtml=svcWarn.length?`<div class="hint" style="margin-top:6px;color:var(--warn,#e0a33e)">\u26a0 ${svcWarn.map(esc).join('<br>\u26a0 ')}</div>`:'';
   const natLead=n[0]||null, natBlocked=n[1]||null;
   const natCell=!natLead?(P.value?'No match':'Not checked')
     :`Rule ${esc(natLead.rule)} <span class="pill ${natLead.confidence==='exact'?'good':'warn'}">${esc(String(natLead.confidence||'').toUpperCase())}</span>`;
   const natDetail=!natLead?'—'
     :(natLead.state==='unknown'
        ?esc(natLead.reason||'This NAT rule uses object(s) with no static model.')
          +(natBlocked?` Later Rule ${esc(natBlocked.rule)} matches, but cannot be declared the rule that runs.`:'')
        :`Source → ${esc(natLead.translated_source)} · Destination → ${esc(natLead.translated_destination)}`);
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
             <td>Src: ${esc(x.source_match||'—')}<br>Dst: ${esc(x.destination_match||'—')}<br>Svc: ${esc(x.service_match||'—')}${x.vpn_state&&x.vpn_state!=='match'?`<br><span class="pill warn">VPN</span> ${esc(x.vpn_match||'')}`:''}</td>
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
     <tr><td>Service</td><td>${esc(d.query.service_display||d.query.service_input||'—')}</td><td>${esc(w?.service_match||'—')} · resolved by ${esc(d.query.service_resolved_by||'—')}${svcWarnHtml}</td></tr>
     ${(w||possible)&&(w||possible).vpn_state&&(w||possible).vpn_state!=='match'?`<tr><td>VPN</td><td><span class="pill warn">UNKNOWN</span></td><td>${esc((w||possible).vpn_match||'')}</td></tr>`:''}
     <tr><td>Access Rule</td><td>${w?'Rule '+esc(w.display_rule||w.rule):'No match'}</td><td>${w?`${esc(w.layer||'—')} · ${esc(w.name||'—')}`:esc(d.access.reason||'—')}</td></tr>
     <tr><td>Action</td><td>${esc(w?.action||(confidence==='unknown'?'UNVERIFIED':'—'))}</td><td>${esc(d.access.reason||'—')} · Confidence: ${esc(confidence)}</td></tr>
     <tr><td>NAT</td><td>${natCell}</td><td>${natDetail}</td></tr>
   </table></div>
   ${pathHtml}
   ${d.map_path?`<div class="card" style="margin-top:16px">
     <div class="section-title"><h3>On the Network Map</h3>
       <span class="hint">policy certainty: ${esc(d.map_path.policy_confidence)} · topology certainty: ${esc(d.map_path.topology_confidence)}</span></div>
     <p style="margin:10px 0 0">${(d.map_path.hops||[]).map(h=>esc(h.name||h.node_id)).join(' → ')||'No path could be drawn.'}</p>
     <div class="hint" style="margin-top:6px">${esc(d.map_path.source.detail)}<br>${esc(d.map_path.destination.detail)}</div>
     <div class="hint" style="margin-top:6px">${(d.map_path.limitations||[]).map(esc).join(' · ')}</div>
     <button class="primary" style="margin-top:12px" onclick="showTraceOnMap()">Show this path on the Network Map</button>
   </div>`:''}
   <div class="hint" style="margin-top:12px">${(d.limitations||[]).map(esc).join(' · ')}</div>`;
   LAST_TRACE_PATH=d.map_path||null;
   if(d.map_path_error) notify('warn','Network map overlay unavailable',d.map_path_error+' The Access result above is unaffected.');
   reportDataQuality(d.data_quality,'Traffic Path');
   if(d.nat_error) notify('warn','NAT correlation failed',d.nat_error+' The Access result above is unaffected.');
   if(svcWarn.length) notify('warn','Service name resolved to a policy object',
     svcWarn.join(' ')+' Re-run with the exact object name if this is not the flow you meant.',{duration:14000});
   if(natLead&&natLead.state==='unknown') notify('warn','NAT correlation unverified',
     (natLead.reason||'')+' Check the NAT rulebase in SmartConsole before relying on the translation shown.',{duration:12000});
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

async function loadMap(ev, withRouting){
  return task('map', withRouting?'Loading topology and routing':'Loading gateway topology',async()=>{
    mapData=await api('/api/network-map?force=true'+(withRouting?'&routing=true':''));
    // "I did not read routes" and "there are no routes" must not look alike.
    if(withRouting){
      const r=mapData.routing||{};
      if(r.enabled===false)
        notify('warn','Routing not read',
          'GAIA_ENABLED is false in .env, so no routing was read and none is drawn. This map shows configured interfaces only — it is not evidence that the gateways have no routes.',
          {duration:14000});
      else if(r.routes_unparsed)
        notify('warn','Some routes could not be parsed',
          `${r.routes_unparsed} route entr(y/ies) were not understood and are NOT drawn. Run tools/probe_gaia.py and narrow the readers to this build's shape.`,
          {duration:14000});
      else if(r.routes_parsed)
        notify('success','Routing overlaid',
          `${r.routes_parsed} route(s) read from ${r.gateways_read} gateway(s).`);
      if((r.unreachable||[]).length)
        notify('warn','Some gateways were not read',
          'No routing from: '+r.unreachable.join('; ')+'. They are drawn without routes, which can make the map look like they have none.',
          {duration:14000});
    }
    inventory.innerHTML=mapData.nodes.map(n=>`<div class="node"><b>${esc(n.name)}</b><br><span class="muted">${esc(n.role||n.type)}</span><br>${esc(n.cidr||(n.ips||[]).join(', '))}</div>`).join('');
    topoLoadSaved(mapData);
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
/* ============================================================
   Network Mapping.

   Two ways to read the same data, because they answer different questions.

   GRAPH (default) - the AlgoSec "Discover and Map" shape: a physics layout
   where gateways become hubs and the subnets behind them orbit as leaves.
   Answers "what does this network look like, and what sits between A and B".
   Nodes can be dragged, the arrangement saved, and near-identical subnets
   merged so a large estate stays readable.

   CARDS - two columns, interfaces as rows inside the device card. Answers
   "which port on this gateway reaches which subnet", which the graph
   deliberately hides to stay legible.

   What neither view does is invent facts. Everything drawn comes from
   show-gateways-and-servers: configured interface addresses and the subnets
   implied by their masks. Physical cabling, switching, routing protocols and
   live routes are NOT discovered, so this is a logical map, not a survey.
   ============================================================ */

const TOPO = {
  mode: 'graph',        // 'graph' | 'cards'
  expanded: new Set(),  // cards mode: device cards showing interface rows
  collapsed: new Set(), // graph mode: devices whose leaf subnets are hidden
  focus: null,
  query: '',
  hits: [], hitIdx: -1,
  merge: false,
  unmerged: new Set(),  // merge groups the user opened back up
  legend: true,
  graph: null,
  trace: null,        // the traced path overlay, or null when none is shown
  pinned: new Map(),    // id -> [x,y] the user placed by hand and saved
  at: new Map(),        // id -> [x,y] where the layout last put it
  view: {scale: 1, tx: 0, ty: 0},
  vb: {w: 1600, h: 1000},
  anim: 0,
};

const TOPO_W = 320, TOPO_NET_W = 250, TOPO_COL_GAP = 300;
const TOPO_HEAD = 62, TOPO_ROW = 30, TOPO_GAP = 20;

/* The SVG's coordinate space is set to the container's own pixel size, so one
   world unit is one CSS pixel and `preserveAspectRatio` never letterboxes. A
   fixed 1600x1000 viewBox looked fine on a 3:2 panel and wasted a third of the
   width on a wide one: the graph was pinned inside a centred 1.6:1 box while
   the panel around it sat empty. */
const VB_FALLBACK = {w: 1600, h: 1000};
function topoVB(){
  const r = topology && topology.getBoundingClientRect
    ? topology.getBoundingClientRect() : null;
  if(!r || r.width < 80 || r.height < 80) return VB_FALLBACK;
  return {w: Math.round(r.width), h: Math.round(r.height)};
}
/* Ideal edge length. It has to follow the panel: a fixed value laid 11 nodes
   out over ~1300x850, which then had to be fitted into a 1140x590 panel at 67%
   - so a bigger screen bought you smaller labels, which is backwards. Scale
   the spacing to the space available, and clamp so a dense estate still
   overflows and is explored by zooming rather than squeezed into the frame. */
function topoK(n, vb){
  const ideal = Math.sqrt(Math.max(vb.w * vb.h, 240000) / Math.max(n, 2)) * 0.45;
  return Math.max(90, Math.min(170, ideal));
}

// --------------------------------------------------------------------------
// shared model
// --------------------------------------------------------------------------
function buildTopoModel(d){
  const nodes = d.nodes || [], edges = d.edges || [];
  const byId = new Map(nodes.map(n => [n.id, n]));
  const devices = nodes.filter(n =>
    ['gateway','management','device','cluster','cluster-member'].includes(n.role));
  const nets = nodes.filter(n => n.role === 'network');
  const ifaces = new Map();

  nodes.filter(n => n.role === 'interface').forEach(i => {
    const link = edges.find(e => e.from === i.id && byId.get(e.to)?.role === 'network');
    const list = ifaces.get(i.parent) || [];
    list.push({
      id: i.id,
      name: i.name || 'interface',
      cidr: i.cidr || (i.ips || [])[0] || '',
      subnet: link ? link.to : null,
    });
    ifaces.set(i.parent, list);
  });
  devices.forEach(dv => (ifaces.get(dv.id) || []).sort((a,b) => a.name.localeCompare(b.name)));
  return {byId, devices, nets, ifaces};
}

function topoMatches(text){
  if(!TOPO.query) return true;
  return String(text || '').toLowerCase().includes(TOPO.query.toLowerCase());
}

function topoShortIf(name){ return String(name || '').replace(/^interface\s*/i, 'if'); }

/* A stable hash of the node set. A saved arrangement belongs to the topology
   it was drawn for; if the estate changes, the old coordinates are not
   silently reapplied to different objects. */
function topoKey(d){
  const ids = (d.nodes || []).map(n => n.id).sort().join('|');
  let h = 5381;
  for(let i = 0; i < ids.length; i++) h = ((h * 33) ^ ids.charCodeAt(i)) >>> 0;
  return 'fw-map-' + h.toString(36);
}

// --------------------------------------------------------------------------
// graph model: devices + subnets, with optional merge and collapse
// --------------------------------------------------------------------------
function buildTopoGraph(d){
  const m = buildTopoModel(d);
  const raw = d.edges || [];
  // Relationship edges the backend derived from API fields, not from
  // interfaces: cluster membership (from the cluster's cluster-member-names)
  // and management HA (from management-blades.secondary).
  const rel = raw.filter(e => e.kind === 'membership' || e.kind === 'mgmt-ha');
  const routeEdges = raw.filter(e => e.kind === 'route');
  const memberOf = new Map();                 // memberId -> clusterId
  rel.filter(e => e.kind === 'membership').forEach(e => memberOf.set(e.to, e.from));

  // who connects to each subnet, and through which interfaces
  const users = new Map();                      // netId -> Map(devId -> [ifName])
  for(const dv of m.devices){
    for(const f of (m.ifaces.get(dv.id) || [])){
      if(!f.subnet) continue;
      const per = users.get(f.subnet) || new Map();
      per.set(dv.id, (per.get(dv.id) || []).concat(topoShortIf(f.name)));
      users.set(f.subnet, per);
    }
  }

  // Auto Merge: subnets reached through exactly the same set of devices are
  // interchangeable on a topology map, so they can share one node. This is a
  // presentation grouping - no subnet is dropped and the count is shown.
  let cells = m.nets.map(n => ({kind: 'net', members: [n], id: n.id, name: n.name,
                                external: !!n.external,
                                users: users.get(n.id) || new Map()}));
  let mergedFrom = 0;
  if(TOPO.merge){
    const groups = new Map();
    for(const c of cells){
      const sig = [...c.users.keys()].sort().join('|') || '(none)';
      if(!groups.has(sig)) groups.set(sig, []);
      groups.get(sig).push(c);
    }
    cells = [];
    for(const [sig, group] of groups){
      // A merged node answers "how many subnets sit behind these devices"; a
      // click has to be able to ask "which ones", or the answer is a dead end.
      if(group.length < 2 || TOPO.unmerged.has('merged:' + sig)){
        cells.push(...group); continue;
      }
      mergedFrom += group.length;
      const merged = new Map();
      for(const c of group) for(const [dev, names] of c.users)
        merged.set(dev, (merged.get(dev) || []).concat(names));
      cells.push({kind: 'merged', members: group.flatMap(c => c.members),
                  id: 'merged:' + sig, name: `${group.length} subnets`,
                  external: group.some(c => c.external), users: merged});
    }
  }

  // A cluster's members are hidden while it is collapsed: the cluster is one
  // enforcement point, and its members are how it is built, not peers of it.
  const clusterHidden = new Set();
  for(const [mem, cl] of memberOf) if(TOPO.collapsed.has(cl)) clusterHidden.add(mem);

  // Collapse hides the subnets that hang off exactly one device - they add
  // nothing to a path between two gateways, which is what a map is read for.
  const hidden = new Set();
  for(const c of cells){
    const only = c.users.size === 1 ? [...c.users.keys()][0] : null;
    if(only && TOPO.collapsed.has(only)){ hidden.add(c.id); continue; }
    // A network only a collapsed cluster's members touch folds away with
    // them; leaving it behind would strand it with no links at all.
    if(c.users.size && [...c.users.keys()].every(u => clusterHidden.has(u))) hidden.add(c.id);
  }

  const nodes = [], links = [], byId = new Map();
  const push = n => { nodes.push(n); byId.set(n.id, n); return n; };

  // A route can point at a subnet that Auto Merge folded into a shared node,
  // or at a cluster member the cluster is currently hiding. Resolving through
  // both is what stops the routing overlay from vanishing the moment somebody
  // merges or collapses - the same problem the traced-path overlay has.
  const cellOf = new Map();
  for(const c of cells) for(const m of (c.members || [])) cellOf.set(m.id, c.id);
  const routeTarget = id => {
    if(byId.has(id)) return id;
    const cell = cellOf.get(id);
    if(cell && !hidden.has(cell)) return cell;
    const cl = memberOf.get(id);
    return cl && byId.has(cl) ? cl : null;
  };

  for(const dv of m.devices){
    if(clusterHidden.has(dv.id)) continue;
    const list = m.ifaces.get(dv.id) || [];
    const leaves = cells.filter(c => c.users.size === 1 && c.users.has(dv.id));
    const kids = dv.role === 'cluster'
      ? (dv.member_ids || []).filter(id => m.byId.has(id)).length : 0;
    push({id: dv.id, kind: 'device', role: dv.role || 'device', name: dv.name,
          sub: dv.mgmt_role ? `${(dv.ips || [])[0] || ''} · ${dv.mgmt_role}`
                            : ((dv.ips || [])[0] || dv.type || ''),
          ports: list.length, members: kids, mgmt: dv.mgmt_role || '',
          cluster: memberOf.get(dv.id) || null,
          leaves: leaves.length + kids, collapsed: TOPO.collapsed.has(dv.id),
          // The label sits under the chip and is usually wider than it, so a
          // radius based on the chip alone let two names overlap while the
          // shapes were still comfortably apart.
          r: Math.max(52, String(dv.name || '').length * 4.2),
          w: 1.7, node: dv});
  }
  for(const c of cells){
    if(hidden.has(c.id)) continue;
    push({id: c.id, kind: c.kind, role: 'network', name: c.name,
          sub: c.kind === 'merged'
            ? c.members.slice(0, 2).map(n => n.name).join(', ') + (c.members.length > 2 ? ' …' : '')
            : `${c.users.size} connection${c.users.size === 1 ? '' : 's'}`,
          members: c.members, external: !!c.external,
          r: Math.max(c.kind === 'merged' ? 46 : 38, String(c.name || '').length * 4),
          w: c.kind === 'merged' ? 1.25 : 1});
  }
  // Prefixes a gateway says it can reach but the map cannot see into. Drawn as
  // an outline rather than a solid chip: the estate knows this subnet exists
  // only because a routing table mentioned it.
  for(const rn of (d.nodes || []).filter(n => n.role === 'routed-network')){
    if(byId.has(rn.id)) continue;
    push({id: rn.id, kind: 'routed-network', role: 'routed-network', name: rn.name,
          sub: rn.default_route ? 'default route' : 'from a routing table',
          r: Math.max(40, String(rn.name || '').length * 4), w: 1.1});
  }

  for(const c of cells){
    if(hidden.has(c.id)) continue;
    for(const [dev, names] of c.users){
      const a = byId.get(dev), b = byId.get(c.id);
      if(a && b) links.push({a, b, from: dev, to: c.id, kind: 'subnet',
                             label: [...new Set(names)].join(', ')});
    }
  }

  // Route links last, so a device already placed by its interfaces keeps that
  // geometry and the route only adds to it.
  for(const e of routeEdges){
    const from = routeTarget(e.from), to = routeTarget(e.to);
    if(!from || !to || from === to) continue;
    const a = byId.get(from), b = byId.get(to);
    if(a && b) links.push({a, b, from, to, kind: 'route', len: 1.15,
                           label: e.label || '', route: e});
  }
  // Relationship links are drawn differently on purpose: "is a member of" and
  // "is the HA peer of" are not traffic paths, and a map that draws them the
  // same way as a subnet invites reading a data path that does not exist.
  for(const e of rel){
    const a = byId.get(e.from), b = byId.get(e.to);
    // A member belongs to its cluster, so its link is pulled shorter than a
    // subnet link. HA keeps the normal length - the pair is a relationship
    // between equals, not a containment.
    if(a && b) links.push({a, b, from: e.from, to: e.to, kind: e.kind,
                           len: e.kind === 'membership' ? 0.78 : 1,
                           // The dashed line into a cluster plate already says
                           // "member"; the word only added a label to collide
                           // with. "HA" earns its place - two plain boxes with
                           // a line between them say nothing on their own.
                           label: e.kind === 'mgmt-ha' ? 'HA' : ''});
  }

  // A subnet no cluster interface touches, reached only through members of one
  // cluster, is internal to that cluster - on a real deployment, the sync
  // network. This is read off the graph, not off the addresses.
  for(const nd of nodes){
    if(nd.role !== 'network') continue;
    const cell = cells.find(c => c.id === nd.id);
    if(!cell || !cell.users.size) continue;
    const owners = [...cell.users.keys()];
    const cl = [...new Set(owners.map(o => memberOf.get(o)))];
    if(cl.length === 1 && cl[0] && owners.every(o => memberOf.has(o))){
      nd.internal = byId.get(cl[0]) ? byId.get(cl[0]).name : '';
    }
  }

  for(const nd of nodes) nd.deg = 0;
  for(const l of links){ l.a.deg++; l.b.deg++; }

  // The layout box takes the panel's aspect, so a wide panel gets a wide map
  // instead of a tall one that has to be scaled down to fit.
  const n = Math.max(nodes.length, 1);
  // Spacing has to clear the widest node, whose radius follows its label -
  // otherwise a panel-derived k can end up smaller than the labels it has to
  // keep apart, and no amount of settling separates them.
  const widest = nodes.reduce((mx, nd) => Math.max(mx, nd.r), 0);
  const k = Math.max(topoK(n, TOPO.vb), widest * 1.35);
  const side = Math.max(900, 1.4 * k * Math.sqrt(n));
  const aspect = Math.max(0.6, Math.min(2.6, TOPO.vb.w / TOPO.vb.h));
  return {nodes, links, byId, k, aspect,
          box: {w: side * Math.sqrt(aspect), h: side / Math.sqrt(aspect)},
          totalCells: cells.length, hidden: hidden.size, mergedFrom,
          totalNets: m.nets.length};
}

// --------------------------------------------------------------------------
// layout: Fruchterman-Reingold, seeded deterministically
// --------------------------------------------------------------------------
function topoSeed(g){
  const cx = g.box.w / 2, cy = g.box.h / 2;
  const R = Math.min(cx, cy) * 0.85;
  const GA = Math.PI * (3 - Math.sqrt(5));   // golden angle
  let fresh = 0;
  g.nodes.forEach((nd, i) => {
    const pin = TOPO.pinned.get(nd.id);
    const was = TOPO.at.get(nd.id);
    nd.fixed = !!pin;
    if(pin){ nd.x = pin[0]; nd.y = pin[1]; }
    else if(was){ nd.x = was[0]; nd.y = was[1]; }   // survives a re-render
    else{
      // No Math.random: the same topology must lay out the same way every
      // time, or a saved arrangement would be meaningless and two runs of
      // the same lab would never look alike.
      fresh++;
      const t = (i + 0.5) / g.nodes.length;
      const r = R * Math.sqrt(t);
      nd.x = cx + r * Math.cos(i * GA);
      nd.y = cy + r * Math.sin(i * GA);
      nd.seeded = true;
    }
  });
  // A node that appears in an arrangement that already exists - unmerging a
  // group, say - starts on the spiral in the middle of everything and drags
  // its links across the map. Start it where its neighbours already are.
  if(fresh && fresh < g.nodes.length){
    for(const nd of g.nodes){
      if(!nd.seeded) continue;
      const near = g.links
        .map(l => l.a === nd ? l.b : l.b === nd ? l.a : null)
        .filter(o => o && !o.seeded);
      if(!near.length) continue;
      nd.x = near.reduce((t, o) => t + o.x, 0) / near.length + 24;
      nd.y = near.reduce((t, o) => t + o.y, 0) / near.length + 24;
    }
  }
  return fresh;
}

function topoRemember(g){
  g.nodes.forEach(nd => TOPO.at.set(nd.id, [nd.x, nd.y]));
}

function topoRelax(g, iters, from, total){
  const n = g.nodes.length;
  if(n < 2) return;
  const K = g.k || 150;
  const cx = g.box.w / 2, cy = g.box.h / 2;
  // Anisotropic gravity: pulling harder on one axis compresses it, so a
  // sqrt(aspect) split makes the settled cloud roughly the panel's shape.
  const ax = 1 / Math.sqrt(g.aspect || 1), ay = Math.sqrt(g.aspect || 1);
  for(let it = 0; it < iters; it++){
    const prog = Math.min(1, (from + it) / Math.max(total, 1));
    const temp = 120 * Math.pow(1 - prog, 1.6) + 0.6;
    for(const nd of g.nodes){ nd.dx = 0; nd.dy = 0; }

    for(let i = 0; i < n; i++){
      const a = g.nodes[i];
      for(let j = i + 1; j < n; j++){
        const b = g.nodes[j];
        let dx = a.x - b.x, dy = a.y - b.y;
        let d = Math.sqrt(dx*dx + dy*dy);
        if(d < 0.01){ dx = ((i*7)%11)/11 - 0.5; dy = ((j*13)%17)/17 - 0.5; d = 0.6; }
        const gap = a.r + b.r;
        // k^2/d is the standard repulsion; the second term is a hard shove
        // that only applies while two nodes physically overlap, which is what
        // stops labels being drawn on top of each other.
        const f = (K * K / d) * a.w * b.w + (d < gap ? (gap - d) * 8 : 0);
        const ux = dx/d, uy = dy/d;
        a.dx += ux*f; a.dy += uy*f;
        b.dx -= ux*f; b.dy -= uy*f;
      }
    }
    for(const l of g.links){
      const a = l.a, b = l.b;
      let dx = a.x - b.x, dy = a.y - b.y;
      const d = Math.sqrt(dx*dx + dy*dy) || 0.01;
      const f = d * d / (K * (l.len || 1));
      const ux = dx/d, uy = dy/d;
      a.dx -= ux*f; a.dy -= uy*f;
      b.dx += ux*f; b.dy += uy*f;
    }
    for(const nd of g.nodes){
      if(nd.fixed) continue;
      // A node with no links feels only repulsion, so plain gravity lets it
      // drift to the far edge and stretch the whole map around nothing. Pull
      // those in harder - an unmanaged host should sit beside the estate, not
      // define its bounding box.
      const grav = nd.deg ? 0.9 : 1.7;
      nd.dx += (cx - nd.x) * grav * ax;
      nd.dy += (cy - nd.y) * grav * ay;
      const disp = Math.sqrt(nd.dx*nd.dx + nd.dy*nd.dy) || 1;
      const lim = Math.min(disp, temp);
      nd.x += nd.dx / disp * lim;
      nd.y += nd.dy / disp * lim;
    }
  }
}

/* Fruchterman-Reingold assumes one connected graph. Give it two - a firewall
   estate plus a management HA pair with no interface between them - and
   gravity pulls both toward the middle while repulsion shoves them apart, so
   one component ends up compressed and the other flung to the edge.

   Lay them out together, then move each component as a rigid body into a
   shelf packing. Deterministic: components are ordered by area, and JS sort
   is stable, so the same graph packs the same way every time. */
function topoComponents(g){
  const adj = new Map(g.nodes.map(n => [n.id, []]));
  for(const l of g.links){
    if(adj.has(l.a.id)) adj.get(l.a.id).push(l.b.id);
    if(adj.has(l.b.id)) adj.get(l.b.id).push(l.a.id);
  }
  const seen = new Set(), comps = [];
  for(const n of g.nodes){
    if(seen.has(n.id)) continue;
    seen.add(n.id);
    const stack = [n.id], comp = [];
    while(stack.length){
      const id = stack.pop();
      comp.push(g.byId.get(id));
      for(const nb of adj.get(id) || []) if(!seen.has(nb)){ seen.add(nb); stack.push(nb); }
    }
    comps.push(comp.filter(Boolean));
  }
  return comps;
}

function topoPack(g){
  // Once the user has placed anything by hand they own the arrangement;
  // shifting whole components under them would undo that silently.
  if([...TOPO.pinned.keys()].some(id => g.byId.has(id))) return;
  const comps = topoComponents(g);
  if(comps.length < 2) return;
  // Pad each component by its own nodes' radii, not a constant: a radius
  // already tracks the label width, and a fixed pad let a long subnet name in
  // one component print over a management server's name in the next.
  const gap = 46;
  const boxes = comps.map(c => {
    const x0 = Math.min(...c.map(nd => nd.x - nd.r * 0.85)) - 12;
    const y0 = Math.min(...c.map(nd => nd.y - nd.r * 0.55)) - 12;
    const x1 = Math.max(...c.map(nd => nd.x + nd.r * 0.85)) + 12;
    const y1 = Math.max(...c.map(nd => nd.y + nd.r * 0.55)) + 12;
    return {c, x0, y0, w: x1 - x0, h: y1 - y0};
  }).sort((a, b) => b.w * b.h - a.w * a.h);

  /* A single guessed shelf width put the lab's management pair BELOW the
     firewall estate on a panel twice as wide as it was tall, so fit had to
     shrink everything to make the extra height work. Rather than tune a
     constant, lay the shelves out at a few widths and keep the one that
     renders biggest - which is exactly what "best" means here. */
  const base = Math.sqrt(boxes.reduce((t, b) => t + b.w * b.h, 0) * (g.aspect || 1.6));
  const shelf = (target) => {
    const place = [];
    let x = 0, y = 0, rowH = 0, W = 0, H = 0;
    for(const b of boxes){
      if(x > 0 && x + b.w > target){ x = 0; y += rowH + gap; rowH = 0; }
      place.push({b, x, y});
      x += b.w + gap;
      rowH = Math.max(rowH, b.h);
      W = Math.max(W, x - gap); H = Math.max(H, y + b.h);
    }
    return {place, scale: Math.min(TOPO.vb.w / Math.max(W, 1), TOPO.vb.h / Math.max(H, 1))};
  };
  let best = null;
  for(const k of [0.7, 1, 1.3, 1.7, 2.2, 1e9]){
    const got = shelf(base * k);
    if(!best || got.scale > best.scale + 1e-6) best = got;   // ties keep the first
  }
  for(const {b, x, y} of best.place){
    const dx = x - b.x0, dy = y - b.y0;
    for(const nd of b.c){ nd.x += dx; nd.y += dy; }
  }
}

function topoIterations(n){
  return n > 400 ? 120 : n > 150 ? 220 : 400;
}

// --------------------------------------------------------------------------
// graph painting
// --------------------------------------------------------------------------
/* The overlay speaks in backend node ids; the graph draws something else.
   A subnet can be folded into a merged cell, and a cluster member can be
   hidden inside its cluster. Resolving through both is what keeps a
   highlighted path from vanishing the moment the user merges or collapses. */
function topoTraceResolve(id){
  if(!TOPO.graph || !id) return null;
  const nodes = TOPO.graph.nodes || [];
  if(nodes.some(n => n.id === id)) return id;
  const merged = nodes.find(n => n.kind === 'merged'
    && (n.members || []).some(m => m.id === id));
  if(merged) return merged.id;
  const cluster = nodes.find(n => n.role === 'cluster'
    && ((n.node && n.node.member_ids) || []).includes(id));
  return cluster ? cluster.id : null;
}

/* Hop ids as the graph currently draws them, with consecutive duplicates
   dropped: two hops that fold into the same merged node are one node here. */
function topoTraceHops(){
  const t = TOPO.trace;
  if(!t) return [];
  const out = [];
  for(const hop of t.hops || []){
    const id = topoTraceResolve(hop.node_id);
    if(id && id !== out[out.length - 1]) out.push(id);
  }
  return out;
}

function topoTraceClass(){
  const t = TOPO.trace;
  return t ? 'path-' + (t.draw || 'none') : '';
}

function topoNodeSvg(nd){
  const cls = ['topo-g-node', nd.kind === 'device' ? nd.role : nd.kind];
  const hit = topoMatches(nd.name) || topoMatches(nd.sub);
  if(TOPO.query){ cls.push(hit ? 'hit' : 'dim'); }
  if(TOPO.focus && !topoNear(nd.id)) cls.push('dim');
  if(nd.fixed) cls.push('pinned');
  // A node on a traced path is marked with the path's own certainty, never
  // with a single "highlighted" style: an unverified path that looks like a
  // proven one is the exact mistake Chapter 6 warned about.
  if(TOPO.trace){
    const hops = topoTraceHops();
    const at = hops.indexOf(nd.id);
    if(at >= 0){
      cls.push('on-path', topoTraceClass());
      if(at === 0 || at === hops.length - 1) cls.push('path-end');
    }else if(hops.length){ cls.push('off-path'); }
  }

  const canExpand = (nd.kind === 'device' && nd.leaves > 0) || nd.kind === 'merged';
  let shape, label;
  if(nd.kind === 'device'){
    if(canExpand) cls.push('expandable');
    // A cluster gets a second plate behind it: it is one enforcement point
    // made of several boxes, and that has to be visible without reading the
    // label, or it looks like just another gateway.
    shape = (nd.role === 'cluster'
              ? `<rect class="chip plate" x="-25" y="-21" width="42" height="34" rx="8"/>` : '')
      + `<rect class="chip" x="-21" y="-17" width="42" height="34" rx="8"/>`
      + topoGlyph(nd.role)
      + (nd.leaves && nd.collapsed
          ? `<g class="stub"><circle cx="20" cy="-15" r="9"/>`
            + `<text x="20" y="-11.5" text-anchor="middle">${nd.leaves}</text></g>`
          : '');
    label = `<text class="lbl" y="32" text-anchor="middle">${esc(nd.name)}</text>`
      + `<text class="sub" y="45" text-anchor="middle">${esc(nd.sub)}</text>`;
  }else{
    const w = nd.kind === 'merged' ? 26 : 18;
    if(nd.internal) cls.push('internal');
    if(nd.external) cls.push('external');
    if(nd.kind === 'merged') cls.push('expandable');
    shape = `<rect class="chip" x="${-w/2}" y="-7" width="${w}" height="14" rx="4"/>`
      + (nd.kind === 'merged' ? `<rect class="chip stack" x="${-w/2+3}" y="-11" width="${w}" height="14" rx="4"/>` : '');
    label = `<text class="lbl" y="24" text-anchor="middle">${esc(nd.name)}</text>`
      + `<text class="sub" y="37" text-anchor="middle">${esc(nd.sub)}</text>`;
  }
  const title = nd.kind === 'merged'
    ? nd.members.map(n => n.name).join('\n')
    : nd.internal
      ? `${nd.name}\nNo interface of ${nd.internal} is on this network - only its members are.`
        + `\nOn a ClusterXL deployment that is the sync network.`
    : nd.role === 'cluster'
      ? `${nd.name}\n${nd.members} member(s), from the cluster object's own member list`
    : nd.mgmt
      ? `${nd.name}\nManagement server, ${nd.mgmt} (from management-blades)`
        + `\nHA is shown as configured; live sync state is not exposed by the API.`
    : `${nd.name}${nd.sub ? ' · ' + nd.sub : ''}`;
  // A device with nothing behind it has nothing to collapse, so clicking it
  // does the other useful thing instead: isolates its neighbourhood. Without
  // this, clicking a management server with no modelled subnets did nothing.
  return `<g class="${cls.join(' ')}" data-id="${esc(nd.id)}"`
    + `${canExpand ? ' data-expandable="1"' : ''}`
    + `${nd.kind === 'merged' ? ` aria-expanded="false"` : ''}`
    + ` transform="translate(${nd.x.toFixed(1)},${nd.y.toFixed(1)})"`
    + ` role="button" tabindex="0" aria-label="${esc(nd.name)}"`
    + `${canExpand ? ` aria-expanded="${!nd.collapsed}"` : ''}>`
    + `<title>${esc(title)}</title><circle class="halo" r="${nd.kind === 'device' ? 26 : 13}"/>`
    + shape
    + `<circle class="pin" cx="${nd.kind === 'device' ? 22 : 13}" `
    + `cy="${nd.kind === 'device' ? 16 : 6}" r="2.6"/>`
    + label + `</g>`;
}

function topoGlyph(role){
  if(role === 'cluster' || role === 'cluster-member' || role === 'gateway'){
    return `<g class="glyph"><rect x="-13" y="-9" width="26" height="18" rx="2"/>`
      + `<path d="M-13 -3h26M-13 3h26M-5 -9v6M4 -9v6M-9 3v6M0 3v6M8 3v6"/></g>`;
  }
  if(role === 'management'){
    return `<g class="glyph"><rect x="-12" y="-9" width="24" height="18" rx="2"/>`
      + `<path d="M-8 -4h12M-8 1h12M-8 6h7"/></g>`;
  }
  return `<g class="glyph"><rect x="-13" y="-9" width="26" height="18" rx="2"/>`
    + `<path d="M-13 -3h26M-13 3h26M-5 -9v6M4 -9v6M-9 3v6M0 3v6M8 3v6"/></g>`;
}

function topoNear(id){
  if(!TOPO.focus) return true;
  if(TOPO.focus === id) return true;
  return (TOPO.graph.links || []).some(l =>
    (l.from === TOPO.focus && l.to === id) || (l.to === TOPO.focus && l.from === id));
}

/* An edge label sat exactly on the midpoint, which is also where a short edge
   passes under a node's sub-label - "3 connections" and "if2" printed on top of
   each other in the lab. Labels now sit off to one side of the line, are
   skipped entirely on edges too short to hold one, and are painted with a
   background-coloured outline so they stay readable wherever they land. */
function topoLabelAt(l){
  const dx = l.b.x - l.a.x, dy = l.b.y - l.a.y;
  const len = Math.sqrt(dx*dx + dy*dy);
  if(len < ((TOPO.graph && TOPO.graph.k) || 150) * 0.5) return null;
  // The midpoint of a short edge between two long-named nodes lands inside one
  // of their labels. Each node's radius already tracks its label width, so
  // requiring the edge to be longer than the two radii together keeps the
  // midpoint clear of both. An interface name is worth less than a readable
  // node name, so this drops the interface label rather than crowding.
  if(len < (l.a.r + l.b.r) * 0.62) return null;
  const off = 11;
  return {x: (l.a.x + l.b.x) / 2 - dy / len * off,
          y: (l.a.y + l.b.y) / 2 + dx / len * off + 3.5};
}

function topoLinkSvg(l, showLabel){
  const on = !TOPO.focus || l.from === TOPO.focus || l.to === TOPO.focus;
  const kind = l.kind && l.kind !== 'subnet' ? ' ' + l.kind : '';
  let path = '';
  if(TOPO.trace){
    const hops = topoTraceHops();
    for(let i = 0; i < hops.length - 1; i++){
      if((l.from === hops[i] && l.to === hops[i+1])
       || (l.to === hops[i] && l.from === hops[i+1])){
        path = ' on-path ' + topoTraceClass(); break;
      }
    }
    if(!path && hops.length) path = ' off-path';
  }
  // Every labelled link gets its <text> even when it is currently too short to
  // show one: nodes move while the simulation runs, so emitting conditionally
  // would slide the DOM index away from the link it belongs to.
  const at = showLabel && l.label ? topoLabelAt(l) : null;
  return `<g class="topo-g-edge${kind}${path}${on ? '' : ' dim'}">`
    + `<line x1="${l.a.x.toFixed(1)}" y1="${l.a.y.toFixed(1)}"`
    + ` x2="${l.b.x.toFixed(1)}" y2="${l.b.y.toFixed(1)}"/>`
    + (showLabel && l.label
        ? `<text x="${(at ? at.x : 0).toFixed(1)}" y="${(at ? at.y : 0).toFixed(1)}"`
          + ` text-anchor="middle"${at ? '' : ' display="none"'}>${esc(l.label)}</text>`
        : '')
    + `</g>`;
}

function renderTopoGraph(d){
  TOPO.vb = topoVB();
  const g = buildTopoGraph(d);
  TOPO.graph = g;
  const fresh = topoSeed(g);

  // Labels are the first thing to make a big map unreadable, so they appear
  // only when there are few enough to read, or when a focus has narrowed the
  // picture to one node's neighbourhood.
  const showLabels = g.links.length <= 26 || !!TOPO.focus;

  const paint = () => {
    topology.innerHTML =
      `<svg id="topoSvg" viewBox="0 0 ${TOPO.vb.w} ${TOPO.vb.h}" preserveAspectRatio="xMidYMid meet">`
      + `<g id="world">`
      + `<g id="topoEdges">${g.links.map(l => topoLinkSvg(l, showLabels)).join('')}</g>`
      + `<g id="topoNodes">${g.nodes.map(topoNodeSvg).join('')}</g>`
      + `</g></svg>`;
    TOPO.dom = {
      lines: [...topology.querySelectorAll('#topoEdges line')],
      texts: [...topology.querySelectorAll('#topoEdges text')],
      nodes: [...topology.querySelectorAll('#topoNodes .topo-g-node')],
    };
    topoBindEvents();
  };

  const move = () => {
    const {lines, nodes} = TOPO.dom;
    g.links.forEach((l, i) => {
      const ln = lines[i]; if(!ln) return;
      ln.setAttribute('x1', l.a.x.toFixed(1)); ln.setAttribute('y1', l.a.y.toFixed(1));
      ln.setAttribute('x2', l.b.x.toFixed(1)); ln.setAttribute('y2', l.b.y.toFixed(1));
    });
    g.nodes.forEach((nd, i) => {
      const el = nodes[i]; if(!el) return;
      el.setAttribute('transform', `translate(${nd.x.toFixed(1)},${nd.y.toFixed(1)})`);
    });
    topoLabels(showLabels);
  };

  const total = topoIterations(g.nodes.length);
  const still = window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches;

  // Only a genuinely new node needs the physics. Toggling a focus or a filter
  // re-renders the same map, and re-settling it there would throw the user's
  // arrangement and zoom away for no reason.
  if(!fresh){
    paint(); topoDeclutter(); topoRemember(g); topoApplyView();
  }else if(still || g.nodes.length > 220){
    topoRelax(g, total, 0, total);
    topoPack(g);
    paint(); topoDeclutter(); topoRemember(g); topoFit();
  }else{
    // Run the simulation on screen so the map visibly settles. It also shows
    // honestly that the layout is computed, not authored.
    topoRelax(g, 40, 0, total);
    paint();
    const token = ++TOPO.anim;
    let done = 40;
    const step = () => {
      if(token !== TOPO.anim) return;             // a re-render superseded us
      topoRelax(g, 14, done, total);
      done += 14;
      move();
      if(done < total) requestAnimationFrame(step);
      else { topoPack(g); move(); topoDeclutter(); topoRemember(g); topoFit(); }
    };
    requestAnimationFrame(step);
  }
  topoStatus(g);
}

function topoLabels(show){
  if(!show || !TOPO.dom) return;
  const labelled = TOPO.graph.links.filter(l => l.label);
  TOPO.dom.texts.forEach((t, i) => {
    const l = labelled[i]; if(!l) return;
    const at = topoLabelAt(l);
    if(!at){ t.setAttribute('display', 'none'); return; }
    t.removeAttribute('display');
    t.setAttribute('x', at.x.toFixed(1));
    t.setAttribute('y', at.y.toFixed(1));
  });
}

/* Geometry gets an edge label clear of its own two endpoints, but it can still
   land on a THIRD node's label, and no cheap formula predicts that. So once the
   layout has settled, measure what actually rendered and hide the few labels
   that collide. A node name is worth more than an interface name, so the edge
   label is the one that gives way.

   One forced reflow on a few dozen boxes, once per settle - not per frame. */
function topoDeclutter(){
  if(!TOPO.dom) return;
  const texts = TOPO.dom.texts.filter(t => !t.getAttribute('display'));
  if(!texts.length || texts.length > 200) return;
  const labels = [...topology.querySelectorAll('.topo-g-node .lbl, .topo-g-node .sub')]
    .map(e => e.getBoundingClientRect());
  const hits = (a, b) => a.right > b.left + 1 && a.left < b.right - 1
                      && a.bottom > b.top + 1 && a.top < b.bottom - 1;
  const boxes = texts.map(t => t.getBoundingClientRect());
  texts.forEach((t, i) => {
    if(labels.some(l => hits(boxes[i], l))) t.setAttribute('display', 'none');
  });
}

function topoStatus(g){
  const el = document.getElementById('topoCount');
  if(!el) return;
  const bits = [`${g.nodes.length} node(s)`, `${g.links.length} link(s)`];
  if(g.hidden) bits.push(`${g.hidden} hidden`);
  if(g.mergedFrom) bits.push(`${g.mergedFrom} subnets merged`);
  if(TOPO.pinned.size) bits.push(`${TOPO.pinned.size} placed`);
  el.textContent = bits.join(' · ');
  topoTraceBar();
}

/* The bar states both certainties, because they fail independently: a proven
   verdict can sit on a path the map cannot see, and vice versa. Hiding either
   behind one word would be a claim the data does not carry. */
const TRACE_DRAW_TEXT = {
  exact:      ['Verified path', 'good'],
  inferred:   ['Inferred path', 'warn'],
  unverified: ['UNVERIFIED path', 'warn'],
  none:       ['No path drawn', 'bad'],
};
function topoTraceBar(){
  const bar = document.getElementById('topoTraceBar');
  if(!bar) return;
  const t = TOPO.trace;
  if(!t){ bar.style.display = 'none'; bar.innerHTML = ''; return; }
  const [text, tone] = TRACE_DRAW_TEXT[t.draw] || TRACE_DRAW_TEXT.none;
  const hops = (t.hops || []).map(h => esc(h.name || h.node_id)).join(' → ') || '—';
  bar.style.display = 'block';
  bar.innerHTML = `<div class="trace-bar ${esc(t.draw)}">
    <div class="trace-bar-head">
      <span class="pill ${tone}">${esc(text)}</span>
      <b>${esc(t.source.ip)} → ${esc(t.destination.ip)}</b>
      <span class="pill ${String(t.verdict||'').toLowerCase().includes('accept')?'good':(String(t.verdict||'').toLowerCase().includes('drop')?'bad':'warn')}">${esc(t.verdict)}</span>
      ${t.rule?`<span class="rule-no">Rule ${esc(t.rule)}</span>`:''}
      <span class="hint">policy: ${esc(t.policy_confidence)} · topology: ${esc(t.topology_confidence)}</span>
      <button class="ghost" onclick="clearTraceOnMap()">Clear</button>
    </div>
    <div class="hint">${hops}</div>
    <div class="hint">${esc(t.source.detail)} · ${esc(t.destination.detail)}</div>
    <div class="hint">${(t.limitations||[]).map(esc).join(' · ')}</div>
  </div>`;
}

function clearTraceOnMap(){
  TOPO.trace = null;
  if(mapData) renderTopology(mapData);
  topoTraceBar();
}

/* Jump from a finished trace to the map with the path marked on it. */
let LAST_TRACE_PATH = null;
async function showTraceOnMap(){
  if(!LAST_TRACE_PATH){
    notify('warn','No traced path yet','Run Analyze Path first.');
    return;
  }
  goTo('map');
  if(!mapData) await loadMap();
  if(!mapData) return;
  TOPO.trace = LAST_TRACE_PATH;
  if(TOPO.mode !== 'graph'){
    notify('info','Switched to graph view','The traced path is drawn on the graph layout.');
    topoSetMode('graph');
  }else{
    renderTopology(mapData);
  }
  topoTraceBar();
}

// --------------------------------------------------------------------------
// cards mode (unchanged behaviour, now one of two layouts)
// --------------------------------------------------------------------------
function topoLayout(m){
  const pos = new Map();
  let y = 30;
  for(const dv of m.devices){
    const list = m.ifaces.get(dv.id) || [];
    const open = TOPO.expanded.has(dv.id) && list.length > 0;
    const h = TOPO_HEAD + (open ? list.length * TOPO_ROW + 8 : 0);
    pos.set(dv.id, {x: 30, y, h, open, ifaces: list});
    y += h + TOPO_GAP;
  }
  const deviceBottom = y;

  // Order networks by the mean Y of whatever connects to them: the cheapest
  // way to stop edges crossing without running a real layout algorithm.
  const score = new Map();
  for(const net of m.nets){
    const ys = [];
    for(const dv of m.devices){
      const p = pos.get(dv.id);
      (m.ifaces.get(dv.id) || []).forEach((f, idx) => {
        if(f.subnet !== net.id) return;
        ys.push(p.open ? p.y + TOPO_HEAD + idx * TOPO_ROW : p.y + TOPO_HEAD / 2);
      });
    }
    score.set(net.id, ys.length ? ys.reduce((a,b) => a+b, 0) / ys.length : 1e9);
  }
  const ordered = [...m.nets].sort((a,b) => score.get(a.id) - score.get(b.id));

  let ny = 30;
  for(const net of ordered){
    const want = score.get(net.id);
    ny = Math.max(ny, Number.isFinite(want) ? want - 26 : ny);
    pos.set(net.id, {x: 30 + TOPO_W + TOPO_COL_GAP, y: ny, h: 54});
    ny += 54 + 16;
  }
  return {pos, height: Math.max(deviceBottom, ny) + 30,
          width: 30 + TOPO_W + TOPO_COL_GAP + TOPO_NET_W + 30};
}

function topoAnchor(pos, dv, m, ifaceIdx){
  const p = pos.get(dv.id);
  if(!p) return null;
  if(p.open && ifaceIdx >= 0) return {x: p.x + TOPO_W, y: p.y + TOPO_HEAD + ifaceIdx * TOPO_ROW + 15};
  return {x: p.x + TOPO_W, y: p.y + TOPO_HEAD / 2};
}

function renderTopoCards(d){
  const m = buildTopoModel(d);
  const {pos, height, width} = topoLayout(m);

  const edges = [];
  for(const dv of m.devices){
    const p = pos.get(dv.id);
    const list = m.ifaces.get(dv.id) || [];
    if(p.open){
      list.forEach((f, idx) => {
        if(!f.subnet || !pos.get(f.subnet)) return;
        edges.push({from: dv.id, to: f.subnet, a: topoAnchor(pos, dv, m, idx),
                    b: pos.get(f.subnet), label: ''});
      });
    }else{
      const seen = new Map();
      list.forEach(f => {
        if(!f.subnet || !pos.get(f.subnet)) return;
        const names = seen.get(f.subnet) || [];
        names.push(topoShortIf(f.name));
        seen.set(f.subnet, names);
      });
      for(const [subnet, names] of seen){
        edges.push({from: dv.id, to: subnet, a: topoAnchor(pos, dv, m, -1),
                    b: pos.get(subnet), label: names.join(', ')});
      }
    }
  }

  const active = id => !TOPO.focus || TOPO.focus === id ||
    edges.some(e => (e.from === TOPO.focus && e.to === id) || (e.to === TOPO.focus && e.from === id));

  const edgeSvg = edges.map(e => {
    if(!e.a || !e.b) return '';
    const x1 = e.a.x, y1 = e.a.y, x2 = e.b.x, y2 = e.b.y + 27;
    const mx = (x1 + x2) / 2;
    const on = !TOPO.focus || e.from === TOPO.focus || e.to === TOPO.focus;
    return `<g class="topo-edge${on ? '' : ' dim'}">`
      + `<path d="M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}"/>`
      + (e.label ? `<text x="${mx}" y="${(y1+y2)/2 - 6}" text-anchor="middle">${esc(e.label)}</text>` : '')
      + `</g>`;
  }).join('');

  const deviceSvg = m.devices.map(dv => {
    const p = pos.get(dv.id);
    const list = p.ifaces;
    const ip = (dv.ips || [])[0] || '';
    const hit = topoMatches(dv.name) || topoMatches(ip);
    const cls = [dv.role || 'device'];
    if(!active(dv.id)) cls.push('dim');
    if(TOPO.query && !hit) cls.push('dim');
    if(TOPO.query && hit) cls.push('hit');

    const rows = p.open ? list.map((f, idx) => {
      return `<g class="topo-if" transform="translate(0,${TOPO_HEAD + idx * TOPO_ROW})">`
        + `<line x1="14" y1="15" x2="${TOPO_W - 12}" y2="15" class="if-rule"/>`
        + `<text class="if-name" x="20" y="19">${esc(f.name)}</text>`
        + `<text class="if-cidr" x="${TOPO_W - 20}" y="19" text-anchor="end">${esc(f.cidr || '—')}</text>`
        + `</g>`;
    }).join('') : '';

    // The pill holds text AND a chevron, so it is sized for the widest
    // label ("12 ports") with the chevron parked clear of it. A tighter
    // box clipped the trailing "s" at some zoom levels.
    const badge = list.length
      ? `<g class="topo-badge" transform="translate(${TOPO_W - 86},14)">`
        + `<rect width="72" height="22" rx="11"/>`
        + `<text x="28" y="15" text-anchor="middle">${list.length} port${list.length > 1 ? 's' : ''}</text>`
        + `<path class="chev" d="${p.open ? 'M56 8l-4 4 4 4' : 'M56 8l4 4-4 4'}"/></g>`
      : '';

    return `<g class="topo-node ${cls.join(' ')}" data-id="${esc(dv.id)}"`
      + `${list.length ? ' data-expandable="1"' : ''} transform="translate(${p.x},${p.y})"`
      + ` role="button" tabindex="0" aria-expanded="${p.open}">`
      + `<rect class="card" width="${TOPO_W}" height="${p.h}" rx="14"/>`
      + topoIcon(dv.role)
      + `<text class="n-name" x="52" y="27">${esc(dv.name).slice(0, 26)}</text>`
      + `<text class="n-sub" x="52" y="46">${esc(ip || dv.type || '')}</text>`
      + badge + rows + `</g>`;
  }).join('');

  const netSvg = m.nets.map(net => {
    const p = pos.get(net.id);
    if(!p) return '';
    const users = edges.filter(e => e.to === net.id).length;
    const hit = topoMatches(net.name);
    const cls = ['network'];
    if(!active(net.id)) cls.push('dim');
    if(TOPO.query && !hit) cls.push('dim');
    if(TOPO.query && hit) cls.push('hit');
    return `<g class="topo-node ${cls.join(' ')}" data-id="${esc(net.id)}"`
      + ` transform="translate(${p.x},${p.y})" role="button" tabindex="0">`
      + `<rect class="card" width="${TOPO_NET_W}" height="54" rx="14"/>`
      + `<text class="n-name" x="18" y="26">${esc(net.name)}</text>`
      + `<text class="n-sub" x="18" y="44">${users} connection${users === 1 ? '' : 's'}</text>`
      + `</g>`;
  }).join('');

  topology.innerHTML =
    `<svg id="topoSvg" viewBox="0 0 ${width} ${height}" preserveAspectRatio="xMidYMin meet">`
    + `<g id="world">${edgeSvg}${deviceSvg}${netSvg}</g></svg>`;
  TOPO.dom = null;
  topoBindEvents();
  topoApplyView();
  const total = m.devices.length + m.nets.length;
  const el = document.getElementById('topoCount');
  if(el) el.textContent = `${total} node(s) · ${edges.length} link(s)`
    + (TOPO.expanded.size ? ` · ${TOPO.expanded.size} expanded` : '');
}

// --------------------------------------------------------------------------
// dispatcher and controls
// --------------------------------------------------------------------------
function renderTopology(d){
  if(!d || !(d.nodes || []).length){
    topology.innerHTML = emptyState('⌘','No topology objects',
      'show-gateways-and-servers returned nothing. Check that this API user can read gateway objects.',
      'Reload','onclick="loadMap(event)"');
    return;
  }
  document.body.classList.toggle('topo-graph', TOPO.mode === 'graph');
  if(TOPO.mode === 'graph') renderTopoGraph(d); else renderTopoCards(d);
  topoSyncControls();
}

function topoSetMode(mode){
  if(TOPO.mode === mode) return;
  TOPO.mode = mode;
  TOPO.at = new Map();
  TOPO.focus = null;
  TOPO.view = {scale: 1, tx: 0, ty: 0};
  try{ localStorage.setItem('fw-topo-mode', mode); }catch(e){}
  renderTopology(mapData);
}

function topoSyncControls(){
  const graph = TOPO.mode === 'graph';
  document.querySelectorAll('[data-topo-mode]').forEach(b =>
    b.classList.toggle('on', b.dataset.topoMode === TOPO.mode));
  document.querySelectorAll('[data-graph-only]').forEach(b => b.classList.toggle('hidden', !graph));
  const mg = document.getElementById('topoMerge');
  if(mg) mg.classList.toggle('on', TOPO.merge);
  const lg = document.querySelector('.topo-legend');
  if(lg) lg.classList.toggle('hidden', !TOPO.legend);
  const lb = document.getElementById('topoLegendBtn');
  if(lb) lb.textContent = TOPO.legend ? 'Hide Legend' : 'Show Legend';
}

function topoToggle(id){
  if(TOPO.mode === 'graph'){
    if(String(id).startsWith('merged:')){
      if(TOPO.unmerged.has(id)) TOPO.unmerged.delete(id); else TOPO.unmerged.add(id);
      TOPO.at.delete(id);
      renderTopology(mapData);
      return;
    }
    if(TOPO.collapsed.has(id)) TOPO.collapsed.delete(id); else TOPO.collapsed.add(id);
    TOPO.at.delete(id);         // let its freed leaves find a new home
  }else{
    if(TOPO.expanded.has(id)) TOPO.expanded.delete(id); else TOPO.expanded.add(id);
  }
  renderTopology(mapData);
}

function topoExpandAll(open){
  const m = buildTopoModel(mapData);            // build once, not per device
  if(TOPO.mode === 'graph'){
    TOPO.collapsed.clear();
    if(!open) m.devices.forEach(d => TOPO.collapsed.add(d.id));
  }else{
    TOPO.expanded.clear();
    if(open) m.devices.forEach(d => {
      if((m.ifaces.get(d.id) || []).length) TOPO.expanded.add(d.id);
    });
  }
  renderTopology(mapData);
}

function topoAutoMerge(){
  TOPO.merge = !TOPO.merge;
  TOPO.unmerged.clear();
  TOPO.at = new Map();          // merging changes which nodes exist
  renderTopology(mapData);
  const g = TOPO.graph;
  if(TOPO.merge){
    if(g && g.mergedFrom) notify('info','Auto Merge on',
      `${g.mergedFrom} subnets that are reached through exactly the same devices now share a node. No subnet was dropped - open a merged node's tooltip to see its members.`);
    else notify('info','Nothing to merge',
      'Every subnet here is reached through a different set of devices, so merging would not simplify the map.');
  }
}

function topoToggleLegend(){
  TOPO.legend = !TOPO.legend;
  try{ localStorage.setItem('fw-topo-legend', TOPO.legend ? '1' : '0'); }catch(e){}
  topoSyncControls();
}

// ---- search --------------------------------------------------------------
function topoSearch(v){
  TOPO.query = v || '';
  TOPO.hitIdx = -1;
  renderTopology(mapData);
  TOPO.hits = [...topology.querySelectorAll('.hit')].map(el => el.dataset.id);
  const el = document.getElementById('topoHits');
  if(el) el.textContent = TOPO.query ? `${TOPO.hits.length} match${TOPO.hits.length === 1 ? '' : 'es'}` : '';
}

function topoStepHit(dir){
  if(!TOPO.hits.length){
    notify('info','Nothing to step through','Type an address or a name in the filter box first.');
    return;
  }
  TOPO.hitIdx = (TOPO.hitIdx + dir + TOPO.hits.length) % TOPO.hits.length;
  const id = TOPO.hits[TOPO.hitIdx];
  topoCentre(id);
  const el = document.getElementById('topoHits');
  if(el) el.textContent = `${TOPO.hitIdx + 1} of ${TOPO.hits.length}`;
}

function topoCentre(id){
  const g = TOPO.graph;
  let x, y;
  if(TOPO.mode === 'graph' && g){
    const nd = g.byId.get(id); if(!nd) return;
    x = nd.x; y = nd.y;
  }else{
    const el = topology.querySelector(`.topo-node[data-id="${CSS.escape(id)}"]`);
    if(!el) return;
    const b = el.getBBox();
    const t = el.getAttribute('transform') || '';
    const mth = /translate\(([-\d.]+),\s*([-\d.]+)\)/.exec(t) || [0,0,0];
    x = Number(mth[1]) + b.width / 2; y = Number(mth[2]) + b.height / 2;
  }
  TOPO.view.scale = Math.max(TOPO.view.scale, 1.2);
  TOPO.view.tx = TOPO.vb.w / 2 - TOPO.view.scale * x;
  TOPO.view.ty = TOPO.vb.h / 2 - TOPO.view.scale * y;
  topoApplyView();
  topology.querySelectorAll('.flash').forEach(e => e.classList.remove('flash'));
  const node = topology.querySelector(`[data-id="${CSS.escape(id)}"]`);
  if(node) node.classList.add('flash');
}

// ---- saved arrangements --------------------------------------------------
function topoSaveMap(){
  if(TOPO.mode !== 'graph' || !TOPO.graph){
    notify('warn','Nothing to save','Switch to the Graph view to arrange and save a map.');
    return;
  }
  const pos = {};
  TOPO.graph.nodes.forEach(n => { pos[n.id] = [Math.round(n.x), Math.round(n.y)]; });
  try{
    localStorage.setItem(topoKey(mapData), JSON.stringify(pos));
    TOPO.pinned = new Map(Object.entries(pos));
    renderTopology(mapData);      // so the placed markers appear straight away
    topoStatus(TOPO.graph);
    notify('ok','Map saved',
      `${Object.keys(pos).length} node positions stored in this browser. They are reapplied only to this exact set of objects - if the estate changes, the map is laid out fresh.`);
  }catch(e){
    notify('warn','Could not save the map',
      'Browser storage refused the write. Private-mode windows and some group policies block it.');
  }
}

function topoLoadSaved(d){
  TOPO.pinned = new Map();
  TOPO.at = new Map();
  try{
    const raw = localStorage.getItem(topoKey(d));
    if(raw) TOPO.pinned = new Map(Object.entries(JSON.parse(raw)));
  }catch(e){ TOPO.pinned = new Map(); }
}

function topoResetMap(){
  TOPO.pinned = new Map();
  TOPO.at = new Map();
  TOPO.collapsed.clear();
  TOPO.expanded.clear();
  TOPO.focus = null;
  TOPO.merge = false;
  TOPO.view = {scale: 1, tx: 0, ty: 0};
  try{ localStorage.removeItem(topoKey(mapData)); }catch(e){}
  renderTopology(mapData);
  notify('ok','Map reset','Saved positions cleared and the layout recomputed from scratch.');
}

// ---- view ----------------------------------------------------------------
function topoApplyView(){
  const w = document.getElementById('world');
  if(w) w.setAttribute('transform',
    `translate(${TOPO.view.tx.toFixed(1)} ${TOPO.view.ty.toFixed(1)}) scale(${TOPO.view.scale.toFixed(3)})`);
  const s = document.getElementById('topoZoomRange');
  if(s) s.value = String(Math.round(TOPO.view.scale * 100));
}

function topoZoom(f){
  TOPO.view.scale = Math.max(.3, Math.min(3, TOPO.view.scale * f));
  topoApplyView();
}
function topoZoomTo(pct){
  TOPO.view.scale = Math.max(.3, Math.min(3, Number(pct) / 100));
  topoApplyView();
}
function topoPan(dx, dy){
  TOPO.view.tx += dx; TOPO.view.ty += dy;
  topoApplyView();
}

function topoFit(){
  const world = document.getElementById('world');
  if(!world){ TOPO.view = {scale: 1, tx: 0, ty: 0}; topoApplyView(); return; }
  TOPO.view = {scale: 1, tx: 0, ty: 0};
  topoApplyView();
  let b;
  try{ b = world.getBBox(); }catch(e){ b = null; }
  if(!b || !b.width || !b.height){ topoApplyView(); return; }
  // The pan/zoom pad floats over the canvas, so the fit has to treat its
  // footprint as unusable - otherwise the node nearest the bottom-right
  // corner ends up sitting behind it, which is how CP-MGMT-01 disappeared.
  const vb = TOPO.vb;
  const pad = document.querySelector('.topo-pad');
  const pr = pad ? pad.getBoundingClientRect() : null;
  const usableW = Math.max(240, vb.w - (pr ? pr.width + 26 : 0));
  const usableH = Math.max(200, vb.h - (pr ? pr.height + 26 : 0));
  const s = Math.max(.3, Math.min(2.4, Math.min(usableW / b.width, usableH / b.height) * 0.95));
  TOPO.view = {scale: s,
               tx: usableW / 2 - s * (b.x + b.width / 2),
               ty: usableH / 2 - s * (b.y + b.height / 2)};
  topoApplyView();
}

// ---- export --------------------------------------------------------------
/* The SVG is styled by the page stylesheet, which does not travel with a
   serialised copy. So export re-attaches the topology rules and resolves the
   custom properties they reference - otherwise the exported image is a set of
   black-on-transparent shapes. */
function topoStyleBlock(){
  const wanted = [];
  for(const sheet of document.styleSheets){
    let rules;
    try{ rules = sheet.cssRules; }catch(e){ continue; }
    for(const r of rules || []){
      if(r.selectorText && /\.topo|#world|#topo/.test(r.selectorText)) wanted.push(r.cssText);
    }
  }
  const css = wanted.join('\n');
  const vars = [...new Set([...css.matchAll(/var\((--[a-z0-9-]+)/gi)].map(m => m[1]))];
  const cs = getComputedStyle(document.body);
  const decl = vars.map(v => `${v}:${cs.getPropertyValue(v).trim() || '#888'}`).join(';');
  return `<style>svg{${decl}}\n${css}</style>`;
}

function topoExportPng(){
  const svg = document.getElementById('topoSvg');
  if(!svg){ notify('warn','Nothing to export','Load the topology first.'); return; }
  const clone = svg.cloneNode(true);
  clone.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
  clone.setAttribute('width', TOPO.vb.w); clone.setAttribute('height', TOPO.vb.h);
  const bg = getComputedStyle(document.body).getPropertyValue('--panel').trim() || '#ffffff';
  clone.insertAdjacentHTML('afterbegin',
    topoStyleBlock() + `<rect width="100%" height="100%" fill="${bg}"/>`);
  const blob = new Blob([new XMLSerializer().serializeToString(clone)], {type: 'image/svg+xml'});
  const url = URL.createObjectURL(blob);
  const img = new Image();
  img.onload = () => {
    const c = document.createElement('canvas');
    c.width = TOPO.vb.w * 2; c.height = TOPO.vb.h * 2;   // 2x so text stays crisp
    const ctx = c.getContext('2d');
    ctx.fillStyle = bg; ctx.fillRect(0, 0, c.width, c.height);
    ctx.drawImage(img, 0, 0, c.width, c.height);
    URL.revokeObjectURL(url);
    c.toBlob(b => {
      const a = document.createElement('a');
      a.href = URL.createObjectURL(b);
      a.download = 'network-map.png';
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 4000);
      notify('ok','Image exported','network-map.png saved to your downloads.');
    }, 'image/png');
  };
  img.onerror = () => {
    URL.revokeObjectURL(url);
    notify('warn','Image export failed',
      'The browser refused to rasterise the map. Use the CSV export, or take a screenshot.');
  };
  img.src = url;
}

function topoExportCsv(){
  if(!mapData){ notify('warn','Nothing to export','Load the topology first.'); return; }
  const q = s => `"${String(s == null ? '' : s).replace(/"/g,'""')}"`;
  const byId = new Map((mapData.nodes || []).map(n => [n.id, n]));
  const rows = [['Kind','Name','Role','Type','Addresses','Connects to'].map(q).join(',')];
  for(const n of mapData.nodes || []){
    const out = (mapData.edges || []).filter(e => e.from === n.id)
      .map(e => (byId.get(e.to) || {}).name || e.to);
    rows.push([ 'node', n.name, n.role || '', n.type || '',
                (n.cidr ? [n.cidr] : (n.ips || [])).join(' '), out.join(' ') ].map(q).join(','));
  }
  const blob = new Blob([rows.join('\r\n')], {type: 'text/csv;charset=utf-8'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'network-map.csv';
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 4000);
}

// ---- events --------------------------------------------------------------
/* Drag state lives on TOPO, not in a closure, because the SVG is rebuilt on
   every render: a per-render `window` listener would be added again each time
   and never removed, so a long session would accumulate hundreds of them. */
const DRAG = {panning: false, node: null, moved: 0, lx: 0, ly: 0};

window.addEventListener('mouseup', () => {
  if(DRAG.node && DRAG.moved > 4){
    // A node the user placed stays where they put it, and the rest of the
    // map re-settles around it rather than snapping back.
    DRAG.node.fixed = true;
    TOPO.pinned.set(DRAG.node.id, [Math.round(DRAG.node.x), Math.round(DRAG.node.y)]);
    TOPO.at.set(DRAG.node.id, [DRAG.node.x, DRAG.node.y]);
    if(TOPO.graph) topoStatus(TOPO.graph);
  }
  DRAG.node = null; DRAG.panning = false;
});

function topoBindEvents(){
  const svg = document.getElementById('topoSvg');
  if(!svg) return;

  // One world unit is one CSS pixel (see topoVB), so the only factor left
  // between a mouse delta and a world delta is the zoom.
  const unit = () => 1 / TOPO.view.scale;

  svg.addEventListener('wheel', e => {
    e.preventDefault();
    topoZoom(e.deltaY < 0 ? 1.12 : 0.89);
  }, {passive: false});

  svg.addEventListener('mousedown', e => {
    DRAG.moved = 0; DRAG.lx = e.clientX; DRAG.ly = e.clientY;
    const g = e.target.closest('.topo-g-node');
    if(g && TOPO.mode === 'graph' && TOPO.graph){
      DRAG.node = TOPO.graph.byId.get(g.dataset.id) || null;
      if(DRAG.node) DRAG.node.el = g;
    }else DRAG.panning = true;
  });
  svg.addEventListener('mousemove', e => {
    if(!DRAG.panning && !DRAG.node) return;
    DRAG.moved += Math.abs(e.clientX - DRAG.lx) + Math.abs(e.clientY - DRAG.ly);
    const k = unit();
    const dx = (e.clientX - DRAG.lx) * k, dy = (e.clientY - DRAG.ly) * k;
    DRAG.lx = e.clientX; DRAG.ly = e.clientY;
    if(DRAG.node){
      const nd = DRAG.node;
      nd.x += dx; nd.y += dy;
      nd.el.setAttribute('transform', `translate(${nd.x.toFixed(1)},${nd.y.toFixed(1)})`);
      TOPO.graph.links.forEach((l, i) => {
        if(l.a !== nd && l.b !== nd) return;
        const ln = TOPO.dom && TOPO.dom.lines[i]; if(!ln) return;
        ln.setAttribute('x1', l.a.x.toFixed(1)); ln.setAttribute('y1', l.a.y.toFixed(1));
        ln.setAttribute('x2', l.b.x.toFixed(1)); ln.setAttribute('y2', l.b.y.toFixed(1));
      });
      topoLabels(true);
    }else{
      TOPO.view.tx += dx * TOPO.view.scale; TOPO.view.ty += dy * TOPO.view.scale;
      topoApplyView();
    }
  });

  svg.addEventListener('click', e => {
    if(DRAG.moved > 4) return;                  // a drag is not a click
    const g = e.target.closest('.topo-node, .topo-g-node');
    if(!g){ TOPO.focus = null; renderTopology(mapData); return; }
    const id = g.dataset.id;
    if(g.dataset.expandable){ topoToggle(id); return; }
    TOPO.focus = (TOPO.focus === id) ? null : id;
    renderTopology(mapData);
  });

  // Double click always isolates. On an expandable device the two single
  // clicks toggle it there and back first, so the net effect is just a focus.
  svg.addEventListener('dblclick', e => {
    const g = e.target.closest('.topo-node, .topo-g-node');
    if(!g) return;
    TOPO.focus = (TOPO.focus === g.dataset.id) ? null : g.dataset.id;
    renderTopology(mapData);
  });

  svg.addEventListener('keydown', e => {
    if(e.key !== 'Enter' && e.key !== ' ') return;
    const g = e.target.closest('.topo-node, .topo-g-node');
    if(!g) return;
    e.preventDefault();
    if(g.dataset.expandable) topoToggle(g.dataset.id);
    else { TOPO.focus = (TOPO.focus === g.dataset.id) ? null : g.dataset.id; renderTopology(mapData); }
  });
}

/* The viewBox is the container's pixel size, so a window resize (or opening
   the sidebar rail) changes it. Repaint on a trailing edge only - a resize
   fires continuously and the simulation must not restart per frame. */
let topoResizeTimer = null;
window.addEventListener('resize', () => {
  if(TOPO.mode !== 'graph' || !TOPO.graph || !mapData) return;
  clearTimeout(topoResizeTimer);
  topoResizeTimer = setTimeout(() => {
    const svg = document.getElementById('topoSvg');
    if(!svg) return;
    TOPO.vb = topoVB();
    svg.setAttribute('viewBox', `0 0 ${TOPO.vb.w} ${TOPO.vb.h}`);
    topoFit();
  }, 180);
});

try{
  if(localStorage.getItem('fw-topo-mode') === 'cards') TOPO.mode = 'cards';
  if(localStorage.getItem('fw-topo-legend') === '0') TOPO.legend = false;
}catch(e){}

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

  // Install-on targets. A check that did not run must not render as a clean
  // result: with no gateway list there is nothing to compare against, and an
  // empty table would read as "all targets are fine".
  const checked=((data&&data.summary)||{}).install_on_checked===true;
  const ioFindings=((data&&data.findings)||{}).install_on_findings||[];
  const byRule=new Map(rules.map(r=>[norm(r.rule),r]));
  const iob=document.getElementById('nat-installon-body');
  if(iob){
    iob.innerHTML=!checked
      ?'<tr><td colspan="4" class="muted">Not checked \u2014 the gateway list from show-gateways-and-servers was not available, so no install-on target could be verified.</td></tr>'
      :(ioFindings.length?ioFindings.map(f=>{
          const r=byRule.get(norm(f.rule))||{};
          return `<tr>
      <td><strong>Rule ${esc(f.rule)}</strong></td>
      <td>${esc(r.name||'—')}</td>
      <td>${esc(f.target)}</td>
      <td>${esc(f.reason)}</td>
    </tr>`;}).join('')
        :'<tr><td colspan="4" class="muted">Every install-on target matches a gateway show-gateways-and-servers returned.</td></tr>');
  }
  const ion=document.getElementById('nat-installon-note');
  if(ion&&!checked) ion.textContent='This check did not run: the gateway list from show-gateways-and-servers was not available to this analysis.';
  const ioc=document.getElementById('nat-installon-tab-count');
  if(ioc)ioc.textContent=checked?`(${ioFindings.length})`:'(n/a)';

  const dc=document.getElementById('nat-disabled-tab-count');
  if(dc)dc.textContent=`(${disabled.length})`;
  const nc=document.getElementById('nat-notrans-tab-count');
  if(nc)nc.textContent=`(${noTrans.length})`;
}

// Extend the existing NAT tab switcher without changing the current rulebase/duplicate/broad behavior.


function showNatTab(tab,btn){
  // Hide every NAT content area first.
  const ids=['nat-disabled-view','nat-notrans-view','nat-installon-view'];
  ids.forEach(id=>{const el=document.getElementById(id);if(el)el.style.display='none';});

  // renderNat() owns rulebase / duplicates / broad views.
  // Clear its container when entering the custom views.
  if(tab==='disabled' || tab==='notrans' || tab==='installon'){
    if(typeof natResults!=='undefined' && natResults) natResults.innerHTML='';

    const target=document.getElementById('nat-'+(tab==='disabled'?'disabled':tab==='notrans'?'notrans':'installon')+'-view');
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


// --------------------------------------------------------------------------
// Policy Diff (v4.25): what changed between two snapshots
//
// The whole page exists to answer one question periodic review always starts
// from and no other screen here answers: what moved since last time. Three
// things it must not blur, and the rendering keeps them apart:
//   modified            somebody edited a field of the rule
//   moved               nothing was edited, but first-match-wins order changed
//   scope changed       the rule is untouched; an object inside it grew
// and a fourth that is not a finding but must never be silently dropped:
//   scope unverifiable  an object has no static model, so we cannot compare
// --------------------------------------------------------------------------
let snapshotList = [];

async function loadSnapshots(ev){
  return task('snapshots','Reading saved snapshots',async()=>{
    const d=await api('/api/snapshots');
    snapshotList=d.snapshots||[];
    const opts=snapshotList.map(s=>
      `<option value="${esc(s.id)}">${esc(s.package)} · ${esc(String(s.taken_at||'').replace('T',' ').slice(0,16))} · ${esc(s.access_rules)} rules · v${esc(s.app_version)}</option>`).join('');
    // A is the older one, so it defaults to the bottom of a newest-first list.
    snapA.innerHTML=opts; snapB.innerHTML=opts;
    if(snapshotList.length>1){ snapA.selectedIndex=1; snapB.selectedIndex=0; }
    snapNote.textContent=snapshotList.length
      ? `${snapshotList.length} snapshot(s) in ${d.directory}`
      : `No snapshots yet. Capture one, change something in SmartConsole, capture another, then compare. Saved to ${d.directory}`;
    setStatus(`${snapshotList.length} snapshot(s) available.`, 'success');
    return d;
  },{button:ev&&ev.currentTarget,successMessage:null}).catch(()=>{});
}

async function takeSnapshot(ev){
  if(!P.value){setStatus('Select a Policy Package first.','warn');notify('warn','No Policy Package selected','A snapshot is of one package. Choose one from the selector at the top of the page.');return}
  const rid=newRid();
  const stop=trackProgress(rid);
  return task('snapshot','Capturing policy snapshot',async()=>{
    const d=await api('/api/snapshot?package='+encodeURIComponent(P.value)+'&rid='+rid);
    await loadSnapshots();
    if(d.nat_error) notify('warn','NAT rulebase not captured',d.nat_error+' The Access rules in this snapshot are unaffected, but a NAT diff against it will be empty.');
    notify('success','Snapshot captured',
      `${d.summary.access_rules} Access rule(s) and ${d.summary.nat_rules} NAT rule(s) written to ${d.saved_to}`,
      {duration:11000});
    return d;
  },{
    button:ev&&ev.currentTarget,
    sub:'Reading the package · elapsed',
    steps:['Load package and inline layers','Read the NAT rulebase',"Resolve each rule's reach and write the file"],
    successMessage:null,
  }).catch(()=>{}).finally(()=>stop());
}

function diffRows(rows,cols){
  if(!rows.length) return '<p class="muted">None.</p>';
  return `<div class="table-wrap"><table><thead><tr>${cols.map(c=>`<th>${esc(c[0])}</th>`).join('')}</tr></thead><tbody>`
    + rows.map(r=>`<tr>${cols.map(c=>`<td>${c[1](r)}</td>`).join('')}</tr>`).join('')
    + '</tbody></table></div>';
}

function diffSection(title, hint, tone, rows, cols){
  return `<div class="card" style="margin:14px 0">
    <div class="section-title"><h3><span class="pill ${tone}">${esc(rows.length)}</span> ${esc(title)}</h3>
      <span class="hint">${esc(hint)}</span></div>
    ${diffRows(rows,cols)}
  </div>`;
}

const RULE_CELL = r=>`<span class="rule-no">Rule ${esc(r.display_rule||'—')}</span> ${esc(r.name||'')}`;

async function runDiff(ev){
  if(!snapA.value||!snapB.value){setStatus('Pick two snapshots first.','warn');notify('warn','Two snapshots needed','Capture at least two, then choose the older one as A and the newer one as B.');return}
  if(snapA.value===snapB.value){setStatus('Those are the same snapshot.','warn');notify('warn','Same snapshot twice','Comparing a snapshot with itself always reports no change, which tells you nothing.');return}
  return task('diff','Comparing snapshots',async()=>{
    const d=await api('/api/snapshot-diff?a='+encodeURIComponent(snapA.value)+'&b='+encodeURIComponent(snapB.value));
    const s=d.summary;
    const head=`<div class="flow">
      <div class="step"><span class="muted">A · older</span><br><b>${esc(d.a.package)}</b><br><span class="muted">${esc(String(d.a.taken_at||'').replace('T',' ').slice(0,16))} · v${esc(d.a.app_version)}</span></div>
      <div class="arrow">→</div>
      <div class="step"><span class="muted">B · newer</span><br><b>${esc(d.b.package)}</b><br><span class="muted">${esc(String(d.b.taken_at||'').replace('T',' ').slice(0,16))} · v${esc(d.b.app_version)}</span></div>
      <div class="arrow">→</div>
      <div class="step"><span class="muted">Verdict</span><br><span class="pill ${d.identical?'good':'warn'}">${d.identical?'NO CHANGE':'CHANGED'}</span></div>
    </div>`;

    const warn=(d.warnings||[]).length
      ? `<div class="card" style="margin-top:14px;border-color:rgba(246,196,83,.46)">
           <div class="section-title"><h3>Read this before acting on the result</h3></div>
           <ul style="margin:8px 0 0 18px">${d.warnings.map(w=>`<li>${esc(w)}</li>`).join('')}</ul>
         </div>` : '';

    diffResult.innerHTML = head + warn
      + `<div class="cards" style="margin-top:16px">`
      + [['Added',s.added],['Removed',s.removed],['Modified',s.modified],['Moved',s.moved],
         ['Scope changed',s.scope_changed],['Unverifiable',s.scope_unverifiable],
         ['Unchanged',s.unchanged],['NAT changes',s.nat_added+s.nat_removed+s.nat_modified]]
          .map(x=>`<div class="card"><div class="metric-label">${esc(x[0])}</div><div class="metric num">${esc(x[1])}</div></div>`).join('')
      + `</div>`

      + diffSection('Added','Rules present in B and not in A','good',d.access.added,
          [['Rule',RULE_CELL],['Layer',r=>esc(r.layer||'')],['Action',r=>esc(r.action||'')],
           ['Source',r=>esc(r.source||'')],['Destination',r=>esc(r.destination||'')],['Service',r=>esc(r.service||'')]])

      + diffSection('Removed','Rules present in A and not in B','bad',d.access.removed,
          [['Rule',RULE_CELL],['Layer',r=>esc(r.layer||'')],['Action',r=>esc(r.action||'')],
           ['Source',r=>esc(r.source||'')],['Destination',r=>esc(r.destination||'')],['Service',r=>esc(r.service||'')]])

      + diffSection('Modified','A field of the rule was edited','warn',d.access.modified,
          [['Rule',RULE_CELL],['Layer',r=>esc(r.layer||'')],
           ['Changes',r=>r.changes.map(c=>`<b>${esc(c.field)}</b>: ${esc(String(c.from??'—'))} → ${esc(String(c.to??'—'))}`).join('<br>')]])

      + diffSection('Moved','Nothing was edited, but the position changed — and Access Control is first match wins, so position is part of the meaning','warn',d.access.moved,
          [['Rule',RULE_CELL],['From',r=>esc(r.from_position)],['To',r=>esc(r.to_position)],
           ['Why this matters',r=>esc(r.reason||'')]])

      + diffSection('Scope changed without the rule changing','The rule text, its uids and its number are identical — an object inside it grew or shrank. A textual diff cannot see this','warn',d.access.scope_changed,
          [['Rule',RULE_CELL],['Dimension',r=>`<span class="pill purple">${esc(r.dimension)}</span>`],
           ['Object',r=>esc(r.text||'')],
           ['Direction',r=>`<span class="pill ${r.direction==='widened'?'bad':'warn'}">${esc(r.direction)}</span>`],
           ['Intervals',r=>`${esc(r.from_intervals)} → ${esc(r.to_intervals)}`]])

      + diffSection('Could not be compared','An object on this dimension has no static model, so whether its reach changed cannot be decided. Reported rather than counted as unchanged','warn',d.access.scope_unverifiable,
          [['Rule',RULE_CELL],['Dimension',r=>esc(r.dimension)],['Object',r=>esc(r.text||'')],
           ['Reason',r=>esc(r.reason||'')]])

      + diffSection('NAT added','','good',d.nat.added,
          [['Rule',r=>`<span class="rule-no">Rule ${esc(r.rule)}</span> ${esc(r.name||'')}`],
           ['Original src',r=>esc(r.original_source||'')],['Translated src',r=>esc(r.translated_source||'')],
           ['Method',r=>esc(r.method||'')]])
      + diffSection('NAT removed','','bad',d.nat.removed,
          [['Rule',r=>`<span class="rule-no">Rule ${esc(r.rule)}</span> ${esc(r.name||'')}`],
           ['Original src',r=>esc(r.original_source||'')],['Translated src',r=>esc(r.translated_source||'')],
           ['Method',r=>esc(r.method||'')]])
      + diffSection('NAT modified','','warn',d.nat.modified,
          [['Rule',r=>`<span class="rule-no">Rule ${esc(r.rule)}</span> ${esc(r.name||'')}`],
           ['Changes',r=>r.changes.map(c=>`<b>${esc(c.field)}</b>: ${esc(String(c.from??'—'))} → ${esc(String(c.to??'—'))}`).join('<br>')]])

      + `<div class="hint" style="margin-top:12px">${(d.notes||[]).map(esc).join(' · ')}</div>`;

    if(d.identical) notify('success','No change','Every tracked rule matched, in the same order, with the same resolved reach.');
    else notify('warn','Policy changed',
      `${s.added} added · ${s.removed} removed · ${s.modified} modified · ${s.moved} moved · ${s.scope_changed} changed scope without changing`,
      {duration:13000});
    setStatus(d.identical?'No change between the two snapshots.':'Differences found between the two snapshots.',
      d.identical?'success':'warn');
    return d;
  },{button:ev&&ev.currentTarget,successMessage:null}).catch(()=>{});
}


// --------------------------------------------------------------------------
// Compliance (v4.26): the customer's standard, not ours
//
// Four statuses, and the rendering keeps them apart because collapsing any two
// of them is how a compliance report stops being evidence:
//   pass            proven to satisfy the check
//   fail            proven to violate it, with the offending rules named
//   unverifiable    an input could not be resolved - NEVER rounded up to pass
//   not_applicable  nothing in this package for the check to test
// Plus a fifth thing that is not a status: whether the check cites a standard
// at all. A house rule is a fine reason to fix something and a bad reason to
// tell an auditor you are non-compliant with NIST.
// --------------------------------------------------------------------------
const COMPLIANCE_TONE = {pass:'good', fail:'bad', unverifiable:'warn', not_applicable:'purple'};

async function loadProfiles(ev){
  return task('profiles','Reading compliance profiles',async()=>{
    const d=await api('/api/compliance-profiles');
    profileSel.innerHTML=(d.profiles||[]).map(p=>
      `<option value="${esc(p.id)}">${esc(p.name)} · ${esc(p.checks)} checks · ${esc(p.cited_checks)} cited</option>`).join('');
    profileNote.textContent=(d.profiles||[]).length
      ? `${d.profiles.length} profile(s) in ${d.directory} — copy one and edit it to make it yours.`
      : `No profiles found in ${d.directory}.`;
    return d;
  },{button:ev&&ev.currentTarget,successMessage:null}).catch(()=>{});
}

function complianceSourceChanged(){
  const snap=complianceSource.value==='snapshot';
  complianceSnapWrap.style.display=snap?'':'none';
  if(snap && !complianceSnap.options.length){
    complianceSnap.innerHTML=(snapshotList||[]).map(s=>
      `<option value="${esc(s.id)}">${esc(s.package)} · ${esc(String(s.taken_at||'').replace('T',' ').slice(0,16))}</option>`).join('')
      || '<option value="">No snapshots captured yet</option>';
  }
}

function complianceSource_cite(r){
  const s=r.source||{};
  if(!r.cited) return `<span class="pill purple">HOUSE RULE</span> <span class="muted">${esc(s.note||'no external standard cited')}</span>`;
  const head=`<b>${esc(s.standard||'')}</b>${s.clause?' · '+esc(s.clause):''}`;
  const body=[s.quote?`<div class="hint" style="margin-top:4px">&ldquo;${esc(s.quote)}&rdquo;</div>`:'',
              s.note?`<div class="hint" style="margin-top:4px">${esc(s.note)}</div>`:'',
              s.url?`<div class="hint" style="margin-top:4px"><code>${esc(s.url)}</code></div>`:''].join('');
  return head+body;
}

async function runCompliance(ev){
  if(!profileSel.value){setStatus('Pick a profile first.','warn');notify('warn','No profile selected','A profile is the list of checks to run. Refresh the list, or add a YAML file to the profiles directory.');return}
  const bySnapshot=complianceSource.value==='snapshot';
  if(bySnapshot && !complianceSnap.value){setStatus('Pick a snapshot.','warn');notify('warn','No snapshot selected','Capture one on the Policy Diff page first.');return}
  if(!bySnapshot && !P.value){setStatus('Select a Policy Package first.','warn');notify('warn','No Policy Package selected','Choose a package at the top of the page, or evaluate a stored snapshot instead.');return}

  const rid=newRid();
  const stop=trackProgress(rid);
  return task('compliance','Running the compliance profile',async()=>{
    const q=bySnapshot
      ? 'profile='+encodeURIComponent(profileSel.value)+'&snapshot='+encodeURIComponent(complianceSnap.value)
      : 'profile='+encodeURIComponent(profileSel.value)+'&package='+encodeURIComponent(P.value)+'&rid='+rid;
    const d=await api('/api/compliance?'+q);
    const s=d.summary;

    const head=`<div class="flow">
      <div class="step"><span class="muted">Profile</span><br><b>${esc(d.profile.name)}</b><br><span class="muted">${esc(s.total)} check(s) · ${esc(s.uncited_checks)} uncited</span></div>
      <div class="arrow">→</div>
      <div class="step"><span class="muted">Evaluated</span><br><b>${esc(d.evaluated.package||d.evaluated.id||'—')}</b><br><span class="muted">${esc(d.evaluated.kind)}${d.taken_at?' · '+esc(String(d.taken_at).replace('T',' ').slice(0,16)):''}</span></div>
      <div class="arrow">→</div>
      <div class="step"><span class="muted">Verdict</span><br><span class="pill ${d.conformant?'good':'warn'}">${d.conformant?'CONFORMANT':'NOT CONFORMANT'}</span><br><span class="muted">${esc(s.failed)} failed · ${esc(s.unverifiable)} unverifiable</span></div>
    </div>`;

    const cards=`<div class="cards" style="margin-top:16px">`
      + [['Checks',s.total],['Passed',s.passed],['Failed',s.failed],
         ['Unverifiable',s.unverifiable],['Not applicable',s.not_applicable]]
        .map(x=>`<div class="card"><div class="metric-label">${esc(x[0])}</div><div class="metric num">${esc(x[1])}</div></div>`).join('')
      + `</div>`;

    const order={fail:0, unverifiable:1, pass:2, not_applicable:3};
    const rows=(d.results||[]).slice().sort((a,b)=>(order[a.status]??9)-(order[b.status]??9));

    const body=rows.map(r=>`<div class="card" style="margin:12px 0">
      <div class="section-title">
        <h3><span class="pill ${COMPLIANCE_TONE[r.status]||'purple'}">${esc(String(r.status).replace('_',' ').toUpperCase())}</span>
          ${esc(r.title)}</h3>
        <span class="hint">${esc(r.id)} · severity ${esc(r.severity)}</span>
      </div>
      <p style="margin:8px 0 0">${esc(r.detail)}</p>
      ${(r.offenders||[]).length?`<div class="table-wrap" style="margin-top:10px"><table>
        <thead><tr><th>Rule</th><th>Layer</th><th>Action</th><th>Source</th><th>Destination</th><th>Service</th><th>Why</th></tr></thead>
        <tbody>${r.offenders.map(o=>`<tr>
          <td><span class="rule-no">Rule ${esc(o.display_rule||'—')}</span> ${esc(o.name||'')}</td>
          <td>${esc(o.layer||'')}</td><td>${esc(o.action||'')}</td>
          <td>${esc(o.source||'')}</td><td>${esc(o.destination||'')}</td><td>${esc(o.service||'')}</td>
          <td>${esc(o.reason||'matches the forbidden condition')}</td></tr>`).join('')}</tbody></table></div>`:''}
      ${(r.unverifiable_rules||[]).length?`<div class="hint" style="margin-top:10px"><b>Could not be decided for:</b><br>
        ${r.unverifiable_rules.map(o=>`Rule ${esc(o.display_rule||'—')} ${esc(o.name||'')} — ${esc(o.reason||'')}`).join('<br>')}</div>`:''}
      <div class="hint" style="margin-top:10px">${complianceSource_cite(r)}</div>
    </div>`).join('');

    // What the profile author already knows this tool cannot decide. Printed
    // BELOW the results and clearly separated, so a clean run never reads as
    // "the standard is satisfied".
    const notChecked=(d.not_checkable||[]).length?`<div class="card" style="margin-top:18px;border-color:rgba(246,196,83,.46)">
      <div class="section-title"><h3>Not checked by this tool</h3>
        <span class="hint">Requirements this profile declares out of scope for a configuration reader</span></div>
      <div class="table-wrap" style="margin-top:10px"><table>
        <thead><tr><th>Requirement</th><th>Clause</th><th>Why not</th></tr></thead>
        <tbody>${d.not_checkable.map(n=>`<tr><td>${esc(n.requirement||'')}</td><td>${esc(n.clause||'')}</td><td>${esc(n.why||'')}</td></tr>`).join('')}</tbody>
      </table></div></div>`:'';

    complianceResult.innerHTML=head+cards+body+notChecked
      +`<div class="hint" style="margin-top:12px">${(d.notes||[]).map(esc).join(' · ')}</div>`;

    if(d.data_quality) reportDataQuality(d.data_quality,'Compliance');
    if(s.unverifiable) notify('warn','Some checks could not be decided',
      `${s.unverifiable} check(s) are unverifiable. They are not counted as passes, and the run is not conformant while one remains.`,
      {duration:12000});
    setStatus(d.conformant?'Conformant with this profile.':`${s.failed} failed, ${s.unverifiable} unverifiable.`,
      d.conformant?'success':'warn');
    return d;
  },{
    button:ev&&ev.currentTarget,
    sub:'Reading the package · elapsed',
    steps:['Load package and inline layers','Read the NAT rulebase','Analyse the rulebase','Evaluate the profile'],
    successMessage:null,
  }).catch(()=>{}).finally(()=>stop());
}



// --------------------------------------------------------------------------
// Gateway Health (v4.28): state now, and what moved since the baseline
//
// The one thing this page must never do is let silence read as health. A
// gateway that did not answer gets a finding of its own, at high severity, and
// the summary counts it separately from the ones that did.
// --------------------------------------------------------------------------
const SEV_TONE = {high:'bad', medium:'warn', low:'purple'};

async function loadBaselines(ev){
  return task('baselines','Reading health baselines',async()=>{
    const d=await api('/api/health-baselines');
    healthBaseline.innerHTML='<option value="">Do not compare</option>'
      +(d.baselines||[]).map(b=>`<option value="${esc(b.id)}">${esc(String(b.taken_at||'').replace('T',' ').slice(0,16))} · ${esc(b.gateways)} gw · ${esc(b.findings)} finding(s)</option>`).join('');
    healthNote.textContent=(d.baselines||[]).length
      ? `${d.baselines.length} baseline(s) in ${d.directory}`
      : `No baselines yet — every reading is saved as one, in ${d.directory}`;
    return d;
  },{button:ev&&ev.currentTarget,successMessage:null}).catch(()=>{});
}

async function runHealth(ev){
  return task('health','Reading gateway state',async()=>{
    const q=healthBaseline.value?'?baseline='+encodeURIComponent(healthBaseline.value):'';
    const d=await api('/api/health'+q);
    const s=d.summary;

    const head=`<div class="flow">
      <div class="step"><span class="muted">Read</span><br><b>${esc(s.gateways_read)} gateway(s)</b><br><span class="muted">${esc(String(d.taken_at||'').replace('T',' ').slice(0,16))}</span></div>
      <div class="arrow">→</div>
      <div class="step"><span class="muted">Not reached</span><br><b>${esc(s.gateways_unreachable)}</b><br><span class="muted">${s.gateways_unreachable?'state unknown':'none'}</span></div>
      <div class="arrow">→</div>
      <div class="step"><span class="muted">Findings</span><br><span class="pill ${s.high?'bad':(s.findings?'warn':'good')}">${esc(s.findings)}</span><br><span class="muted">${esc(s.high)} high</span></div>
    </div>`;

    const findings=(d.findings||[]).length?`<div class="card" style="margin-top:16px">
      <div class="section-title"><h3>Findings</h3><span class="hint">State of the estate, reported and never scored</span></div>
      <div class="table-wrap" style="margin-top:10px"><table>
        <thead><tr><th>Severity</th><th>Where</th><th>What</th><th>Detail</th></tr></thead>
        <tbody>${d.findings.map(f=>`<tr>
          <td><span class="pill ${SEV_TONE[f.severity]||'purple'}">${esc(String(f.severity).toUpperCase())}</span></td>
          <td>${esc(f.host)}</td><td>${esc(f.kind)} · ${esc(f.subject||'')}</td>
          <td>${esc(f.detail)}</td></tr>`).join('')}</tbody></table></div></div>`
      :'<div class="card" style="margin-top:16px"><p>No findings on the gateways that answered.</p></div>';

    const gws=(d.gateways||[]).map(g=>`<div class="card" style="margin:12px 0">
      <div class="section-title"><h3>${esc(g.host)}</h3>
        <span class="hint">${esc(g.version.product||'')} build ${esc(g.version.build||'?')} · ${esc(g.interfaces_up)} of ${esc(g.interfaces.length)} interfaces up</span></div>
      ${g.cluster.readable?`<p style="margin:8px 0 0">${esc(g.cluster.mode)} · status <span class="pill ${g.cluster.status==='ok'?'good':'bad'}">${esc(g.cluster.status)}</span> — ${g.cluster.members.map(m=>`<b>${esc(m.name)}</b> <span class="pill ${m.status==='active'?'good':'purple'}">${esc(m.status)}</span>`).join(' · ')}</p>`:'<p class="muted" style="margin:8px 0 0">No cluster state returned by this gateway.</p>'}
      <div class="table-wrap" style="margin-top:10px"><table>
        <thead><tr><th>Interface</th><th>Type</th><th>State</th><th>Address</th><th>Comment</th></tr></thead>
        <tbody>${g.interfaces.map(i=>`<tr>
          <td><b>${esc(i.name)}</b></td><td>${esc(i.type)}</td>
          <td><span class="pill ${i.enabled?'good':(i.configured?'bad':'purple')}">${i.enabled?'up':'down'}</span></td>
          <td>${esc(i.cidr||'—')}</td><td>${esc(i.comments||'')}</td></tr>`).join('')}</tbody></table></div></div>`).join('');

    const unreachable=(d.unreachable||[]).length?`<div class="card" style="margin-top:16px;border-color:rgba(255,113,132,.45)">
      <div class="section-title"><h3>Not reached</h3><span class="hint">Nothing above says anything about these</span></div>
      <ul style="margin:8px 0 0 18px">${d.unreachable.map(u=>`<li><b>${esc(u.host)}</b> — ${esc(u.error)}</li>`).join('')}</ul></div>`:'';

    const diff=d.diff?`<div class="card" style="margin-top:18px">
      <div class="section-title"><h3><span class="pill ${d.diff.unchanged?'good':'warn'}">${d.diff.unchanged?'NO CHANGE':esc(d.diff.summary.changes)+' CHANGE(S)'}</span> Since baseline</h3>
        <span class="hint">${esc(String(d.diff.baseline.taken_at||'').replace('T',' ').slice(0,16))} → now</span></div>
      ${d.diff.changes.length?`<div class="table-wrap" style="margin-top:10px"><table>
        <thead><tr><th>Gateway</th><th>What</th><th>Change</th></tr></thead>
        <tbody>${d.diff.changes.map(c=>`<tr><td>${esc(c.host)}</td><td>${esc(c.kind)} · ${esc(c.subject||'')}</td><td>${esc(c.detail)}</td></tr>`).join('')}</tbody>
      </table></div>`:'<p style="margin:8px 0 0">Interfaces, cluster roles and builds all match the baseline.</p>'}
      <div class="hint" style="margin-top:10px">${(d.diff.notes||[]).map(esc).join(' · ')}</div></div>`:'';

    healthResult.innerHTML=head+findings+diff+gws+unreachable
      +`<div class="hint" style="margin-top:12px">${(d.notes||[]).map(esc).join(' · ')}${d.saved_as?' · Saved as baseline '+esc(d.saved_as):''}</div>`;

    await loadBaselines();
    if(s.gateways_unreachable) notify('warn','Some gateways were not read',
      `${s.gateways_unreachable} gateway(s) did not answer. They produce no findings, which is not the same as having none.`,
      {duration:13000});
    if(d.diff && !d.diff.unchanged) notify('warn','State changed since the baseline',
      d.diff.changes.slice(0,3).map(c=>c.detail).join(' · '),{duration:14000});
    setStatus(s.findings?`${s.findings} finding(s), ${s.high} high.`:'No findings on the gateways that answered.',
      s.high?'warn':'success');
    return d;
  },{button:ev&&ev.currentTarget,successMessage:null}).catch(e=>{
    if(String(e&&e.message||'').includes('GAIA_ENABLED'))
      healthResult.innerHTML='<div class="card"><p>'+esc(String(e.message))+'</p></div>';
  });
}
