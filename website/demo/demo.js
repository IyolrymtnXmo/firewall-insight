/* Firewall Insight — interactive demo: the parts of the real app that would
 * reach a server outside fetch() (file downloads, PDF links, sign-out), the
 * guide dock, and the inputs that must not collect real secrets on a public
 * page. Loaded after app.js. */
(function () {
  'use strict';
  const D = window.FIDemo;
  const $ = id => document.getElementById(id);
  const store = {
    get(k) { try { return sessionStorage.getItem(k); } catch (_) { return null; } },
    set(k, v) { try { sessionStorage.setItem(k, v); } catch (_) { /* private mode */ } },
  };

  /* ---------------------------------------------------------- downloads */
  function download(name, text, type) {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([text], {type}));
    a.download = name;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1500);
  }
  const cell = v => { const s = String(v ?? ''); return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
  const csv = (rows, cols) => [cols.map(c => c[0]).join(',')]
    .concat(rows.map(r => cols.map(c => cell(c[1](r))).join(','))).join('\r\n');
  const COLS = [['Layer', r => r.layer], ['Layer Path', r => r.layer_path], ['Rule', r => r.display_rule],
    ['Section', r => r.section], ['Name', r => r.name], ['Enabled', r => r.enabled], ['Source', r => r.source],
    ['Destination', r => r.destination], ['VPN', r => r.vpn], ['Service', r => r.service], ['Action', r => r.action],
    ['Track', r => r.track], ['Install On', r => r.install_on], ['Time', r => r.time], ['Hits', r => r.hits],
    ['Last Hit', r => r.last_hit], ['Comments', r => r.comments]];
  const today = () => new Date().toISOString().slice(0, 16).replace(/[-:T]/g, '').replace(/^(\d{8})/, '$1-');

  window.exportRawPolicy = async function () {
    if (!P.value) { notify('warn', 'No Policy Package selected', 'Choose a package from the selector at the top of the page.'); return; }
    const d = await D.getData(`pkg/${P.value}/browser.json`);
    download(`access-policy-${P.value}.csv`, csv(d.rules, COLS), 'text/csv;charset=utf-8');
    notify('success', 'CSV export ready', 'Inline rules are included, each with its display rule (7.1) and layer path.');
  };
  window.exportAccess = async function () {
    if (!L.value) { notify('warn', 'No Access Layer selected', 'Pick an Access Layer before exporting.'); return; }
    for (const pkg of D.PACKAGES) {
      const d = await D.getData(`pkg/${pkg}/browser.json`);
      const rows = d.rules.filter(r => r.layer === L.value);
      if (rows.length) { download(`access-layer-${L.value.replace(/\s+/g, '_')}.csv`, csv(rows, COLS), 'text/csv;charset=utf-8'); return; }
    }
    notify('info', 'Nothing to export', `The layer ${L.value} has no rules in this demo.`);
  };
  window.downloadCleanup = async function () {
    if (!P.value) { notify('warn', 'No Policy Package selected', 'Pick a package at the top first.'); return; }
    const q = cleanupQuery();
    const d = await D.cleanup(q);
    if (d.error) { notify('warn', 'Script refused', d.error); return; }
    const ext = d.format === 'ansible' ? 'yml' : 'sh';
    download(`cleanup-${P.value}-${today()}.${ext}`, d.script, 'text/plain;charset=utf-8');
    notify('success', 'Script downloaded', 'Nothing was run. Read every line before using it anywhere.');
  };
  window.signOut = function () { location.href = '../'; };

  /* The trace needs an Access Layer. Pick the package's own when none is set,
     so a first trace never stops on an empty selector. */
  const ROOT = {'External-FW': 'External-FW Network', 'Internal-FW': 'Internal-FW Network', Standard: 'Network'};
  const realTrace = window.trace;
  window.trace = function () {
    if (!L.value && ROOT[P.value]) L.value = ROOT[P.value];
    return realTrace.apply(this, arguments);
  };
  P.addEventListener('change', () => {
    if (ROOT[P.value] && (!L.value || Object.values(ROOT).includes(L.value))) L.value = ROOT[P.value];
  });

  /* PDF report links and any other /api/ link the app renders. Opened in the
     click itself (no await first), so a phone's popup blocker allows it. */
  let storedRuns = new Set();
  D.getData('runs.json').then(d => { storedRuns = new Set(d.runs.map(r => r.id)); }).catch(() => {});
  document.addEventListener('click', e => {
    const a = e.target.closest && e.target.closest('a[href*="/api/"]');
    if (!a) return;
    e.preventDefault();
    const m = /\/api\/runs\/([^/]+)\/report\.pdf\?detail=(\w+)/.exec(a.getAttribute('href'));
    if (m) {
      const id = decodeURIComponent(m[1]);
      if (storedRuns.has(id)) { window.open(`data/pdf/${id}-${m[2]}.pdf`, '_blank', 'noopener'); return; }
      notify('info', 'No PDF for this run', 'A review started in the demo has no PDF. The stored reviews below it each have all three detail levels.');
      return;
    }
    notify('info', 'Download not available', D.DEMO_NOTE);
  }, true);

  /* ---------------------------------------- inputs that would take secrets */
  function lockSecrets() {
    for (const id of ['authPass', 'cpPass', 'gaiaPass', 'alPass', 'alUrl']) {
      const el = $(id);
      if (!el) continue;
      el.disabled = true;
      el.value = '';
      el.placeholder = 'Disabled in the demo';
      el.autocomplete = 'off';
    }
    const settings = $('settings');
    if (settings && !$('demoSettingsNote')) {
      const note = document.createElement('div');
      note.id = 'demoSettingsNote';
      note.className = 'demo-note';
      note.innerHTML = '<b>Demo.</b> These are the lab’s settings as the application shows them. Nothing can be saved, tested or deleted here, and password fields are switched off: this page has no server and never asks for real credentials.';
      const head = settings.querySelector('.page-head');
      (head ? head.parentNode : settings).insertBefore(note, head ? head.nextSibling : settings.firstChild);
    }
  }

  /* ---------------------------------------------------------- guide dock */
  const TRIES = {
    exact: {src: '192.168.10.5', dst: '192.168.20.10', proto: 'tcp', port: '443'},
    unknown: {src: '192.168.20.5', dst: '192.168.10.10', proto: 'tcp', port: '3389'},
    e5: {src: '192.168.10.5', dst: '1.1.1.1', proto: 'tcp', port: '8082'},
  };
  async function ready() {
    if (typeof ensurePackages === 'function') await ensurePackages();
    if (!P.value) { P.value = 'External-FW'; if (typeof renderContextChips === 'function') renderContextChips(); }
  }
  async function tryTrace(key) {
    await ready();
    goTo('traffic');
    const t = TRIES[key];
    if (!L.value || ![...L.options].some(o => o.value === L.value)) L.value = 'External-FW Network';
    src.value = t.src; dst.value = t.dst; proto.value = t.proto; port.value = t.port;
    minimise();
    trace();
  }
  async function tryAsk() {
    await ready();
    goTo('traffic');
    const input = $('askInput');
    if (input) input.value = 'ทำไม 192.168.20.5 เข้า AD-Server_192.168.10.10 ด้วย RDP ไม่ได้';
    minimise();
    askTraffic();
  }
  function minimise() { setOpen(false); }

  const dock = document.createElement('aside');
  dock.id = 'demoDock';
  dock.className = 'demo-dock';
  dock.setAttribute('aria-label', 'Demo guide');
  dock.innerHTML = `
    <button class="dd-pill" type="button" aria-expanded="false" aria-controls="ddPanel">
      <span class="dd-dot" aria-hidden="true"></span><span>Demo guide</span>
    </button>
    <div class="dd-panel" id="ddPanel" role="dialog" aria-labelledby="ddTitle">
      <div class="dd-head">
        <span class="dd-dot" aria-hidden="true"></span>
        <div><b id="ddTitle">Interactive demo</b><span>Sample lab data &middot; runs in your browser</span></div>
        <button class="dd-close" type="button" aria-label="Minimise the guide">&minus;</button>
      </div>
      <p class="dd-lead">This is the real Firewall Insight interface. The data is the External-FW lab captured on 15&nbsp;Oct&nbsp;2026, with its addresses changed. No firewall is contacted, and nothing you do here is saved.</p>
      <p class="dd-k">Try a trace</p>
      <button class="dd-try" type="button" data-try="exact"><span>VLAN10 &rarr; web server, HTTPS</span><em class="ok">EXACT</em></button>
      <button class="dd-try" type="button" data-try="unknown"><span>VLAN20 &rarr; AD server, RDP</span><em class="warn">UNVERIFIED</em></button>
      <button class="dd-try" type="button" data-try="e5"><span>Rule with a time window</span><em class="warn">UNVERIFIED</em></button>
      <button class="dd-try" type="button" data-ask><span>Ask a question in Thai</span><em>ASK</em></button>
      <p class="dd-k">Or open</p>
      <div class="dd-go">
        <button type="button" data-go="dashboard">Dashboard</button>
        <button type="button" data-go="compliance">Compliance</button>
        <button type="button" data-go="mapping">Network map</button>
        <button type="button" data-go="diff">Policy diff</button>
        <button type="button" data-go="health">Gateway health</button>
        <button type="button" data-go="runs">Reviews &amp; PDF</button>
      </div>
      <a class="dd-back" href="../">&larr; Back to the Firewall Insight site</a>
    </div>`;
  const pill = dock.querySelector('.dd-pill');
  function setOpen(open) {
    dock.classList.toggle('open', open);
    pill.setAttribute('aria-expanded', String(open));
    store.set('fi-demo-dock', open ? 'open' : 'closed');
    const scrim = document.querySelector('.m-scrim');
    if (scrim) scrim.classList.toggle('on', open && isPhone());
    syncTabs();
  }
  pill.addEventListener('click', () => setOpen(true));
  dock.querySelector('.dd-close').addEventListener('click', () => setOpen(false));
  dock.addEventListener('click', e => {
    const b = e.target.closest('button');
    if (!b) return;
    if (b.dataset.try) tryTrace(b.dataset.try);
    else if ('ask' in b.dataset) tryAsk();
    else if (b.dataset.go) { goTo(b.dataset.go); minimise(); }
  });
  document.addEventListener('keydown', e => { if (e.key === 'Escape' && dock.classList.contains('open')) setOpen(false); });

  /* ------------------------------------------------------------ phones */
  const phoneMQ = window.matchMedia('(max-width: 900px)');
  const cardMQ = window.matchMedia('(max-width: 700px)');
  const isPhone = () => phoneMQ.matches;
  const current = () => (document.querySelector('.page.active') || {}).id;

  const TABS = [
    ['dashboard', 'Home', '<path d="M4 17a8 8 0 1 1 16 0"/><path d="M12 17l4.2-5"/>'],
    ['browser', 'Policy', '<rect x="3.2" y="4.6" width="17.6" height="14.8" rx="2"/><path d="M3.2 9.5h17.6M3.2 14.5h17.6"/>'],
    ['traffic', 'Trace', '<circle cx="6" cy="6" r="2.2"/><circle cx="18" cy="18" r="2.2"/><path d="M8.2 6h5.3a3 3 0 0 1 0 6h-3a3 3 0 0 0 0 6h5.3"/>'],
    ['mapping', 'Map', '<rect x="9.4" y="3.6" width="5.2" height="4.4" rx="1"/><rect x="3" y="16" width="5.2" height="4.4" rx="1"/><rect x="15.8" y="16" width="5.2" height="4.4" rx="1"/><path d="M12 8v4.2M5.6 16v-3.8h12.8V16"/>'],
    ['guide', 'Guide', '<circle cx="12" cy="12" r="8.6"/><path d="M9.6 9.4a2.5 2.5 0 1 1 3.4 2.3c-.6.3-1 .8-1 1.5v.6"/><path d="M12 16.6v.2"/>'],
  ];
  const tabbar = document.createElement('nav');
  tabbar.className = 'm-tabbar';
  tabbar.setAttribute('aria-label', 'Main pages');
  tabbar.innerHTML = TABS.map(([id, label, icon]) =>
    `<button type="button" data-tab="${id}"><svg viewBox="0 0 24 24" aria-hidden="true"${id === 'guide' ? ' class="m-dot"' : ''}>${icon}</svg><span>${label}</span></button>`).join('');
  tabbar.addEventListener('click', e => {
    const b = e.target.closest('button[data-tab]');
    if (!b) return;
    if (b.dataset.tab === 'guide') { setOpen(!dock.classList.contains('open')); return; }
    setOpen(false);
    if (typeof toggleNav === 'function') try { toggleNav(false); } catch (_) { /* menu closed already */ }
    goTo(b.dataset.tab);
  });
  function syncTabs() {
    const open = dock.classList.contains('open');
    const page = current();
    tabbar.querySelectorAll('button').forEach(b => {
      const on = b.dataset.tab === 'guide' ? open : (!open && b.dataset.tab === page);
      b.classList.toggle('on', on);
      if (on) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current');
    });
    const dot = tabbar.querySelector('.m-dot');
    if (dot && open) { dot.classList.remove('m-dot'); store.set('fi-demo-seen', '1'); }
  }

  /* page changes start at the top of the page on a phone, where the document scrolls */
  const realShow = window.showPage;
  window.showPage = function (id, btn) {
    lastShow = Date.now();
    const r = realShow.apply(this, arguments);
    if (isPhone()) window.scrollTo(0, 0);
    syncTabs();
    if (id === 'mapping' && isPhone()) setTimeout(() => { try { topoFit(); } catch (_) { /* not drawn yet */ } }, 900);
    return r;
  };

  /* tables -> labelled cards; long notes -> three lines and "Show more" */
  function headerCells(table) {
    const head = table.tHead && table.tHead.rows[0];
    if (head) return {cells: [...head.cells], row: head};
    const first = table.rows[0];
    if (first && first.cells.length && [...first.cells].every(c => c.tagName === 'TH')) return {cells: [...first.cells], row: first};
    return null;
  }
  function cardify(table) {
    if (table.closest('#topology, .topo-preview, .m-keep')) return;
    const h = headerCells(table);
    if (!h || h.cells.length < 3) return;
    const labels = [];
    h.cells.forEach(c => { for (let i = 0; i < (c.colSpan || 1); i++) labels.push(c.textContent.replace(/[▲▼]/g, '').trim()); });
    if (h.row) h.row.classList.add('m-head');
    for (const tr of table.rows) {
      if (tr === h.row) continue;
      let col = 0;
      for (const td of tr.cells) {
        if (td.tagName === 'TH' && tr.cells.length === labels.length && tr !== h.row) { /* row headers */ }
        if ((td.colSpan || 1) >= labels.length) td.classList.add('m-full');
        else {
          const label = labels[col] || '';
          td.setAttribute('data-label', label);
          td.classList.toggle('m-nolabel', !label);
          td.classList.toggle('m-wide', (td.textContent || '').trim().length > 34 || /^(details?|meaning|why|reason|note|match details|comments?|change|finding|what)$/i.test(label));
        }
        col += td.colSpan || 1;
      }
    }
    table.classList.add('m-cards');
    const wrap = table.closest('.table-wrap');
    if (wrap) wrap.classList.add('m-wrap');
  }
  function clampNotes(root) {
    root.querySelectorAll('.page .hint, .page .muted, #mapNote').forEach(el => {
      if (el.dataset.mClamp || el.closest('table, .flow, .ctx-chip, .topo-bar, .demo-dock')) return;
      if ((el.textContent || '').length < 260 || el.children.length > 6) return;
      el.dataset.mClamp = '1';
      el.classList.add('m-clamp');
      const more = document.createElement('button');
      more.type = 'button';
      more.className = 'm-more';
      more.textContent = 'Show more';
      more.addEventListener('click', () => {
        const open = el.classList.toggle('m-clamp');
        more.textContent = open ? 'Show more' : 'Show less';
      });
      el.after(more);
    });
  }
  let pending = false;
  function refresh() {
    pending = false;
    if (!cardMQ.matches) return;
    document.querySelectorAll('.main table').forEach(t => { if (!t.classList.contains('m-cards') || t.dataset.mRows !== String(t.rows.length)) { cardify(t); t.dataset.mRows = String(t.rows.length); } });
    clampNotes(document);
  }
  const observer = new MutationObserver(() => { if (!pending) { pending = true; requestAnimationFrame(refresh); } });

  /* network map: one finger pans, two fingers zoom */
  function bindMapTouch() {
    const host = document.getElementById('topology');
    if (!host || host.dataset.mTouch) return;
    host.dataset.mTouch = '1';
    let last = null;
    const pts = e => [...e.touches].map(t => ({x: t.clientX, y: t.clientY}));
    host.addEventListener('touchstart', e => { if (e.target.closest('svg')) last = pts(e); }, {passive: true});
    host.addEventListener('touchmove', e => {
      if (!last || typeof TOPO === 'undefined' || !TOPO.view) return;
      const now = pts(e);
      e.preventDefault();
      const v = TOPO.view;
      if (now.length === 1 && last.length === 1) {
        v.tx += now[0].x - last[0].x; v.ty += now[0].y - last[0].y;
      } else if (now.length >= 2 && last.length >= 2) {
        const svg = host.querySelector('svg');
        const r = svg.getBoundingClientRect();
        const d = (a, b) => Math.hypot(a.x - b.x, a.y - b.y) || 1;
        const mid = (a, b) => ({x: (a.x + b.x) / 2 - r.left, y: (a.y + b.y) / 2 - r.top});
        const s1 = Math.max(.3, Math.min(3, v.scale * d(now[0], now[1]) / d(last[0], last[1])));
        const m0 = mid(last[0], last[1]), m1 = mid(now[0], now[1]);
        const wx = (m0.x - v.tx) / v.scale, wy = (m0.y - v.ty) / v.scale;
        v.scale = s1; v.tx = m1.x - s1 * wx; v.ty = m1.y - s1 * wy;
      }
      last = now;
      try { topoApplyView(); } catch (_) { /* map not drawn */ }
    }, {passive: false});
    host.addEventListener('touchend', e => { last = e.touches.length ? pts(e) : null; }, {passive: true});
  }

  /* the two arrival toasts would sit on top of the guide sheet on a phone */
  const realNotify = window.notify;
  const quietUntil = Date.now() + 6000;
  let lastShow = 0;
  window.notify = function (kind, title) {
    if (isPhone() && Date.now() < quietUntil && (title === 'Read-only tool' || title === 'Metadata loaded')) return;
    /* opening Compliance, Diff or Reviews starts two list reads at once and the
       app refuses the second with this toast, then reads it anyway */
    if (title === 'Task in progress' && Date.now() - lastShow < 2500) return;
    return realNotify.apply(this, arguments);
  };

  function setupPhone() {
    document.body.appendChild(tabbar);
    const scrim = document.createElement('div');
    scrim.className = 'm-scrim';
    scrim.addEventListener('click', () => setOpen(false));
    document.body.appendChild(scrim);
    const navScrim = document.createElement('div');
    navScrim.className = 'm-navscrim';
    navScrim.addEventListener('click', () => toggleNav(false));
    (document.querySelector('.app') || document.body).appendChild(navScrim);   // same stacking context as the menu
    document.querySelectorAll('.sidebar .menu button').forEach(b => b.addEventListener('click', () => {
      if (isPhone()) toggleNav(false);
    }));
    if (store.get('fi-demo-seen')) { const dot = tabbar.querySelector('.m-dot'); if (dot) dot.classList.remove('m-dot'); }
    observer.observe(document.querySelector('main.main') || document.body, {childList: true, subtree: true});
    cardMQ.addEventListener ? cardMQ.addEventListener('change', refresh) : cardMQ.addListener(refresh);
    refresh();
    bindMapTouch();
    syncTabs();
  }

  /* fill the dashboard once, quietly: the same three reads "Analyze Selected
     Policies" makes, so its tiles and findings are not dashes on arrival */
  const realHydrate = window.hydrateDashboard;
  let warmed = false;
  window.hydrateDashboard = async function () {
    const r = await realHydrate.apply(this, arguments);
    if (!warmed) { warmed = true; warmDashboard(); }
    return r;
  };
  async function warmDashboard() {
    const realNotify = window.notify;
    window.notify = function () {};
    try {
      if (typeof ensurePackages === 'function') await ensurePackages();
      if (!P.value) P.value = 'External-FW';
      if (!L.value) L.value = ROOT[P.value] || '';
      await runAccess();
      await loadPolicyBrowser();
      await runNat();
      setStatus('Demo ready: External-FW lab data, analysed in your browser. Nothing here reaches a firewall.', 'success');
    } catch (e) { console.warn('[demo] dashboard warm-up', e); }
    finally { window.notify = realNotify; }
  }

  window.addEventListener('DOMContentLoaded', () => {
    document.title = 'Firewall Insight — Interactive demo';
    const brand = document.querySelector('.topbar .brand');
    if (brand && !brand.querySelector('.demo-tag')) {
      const tag = document.createElement('span');
      tag.className = 'demo-tag';
      tag.textContent = 'DEMO';
      tag.title = 'Sample lab data. Nothing here reaches a firewall.';
      brand.appendChild(tag);
    }
    const signOutBtn = document.querySelector('.topbar-right button[onclick="signOut()"]');
    if (signOutBtn) { signOutBtn.innerHTML = 'Exit<span class="exit-wide"> demo</span>'; signOutBtn.title = 'Back to the Firewall Insight site'; }
    document.body.appendChild(dock);
    setupPhone();
    setOpen(store.get('fi-demo-dock') !== 'closed');
    lockSecrets();
  });
})();
