/* Firewall Insight — interactive demo back end.
 *
 * Loaded before the application's own app.js. It answers every /api/* request
 * the real interface makes, in the browser, from the static files in ./data
 * (produced by the application's own engine over the External-FW lab data,
 * with addresses changed). Nothing leaves this page: there is no server, no
 * Management API and no gateway behind it.
 *
 * Traffic Path and Ask are computed live, by a port of the tri-state tracer
 * (app/traffic.py, matching.py, envelope.py, implied.py, nat_correlate.py,
 * path_map.py and ask.py), so any source, destination and service can be tried.
 */
(function () {
  'use strict';

  const realFetch = window.fetch.bind(window);
  const BASE = new URL('data/', document.currentScript ? document.currentScript.src : location.href).href;
  const cache = new Map();
  const getData = path => {
    if (!cache.has(path)) {
      cache.set(path, realFetch(BASE + path).then(r => {
        if (!r.ok) throw new Error('HTTP ' + r.status + ' for ' + path);
        return r.json();
      }));
    }
    return cache.get(path);
  };
  /* Families of small results live in one bundle file each (diffs.json,
     compliance.json, pkg/X/usage.json ...); `part` reads one entry. */
  const part = async (file, key) => {
    const b = await getData(file);
    if (!(key in b)) { const e = new Error(`Not available in this demo (${key}).`); e.status = 404; e.detail = e.message; throw e; }
    return b[key];
  };
  const sleep = ms => new Promise(r => setTimeout(r, ms));
  const clone = o => JSON.parse(JSON.stringify(o));
  const pad = n => String(n).padStart(2, '0');
  const isoNow = () => new Date().toISOString().replace(/\.\d+Z$/, '+00:00');
  const stamp = d => d.getUTCFullYear() + pad(d.getUTCMonth() + 1) + pad(d.getUTCDate())
    + pad(d.getUTCHours()) + pad(d.getUTCMinutes()) + pad(d.getUTCSeconds());

  const DEMO_NOTE = 'Demo: this page has no server, so nothing is saved or sent anywhere.';
  const PACKAGES = ['External-FW', 'Internal-FW', 'Standard'];

  /* ---------------------------------------------------------------- state */
  const state = {
    newRuns: [],            // runs started in this visit
    newSnaps: [],           // {id, base, package, taken_at}
    schedules: null,
    alerts: {destinations: [], public_url: ''},
  };

  /* ------------------------------------------------------------ addresses */
  function parseV4(s) {
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
    if (!m) return null;
    const p = m.slice(1).map(Number);
    if (p.some(x => x > 255)) return null;
    if (m.slice(1).some(x => x.length > 1 && x[0] === '0')) return null;
    return {v: 4, n: BigInt(((p[0] * 256 + p[1]) * 256 + p[2]) * 256 + p[3]), text: p.join('.')};
  }
  function parseV6(s) {
    if (s.indexOf(':') < 0 || !/^[0-9a-fA-F:.]+$/.test(s)) return null;
    let tail = [], str = s;
    const m = /^(.*:)(\d+\.\d+\.\d+\.\d+)$/.exec(s);
    if (m) {
      const p = parseV4(m[2]);
      if (!p) return null;
      const n = Number(p.n);
      tail = [Math.floor(n / 65536), n % 65536];
      str = m[1].endsWith('::') ? m[1] : m[1].slice(0, -1);
    }
    const halves = str.split('::');
    if (halves.length > 2) return null;
    const groups = h => (h === '' ? [] : h.split(':').map(x => (/^[0-9a-fA-F]{1,4}$/.test(x) ? parseInt(x, 16) : NaN)));
    const head = groups(halves[0]);
    const back = halves.length === 2 ? groups(halves[1]) : [];
    if (head.concat(back).some(Number.isNaN)) return null;
    let full;
    if (halves.length === 2) {
      const fill = 8 - head.length - back.length - tail.length;
      if (fill < 1) return null;
      full = head.concat(new Array(fill).fill(0), back, tail);
    } else full = head.concat(tail);
    if (full.length !== 8) return null;
    let n = 0n;
    for (const g of full) n = (n << 16n) + BigInt(g);
    return {v: 6, n, text: s.toLowerCase()};
  }
  const parseIP = s => {
    const t = String(s || '').trim();
    return parseV4(t) || parseV6(t);
  };
  const v4text = n => [Number((n >> 24n) & 255n), Number((n >> 16n) & 255n), Number((n >> 8n) & 255n), Number(n & 255n)].join('.');

  /* ----------------------------------------------------------- the model */
  let MODEL = null, NETMAP = null;
  async function model() {
    if (MODEL) return MODEL;
    const m = await getData('model.json');
    for (const o of Object.values(m.objects)) {
      if (o.atoms) o.atoms = o.atoms.map(a => (a[0] === 4 || a[0] === 6) ? [a[0], BigInt(a[1]), BigInt(a[2])] : [a[0], Number(a[1]), Number(a[2])]);
    }
    for (const rows of Object.values(m.nat)) for (const r of rows) {
      for (const k of ['src_atoms', 'dst_atoms']) if (r[k]) r[k] = r[k].map(a => [a[0], BigInt(a[1]), BigInt(a[2])]);
    }
    m.byName = {};
    for (const [uid, o] of Object.entries(m.objects)) { o.uid = uid; m.byName[o.name] = o; }
    m.deviceSet = new Set(m.device_addresses);
    MODEL = m;
    return m;
  }
  async function netmap() {
    if (!NETMAP) NETMAP = await getData('network-map.json');
    return NETMAP;
  }

  /* ------------------------------------------------------ matching.py port */
  const ANY = 'Any';
  function isAny(o) { return !!(o && o.any); }

  function addressMatchState(M, uids, text) {
    const raw = String(text || '').trim();
    const ip = parseIP(raw);
    const isDomain = !ip;
    let sawUnknown = false;
    const unknownNames = [];
    for (const uid of uids) {
      const o = M.objects[uid] || {name: uid, atoms: [], complete: false, type: 'unknown'};
      if (isAny(o)) return ['match', ANY];
      let complete = o.complete !== false;
      if (ip && (o.atoms || []).some(a => a[0] === ip.v && a[1] <= ip.n && ip.n <= a[2])) return ['match', o.describe];
      if (ip && complete && (o.member_addresses || []).includes(ip.text)) complete = false;
      if (!complete) {
        sawUnknown = true;
        const label = `${o.name} [${o.type || 'unknown'}]`;
        if (!unknownNames.includes(label)) unknownNames.push(label);
      }
    }
    if (sawUnknown) return ['unknown', 'Static match unavailable for ' + unknownNames.slice(0, 4).join(', ')];
    if (isDomain) return ['unknown', `${raw} did not resolve, so membership in these objects cannot be decided (this demo runs in your browser and resolves no hostnames)`];
    return ['no-match', 'No matching object'];
  }

  function serviceMatchState(M, uids, query) {
    const q = query.atoms || [];
    let sawUnknown = false;
    const unknownNames = [];
    for (const uid of uids) {
      const o = M.objects[uid] || {name: uid, atoms: [], complete: false};
      if (isAny(o)) return ['match', ANY];
      for (const [qp, qs, qe] of q) {
        for (const a of o.atoms || []) {
          const protoOk = a[0] === 'any' || qp === 'any' || a[0] === qp;
          if (protoOk && !(qe < a[1] || qs > a[2])) {
            if (!(o.quals || []).length) return ['match', o.describe];
            sawUnknown = true;
            const entry = `${o.name} (also requires ${o.quals.join(', ')})`;
            if (!unknownNames.includes(entry)) unknownNames.push(entry);
          }
        }
      }
      if (o.complete === false) {
        sawUnknown = true;
        for (const b of (o.unmodelled || [`${o.name} [${o.type || 'unknown'}]`])) {
          const entry = b === `${o.name} [${o.type || 'unknown'}]` ? b : `${o.name} → ${b}`;
          if (!unknownNames.includes(entry)) unknownNames.push(entry);
        }
      }
    }
    if (sawUnknown) return ['unknown', 'Static service match unavailable for ' + unknownNames.slice(0, 4).join(', ')];
    return ['no-match', 'No matching service'];
  }

  function vpnMatchState(M, uids) {
    if (!uids || !uids.length) return ['match', ANY];
    const scoped = uids.filter(u => !isAny(M.objects[u]));
    if (!scoped.length) return ['match', ANY];
    const names = scoped.slice(0, 4).map(u => (M.objects[u] || {name: u}).name).join(', ');
    return ['unknown', `Rule applies only to VPN community ${names}; whether this flow arrives through it is live connection state, not configuration`];
  }

  /* envelope.py: Time / Content / Install On */
  function envelopeState(M, rule, target) {
    const cols = [];
    if (rule.time) cols.push('Time');
    const inst = (rule.install_on || []).map(u => M.objects[u] || {name: u});
    const notPT = inst.filter(o => o.name !== 'Policy Targets');
    if (notPT.length) cols.push('Install On');
    if (!cols.length) return ['match', 'Time, Content and Install On are defaults'];
    const notes = [];
    if (cols.includes('Install On')) {
      let st, why;
      if (!target) {
        st = 'unknown'; why = 'Install On names specific targets and the traced gateway is not known';
      } else {
        const hit = notPT.find(o => o.name === target);
        if (hit) { st = 'match'; why = `Installed on ${hit.name}, the traced gateway`; }
        else if (notPT.every(o => o.gateway)) { st = 'no-match'; why = 'Not installed on the traced gateway'; }
        else { st = 'unknown'; why = 'Install On contains an object that is not a single gateway'; }
      }
      if (st === 'no-match') return ['no-match', why];
      if (st === 'match') {
        cols.splice(cols.indexOf('Install On'), 1);
        notes.push(why);
        if (!cols.length) return ['match', notes.join('; ')];
      }
    }
    return ['unknown', cols.join(', ') + ' not modelled: the rule may not apply to this connection, so it cannot be a proven match'];
  }

  /* resolve_service_query */
  const STD = {
    tcp: {http: 80, https: 443, ssh: 22, telnet: 23, ftp: 21, smtp: 25, domain: 53, pop3: 110, imap: 143, imaps: 993,
          pop3s: 995, ldap: 389, ldaps: 636, kerberos: 88, 'microsoft-ds': 445, 'ms-sql-s': 1433, mysql: 3306,
          postgresql: 5432, 'ms-wbt-server': 3389, rdp: 3389, ntp: 123, submission: 587, bgp: 179, 'http-alt': 8080,
          webcache: 8080, rsync: 873, nntp: 119, sunrpc: 111, finger: 79, whois: 43},
    udp: {domain: 53, ntp: 123, snmp: 161, 'snmp-trap': 162, syslog: 514, tftp: 69, bootps: 67, bootpc: 68,
          kerberos: 88, ldap: 389, 'netbios-ns': 137, 'netbios-dgm': 138, isakmp: 500, radius: 1812, sunrpc: 111},
  };
  function resolveServiceQuery(M, input, proto) {
    const raw = String(input || '').trim();
    const p = String(proto || 'tcp').toLowerCase();
    if (/^\d+$/.test(raw)) {
      const port = Number(raw);
      if (p === 'icmp' || p === 'icmp6') {
        if (port > 255) throw httpError(400, 'ICMP type must be between 0 and 255');
        return {input: raw, protocol: p, port, atoms: [[p, port, port]], resolved_by: 'numeric-icmp-type', display: `${p.toUpperCase()} type ${port}`};
      }
      if (port > 65535) throw httpError(400, 'Port must be between 0 and 65535');
      return {input: raw, protocol: p, port, atoms: [[p, port, port]], resolved_by: 'numeric-port', display: `${p.toUpperCase()}/${port}`};
    }
    const obj = Object.values(M.objects).find(o => o.kind === 'svc' && o.name === raw)
      || Object.values(M.objects).find(o => o.kind === 'svc' && o.name.toLowerCase() === raw.toLowerCase());
    if (obj) {
      const atoms = obj.atoms.map(a => [a[0], a[1], a[2]]);
      const sel = atoms.find(a => a[0] === p || a[0] === 'any') || atoms[0];
      const warnings = [];
      if (!atoms.some(a => a[0] === p || a[0] === 'any')) {
        const shown = [...new Set(atoms.map(a => a[0].toUpperCase()))].join('/');
        warnings.push(`You selected ${p.toUpperCase()}, but the policy object '${obj.name}' is ${shown} - ${obj.describe}. The trace evaluates the object, so this answers a different flow from ${p.toUpperCase()} traffic to the same destination.`);
      }
      return {input: raw, protocol: sel[0] !== 'any' ? sel[0] : p, port: sel[1], atoms, resolved_by: 'checkpoint-service-object',
              object_uid: obj.uid, display: obj.describe, warnings};
    }
    const port = (STD[p] || {})[raw.toLowerCase()];
    if (port != null) return {input: raw, protocol: p, port, atoms: [[p, port, port]], resolved_by: 'standard-service-name', display: `${raw} (${p.toUpperCase()}/${port})`};
    throw httpError(400, `Unknown service '${raw}'. Enter a port number, a standard service name (for example https/ssh/smtp), or an exact Check Point service object name.`);
  }

  /* ------------------------------------------------------- traffic.py port */
  function layerCandidates(M, layer, src, dst, query, target) {
    const out = [];
    for (const r of layer.rules) {
      if (r.enabled === false) continue;
      const [ss, so] = addressMatchState(M, r.source, src);
      if (ss === 'no-match') continue;
      const [ds, dout] = addressMatchState(M, r.destination, dst);
      if (ds === 'no-match') continue;
      const [vs, vo] = serviceMatchState(M, r.service, query);
      if (vs === 'no-match') continue;
      const [ns, no] = vpnMatchState(M, r.vpn);
      const [es, eo] = envelopeState(M, r, target);
      if (es === 'no-match') continue;
      const overall = [ss, ds, vs, ns, es].every(x => x === 'match') ? 'match' : 'unknown';
      out.push({rule: r.rule, name: r.name || '', action: r.action, inline_layer: r.inline_layer || null, state: overall,
                source_state: ss, destination_state: ds, service_state: vs, vpn_state: ns,
                source_match: so, destination_match: dout, service_match: vo, vpn_match: no,
                envelope_state: es, envelope_match: eo, track: r.track, comments: r.comments || ''});
    }
    return out;
  }

  function traceTree(M, tree, src, dst, query, selectedRoot) {
    const nodes = tree.layers;
    const byName = Object.fromEntries(nodes.map(n => [n.name, n]));
    const childBy = {};
    for (const n of nodes) if (n.parent_layer && n.parent_rule != null) childBy[n.parent_layer + '::' + n.parent_rule] = n;
    const root = byName[selectedRoot] || byName[tree.root_layers[0]] || nodes[0];

    function recurse(cur, path, depth) {
      if (depth > 12) return {matched: false, winner: null, path, result: 'Trace depth exceeded', confidence: 'none',
                              reason: 'Inline Layer nesting exceeded supported trace depth.'};
      let firstUncertain = null;
      for (const cand of layerCandidates(M, cur, src, dst, query, tree.target)) {
        const prefix = String(cur.display_prefix || '');
        const display = prefix ? `${prefix}.${cand.rule}` : String(cand.rule);
        const step = {...cand, layer: cur.name, layer_path: cur.path, depth: cur.depth, display_rule: display, parent_rule: cur.parent_rule};
        let child = childBy[cur.name + '::' + cand.rule];
        if (!child && cand.inline_layer) child = byName[cand.inline_layer];
        if (child) {
          step.transition = 'inline-layer';
          step.inline_layer = child.name;
          const cr = recurse(child, path.concat([step]), depth + 1);
          const parentUnknown = cand.state === 'unknown';
          if (firstUncertain) {
            return {matched: false, winner: null, possible_winner: firstUncertain, later_exact_rule: step,
                    path: path.concat([firstUncertain]), result: 'UNVERIFIED', confidence: 'unknown',
                    reason: `Earlier Rule ${firstUncertain.display_rule} contains condition(s) this static simulator cannot evaluate, so the path through Inline Layer ${child.name} cannot be declared final.`};
          }
          if (cr.matched) {
            const childUnknown = cr.confidence !== 'exact';
            cr.confidence = (parentUnknown || childUnknown) ? 'inferred' : 'exact';
            if (parentUnknown) cr.reason = `Inline child matched, but Parent Rule ${display} contains condition(s) that require gateway context. Result is inferred from configured policy path.`;
            return cr;
          }
          const settled = ['none', 'exact'].includes(cr.confidence);
          if (parentUnknown || !settled) {
            if (!parentUnknown) { cr.path = cr.path || path.concat([step]); return cr; }
            if (!firstUncertain) firstUncertain = step;
            continue;
          }
          if (cr.result === 'No final matching rule') return cr;
          return {matched: false, winner: null, path: path.concat([step]), result: 'No final matching rule', confidence: 'exact',
                  reason: `Parent Rule ${display} matched exactly and entered Inline Layer ${child.name}, but no child rule matched; that layer's implicit cleanup action decides.`};
        }
        if (cand.state === 'match') {
          if (firstUncertain) {
            return {matched: false, winner: null, possible_winner: firstUncertain, later_exact_rule: step,
                    path: path.concat([firstUncertain]), result: 'UNVERIFIED', confidence: 'unknown',
                    reason: `Earlier Rule ${firstUncertain.display_rule} contains condition(s) this static simulator cannot evaluate. Later Rule ${display} matches, but cannot be declared final.`};
          }
          step.transition = 'final';
          return {matched: true, winner: step, path: path.concat([step]), result: step.action || 'Matched', confidence: 'exact',
                  reason: 'Terminal Access rule matched exactly.'};
        }
        if (!firstUncertain) firstUncertain = step;
      }
      if (firstUncertain) {
        return {matched: false, winner: null, possible_winner: firstUncertain, path: path.concat([firstUncertain]),
                result: 'UNVERIFIED', confidence: 'unknown',
                reason: `Earlier Rule ${firstUncertain.display_rule} contains conditions this static simulator cannot evaluate. A later Cleanup rule must not be reported as definitive.`};
      }
      return {matched: false, winner: null, path, result: 'No matching rule', confidence: 'none', reason: `No matching rule in layer ${cur.name}.`};
    }

    const out = recurse(root, [], 0);
    out.gateway_final = ['exact', 'none'].includes(out.confidence);
    // implied.py: endpoint addresses of Check Point devices
    const reasons = [];
    let rules = [];
    for (const [label, text] of [['source', src], ['destination', dst]]) {
      const ip = parseIP(text);
      if (!ip) {
        reasons.push(`The ${label} ${text} has no single address, so it cannot be shown that it is not a Check Point device.`);
        continue;
      }
      if (ip.v === 4 && M.deviceSet.has(v4text(ip.n))) {
        reasons.push(`The ${label} ${text} is an address of a Check Point gateway or server. Implied rules for control, administration and gateway-originated traffic are enforced outside the rulebase the API returns.`);
        rules = rules.concat(M.implied_enabled);
      }
    }
    if (reasons.length) {
      out.implied_rules = {state: 'possible', reasons, rules: [...new Set(rules)].sort()};
      if (out.matched && out.confidence === 'exact') out.confidence = 'inferred';
      else if (!out.matched && ['exact', 'none'].includes(out.confidence)) { out.result = 'UNVERIFIED'; out.confidence = 'unknown'; }
      out.reason = ((out.reason || '') + ' ' + reasons.join(' ')).trim();
      out.gateway_final = false;
    } else {
      out.implied_rules = {state: 'clear', rules: [], reasons: ['No implied rule that is switched on can match this connection.']};
    }
    out.scope_notes = [];
    return out;
  }

  function natState(atoms, text, ip, raw) {
    if (text === 'Any' || text === 'Original') return ['match', 'Any'];
    if (!atoms) return ['unknown', 'Static match unavailable for ' + text];
    if (!ip) return ['unknown', `${raw} did not resolve, so membership in these objects cannot be decided (this demo runs in your browser and resolves no hostnames)`];
    if (atoms.some(a => a[0] === ip.v && a[1] <= ip.n && ip.n <= a[2])) return ['match', text];
    return ['no-match', 'No matching object'];
  }
  function correlateNat(M, pkg, src, dst) {
    const s = parseIP(src), d = parseIP(dst);
    let blocker = null;
    for (const r of M.nat[pkg] || []) {
      if (r.enabled === false) continue;
      const [ss, so] = natState(r.src_atoms, r.original_source, s, src);
      if (ss === 'no-match') continue;
      const [ds, dout] = natState(r.dst_atoms, r.original_destination, d, dst);
      if (ds === 'no-match') continue;
      const e = {rule: r.rule, name: r.name || '', original_source: so, original_destination: dout,
                 translated_source: r.translated_source, translated_destination: r.translated_destination,
                 translated_service: r.translated_service, source_state: ss, destination_state: ds,
                 state: ss === 'match' && ds === 'match' ? 'match' : 'unknown'};
      if (e.state === 'match') {
        if (!blocker) { e.confidence = 'exact'; return [e]; }
        e.confidence = 'unverified';
        e.blocked_by = blocker.rule;
        e.reason = `NAT Rule ${e.rule} matches, but earlier NAT Rule ${blocker.rule} could not be evaluated. NAT is first-match-wins, so this cannot be declared the rule that runs.`;
        return [blocker, e];
      }
      if (!blocker) {
        e.confidence = 'unverified';
        e.reason = `NAT Rule ${e.rule} uses object(s) with no static model, so whether it takes this flow cannot be decided here.`;
        blocker = e;
      }
    }
    return blocker ? [blocker] : [];
  }

  /* ------------------------------------------------------- path_map.py port */
  const RANK = {exact: 3, inferred: 2, unverified: 1, unknown: 1, none: 0};
  const weakest = (...v) => v.reduce((a, b) => ((RANK[b] ?? 0) < (RANK[a] ?? 0) ? b : a));
  function cidrOf(name) {
    const m = /^(.+)\/(\d+)$/.exec(String(name));
    if (!m) return null;
    const ip = parseIP(m[1]);
    if (!ip) return null;
    const bits = ip.v === 4 ? 32 : 128;
    const len = Number(m[2]);
    const size = 1n << BigInt(bits - len);
    const lo = (ip.n / size) * size;
    return {v: ip.v, lo, hi: lo + size - 1n, len, name};
  }
  function traceOverlay(net, src, dst, access) {
    const winner = access.winner || access.possible_winner || {};
    const policyConf = String(access.confidence || 'none');
    const subnets = net.nodes.filter(n => n.role === 'network').map(n => [cidrOf(n.name), n]).filter(x => x[0]);
    const parent = Object.fromEntries(net.nodes.filter(n => n.role === 'interface').map(n => [n.id, n.parent]));
    const owners = {};
    for (const e of net.edges) {
      if (e.label !== 'connected subnet') continue;
      const dev = parent[e.from];
      if (!dev) continue;
      (owners[e.to] = owners[e.to] || []);
      if (!owners[e.to].includes(dev)) owners[e.to].push(dev);
    }
    const device = uid => net.nodes.find(n => n.id === uid) || {id: uid, name: uid};
    const endpoint = text => {
      const ip = parseIP(text);
      if (!ip) return {ip: String(text), node_id: null, state: 'unresolved',
                       detail: `'${text}' is not an IP address, so it cannot be placed on the map. The trace itself may still have resolved it.`};
      let best = null;
      for (const [c, node] of subnets) {
        if (c.v !== ip.v || ip.n < c.lo || ip.n > c.hi) continue;
        if (!best || c.len > best[0].len) best = [c, node];
      }
      if (!best) return {ip: ip.text, node_id: null, state: 'off-map', detail: `${ip.text} is not inside any subnet the map derived from interface addresses.`};
      return {ip: ip.text, node_id: best[1].id, state: 'on-map', detail: `${ip.text} is inside ${best[0].name}`};
    };
    const source = endpoint(src), destination = endpoint(dst);
    const limitations = [];
    const srcOwners = owners[String(source.node_id)] || [];
    const dstOwners = owners[String(destination.node_id)] || [];
    for (const [side, ep] of [['source', source], ['destination', destination]]) {
      if (ep.state !== 'off-map') continue;
      const ext = net.nodes.find(n => n.role === 'network' && n.external);
      if (ext && owners[ext.id]) {
        ep.via_node_id = ext.id;
        ep.detail += ` It is drawn beyond ${ext.name}, which a gateway flagged leads-to-internet.`;
        limitations.push(`The ${side} address is not on the map. It is shown beyond the subnet a gateway flagged leads-to-internet (${ext.name}); the actual route past that interface is not in the object model.`);
      } else {
        limitations.push(`The ${side} address is not on the map and no interface reports leads-to-internet, so no path is drawn to it.`);
      }
    }
    let topo = 'exact';
    const hops = [];
    if (source.state === 'unresolved' || destination.state === 'unresolved') topo = 'unknown';
    else {
      const shared = srcOwners.filter(d => dstOwners.includes(d));
      const start = source.node_id || source.via_node_id;
      const end = destination.node_id || destination.via_node_id;
      if (start) hops.push({node_id: start, kind: 'network', name: device(start).name || start});
      if (shared.length) {
        const dev = device(shared[0]);
        hops.push({node_id: dev.id, kind: 'device', name: dev.name || dev.id, role: dev.role || 'gateway'});
        if (shared.length > 1) {
          topo = weakest(topo, 'inferred');
          limitations.push('More than one enforcement point connects both subnets (' + shared.map(d => device(d).name).join(', ')
            + '); which one carries the flow depends on routing, which show-gateways-and-servers does not expose.');
        }
      } else {
        const all = srcOwners.concat(dstOwners.filter(d => !srcOwners.includes(d)));
        for (const u of all) { const dev = device(u); hops.push({node_id: dev.id, kind: 'device', name: dev.name || dev.id, role: dev.role || 'gateway'}); }
        if (srcOwners.length && dstOwners.length) {
          topo = weakest(topo, 'inferred');
          limitations.push('The two subnets are behind more than one enforcement point (' + all.map(d => device(d).name).join(', ')
            + '). The hop between them is routing, which the map does not know.');
        }
      }
      if (end && end !== start) hops.push({node_id: end, kind: 'network', name: device(end).name || end});
      if (source.state === 'off-map' || destination.state === 'off-map')
        topo = weakest(topo, (source.via_node_id || destination.via_node_id) ? 'inferred' : 'unknown');
      if (!hops.length) topo = 'none';
    }
    const P2D = {exact: 'exact', inferred: 'inferred', unknown: 'unverified', none: 'none', '': 'none'};
    let draw = weakest(P2D[policyConf] || 'none', topo);
    if (draw === 'unknown') draw = 'unverified';
    return {source, destination, hops, verdict: access.result || 'No matching rule',
            rule: winner.display_rule || winner.rule, rule_name: winner.name || '', layer: winner.layer || '',
            reached: !!access.matched, policy_confidence: policyConf, topology_confidence: topo, draw,
            limitations: limitations.concat(['The path is drawn from configured interface addresses and the policy verdict. It is not a route: no routing table, VPN tunnel or PBR rule is visible to this application.'])};
  }

  const TRACE_LIMITATIONS = [
    'This is a configuration-based Access Control simulation.',
    'A hostname endpoint is resolved by the machine running this application, not by the gateway. A name that does not resolve here is reported as unknown rather than as a non-match, because whether it falls inside an object cannot be decided without an address - and split-horizon DNS can make the gateway\'s answer differ from this one.',
    'The trace now follows configured Inline Layers and Access Sections.',
    'Identity Awareness, dynamic objects, time objects, live gateway state, routing and kernel behavior can still make a live log differ.',
    'Implied rules are not in the rulebase the API returns. Global Properties and the gateway list are read to decide whether one could apply; when one could, or when they cannot be read, the result is not reported as definite.',
    'A service that also restricts source port, protocol signature or ICMP code is reported as unknown when its port matches, because the rule is narrower than its port.',
    'A rule scoped to a VPN community is reported as unknown, not as a match: whether a flow arrives through that community is live connection state, not configuration.',
    'NAT correlation is configuration-based and does not emulate the live routing/kernel path.',
    'NAT correlation is tri-state: a NAT rule built on an object with no static model is reported as unverified, never as a non-match.',
    'NAT correlation matches original-source and original-destination only; original-service is not evaluated, so a service-specific NAT rule can be reported when it would not fire.',
    'The network map overlay places the endpoints by subnet containment and reports policy certainty and topology certainty separately; it is not a route.',
  ];

  async function runTrace({layer, src, dst, protocol, serviceInput, pkg}) {
    const M = await model();
    const net = await netmap();
    const p = PACKAGES.includes(pkg) ? pkg : packageForLayer(layer);
    const tree = M.trees[p];
    if (!tree) throw httpError(400, `Layer ${layer} has no rules in this demo.`);
    const query = resolveServiceQuery(M, serviceInput, protocol);
    const access = traceTree(M, tree, src, dst, query, layer);
    const nat = pkg ? correlateNat(M, p, src, dst) : [];
    const analysis = await getData(`pkg/${p}/analysis.json`);
    return {
      query: {source: src, destination: dst, protocol: query.protocol, port: query.port, service_input: serviceInput,
              service_display: query.display, service_resolved_by: query.resolved_by, service_warnings: query.warnings || [],
              layer, package: pkg || null},
      access, map_path: traceOverlay(net, src, dst, access), map_path_error: null, nat, nat_error: null,
      data_quality: analysis.data_quality, limitations: TRACE_LIMITATIONS,
    };
  }
  function packageForLayer(layer) {
    if (layer === 'Internal-FW Network') return 'Internal-FW';
    if (layer === 'Network' || layer === 'InternetLayer') return 'Standard';
    return 'External-FW';
  }

  /* ------------------------------------------------------------ ask.py port */
  const THAI = /[฀-๿]/;
  const IPV4 = /(?<![\w.])((?:\d{1,3}\.){3}\d{1,3})(?:\/(\d{1,2}))?(?::(\d{1,5}))?(?![\w.])/g;
  const FQDN = /(?<![\w.@-])((?=[A-Za-z0-9-]*[A-Za-z])[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})(?![\w.-])/g;
  const PROTO_PORT = /\b(tcp|udp)\s*[/:]?\s*(\d{1,5})\b/i;
  const PORT_WORD = /(?:\bport|พอร์ต)\s*(\d{1,5})/i;
  const SERVICE_WORDS = {
    https: ['tcp', 443], http: ['tcp', 80], ssh: ['tcp', 22], rdp: ['tcp', 3389], 'remote desktop': ['tcp', 3389],
    telnet: ['tcp', 23], ftp: ['tcp', 21], smtp: ['tcp', 25], dns: ['udp', 53], ntp: ['udp', 123], ldaps: ['tcp', 636],
    ldap: ['tcp', 389], smb: ['tcp', 445], mssql: ['tcp', 1433], mysql: ['tcp', 3306], postgres: ['tcp', 5432],
    snmp: ['udp', 161], syslog: ['udp', 514], ping: ['icmp', 8], icmp: ['icmp', 8],
  };
  const FROM_MARKERS = ['from', 'จาก'];
  const TO_MARKERS = ['to', 'reach', 'access', 'ไปหา', 'ไปยัง', 'ไป', 'ถึง', 'เข้าถึง', 'เข้า', '->', '→'];
  const ENDPOINT_TYPES = new Set(['host', 'network', 'address-range', 'group', 'simple-gateway', 'simple-cluster',
                                  'cluster-member', 'checkpoint-host', 'CpmiGatewayCluster']);
  const ADDRESSED = new Set(['host', 'simple-gateway', 'simple-cluster', 'cluster-member', 'checkpoint-host']);
  const reEsc = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

  function lastMarker(win, marker) {
    if (/^[a-z]+$/.test(marker)) {
      let i = -1;
      const re = new RegExp('\\b' + marker + '\\b', 'g');
      let m;
      while ((m = re.exec(win))) i = m.index;
      return i;
    }
    return win.lastIndexOf(marker);
  }
  function role(text, start, prevEnd) {
    const win = text.slice(prevEnd, start).toLowerCase();
    let best = -1, r = null;
    for (const mk of TO_MARKERS) { const i = lastMarker(win, mk); if (i > best) { best = i; r = 'destination'; } }
    for (const mk of FROM_MARKERS) { const i = lastMarker(win, mk); if (i > best) { best = i; r = 'source'; } }
    return r;
  }
  const overlaps = (taken, a, b) => taken.some(([x, y]) => x < b && a < y);
  function findNames(text, objs, taken) {
    const found = [];
    for (const o of objs) {
      const re = new RegExp('(?<![\\w-])' + reEsc(o.name) + '(?![\\w-])', 'gi');
      let m;
      while ((m = re.exec(text))) {
        const span = [m.index, m.index + m[0].length];
        if (overlaps(taken, ...span)) continue;
        taken.push(span);
        found.push([span, o]);
      }
    }
    return found;
  }
  function firstHost(cidr) {
    const c = cidrOf(cidr);
    if (!c) return null;
    const n = c.hi - c.lo >= 2n ? c.lo + 1n : c.lo;
    return c.v === 4 ? v4text(n) : null;
  }
  function addressFor(ep) {
    if (ep.kind === 'ip' || ep.kind === 'fqdn') return [ep.value, {}];
    if (ep.kind === 'cidr') {
      const c = cidrOf(ep.network);
      const netText = c ? `${c.v === 4 ? v4text(c.lo) : ep.network.split('/')[0]}/${c.len}` : ep.network;
      return [null, {why: `${netText} is a network, and a trace needs one address`, suggestion: firstHost(ep.network)}];
    }
    const o = ep.object;
    if (ADDRESSED.has(o.type) && o.ipv4) return [o.ipv4, {}];
    if (o.type === 'network' && o.cidr) return [null, {why: `${o.name} is the network ${o.cidr}; a trace needs one address in it`, suggestion: firstHost(o.cidr)}];
    if (o.type === 'group') return [null, {why: `${o.name} is a group; a trace needs one address from it`}];
    return [null, {why: `${o.name} has no single address this read can use`}];
  }
  function askParse(M, question) {
    const text = String(question || '').trim();
    const lang = THAI.test(text) ? 'th' : 'en';
    const byLen = (a, b) => b.name.length - a.name.length;
    const objs = Object.values(M.objects).filter(o => o.name.length >= 3);
    const endpoints = objs.filter(o => ENDPOINT_TYPES.has(o.type)).sort(byLen);
    const services = objs.filter(o => o.kind === 'svc' && o.type !== 'service-group').sort(byLen);
    const groups = objs.filter(o => o.type === 'service-group').sort(byLen);
    const taken = [];
    const mentions = [];
    for (const [span, o] of findNames(text, endpoints, taken)) mentions.push([span, {text: o.name, kind: 'object', object: o}]);
    const svcNamed = findNames(text, services, taken);
    const groupNamed = findNames(text, groups, taken);
    let portFromIp = null;
    for (const m of text.matchAll(IPV4)) {
      const span = [m.index, m.index + m[0].length];
      if (overlaps(taken, ...span)) continue;
      taken.push(span);
      if (!parseV4(m[1])) continue;
      if (m[3]) portFromIp = Number(m[3]);
      if (m[2]) mentions.push([span, {text: m[0], kind: 'cidr', network: `${m[1]}/${m[2]}`}]);
      else mentions.push([span, {text: m[1], kind: 'ip', value: m[1]}]);
    }
    for (const m of text.matchAll(FQDN)) {
      const span = [m.index, m.index + m[0].length];
      if (overlaps(taken, ...span)) continue;
      if (SERVICE_WORDS[m[1].toLowerCase()]) continue;
      taken.push(span);
      mentions.push([span, {text: m[1], kind: 'fqdn', value: m[1]}]);
    }
    mentions.sort((a, b) => a[0][0] - b[0][0]);
    const roles = {};
    const unplaced = [];
    let prev = 0;
    for (const [span, ep] of mentions) {
      const r = role(text, span[0], prev);
      prev = span[1];
      if (r && !roles[r]) roles[r] = ep; else unplaced.push(ep);
    }
    for (const ep of unplaced) for (const r of ['source', 'destination']) if (!roles[r]) { roles[r] = ep; break; }

    let service = null;
    let m;
    if ((m = PROTO_PORT.exec(text))) service = {input: m[2], protocol: m[1].toLowerCase(), from: m[0]};
    else if ((m = PORT_WORD.exec(text))) service = {input: m[1], protocol: 'tcp', from: m[0]};
    else if (svcNamed.length) {
      const o = svcNamed[0][1];
      service = {input: o.name, protocol: o.type === 'service-udp' ? 'udp' : 'tcp', from: o.name};
    } else {
      const low = text.toLowerCase();
      for (const w of Object.keys(SERVICE_WORDS).sort((a, b) => b.length - a.length)) {
        if (new RegExp('(?<![\\w-])' + reEsc(w) + '(?![\\w-])').test(low)) {
          const [proto, port] = SERVICE_WORDS[w];
          service = {input: String(port), protocol: proto, from: w};
          break;
        }
      }
    }
    if (!service && portFromIp) service = {input: String(portFromIp), protocol: 'tcp', from: ':' + portFromIp};

    const missing = [], clarify = [], resolved = {};
    for (const r of ['source', 'destination']) {
      const ep = roles[r];
      if (!ep) { missing.push(r); continue; }
      const [value, note] = addressFor(ep);
      if (value == null) clarify.push({role: r, text: ep.text, why: note.why, suggestion: note.suggestion || null});
      resolved[r] = {text: ep.text, kind: ep.kind, value};
    }
    if (!service && groupNamed.length) {
      const g = groupNamed[0][1].name;
      clarify.push({role: 'service', text: g, suggestion: null, why: `${g} is a service group; a trace needs one port or service from it`});
    } else if (!service) missing.push('service');
    return {lang, source: resolved.source || null, destination: resolved.destination || null, service,
            missing, clarify, ready: !missing.length && !clarify.length};
  }
  const askRule = (step, th) => {
    if (!step) return '?';
    const name = step.name ? ` (${step.name})` : '';
    return `rule ${step.display_rule}${name} ${th ? 'ใน' : 'in'} ${step.layer}`;
  };
  const unknownReasons = step => ['source', 'destination', 'service', 'vpn']
    .filter(d => (step || {})[d + '_state'] === 'unknown').map(d => `${d}: ${step[d + '_match']}`);
  function askExplain(result, parsed) {
    const th = parsed.lang === 'th';
    const access = result.access || {};
    const q = result.query || {};
    const flow = `${q.source} → ${q.destination} ${q.service_display || ''}`.trim();
    const conf = access.confidence;
    let verdict = 'unknown';
    const lines = [];
    if (access.matched) {
      const step = access.winner || {};
      const action = String(step.action || access.result || '');
      const allowed = ['accept', 'allow'].includes(action.toLowerCase());
      verdict = allowed ? 'allowed' : 'blocked';
      const firm = conf === 'exact';
      if (th) lines.push(`${(allowed ? 'ได้' : 'ไม่ได้') + (firm ? '' : ' (น่าจะ — ความมั่นใจไม่เต็ม)')}: ${flow} ตรงกับ ${askRule(step, true)} ซึ่ง ${action}`);
      else lines.push(`${(allowed ? 'Allowed' : 'Blocked') + (firm ? '' : ' (probably - not certain)')}: ${flow} matches ${askRule(step)}, which says ${action}.`);
      if (!firm) lines.push((th ? 'เหตุผลที่ไม่แน่ชัด: ' : 'Why it is not certain: ') + String(access.reason));
    } else if (access.result === 'UNVERIFIED') {
      const possible = access.possible_winner, later = access.later_exact_rule;
      if (th) {
        lines.push(`ตอบแน่ชัดไม่ได้: ${askRule(possible, true)} อาจเป็น rule ที่ตัดสิน แต่มีเงื่อนไขที่ประเมินจาก configuration ไม่ได้`);
        if (later) lines.push(`ถ้า rule นั้นไม่ตรง ทราฟฟิกจะไปจบที่ ${askRule(later, true)} (${later.action}) — แต่จะบอกว่านั่นคือคำตอบสุดท้ายไม่ได้`);
      } else {
        lines.push(`Cannot say for certain: ${askRule(possible)} may decide this flow, but it has conditions a configuration read cannot evaluate.`);
        if (later) lines.push(`If it does not match, the flow ends at ${askRule(later)} (${later.action}) - but that cannot be declared final.`);
      }
      for (const r of unknownReasons(possible)) lines.push('  • ' + r);
      if (!possible && access.reason) lines.push((th ? 'เหตุผล: ' : 'Why: ') + access.reason);
    } else {
      verdict = 'no-rule';
      lines.push(th ? `ไม่มี rule ที่ตัดสินทราฟฟิกนี้: ${access.reason}` : `No rule decides this flow: ${access.reason}`);
    }
    const nat = (result.nat || []).filter(n => ['match', 'unknown'].includes(n.state));
    if (nat.length) lines.push((th ? `NAT ที่เกี่ยวข้อง ${nat.length} rule` : `${nat.length} NAT rule(s) may apply`) + ' — ' + nat.slice(0, 6).map(n => String(n.rule ?? '?')).join(', '));
    lines.push(th ? 'นี่คือการจำลองจาก configuration ไม่ใช่ log จริงของ gateway' : 'This is a simulation from configuration, not a gateway log.');
    return {verdict, confidence: conf, answer: lines};
  }
  function askClarify(parsed) {
    const th = parsed.lang === 'th';
    const words = {source: ['ต้นทาง', 'a source'], destination: ['ปลายทาง', 'a destination'], service: ['พอร์ตหรือ service', 'a port or service']};
    const lines = [];
    if (parsed.missing.length) lines.push((th ? 'ยังขาด: ' : 'I could not find ') + parsed.missing.map(x => words[x][th ? 0 : 1]).join(', ') + (th ? '' : ' in the question.'));
    for (const c of parsed.clarify) lines.push(`${c.why}.${c.suggestion ? (th ? ` ลองใช้ ${c.suggestion}` : ` Try ${c.suggestion}.`) : ''}`);
    lines.push(th ? "ตัวอย่าง: 'จาก 192.168.10.5 ไป 192.168.20.20 พอร์ต 443'" : "Example: 'from 192.168.10.5 to 192.168.20.20 port 443'");
    return lines;
  }

  /* ------------------------------------------------------- run & snapshot */
  async function snapshotList() {
    const d = clone(await getData('snapshots.json'));
    const extra = state.newSnaps.map(s => ({...s.row}));
    d.snapshots = extra.concat(d.snapshots).sort((a, b) => String(b.taken_at).localeCompare(String(a.taken_at)));
    d.count = d.snapshots.length;
    return d;
  }
  const baseSnap = id => (state.newSnaps.find(s => s.id === id) || {}).base || id;
  async function latestSnapRow(pkg, listedOnly) {
    const d = await getData('snapshots.json');
    const row = d.snapshots.filter(s => s.package === pkg).sort((a, b) => String(b.taken_at).localeCompare(String(a.taken_at)))[0];
    return row || (listedOnly ? null : (d.bases || {})[pkg]);
  }
  async function captureSnapshot(pkg) {
    const base = await latestSnapRow(pkg, false);
    if (!base) throw httpError(404, `No data for package ${pkg} in this demo.`);
    const now = new Date();
    const id = `${pkg}-${stamp(now)}`;
    const row = {...base, id, taken_at: isoNow()};
    state.newSnaps.push({id, base: base.id, package: pkg, row});
    return {id, row, base};
  }
  async function runList() {
    const d = clone(await getData('runs.json'));
    d.runs = state.newRuns.map(r => r.row).concat(d.runs);
    return d;
  }
  async function newRun(pkg, profile) {
    const [acc, nat] = await Promise.all([getData(`pkg/${pkg}/analysis.json`), getData(`pkg/${pkg}/nat.json`)]);
    const mine = state.newSnaps.filter(x => x.package === pkg).slice(-1)[0];
    const prev = mine ? {...mine.row, id: mine.base, shown: mine.id} : await latestSnapRow(pkg, true);
    const snap = await captureSnapshot(pkg);
    let changed;
    if (prev) {
      const d = await part('diffs.json', `${prev.id}__${prev.id}`);
      changed = {first_run: false, compared_with: prev.shown || prev.id, compared_with_taken_at: prev.taken_at,
                 identical: d.identical, summary: d.summary, warnings: d.warnings || []};
    } else changed = {first_run: true, note: 'No earlier snapshot of this package, so there is nothing to compare against yet.'};
    let conf = null;
    if (profile) conf = clone(await part('compliance.json', `${profile}__live__${pkg}`).catch(() => null));
    const health = await part('health.json', '_none');
    const sec = (data, req = true) => ({requested: req, ok: !!data && req, error: null, data: req ? data : null});
    const started = new Date();
    const id = `${pkg}-${stamp(started).slice(0, 8)}T${stamp(started).slice(8)}`;
    const run = {schema: 1, app_version: '4.43.1', package: pkg, started_at: isoNow(),
      duration_seconds: +(2.4 + Math.random()).toFixed(2), profile: profile || null, complete: true, incomplete_sections: [],
      sections: {access: sec(clone(acc)), nat: sec(clone(nat)),
                 snapshot: sec({snapshot_id: snap.id, taken_at: snap.row.taken_at, summary: {access_rules: snap.row.access_rules, nat_rules: snap.row.nat_rules}}),
                 changed: sec(changed), compliance: sec(conf, !!profile),
                 gateways: sec({baseline_id: null, findings: health.findings, gateways: health.gateways})},
      notes: ['A review run issues the same read-only show-* calls the pages issue, through the same paced client.',
              'A section that could not be read is reported as not read. It is never reported as having found nothing.', DEMO_NOTE],
      triggered_by: {kind: 'manual'}, id};
    const REAL = new Set(['added', 'removed', 'modified', 'moved', 'scope_changed', 'nat_added', 'nat_removed', 'nat_modified']);
    const counters = changed.summary || {};
    const row = {id, package: pkg, started_at: run.started_at, duration_seconds: run.duration_seconds, app_version: '4.43.1',
                 profile: run.profile, complete: true, incomplete_sections: [], snapshot_id: snap.id,
                 policy_changed: changed.first_run ? null : Object.entries(counters).some(([k, v]) => REAL.has(k) && v),
                 undecided_rules: counters.scope_unverifiable || 0};
    state.newRuns.unshift({id, run, row});
    return run;
  }

  /* -------------------------------------------------------------- routes */
  function httpError(status, detail) { const e = new Error(detail); e.status = status; e.detail = detail; return e; }
  const ok = body => ({status: 200, body});

  const routes = [
    ['GET', /^\/api\/auth\/status$/, () => ok({required: true, authenticated: true, user: 'demo', setup_mode: false,
      note: 'Interactive demo: you are signed in as "demo". No credentials exist on this page.'})],
    ['POST', /^\/api\/auth\/login$/, () => ok({user: 'demo', expires_in_hours: 720})],
    ['POST', /^\/api\/auth\/logout$/, () => ok({status: 'signed out'})],
    ['GET', /^\/api\/credentials\/status$/, () => ok({
      checkpoint: {configured: true, mgmt: '10.40.31.180', user: 'fi-readonly', domain: '', verify_ssl: false, timeout: 90,
                   min_request_interval: 0.55, rate_limit_retries: 4, rate_limit_base_delay: 2, cache_ttl: 300, connected: true},
      gaia: {configured: true, enabled: true, user: 'fi-gaia-ro', hosts: '10.40.31.176, 10.40.31.177, 10.40.31.178', verify_ssl: false, timeout: 30}})],
    [null, /^\/api\/credentials(\/test)?$/, () => { throw httpError(403, DEMO_NOTE + ' Settings are shown as they look in the lab, but they cannot be changed or tested here.'); }],
    ['GET', /^\/api\/checkpoint\/test$/, () => ok({connected: true, api_server_version: '2.0.1', read_only: true})],
    ['GET', /^\/api\/health$/, async (q) => ok(clone(await part('health.json', q.get('baseline') || '_none')))],
    ['GET', /^\/api\/bootstrap$/, async () => ok(await getData('bootstrap.json'))],
    ['GET', /^\/api\/progress$/, () => ok({phase: 0, total: 0, label: '', done: false})],

    ['GET', /^\/api\/runs$/, async () => ok(await runList())],
    ['POST', /^\/api\/runs$/, async (q) => {
      const pkg = q.get('package');
      if (!PACKAGES.includes(pkg)) throw httpError(404, `Package ${pkg} is not in this demo.`);
      await sleep(1600);
      return ok(await newRun(pkg, q.get('profile')));
    }],
    ['GET', /^\/api\/runs\/([^/]+)$/, async (q, m) => {
      const id = decodeURIComponent(m[1]);
      const mine = state.newRuns.find(r => r.id === id);
      if (mine) return ok(clone(mine.run));
      return ok(await getData(`review/${id}.json`).catch(() => { throw httpError(404, `No run ${id}`); }));
    }],
    ['GET', /^\/api\/schedules$/, async () => {
      if (!state.schedules) state.schedules = clone(await getData('schedule-list.json'));
      const d = clone(state.schedules);
      for (const s of d.schedules) s.next_due = s.enabled ? nextDue(s) : null;
      d.any_enabled = d.schedules.some(s => s.enabled);
      return ok(d);
    }],
    ['PUT', /^\/api\/schedules$/, async (q, m, body) => {
      if (!state.schedules) state.schedules = clone(await getData('schedule-list.json'));
      if (!body || !body.package || !/^\d{1,2}:\d{2}$/.test(String(body.at || ''))) throw httpError(400, "A schedule needs a package and a time as HH:MM, for example 09:00.");
      const id = body.id || `${body.package}-${String(body.at).replace(':', '')}`.toLowerCase();
      const list = state.schedules.schedules;
      const i = list.findIndex(s => s.id === id);
      const entry = {...(i >= 0 ? list[i] : {last_result: null, last_run_at: null}), ...body, id,
                     days: body.days || ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun']};
      if (i >= 0) list[i] = entry; else list.push(entry);
      return ok({...entry, next_due: entry.enabled ? nextDue(entry) : null});
    }],
    ['DELETE', /^\/api\/schedules\/([^/]+)$/, async (q, m) => {
      if (!state.schedules) state.schedules = clone(await getData('schedule-list.json'));
      const id = decodeURIComponent(m[1]);
      const n = state.schedules.schedules.length;
      state.schedules.schedules = state.schedules.schedules.filter(s => s.id !== id);
      if (state.schedules.schedules.length === n) throw httpError(404, `No schedule with id '${id}'.`);
      return ok({status: 'deleted', id});
    }],

    ['GET', /^\/api\/network-map$/, async (q) => ok(await getData(q.get('routing') === 'true' ? 'network-map-routed.json' : 'network-map.json'))],
    ['GET', /^\/api\/package-policy-browser$/, async (q) => ok(await pkgData(q, 'browser'))],
    ['GET', /^\/api\/package-analyze$/, async (q) => { await sleep(700); return ok(await pkgData(q, 'analysis')); }],
    ['GET', /^\/api\/nat-analyze$/, async (q) => ok(await pkgData(q, 'nat'))],
    ['GET', /^\/api\/traffic-path$/, async (q) => {
      const service = (q.get('service') || q.get('port') || '').trim();
      if (!service) throw httpError(400, 'Enter a Port or Service name.');
      await sleep(650);
      return ok(await runTrace({layer: q.get('layer'), src: q.get('src'), dst: q.get('dst'), protocol: q.get('protocol') || 'tcp',
                                serviceInput: service, pkg: q.get('package')}));
    }],
    ['GET', /^\/api\/ask$/, async (q) => {
      const question = q.get('q') || '';
      if (question.trim().length < 3) throw httpError(422, 'Ask a longer question.');
      const pkg = q.get('package');
      const M = await model();
      const parsed = askParse(M, question);
      const strip = p => ({...p, source: p.source && {...p.source}, destination: p.destination && {...p.destination}});
      if (!parsed.ready) return ok({question, parsed: strip(parsed), ran: false, answer: askClarify(parsed)});
      const tree = M.trees[pkg] || M.trees['External-FW'];
      const result = await runTrace({layer: tree.root_layers[0], src: parsed.source.value, dst: parsed.destination.value,
                                     protocol: parsed.service.protocol, serviceInput: parsed.service.input, pkg});
      return ok({question, parsed: strip(parsed), ran: true, ...askExplain(result, parsed), trace: result});
    }],

    ['GET', /^\/api\/snapshots$/, async () => ok(await snapshotList())],
    ['GET', /^\/api\/snapshot$/, async (q) => {
      const pkg = q.get('package');
      await sleep(900);
      const s = await captureSnapshot(pkg);
      return ok({id: s.id, package: pkg, taken_at: s.row.taken_at, app_version: '4.43.1',
                 summary: {access_rules: s.row.access_rules, nat_rules: s.row.nat_rules}, saved_to: `snapshots/${s.id}.json (in this browser tab only)`,
                 nat_error: null, notes: [DEMO_NOTE + ' The capture reuses the most recent stored reading of this package.']});
    }],
    ['GET', /^\/api\/snapshot-diff$/, async (q) => {
      const a = q.get('a'), b = q.get('b');
      const d = clone(await part('diffs.json', `${baseSnap(a)}__${baseSnap(b)}`));
      const list = (await snapshotList()).snapshots;
      for (const [k, id] of [['a', a], ['b', b]]) {
        const row = list.find(s => s.id === id);
        if (row && id !== baseSnap(id)) d[k] = {...d[k], id, taken_at: row.taken_at};
      }
      return ok(d);
    }],
    ['GET', /^\/api\/compliance-profiles$/, async () => ok(await getData('compliance-profiles.json'))],
    ['GET', /^\/api\/compliance$/, async (q) => {
      const profile = q.get('profile'), snap = q.get('snapshot'), pkg = q.get('package');
      if (!pkg && !snap) throw httpError(400, 'Give either package= to evaluate the live policy, or snapshot= to evaluate one captured earlier.');
      await sleep(500);
      const key = snap ? `${profile}__snap__${baseSnap(snap)}` : `${profile}__live__${pkg}`;
      const d = clone(await part('compliance.json', key));
      if (snap) d.evaluated = {kind: 'snapshot', id: snap};
      return ok(d);
    }],
    ['GET', /^\/api\/health-baselines$/, async () => ok(await getData('health-baselines.json'))],
    ['GET', /^\/api\/remediation-script$/, async (q) => {
      const d = await part(`pkg/${pkgOf(q)}/cleanup.json`, cleanupKey(q));
      if (d.error) throw httpError(d.status || 409, d.error);
      return ok(d);
    }],
    ['GET', /^\/api\/objects\/hygiene$/, async () => { await sleep(400); return ok(await getData('objects-hygiene.json')); }],
    ['GET', /^\/api\/objects\/where-used$/, async (q) => ok(await whereUsed(q.get('uid')))],
    ['GET', /^\/api\/rule-usage$/, async (q) => {
      const cap = [500, 1000, 3000].includes(Number(q.get('cap'))) ? Number(q.get('cap')) : 500;
      await sleep(900);
      return ok(await part(`pkg/${pkgOf(q)}/usage.json`, `${q.get('time_frame') || 'last-7-days'}-${cap}`));
    }],
    ['GET', /^\/api\/trends$/, async (q) => ok(await part('trends.json', q.get('package') || '_all'))],
    ['GET', /^\/api\/alerts$/, () => ok(alertsConfig())],
    ['PUT', /^\/api\/alerts\/destinations$/, (q, m, body) => {
      const d = (body && body.destination) || {};
      const id = String(d.name || d.kind || 'destination').toLowerCase().replace(/[^a-z0-9._-]+/g, '-');
      const entry = {...d, id, url_set: !!(body && body.url), password_set: !!(body && body.password)};
      state.alerts.destinations = state.alerts.destinations.filter(x => x.id !== id).concat([entry]);
      return ok({saved: {id}, config: alertsConfig()});
    }],
    ['POST', /^\/api\/alerts\/test$/, () => ok({run_id: 'External-FW-20261015T154508', results: [{ok: false, skipped: DEMO_NOTE}]})],
    ['DELETE', /^\/api\/alerts\/destinations\/([^/]+)$/, (q, m) => {
      state.alerts.destinations = state.alerts.destinations.filter(x => x.id !== decodeURIComponent(m[1]));
      return ok({status: 'deleted'});
    }],
  ];

  function alertsConfig() {
    return {destinations: clone(state.alerts.destinations), public_url: '',
            triggers: ['attention', 'undecided', 'health', 'clean', 'every-run'], kinds: ['teams', 'slack', 'webhook', 'email'],
            details: ['summary', 'findings', 'full']};
  }
  const pkgOf = q => {
    const p = q.get('package');
    if (!PACKAGES.includes(p)) throw httpError(404, `Package ${p} is not in this demo.`);
    return p;
  };
  const pkgData = async (q, kind) => getData(`pkg/${pkgOf(q)}/${kind}.json`);
  function cleanupKey(q) {
    const b = k => (q.get(k) === 'true' ? 1 : 0);
    const fmt = q.get('format') === 'ansible' ? 'ansible' : 'mgmt_cli';
    return `${fmt}-${b('include_zero_hit')}${b('include_disabled')}${b('include_unused_objects')}`;
  }
  async function whereUsed(uid) {
    const M = await model();
    const o = M.objects[uid];
    const out = {uid, total: 0, access_rules: [], nat_rules: 0, objects: [], threat_prevention_rules: 0};
    if (!o) return out;
    for (const [pkg, tree] of Object.entries(M.trees)) {
      for (const layer of tree.layers) for (const r of layer.rules) {
        const cols = ['source', 'destination', 'service', 'install_on'].filter(c => (r[c] || []).includes(uid));
        if (cols.length) out.access_rules.push({rule: r.name || r.rule, layer: layer.name, package: pkg, columns: cols});
      }
      out.nat_rules += (M.nat[pkg] || []).filter(n => [n.original_source, n.original_destination, n.translated_source, n.translated_destination]
        .some(t => String(t).startsWith(o.name + ' (') || t === o.name)).length;
    }
    out.total = out.access_rules.length + out.nat_rules;
    return out;
  }
  function nextDue(s) {
    const days = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'];
    const [h, mi] = String(s.at).split(':').map(Number);
    const now = new Date();
    for (let i = 0; i < 8; i++) {
      const d = new Date(now.getFullYear(), now.getMonth(), now.getDate() + i, h, mi);
      if (d > now && (s.days || days).includes(days[d.getDay()]))
        return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(h)}:${pad(mi)}`;
    }
    return null;
  }

  /* -------------------------------------------------------------- fetch */
  window.fetch = async function (input, init) {
    init = init || {};
    const href = typeof input === 'string' ? input : (input && input.url) || '';
    let url;
    try { url = new URL(href, location.href); } catch (_) { return realFetch(input, init); }
    const at = url.pathname.indexOf('/api/');
    if (url.origin !== location.origin || at < 0) return realFetch(input, init);
    const path = url.pathname.slice(at);
    const method = String(init.method || (input && input.method) || 'GET').toUpperCase();
    let body = null;
    if (init.body) { try { body = JSON.parse(init.body); } catch (_) { body = null; } }
    const signal = init.signal;
    const abortErr = () => new DOMException('The operation was aborted.', 'AbortError');
    if (signal && signal.aborted) throw abortErr();
    for (const [m, re, fn] of routes) {
      const match = re.exec(path);
      if (!match || (m && m !== method)) continue;
      try {
        await sleep(120 + Math.random() * 180);
        if (signal && signal.aborted) throw abortErr();
        const res = await fn(url.searchParams, match, body);
        return new Response(JSON.stringify(res.body), {status: res.status, headers: {'Content-Type': 'application/json'}});
      } catch (e) {
        if (e && e.name === 'AbortError') throw e;
        console.warn('[demo api]', path, e);
        return new Response(JSON.stringify({detail: e.detail || String(e.message || e)}),
                            {status: e.status || 500, headers: {'Content-Type': 'application/json'}});
      }
    }
    return new Response(JSON.stringify({detail: `${path} is not available in this demo.`}), {status: 404, headers: {'Content-Type': 'application/json'}});
  };

  /* For demo.js: files the real app would download from the server. */
  window.FIDemo = {
    getData, part, cleanup: q => part(`pkg/${pkgOf(q)}/cleanup.json`, cleanupKey(q)), PACKAGES, DEMO_NOTE,
    runTrace, model,
  };
})();
