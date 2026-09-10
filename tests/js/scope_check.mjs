/*
 * Run the served frontend in a stubbed DOM and call its renderers.
 *
 * `node --check` proves app.js parses. It does not prove a renderer runs: a
 * reference to an identifier that does not exist is perfectly valid syntax and
 * only throws when the line executes. That is exactly how v4.25 shipped
 *
 *     const checked=(d.summary||{}).install_on_checked===true;
 *
 * inside a function whose parameter is `data`. The NAT page and the dashboard
 * both died with "d is not defined", 668 Python tests passed, and the first
 * person to find out was the user.
 *
 * The stub deliberately does NOT invent globals. Element ids are read out of
 * index.html - browsers expose them as window properties, which is why the
 * code says `natResults` rather than document.getElementById('natResults') -
 * and anything else stays undefined so a stray identifier throws here instead
 * of in front of somebody.
 */

import { readFileSync } from "node:fs";
import { createContext, runInContext } from "node:vm";

const root = process.argv[2];
const html = readFileSync(`${root}/app/templates/index.html`, "utf8");
const source = readFileSync(`${root}/app/static/js/app.js`, "utf8");

const ids = [...html.matchAll(/id="([A-Za-z_][\w-]*)"/g)].map((m) => m[1]);

/* Nodes with an id are remembered, the way a document remembers them.
 *
 * getElementById() used to build a brand new object on every call, so nothing
 * a renderer did to the DOM could be observed here - two calls asking for the
 * same id got two unrelated objects. That is why the toast pile in v4.30 could
 * not be caught: notify() appends to getElementById('toasts'), and every
 * append landed on a different throwaway node.
 *
 * Children are tracked well enough to answer "what is on screen now", which
 * is the question these checks ask. This is not a DOM implementation and is
 * not trying to be one. */
const NODES = new Map();

const el = (id = "") => {
  if (id && NODES.has(id)) return NODES.get(id);
  const node = {
    id, innerHTML: "", textContent: "", value: "", checked: false,
    disabled: false, selectedIndex: 0, options: [], dataset: {},
    className: "", children: [],
    style: new Proxy({}, { get: () => "", set: () => true }),
    classList: { add() {}, remove() {}, toggle() {}, contains: () => false },
    appendChild(child) {
      this.children.push(child);
      if (child) child.parentElement = this;
      return child;
    },
    removeChild(child) {
      const i = this.children.indexOf(child);
      if (i >= 0) this.children.splice(i, 1);
      if (child) child.parentElement = null;
      return child;
    },
    remove() { if (this.parentElement) this.parentElement.removeChild(this); },
    focus() {}, blur() {},
    setAttribute() {}, removeAttribute() {}, getAttribute: () => null,
    addEventListener() {}, removeEventListener() {}, click() {},
    querySelector: () => el(),
    querySelectorAll(sel) {
      if (typeof sel === "string" && sel.startsWith(".")) {
        const want = sel.slice(1);
        return this.children.filter(
          (c) => c && String(c.className || "").split(/\s+/).includes(want));
      }
      return [];
    },
    getBoundingClientRect: () => ({ width: 800, height: 600, top: 0, left: 0,
                                    right: 800, bottom: 600 }),
    closest: () => null, insertAdjacentHTML() {}, scrollIntoView() {},
  };
  node.parentElement = null;
  if (id) NODES.set(id, node);
  return node;
};

/* A body every reader can consume. loadMetadata() reaches straight for
   d.layers.map, so an empty object made it throw inside its own swallowed
   catch: the call happened, nothing was proved, and a stack trace was printed
   on every run. */
const EMPTY_BODY = { layers: [], packages: [], snapshots: [], baselines: [],
                     profiles: [], nodes: [], edges: [], rules: [] };

const document = {
  getElementById: (id) => el(id),
  querySelector: () => el(),
  querySelectorAll: () => [],
  createElement: () => el(),
  addEventListener() {},
  body: el("body"),
  documentElement: el("html"),
};

const context = {
  document,
  console,
  setTimeout, clearTimeout, setInterval, clearInterval,
  requestAnimationFrame: () => 0,
  /* api() reads the body with r.text() and parses it itself, so a stub with
     only json() made every call through api() throw before it ran. */
  fetch: () => Promise.resolve({
    ok: true, status: 200,
    json: () => Promise.resolve(EMPTY_BODY),
    text: () => Promise.resolve(JSON.stringify(EMPTY_BODY)),
  }),
  localStorage: { getItem: () => null, setItem() {}, removeItem() {} },
  matchMedia: () => ({ matches: false, addEventListener() {} }),
  navigator: { clipboard: { writeText: () => Promise.resolve() } },
  /* Real browser globals, stubbed because they exist everywhere the app runs.
     The rule this stub keeps is "do not INVENT globals" - withholding one the
     browser genuinely provides would fail a renderer that is perfectly
     correct, which is just as misleading as missing a typo. Anything not on
     this list still stays undefined. */
  performance: { now: () => 0 },
  confirm: () => true,
  alert: () => {},
  getComputedStyle: () => new Proxy({}, { get: () => "" }),
  AbortController: class { constructor() { this.signal = {}; } abort() {} },
  Blob: class { constructor(parts) { this.parts = parts; } },
  URL: { createObjectURL: () => "blob:stub", revokeObjectURL() {} },
  location: { href: "http://localhost/", search: "", hash: "" },
  URLSearchParams,
  Date, Math, JSON, Map, Set, Promise, Number, String, Array, Object, Error,
  encodeURIComponent, decodeURIComponent, parseInt, parseFloat, isNaN,
};
context.addEventListener = () => {};
context.removeEventListener = () => {};
context.dispatchEvent = () => true;
context.window = context;
context.globalThis = context;
for (const id of ids) if (!(id in context)) context[id] = el(id);

createContext(context);
runInContext(source, context, { filename: "app.js" });

/* ---- the renderers, with payloads shaped like the real API answers ---- */

const NAT_DATA = {
  summary: {
    total_nat_rules: 2, disabled_nat_rules: 1, duplicate_nat_groups: 0,
    broad_original_any_any_any: 0, possible_no_translation_rules: 1,
    nat_hits_available: true, install_on_checked: true,
    install_on_unknown_rules: 1,
  },
  findings: {
    disabled_rule_numbers: [2], broad_rule_numbers: [],
    possible_no_translation_rule_numbers: [1],
    install_on_unknown_rule_numbers: [1],
    install_on_findings: [{ rule: 1, target: "Retired-GW09", reason: "not a live gateway" }],
    duplicates: [],
  },
  rules: [
    { rule: 1, name: "Hide", enabled: true, original_source: "LAB", original_destination: "Any",
      original_service: "Any", translated_source: "GW", translated_destination: "Original",
      translated_service: "Original", install_on: "Retired-GW09", method: "hide", hits: 3 },
    { rule: 2, name: "Old", enabled: false, original_source: "LAB", original_destination: "Any",
      original_service: "Any", translated_source: "Original", translated_destination: "Original",
      translated_service: "Original", install_on: "Policy Targets", method: "static", hits: 0 },
  ],
};

const evalIn = (code) => runInContext(code, context, { filename: "check.js" });

/* v4.31: the Traffic Path render, driven by real API payloads.
 *
 * Everything above calls a renderer directly. `trace()` is different: the
 * render that matters lives inside it, behind an await, and it is the screen
 * the product is judged on. Nothing executed it, which is how
 * `${ARROW_CH}` - an identifier that does not exist - got written into the
 * transition cell while 718 Python tests and every renderer above stayed
 * green.
 *
 * `api` is a top-level function declaration, so it is a property of the
 * context and can be replaced. `L`, `P` are top-level `const`, so they are
 * lexical and need an expression evaluated inside the script's own scope.
 *
 * Captured from the lab, 2026-09-10, package External-FW.
 */
const TRACE_EXACT = {
  query: { source: "192.168.10.50", destination: "8.8.8.8", protocol: "tcp",
           port: 443, service_input: "443", service_display: "https (TCP/443)",
           service_resolved_by: "numeric-port", service_warnings: [],
           layer: "External-FW Network", package: "External-FW" },
  access: {
    matched: true, confidence: "exact", result: "Accept",
    reason: "Terminal Access rule matched exactly.",
    winner: { rule: 1, display_rule: "8.1", name: "Allow-Web", action: "Accept",
              layer: "VPN InternetLayer", depth: 1, state: "match",
              transition: "final", source_match: "LAB-Internal-Nets",
              destination_match: "All_Internet",
              service_match: "https (TCP/443)", vpn_state: "match" },
    path: [
      { rule: 8, display_rule: "8", name: "Lab-Outbound", action: "Inner Layer",
        layer: "External-FW Network", depth: 0, state: "match",
        transition: "inline-layer", inline_layer: "VPN InternetLayer",
        source_match: "LAB-Internal-Nets", destination_match: "All_Internet",
        service_match: "https (TCP/443)", vpn_state: "match" },
      { rule: 1, display_rule: "8.1", name: "Allow-Web", action: "Accept",
        layer: "VPN InternetLayer", depth: 1, state: "match",
        transition: "final", source_match: "LAB-Internal-Nets",
        destination_match: "All_Internet", service_match: "https (TCP/443)",
        vpn_state: "match" },
    ],
  },
  nat: [{ rule: 9, state: "match", confidence: "exact",
          translated_source: "LAB-VLAN10 (192.168.10.0/24)",
          translated_destination: "Original" }],
  nat_error: null, map_path: null, map_path_error: null,
  data_quality: { complete: true, warnings: [] }, limitations: [],
};

/* The defect this whole release is about, as the API actually returns it:
   no winner, a `possible_winner` the engine refused to declare final, and a
   later rule that does match but must not be presented as the answer. */
const TRACE_UNVERIFIED = {
  query: { source: "192.168.10.50", destination: "unverified-destination.invalid",
           protocol: "tcp", port: 443, service_input: "443",
           service_display: "https (TCP/443)", service_resolved_by: "numeric-port",
           service_warnings: [], layer: "External-FW Network",
           package: "External-FW" },
  access: {
    matched: false, confidence: "unknown", result: "UNVERIFIED",
    reason: "Earlier Rule 2 contains condition(s) this static simulator cannot "
          + "evaluate. Later Rule 9 matches, but cannot be declared final.",
    winner: null,
    possible_winner: {
      rule: 2, display_rule: "2", name: "Admin-Access", action: "Accept",
      layer: "External-FW Network", depth: 0, state: "unknown",
      source_match: "Any",
      destination_match: "unverified-destination.invalid did not resolve, so "
                       + "membership in these objects cannot be decided "
                       + "([Errno 11001] getaddrinfo failed)",
      service_match: "https (TCP/443)", destination_state: "unknown",
      vpn_state: "match",
    },
    later_exact_rule: { rule: 9, display_rule: "9", action: "Drop" },
    path: [{
      rule: 2, display_rule: "2", name: "Admin-Access", action: "Accept",
      layer: "External-FW Network", depth: 0, state: "unknown",
      source_match: "Any",
      destination_match: "unverified-destination.invalid did not resolve, so "
                       + "membership in these objects cannot be decided "
                       + "([Errno 11001] getaddrinfo failed)",
      service_match: "https (TCP/443)", destination_state: "unknown",
      vpn_state: "match",
    }],
  },
  nat: [{ rule: 3, state: "unknown", confidence: "unverified",
          reason: "NAT Rule 3 uses object(s) with no static model." }],
  nat_error: null, map_path: null, map_path_error: null,
  data_quality: { complete: true, warnings: [] }, limitations: [],
};

const ORIGINAL_API = context.api;
const runTrace = async (payload) => {
  context.api = async () => payload;
  evalIn("L.value='External-FW Network'; P.value='External-FW';"
       + "src.value='a'; dst.value='b'; proto.value='tcp'; port.value='443';");
  try {
    await context.trace();
  } finally {
    // Put the real one back, and clear the selections this set - otherwise a
    // later check that is gated on "a package is selected" starts running for
    // the first time against a payload meant for the trace.
    context.api = ORIGINAL_API;
    evalIn("L.value=''; P.value=''; src.value=''; dst.value=''; port.value='';");
  }
  return context.traceResult.innerHTML || "";
};

const must = (html, needle, why) => {
  if (!html.includes(needle)) throw new Error(`${why} (missing: ${needle})`);
};
const mustNot = (html, needle, why) => {
  if (html.includes(needle)) throw new Error(`${why} (found: ${needle})`);
};


const ROUTED_MAP = {
  nodes: [
    { id: "gw1", name: "External-GW01", role: "gateway", ips: ["172.23.31.177"],
      type: "simple-gateway" },
    { id: "gwint", name: "Internal-GW01", role: "gateway", ips: ["172.23.31.176"],
      type: "simple-gateway" },
    { id: "gw1:if:0", name: "eth1", role: "interface", parent: "gw1",
      cidr: "172.23.31.177/24", ips: ["172.23.31.177"] },
    { id: "gwint:if:0", name: "eth1", role: "interface", parent: "gwint",
      cidr: "172.23.31.176/24", ips: ["172.23.31.176"] },
    { id: "net:172.23.31.0/24", name: "172.23.31.0/24", role: "network" },
    { id: "route:0.0.0.0/0", name: "0.0.0.0/0", role: "routed-network",
      default_route: true, ips: ["0.0.0.0/0"] },
  ],
  edges: [
    { from: "gw1", to: "gw1:if:0", label: "interface" },
    { from: "gw1:if:0", to: "net:172.23.31.0/24", label: "connected subnet" },
    { from: "gwint", to: "gwint:if:0", label: "interface" },
    { from: "gwint:if:0", to: "net:172.23.31.0/24", label: "connected subnet" },
    { from: "gw1", to: "gwint", kind: "route", label: "192.168.10.0/24 via 172.23.31.176",
      next_hops: ["172.23.31.176"], next_hop_read: true },
    { from: "gw1", to: "route:0.0.0.0/0", kind: "route", label: "Static via 172.23.34.254",
      next_hops: ["172.23.34.254"], next_hop_read: true },
  ],
  limitations: [], count: 6,
};

const withMap = (merge) =>
  evalIn(
    `TOPO.merge=${merge}; TOPO.collapsed=new Set(); TOPO.unmerged=new Set();` +
    `TOPO.expanded=new Set(); TOPO.focus=null; TOPO.query='';` +
    `buildTopoGraph(${JSON.stringify(ROUTED_MAP)})`
  );

const checks = [
  ["renderNatSpecialViews", () => context.renderNatSpecialViews(NAT_DATA)],
  ["renderNatSpecialViews(empty)", () => context.renderNatSpecialViews({})],
  ["renderNatSpecialViews(undefined)", () => context.renderNatSpecialViews(undefined)],
  ["showNatTab:installon", () => { context.natData = NAT_DATA; context.showNatTab("installon", null); }],
  ["showNatTab:rulebase", () => { context.natData = NAT_DATA; context.showNatTab("rulebase", null); }],
  ["showNatTab:duplicates", () => { context.natData = NAT_DATA; context.showNatTab("duplicates", null); }],
  ["showNatTab:disabled", () => { context.natData = NAT_DATA; context.showNatTab("disabled", null); }],
  ["showNatTab:notrans", () => { context.natData = NAT_DATA; context.showNatTab("notrans", null); }],
  ["natTable", () => context.natTable(NAT_DATA.rules)],
  ["complianceSource_cite(cited)", () => context.complianceSource_cite(
      { cited: true, source: { standard: "NIST SP 800-41 Rev. 1", clause: "Section 4",
                               quote: "deny by default", url: "https://example.invalid" } })],
  ["complianceSource_cite(house)", () => context.complianceSource_cite(
      { cited: false, source: { standard: "local", note: "House rule" } })],
  ["complianceSourceChanged", () => context.complianceSourceChanged()],
  ["diffRows", () => context.diffRows([{ a: 1 }], [["A", (r) => String(r.a)]])],
  ["diffSection", () => context.diffSection("T", "h", "good", [], [])],
  // TOPO is a top-level `const`, so it is not a property of the context
  // object. Reaching it needs an expression evaluated inside the same scope.
  ["topoTraceClass", () => evalIn("TOPO.trace={draw:'inferred',hops:[]}; topoTraceClass()")],
  ["topoTraceHops", () => evalIn("TOPO.graph={nodes:[],links:[]}; topoTraceHops()")],
  ["topoTraceBar", () => evalIn("TOPO.trace=null; topoTraceBar()")],
  ["topoTraceBar(with a path)", () => evalIn(
      "TOPO.trace={draw:'unverified',hops:[{node_id:'a',name:'A'}],verdict:'UNVERIFIED'," +
      "source:{ip:'1.1.1.1',detail:'x'},destination:{ip:'2.2.2.2',detail:'y'}," +
      "policy_confidence:'unknown',topology_confidence:'exact',limitations:[]}; topoTraceBar()")],
  ["clearTraceOnMap", () => evalIn("clearTraceOnMap()")],
  ["esc", () => context.esc("<script>&")],

  /* v4.28.2: the routing overlay reached the payload and never reached the
     graph. `routed-network` was not in the model's role list and `kind:'route'`
     was not in its edge list, so the map counted 23 nodes / 31 relationships
     and drew the same 11 / 14 it drew before routing existed. Nothing in the
     Python suite can see that - the JSON was correct. */
  ["buildTopoGraph keeps route edges", () => {
    const g = withMap(false);
    if (!g.links.some((l) => l.kind === "route"))
      throw new Error("route edges were dropped by the graph model");
    if (!g.nodes.some((n) => n.role === "routed-network"))
      throw new Error("the routed-network node was dropped by the graph model");
  }],
  ["buildTopoGraph keeps them through Auto Merge", () => {
    const g = withMap(true);
    if (!g.links.some((l) => l.kind === "route"))
      throw new Error("route edges vanish when subnets are merged");
  }],

  /* v4.31: v4.30 shipped the Aurora dashboard and a Settings page, and neither
     was covered here. That is the newest code in the application, and Settings
     is the one place it writes to disk and talks to a Management Server -
     exactly the combination this harness exists for.

     `browserData`, `accessData`, `lastTrace` and `TOPO` are top-level
     `let`/`const`, so they are lexical bindings rather than properties of the
     context object and have to be reached with an expression evaluated inside
     the same scope. */

  // Empty state first: it is what a freshly loaded page renders, so a typo on
  // that branch is the one that reaches somebody first.
  ["renderHealthGauge(nothing analysed)", () => evalIn("accessData=null; renderHealthGauge()")],
  ["renderHitBars(nothing loaded)", () => evalIn("browserData=null; renderHitBars()")],
  ["renderTopoPreview(no graph)", () => evalIn("TOPO.graph=null; renderTopoPreview()")],
  ["renderTracePreview(nothing traced)", () => evalIn("lastTrace=null; renderTracePreview()")],
  ["renderHealthRows(empty)", () => evalIn("renderHealthRows()")],
  ["renderDashNote(empty)", () => evalIn("renderDashNote()")],
  ["renderContextChips(empty)", () => evalIn("renderContextChips()")],

  // Then with data, which is the branch that reads the payload fields.
  ["renderHealthGauge(analysed)", () => evalIn(
      "accessData={summary:{analyzed_rules:40,total_rules:40," +
      "potential_shadowed_or_redundant:3,duplicate_groups:1,any_any_any_rules:1," +
      "zero_hit_rules:5},findings:{}}; renderHealthGauge()")],
  ["renderHealthRows(analysed)", () => evalIn("renderHealthRows()")],
  ["renderDashNote(analysed)", () => evalIn("renderDashNote()")],
  ["renderContextChips(analysed)", () => evalIn("renderContextChips()")],
  ["renderHitBars(with hits)", () => evalIn(
      "browserData={rules:[{rule:1,name:'a',hits:100},{rule:2,name:'b',hits:0}," +
      "{rule:3,name:'c',hits:null}]}; renderHitBars()")],
  ["renderHitBars(rulebase reports no hits)", () => evalIn(
      "browserData={rules:[{rule:1,name:'a',hits:null}]}; renderHitBars()")],
  ["renderTopoPreview(with a graph)", () => evalIn(
      "TOPO.graph=buildTopoGraph(" + JSON.stringify(ROUTED_MAP) + "); renderTopoPreview()")],
  ["renderTracePreview(with a trace)", () => evalIn(
      "lastTrace={verdict:'MATCH',steps:[{rule:1,layer:'Network',action:'Accept'}]," +
      "policy_confidence:'exact'}; renderTracePreview()")],
  ["renderHitTrend(rows)", () => context.renderHitTrend(
      [{ taken_at: "2026-01-01T00:00:00+00:00", total_hits: 10 },
       { taken_at: "2026-01-02T00:00:00+00:00", total_hits: 20 }])],
  ["renderHitTrend(empty)", () => context.renderHitTrend([])],
  ["refreshAuroraDashboard", () => evalIn("refreshAuroraDashboard()")],

  /* v4.31: notify() used to append unconditionally. The UNVERIFIED toast is
     raised with {duration:0} so it never expires - re-running a trace stacked
     another permanent copy each time, and on the lab screenshot two of them
     were sitting over the NAT row. */
  ["notify() replaces a repeated toast instead of stacking", () => {
    const host = document.getElementById("toasts");
    host.children.length = 0;
    for (let i = 0; i < 3; i++)
      context.notify("warn", "UNVERIFIED", "same message", { duration: 0 });
    if (host.children.length !== 1)
      throw new Error(
        `three identical toasts left ${host.children.length} on screen`);
  }],

  ["notify() keeps toasts that say different things", () => {
    const host = document.getElementById("toasts");
    host.children.length = 0;
    context.notify("warn", "UNVERIFIED", "a", { duration: 0 });
    context.notify("warn", "NAT correlation unverified", "b", { duration: 0 });
    if (host.children.length !== 2)
      throw new Error(
        `two distinct toasts collapsed to ${host.children.length}`);
  }],

  /* v4.31.3: a compliance run has to be readable, and readable must not mean
     "some of the evidence is gone". */
  ["complianceOffenders previews and keeps every row", () => {
    const many = Array.from({length: 13}, (_, i) => ({
      display_rule: String(i + 1), name: "Rule" + i, layer: "L",
      action: "Accept", source: "S", destination: "D", service: "svc",
      reason: "track is empty",
    }));
    const html = context.complianceOffenders({ offenders: many });
    /* One `rule-no` span per offender, so this counts rows without depending
       on how many <thead> blocks the markup happens to have. */
    const count = t => (t.match(/class="rule-no"/g) || []).length;
    if (count(html) !== 13)
      throw new Error(`13 offenders rendered ${count(html)} rows - evidence was dropped`);
    if (!html.includes("Show the remaining 8 of 13"))
      throw new Error("the disclosure does not say how many rows it holds");
    const i = html.indexOf("<details");
    if (i < 0) throw new Error("13 offenders were not folded at all");
    if (count(html.slice(0, i)) !== 5)
      throw new Error(`preview shows ${count(html.slice(0, i))} rows, expected 5`);
  }],

  ["complianceOffenders does not fold a short list", () => {
    const few = [{display_rule: "1", name: "a"}, {display_rule: "2", name: "b"}];
    const html = context.complianceOffenders({ offenders: few });
    if (html.includes("<details")) throw new Error("two rows were put behind a disclosure");
  }],

  ["complianceOffenders survives a check with no offenders", () => {
    if (context.complianceOffenders({}) !== "") throw new Error("expected empty string");
    if (context.complianceOffenders({ offenders: [] }) !== "") throw new Error("expected empty string");
  }],

  ["a citation keeps its standard and clause on the line", () => {
    const html = context.complianceSource_cite({ cited: true, source: {
      standard: "NIST SP 800-41 Rev. 1", clause: "Section 4",
      quote: "deny by default", url: "https://example.invalid" }});
    const summary = html.slice(html.indexOf("<summary>"), html.indexOf("</summary>"));
    if (!summary.includes("NIST SP 800-41 Rev. 1")) throw new Error("the standard is hidden");
    if (!summary.includes("Section 4")) throw new Error("the clause is hidden");
    if (!html.includes("deny by default")) throw new Error("the quotation was dropped, not folded");
  }],

  ["a house rule is still labelled, not folded", () => {
    const html = context.complianceSource_cite({ cited: false, source: { note: "House rule" }});
    if (!html.includes("HOUSE RULE")) throw new Error("the house-rule label is gone");
    if (html.includes("<details")) throw new Error("a one-line label was put behind a disclosure");
  }],

  // Settings. showTestResult renders the banner every one of these ends in.
  ["showTestResult(ok)", () => context.showTestResult("cpTestResult", true, "<b>ok</b>")],
  ["showTestResult(fail)", () => context.showTestResult("cpTestResult", false, "<b>no</b>")],
  ["showTestResult(pending)", () => context.showTestResult("cpTestResult", null, "...")],
  ["togglePassVis", () => context.togglePassVis("cpPass", el("btn"))],
];

/* The credential calls are async. A bad identifier inside one of them rejects
   its promise instead of throwing at the call site, so a try/catch around the
   call would report success on a broken function. They are awaited instead. */
const asyncChecks = [

  /* The honesty properties of the Traffic Path screen, asserted on the markup
     the renderer actually produced. */
  ["trace(exact) renders the matched path", async () => {
    const html = await runTrace(TRACE_EXACT);
    must(html, "Rule 8.1", "the matched rule is not shown");
    must(html, "Matched Policy Path", "the path table lost its heading");
    must(html, "Final rule", "the terminal rule is not marked final");
    must(html, "All_Internet", "the match evidence is not shown");
  }],

  ["trace(unverified) never says 'No match'", async () => {
    const html = await runTrace(TRACE_UNVERIFIED);
    mustNot(html, "No match",
      "the Access Rule row claims a confident non-match on an UNVERIFIED verdict");
    must(html, "UNVERIFIED", "the verdict is not shown as UNVERIFIED");
  }],

  ["trace(unverified) never calls the unevaluated rule final", async () => {
    const html = await runTrace(TRACE_UNVERIFIED);
    mustNot(html, "Final rule",
      "a rule the engine refused to evaluate is presented as the final rule");
    must(html, "not declared final",
      "the transition cell does not say why the rule is not final");
  }],

  ["trace(unverified) does not paint an unknown step as an outcome", async () => {
    const html = await runTrace(TRACE_UNVERIFIED);
    must(html, "pill warn", "the unknown step is not flagged");
    must(html, "configured: Accept",
      "the configured action should be shown as configuration, not as a verdict");
  }],

  ["trace(unverified) still shows the evidence it has", async () => {
    const html = await runTrace(TRACE_UNVERIFIED);
    /* Scope this to the Item/Result/Details table. The same text also appears
       in the path table's Match Details further down, so asserting on the
       whole document passed even with the Destination row blanked out. */
    const summary = html.split("Policy Path")[0];
    must(summary, "did not resolve",
      "the Destination row hides the reason behind an em dash");
  }],

  ["trace(unverified) heading does not announce a match", async () => {
    const html = await runTrace(TRACE_UNVERIFIED);
    must(html, "Policy Path (unverified)", "the path table still says 'Matched'");
  }],
  /* v4.31: two claims the chrome makes about itself. */

  ["api() records the read that just completed", async () => {
    /* The Read chip was fed from three call sites, so a trace, a map load, a
       compliance run and a health read all left it saying "No call yet" while
       the network tab showed the requests. It is set in api() now, which every
       read goes through. */
    evalIn("lastReadLabel=''");
    await context.api("/api/anything");
    const stamp = evalIn("lastReadLabel");
    if (!stamp) throw new Error("a completed read did not update the Read chip");
  }],

  ["progress polling does not retick the Read chip", () => {
    /* trackProgress() calls fetch directly rather than api(), which is what
       keeps a 50-second analysis from restamping the chip twice a second. */
    const body = source.split("function trackProgress")[1].split("\n}")[0];
    if (body.includes("api(")) throw new Error("trackProgress now goes through api()");
  }],

  ["a successful Settings test updates the header badge", async () => {
    /* setConn() used to be reachable only from the header's own button, so the
       Settings page proved the connection and left the badge reading
       "Not tested" right next to its own success message. */
    const conn = document.getElementById("conn");
    conn.innerHTML = "";
    const realFetch = context.fetch;
    context.fetch = async () => ({
      ok: true, status: 200,
      json: async () => ({ success: true, message: "Connected to x",
                           api_version: "2.0.1" }),
      // testCred() now loads metadata too, so the body has to
      // satisfy loadMetadata() as well as the test itself.
      text: async () => JSON.stringify(EMPTY_BODY),
    });
    try { await context.testCred("checkpoint"); }
    finally { context.fetch = realFetch; }
    if (!String(conn.innerHTML).includes("Connected"))
      throw new Error("a successful connection test left the header unchanged");
  }],

  ["a failed Settings test does not claim a connection", async () => {
    const conn = document.getElementById("conn");
    conn.innerHTML = "";
    const realFetch = context.fetch;
    context.fetch = async () => ({
      ok: true, status: 200,
      json: async () => ({ success: false, message: "nope" }),
      // testCred() now loads metadata too, so the body has to
      // satisfy loadMetadata() as well as the test itself.
      text: async () => JSON.stringify(EMPTY_BODY),
    });
    try { await context.testCred("checkpoint"); }
    finally { context.fetch = realFetch; }
    if (String(conn.innerHTML).includes("Connected"))
      throw new Error("a failed test reported a connection");
  }],

  ["a Gaia test never speaks for the Management connection", async () => {
    /* Different API, different credentials. A Gaia result says nothing about
       whether the Management Server is reachable. */
    const conn = document.getElementById("conn");
    conn.innerHTML = "SENTINEL";
    const realFetch = context.fetch;
    context.fetch = async () => ({
      ok: true, status: 200,
      json: async () => ({ success: true, message: "All gateways OK", details: [] }),
      // testCred() now loads metadata too, so the body has to
      // satisfy loadMetadata() as well as the test itself.
      text: async () => JSON.stringify(EMPTY_BODY),
    });
    try { await context.testCred("gaia"); }
    finally { context.fetch = realFetch; }
    if (String(conn.innerHTML) !== "SENTINEL")
      throw new Error("a Gaia test rewrote the Management API badge");
  }],

  /* v4.31.1: connecting used to leave the selectors empty.

     loadMetadata() was reachable from one unlabelled icon button, so a
     successful connection was followed by "pick a package in the selector at
     the top" - pointing at a selector with nothing in it. */

  ["a successful Settings test fills the package selector", async () => {
    const urls = [];
    const realFetch = context.fetch;
    context.fetch = async (u) => {
      urls.push(String(u));
      const body = { success: true, api_version: "2.0.1",
                     layers: [{ name: "L" }], packages: [{ name: "P" }] };
      return { ok: true, status: 200,
               json: async () => body,
               text: async () => JSON.stringify(body) };
    };
    try {
      await context.testCred("checkpoint");
      // loadMetadata() is deliberately not awaited there, so let it run.
      await new Promise((r) => setTimeout(r, 0));
    } finally { context.fetch = realFetch; }
    if (!urls.some((u) => u.includes("/api/bootstrap")))
      throw new Error("connecting did not load the packages, so the selector stays empty");
  }],

  ["ensurePackages() fetches only when the list is empty", async () => {
    let calls = 0;
    const realFetch = context.fetch;
    context.fetch = async () => {
      calls++;
      const body = { layers: [{ name: "L" }], packages: [{ name: "P" }] };
      return { ok: true, status: 200,
               json: async () => body,
               text: async () => JSON.stringify(body) };
    };
    try {
      /* The stub does not turn innerHTML into options, so the return value
         cannot be observed here. Whether it went to the network can. */
      evalIn("P.options = [{}];");          // just the placeholder
      await context.ensurePackages();
      if (calls === 0)
        throw new Error("an empty package list was not loaded");
      const afterFirst = calls;
      evalIn("P.options = [{},{}];");       // now something is in the list
      await context.ensurePackages();
      if (calls !== afterFirst)
        throw new Error("ensurePackages() re-fetched a list that was already there");
    } finally { context.fetch = realFetch; }
  }],

  ["loadCredentialStatus", () => context.loadCredentialStatus()],
  ["saveCred(checkpoint)", () => context.saveCred("checkpoint")],
  ["saveCred(gaia)", () => context.saveCred("gaia")],
  ["testCred(checkpoint)", () => context.testCred("checkpoint")],
  ["testCred(gaia)", () => context.testCred("gaia")],
  ["deleteCred(checkpoint)", () => context.deleteCred("checkpoint")],
  ["dashboardRefresh", () => context.dashboardRefresh()],
];


const failures = [];
for (const [name, run] of checks) {
  try {
    run();
  } catch (error) {
    failures.push(`${name}: ${error && error.message}`);
  }
}

for (const [name, run] of asyncChecks) {
  try {
    await run();
  } catch (error) {
    failures.push(`${name}: ${error && error.message}`);
  }
}

if (failures.length) {
  console.error(failures.join("\n"));
  process.exit(1);
}
console.log(
  `ok - ${checks.length + asyncChecks.length} renderer(s) ran against ${ids.length} element id(s)`);
