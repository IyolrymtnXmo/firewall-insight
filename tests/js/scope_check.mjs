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

const el = (id = "") => {
  const node = {
    id, innerHTML: "", textContent: "", value: "", checked: false,
    disabled: false, selectedIndex: 0, options: [], dataset: {},
    style: new Proxy({}, { get: () => "", set: () => true }),
    classList: { add() {}, remove() {}, toggle() {}, contains: () => false },
    appendChild() {}, removeChild() {}, remove() {}, focus() {}, blur() {},
    setAttribute() {}, removeAttribute() {}, getAttribute: () => null,
    addEventListener() {}, removeEventListener() {}, click() {},
    querySelector: () => el(), querySelectorAll: () => [],
    getBoundingClientRect: () => ({ width: 800, height: 600, top: 0, left: 0,
                                    right: 800, bottom: 600 }),
    closest: () => null, insertAdjacentHTML() {}, scrollIntoView() {},
  };
  node.parentElement = null;
  return node;
};

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
  fetch: () => Promise.resolve({ ok: true, json: () => Promise.resolve({}) }),
  localStorage: { getItem: () => null, setItem() {}, removeItem() {} },
  matchMedia: () => ({ matches: false, addEventListener() {} }),
  navigator: { clipboard: { writeText: () => Promise.resolve() } },
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

];

const failures = [];
for (const [name, run] of checks) {
  try {
    run();
  } catch (error) {
    failures.push(`${name}: ${error && error.message}`);
  }
}

if (failures.length) {
  console.error(failures.join("\n"));
  process.exit(1);
}
console.log(`ok - ${checks.length} renderer(s) ran against ${ids.length} element id(s)`);
