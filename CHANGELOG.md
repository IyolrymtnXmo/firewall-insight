# Changelog

All notable changes to Firewall Insight.

---

## v4.29.0 — a gateway that could not be read is not a gateway that was not there

Found by using the tool, not by reading it. The route on `Internal-GW01` was
corrected, `172.23.31.176` answered the Gaia API for the first time, and the
diff against the 06:26 baseline said:

```
172.23.31.176   gateway-added
"This gateway is in the current reading and not in the baseline."
```

That sentence is false, and the baseline file proves it: the host is sitting in
`unreachable`, with the connection error recorded beside it. `diff_health()`
built its index from `report["gateways"]` alone and never looked at the other
half of the report — so a gateway it had explicitly recorded as *present and
unreadable* came back as one it had never heard of.

The distinction is the whole point of the page. **"A gateway was added to the
estate" and "a gateway we could not read is now readable" call for opposite
responses**: the first is a change somebody should be able to point at a ticket
for, the second is a fault that was fixed — or, read the other way, a firewall
that has just stopped answering. Reporting the second as the first claims the
estate changed when it did not, and silently drops the recorded error, which is
the only evidence that says which of the two happened.

Two new kinds, each carrying the reason:

- `gateway-became-readable` — answered now, did not in the baseline, and the
  baseline's error is quoted in the line. It is deliberately *not* followed by
  an interface-by-interface diff: there is nothing to compare against, and
  inventing an `interface-added` line for every port on the box would bury the
  one fact that matters.
- `gateway-became-unreadable` — read in the baseline, silent now, with the
  current error quoted. Severity is not duplicated here; the read itself
  already raises the **high** `not-read` finding.

Unreadable on both sides stays silent — still broken is not news, and the
current reading says it anyway. A gateway that was unreachable in the baseline
and is absent from the current reading altogether is now reported
`gateway-missing`, which the old loop could not do at all: it iterated the
readable half, so a gateway could be dropped from the configured list without
the diff ever mentioning it, provided it was already unreachable when the
baseline was taken.

Baselines written before this release have no `unreachable` key. Absent is not
the same as empty, but it reads the same way here, and old baselines still diff.

### Tests

677 → 687. The payloads in `test_v429_health_diff_readability.py` are the real
shape, taken from `health-baselines/health-20260908062638.json` — the baseline
that produced the wrong line — trimmed to the fields the diff compares.

---

## v4.28.3 — one failing read must not cost the whole gateway

Found by thinking ahead of the lab rather than behind it. `Internal-GW01` is a
standalone gateway, so `show-cluster-state` will fail on it — and
`read_all_state()` wrapped all three reads in one `try`, so a command that was
never going to apply would have taken its interfaces and its version down with
it. The gateway whose access is currently being restored is exactly that
gateway, so it would have reappeared as *still unreadable*, for a completely
different reason, and the obvious conclusion would have been that the routing
fix had not worked.

This is the rule the routing reader already follows — one gateway failing costs
only that gateway — applied one level down: **one failing read costs only that
read.** Each of the three now stands on its own, what succeeded is kept, and
what failed is reported:

- `cluster` failing is **medium**, and the detail says a standalone gateway has
  no cluster state, *which is expected rather than wrong*.
- `interfaces` failing is **high**, because everything else reported for that
  gateway rests on it.

A gateway that answered nothing at all is still `unreachable`, unchanged.

### Tests

670 → 677, including the client half driven through a fake transport.

---

## v4.28.2 — the routing overlay reached the payload and never reached the map

v4.28.1 fixed the `limit` parameter, the Gaia API answered, and the page said:

```
Loaded 23 nodes and 31 relationships     (was 22 and 25)
11 node(s) · 14 link(s)                  (unchanged)
```

Six route edges and one routed-network node arrived in the JSON and the graph
drew exactly what it drew before routing existed. `buildTopoModel()` keeps
nodes whose role is one of gateway / management / device / cluster /
cluster-member, plus `role === 'network'`; `routed-network` is none of those.
`buildTopoGraph()` turns edges into links from the interface-derived cells and
from `rel`, which filters `kind` to `membership` or `mgmt-ha`; `route` is
neither. Both were dropped in silence, and every Python test still passed
because the payload was correct — the loss happened after it.

Route links and routed-network nodes are now part of the graph, resolved
through Auto Merge and cluster collapse the same way the traced-path overlay
resolves, so the overlay does not vanish the moment somebody merges a subnet.
A routed prefix is drawn as a dashed outline rather than a solid chip, and the
legend says why: **reached by a route only** — the estate knows that subnet
exists because a routing table mentioned it, not because an interface address
puts it there.

`tests/js/scope_check.mjs` now builds the graph from a map carrying route
edges, with Auto Merge both off and on, and fails if either the link or the
node is missing. Verified by re-introducing the defect: both checks fail with
`route edges were dropped by the graph model`.

### Changed

- Map legend gains two entries for the routing overlay.

---

## v4.28.1 — two bugs the lab found, and the test that should have found them first

Both were shipped by this project, both survived 668 passing tests, and the
first person to hit either one was the user, on the lab, a week before the
review. That is the part worth writing down.

**`d is not defined` — the NAT page and the dashboard, both dead.** v4.25 added
the install-on view inside `renderNatSpecialViews(data)` and referred to `data`
as `d`:

```js
const checked=(d.summary||{}).install_on_checked===true;
```

Valid JavaScript. `node --check` passes. Every UI test in the suite looks for
*strings inside app.js*, and the string was there — it just named something
that does not exist at runtime. A source-scanning test can never catch this
class, so `tests/js/scope_check.mjs` now **runs** the real file in a stubbed DOM
and calls twenty renderers with payloads shaped like the API's.

The stub is deliberately mean: element ids are read out of `index.html`,
because a browser exposes them as window properties and that is why the code
can say `natResults` rather than a `getElementById` call — and every *other*
identifier stays undefined, so a stray one throws in the test rather than in
front of somebody. Verified by putting `d.summary` back: the harness fails with
exactly `d is not defined`. It skips, rather than fails, where node is absent.

**The map reported "no routing" from the gateways the probe had just read.**
`GaiaClient.routes()` sent `{"limit": 500}`; R82 answers
`HTTP 400: Validation Error` to a `limit` on `show-routes` and
`show-static-routes`. `tools/probe_gaia.py` sends `{}` and worked perfectly,
which is why the probe output looked healthy while the Network Mapping page
said the same two gateways could not be read. The client now sends what the
probe sends. The payload carries `from`/`to`/`total`, so a routing table larger
than one page will need the real parameter names from that build — a guess
repeated is what caused this.

### Changed

- A compliance offender now says which clause caught it. On the lab, "Telnet
  (TCP/23) is never permitted" fires on rule 1 because its service is `Any`,
  and `matches the forbidden condition` was true and useless. It now reads
  `service Any covers TCP/23`.

### Tests

668 → 670, and the two new ones are the only kind that could have caught the
first bug.

---

## v4.28.0 — the probe met a real gateway, and the readers lost

`tools/probe_gaia.py` existed so the route readers could be narrowed to what a
build actually answers. Its first run against Check Point Gaia R82 reported:

```
show-routes: reader understood 7/7 route entries
  0.0.0.0/0        via            Static
  192.168.10.0/24  via            Static
```

Seven of seven, and **every next hop dropped** — including the default route,
which the gateway plainly reports as via 172.23.34.254. Gaia nests it one level
deeper than the reference examples: `next-hop` is an object carrying a
`gateways` list whose entries hold both the address and the egress interface,
while a connected route carries only `interface` and correctly has no gateway
at all. `show-static-routes` uses a third shape again — a list keyed `gateway`
— which happened to match what had been written, so half the feature looked
fine and the other half failed silently.

That is the same failure this project exists to refuse, committed by this
project: **a counter that reports success while discarding the field that
carries the meaning.** `parsed` now counts routes that were *understood*, not
routes whose prefix happened to be legible, and a route whose next hop is in an
unmodelled shape is counted apart and named on the map.

`tests/fixtures/gaia_r82_probe.py` holds the unedited payloads. They are the
oracle now — principle 11 applied to the second API.

### Added — routing that says something the old map could not

With next hops read, the overlay can do the thing an interface-only map never
could: **a route whose next hop is an address the map already knows draws an
edge between the two devices.** "External-GW01 reaches 192.168.10.0/24 through
Internal-GW01" is a relationship no `show-gateways-and-servers` payload
contains, and it is visible in the lab right now. A connected route to a subnet
the map already draws is counted as confirmation rather than drawn twice, and
`127.0.0.0/8` is skipped with a stated reason rather than dropped.

### Added — Gateway Health (feature 4b)

`app/health.py`, written against the same fixtures. What the real data punishes:

- `"ipv4-address": "Not-Configured"` is a **string**, not an absent field. Read
  carelessly it invents a host called Not-Configured.
- `"ipv4-mask-length": "24"` is a string too.
- `enabled: false` with an address configured is a live finding in the lab —
  `Mgmt`, 192.168.99.1 — and the Management API **cannot see it**, because that
  API reports the configured address, not the link state. This is the finding
  that justifies the second API.

Findings: an interface configured but administratively down; a cluster whose
status is not `ok`; **two members both claiming active** (split brain, detected
across gateways rather than from one); no active member; software build drift
across the estate; and a gateway that did not answer — at high severity,
because *silence is not health* and a page people read for reassurance must
never let it look like it.

Baselines: every reading is saved, and `?baseline=<id>` diffs against an
earlier one. A cluster role flip is reported as what it is — *External-GW01
went active → standby. A failover happened, or somebody moved it.* — alongside
interface state and address changes, and upgrades.

### Tests

620 → 661. New: `test_v428_gaia_real_payload.py` (15) and `test_v428_health.py`
(33), both driven by the captured payloads. Three v4.27 tests were updated
where the semantics deliberately changed, each with a comment saying why.

### Still open

`Internal-GW01` (172.23.31.176) refused the connection during the probe — its
route was removed and no policy permits the Gaia port from the workstation. The
map and the health page both name it rather than drawing the estate as if it
were smaller.

---

## v4.27.0 — routing, and the guarantee that had to grow to hold it

The map has always said the same thing about itself: *logical topology only,
physical cabling, switches and live routing are not inferred*. Routing was the
obvious gap, and the obvious way to close it — SSH to each gateway and parse
`netstat -rn` — would have cost the property the whole project is built on.

The Gaia API closes it without that trade. It is a real HTTPS API on every
gateway, it has `show-routes`, `show-interfaces` and `show-cluster-state`, and
it needs no shell. But it has a shape the Management API does not: those reads
sit in the same command space as `set-static-route`, `add-license`,
`run-script` and `run-reboot`, reachable over the same session. Reaching that
API on the strength of "we only call the read ones" would have downgraded a
structural guarantee into a promise.

So the allowlist in `app/gaia.py` is enforced in code, at call time, before any
request is built — a refused command never reaches the network, not even as an
authentication attempt — and `tests/test_v413_structure.py` now scans for
mutating *Gaia* command strings the same way it has always scanned for
mutating Management ones. Adding a capability tightened the guarantee. That is
the only acceptable direction for a tool people are asked to point at
production.

**The readers do not pretend to know the payload.** Gaia's envelopes differ
between builds and this project has no lab-verified sample of each. Writing a
parser against a shape assumed from documentation is precisely what README
principle 11 forbids, so `app/gaia_topology.py` tries the plausible keys and —
the part that matters — keeps what it could not read. Unparsed entries are
counted, carried with their raw body, surfaced in the map's `limitations` and
raised as a toast. A routing map that silently omits the four routes it did not
understand is worse than one that admits to reading six of ten, because the
first one looks finished.

**"I did not look" and "there is nothing there" are different answers.**
Asking for routing while `GAIA_ENABLED` is false returns a map that says so, in
its limitations and in a notification: *this is not evidence that the gateways
have no routes*. A gateway that failed to answer is named rather than dropped,
for the same reason.

**A route is drawn as a weaker claim than a subnet.** A subnet link comes from
a configured interface address and holds as long as the config does; a route
was read at one instant and can change before the next packet. Different dash,
different colour, and a prefix the map knows only by hearsay is drawn as an
outline rather than a solid chip.

### Added

- `app/gaia.py` — `GaiaClient` with the enforced read allowlist, session
  handling, and `read_all_routes()` which lets one unreachable gateway fail
  without costing the others.
- `app/gaia_topology.py` — shape-tolerant route readers and the map overlay.
- `tools/probe_gaia.py` — read-only. Calls each allowlisted read against each
  configured gateway, prints the envelope shape and what the readers made of
  it, and writes the raw answers to `gaia-probe.json` so the parsers can be
  narrowed to a build's truth instead of widened to every guess.
- `GET /api/network-map?routing=true`, and a **Load with Routing** button.
- `GAIA_ENABLED` / `GAIA_USER` / `GAIA_PASSWORD` / `GAIA_HOSTS` /
  `GAIA_VERIFY_SSL` / `GAIA_TIMEOUT`, documented in `.env.example` and off by
  default — the application behaves exactly as before for anyone who never
  sets them.

### Still to verify against the lab

The route readers have never met a real Gaia payload. `tools/probe_gaia.py`
exists to fix that, and until it has been run against R82 the parsed/unparsed
counts on the map are the only trustworthy statement about how well they did.

### Tests

577 → 620. New: `test_v427_gaia_allowlist.py` (23) — including that a mutating
command raises before any transport call — and `test_v427_gaia_routing.py` (18),
which feeds the readers three different plausible envelopes and asserts the
unreadable entries survive as findings.

---

## v4.26.0 — compliance as code: the customer writes the standard

The question that had to be answered before this feature was worth building
was *why would anyone believe our baseline?* Every estate is different, so a
baseline this application invents is an opinion in the costume of a
requirement, and an auditor is right to throw it out. Check Point's own
Compliance blade already ships vendor-authored regulatory content; a worse
copy of that is not a contribution.

So the tool ships no authority. A **profile** is a YAML or JSON file the
customer owns, listing the checks they have decided apply to them, and the
engine reports conformance against those. The two profiles included are
starting points, and the format makes their status impossible to miss.

**Provenance is part of every result.** A check may declare a `source` —
standard, clause, quote, URL — and it comes back attached to the finding. A
check without one still runs, because house rules are legitimate and common,
but it is labelled `cited: false` and rendered as **HOUSE RULE**, and the
summary counts how many there were. A house rule is a fine reason to fix
something and a terrible reason to tell an auditor you are non-compliant with
NIST; the report keeps those apart on every line.

**Results are tri-state, and `unverifiable` is never rounded up.** A rule
whose service object has no static model cannot be proven to exclude telnet.
The engine says so, the run is not conformant while one remains, and the UI
paints it as a warning rather than a pass. A compliance report that quietly
signs off "we could not tell" is worse than no report, because somebody puts
their name on it.

**There is no compliance percentage.** A single number has to price an
unverifiable check: count it as a pass and the report overstates, as a fail
and it cries wolf, drop it and the denominator moves silently. Every available
price misleads, so the engine reports counts and refuses to pick one. There is
a test that fails if a percentage ever appears in the result.

**A profile declares what it cannot check.** `not_checkable` lists the
requirements the author knows a configuration reader cannot decide — formal
change management, whether a periodic review actually happened, whether logs
are monitored. It is rendered below the results, separated, so a clean run
never reads as "the standard is satisfied".

### Added

- `app/compliance.py` — seven check types over the snapshot's normalised
  rules: `no_rule_matches` (with `source_covers` / `destination_covers` /
  `service_covers` predicates that go tri-state on an unresolvable object),
  `all_rules_have`, `no_disabled_rules`, `cleanup_rule_present`, `max_rules`,
  `no_findings` and `nat_no_findings`.
- `app/compliance_profiles/nist-800-41-baseline.yaml` — three checks, each
  citing NIST SP 800-41 Rev. 1 with the clause and the quoted text, plus three
  `not_checkable` entries. Only clauses that were read in the publication
  itself are cited; nothing was filled in from memory.
- `app/compliance_profiles/house-hygiene.yaml` — six deliberately uncited
  checks, so the labelling is visible the first time anyone runs it.
- `GET /api/compliance-profiles` and `GET /api/compliance`. The run accepts
  `package=` (live) or `snapshot=` (captured earlier). A live run has the
  access and NAT analyses, so analysis-backed checks can be decided; a
  snapshot run does not, so those same checks come back `unverifiable`. The
  same profile against the same policy answers differently depending on how
  much evidence the run had, and says which.
- A live run captures a snapshot on the way through and returns its id, so
  every compliance result is tied to evidence that can be re-evaluated against
  a different profile later.
- **Compliance** page, results ordered failures first, each carrying its
  citation or its house-rule label.
- `PyYAML` added to requirements.txt.

### Tests

530 → 577. New: `test_v426_compliance.py` (42), `test_v426_compliance_routes.py`
(5). The route tests run the same profile twice — once live, once against the
snapshot it produced — and assert the analysis-backed checks change from
decided to `unverifiable`.

---

## v4.25.0 — what changed since last time

Every other page answers "what does the policy say now". Periodic review work
does not start there; it starts from *what moved since the last audit*, and
neither SmartConsole nor this application had a view for it.

A snapshot is a JSON file: one policy package, its Access rules and its NAT
rules, each rule carrying its uid, its position, its fields — and the resolved
address and port intervals of each dimension. No object dictionary, no payload
bodies. Small enough to keep one per audit cycle for years, plain enough to
open in an editor and see what the firewall looked like on a given day.

Four decisions shape the comparison, and each of them is the difference
between a report someone reads twice and one they learn to skip:

**Rules are matched by uid, never by rule number.** Insert one rule at the top
and every number below it shifts. A number-keyed diff would report an entire
rulebase as rewritten after a one-line change.

**"Moved" is its own verdict.** Access Control is first-match-wins, so a
rule's position is part of what it means. A rule that is byte-identical but
now sits above one it used to sit below has changed behaviour — filing that
under "unchanged" hides a real event, and filing it under "modified" claims
fields changed when none did.

**A rule can change without the rule changing.** Add a member to a group and
every rule referencing it permits more traffic, with identical text, identical
uids and an identical rule number. A textual diff sees nothing at all. This is
the finding the feature exists for, and the reason snapshots carry resolved
intervals rather than only names. It is reported as `widened`, `narrowed` or
`redefined`, on the dimension it happened on.

**An unresolvable object makes the comparison unavailable, not equal.** Same
discipline as the tri-state matcher: if either side could not be modelled, the
answer is "cannot compare" and the diff is not `identical`. And because those
intervals are produced by *this application*, comparing snapshots taken by two
different versions of it raises a warning on the whole diff — a scope
difference might be our change rather than the policy's.

Hit counts are recorded in a snapshot and deliberately excluded from the
comparison: they move every day and would bury the policy changes.

### Added

- `app/snapshot.py` — capture and an on-disk store. Snapshot ids are validated
  against a pattern whose first character must be alphanumeric, which rules out
  `..` and dot-files, and the resolved path is re-checked against the store
  directory before any read. A bad id is refused, never sanitised.
- `app/snapshot_diff.py` — the comparison, as a pure function.
- `GET /api/snapshot`, `GET /api/snapshots`, `GET /api/snapshot-diff` — still
  every route a GET. Capturing writes one file to the local disk, which is the
  only write anywhere in this codebase, so the response returns `saved_to`
  rather than leaving the caller to find out. Nothing goes to the Management
  Server but the same `show-*` reads every other page makes.
- **Policy Diff** page: counts across the top, then each category in its own
  section with its own explanation, and any warnings rendered *above* the
  findings rather than under them.
- `snapshots/` added to `.gitignore` — local audit evidence, not source.

### Tests

477 → 530. New: `test_v425_snapshot_diff.py` (18), `test_v425_snapshot_build.py`
(32), `test_v425_snapshot_routes.py` (3). The route test drives the headline
case end to end: a group gains a member between two captures, and the diff
reports zero modified rules and one widened scope.

---

## v4.24.0 — Traffic Path had never read the VPN column

`tools.suggest_cases`, run against the live lab for the first time, skipped
rule 1 for having an Any destination and an Any service. Following that back
through the code found something worse than a skipped test case:

```
analyzer.py        uses vpn in the rule signature and in shadow analysis
policy_browser.py  shows the VPN column
api/export.py      exports the VPN column
traffic.py         the word "vpn" does not appear in the file
```

A rule scoped to one VPN community was matched by the tri-state tracer as
though it applied to every packet. Traffic that is *not* inside that community
would be answered `accept · exact` by the rule that permits the community — a
confident wrong answer, produced by the one feature the whole project exists
to keep honest, on the one lab rule nobody had written a case for.

`vpn_match_state()` treats the column the way the file treats every other
condition it cannot verify. Whether a packet arrives inside a community is
live connection state, not configuration, so the answer is `unknown` — never
`no-match`, because we cannot prove the packet is outside the community
either. An unknown VPN condition makes the whole rule unknown, which stops a
later exact rule from being reported as final. Security Zones and Identity
Awareness already worked this way; the VPN column simply was not wired in.

The verdict changes only where it should: a rule whose addresses do not match
is still a clean `no-match`, and a rule with `vpn: Any` or no VPN field at all
is untouched.

> **Expect acceptance verdicts to move.** Any flow whose path crosses a
> VPN-scoped rule now answers `UNVERIFIED` instead of naming a later rule.
> That is the correct answer, and it is a changed answer — re-run
> `tools.acceptance` against both packages and re-confirm before trusting the
> old expectations.

### Changed

- **`app/matching.py`** — the tri-state predicates (address, service, VPN,
  domain, service-query resolution) moved out of `traffic.py`, which the
  fourth dimension pushed to 715 lines, past the 700-line module guard. The
  split follows the seam that was already there: this file answers "does X
  match Y" and knows nothing about rules, which is why `nat_correlate.py` can
  now import the address matcher directly instead of through the function-local
  import it needed to dodge a cycle. `from app.traffic import ...` still works.
- `tools/suggest_cases.py`, both defects from its first live run:
  - `All_Internet` (0.0.0.0/0) was sampled as `0.0.0.1` — an address that is
    genuinely inside the object, looks like a real test input, and tests
    nothing. Any object covering a /8 or more is now reported as too broad to
    sample, because choosing which off-lab address means something is a human
    decision.
  - `--only 1,2,3,7` also matched inline rules 8.1, 8.2 and 8.3: an inline
    child's `rule-number` restarts at 1 inside its layer. The filter now
    matches the display number, so `--only 8.1` is expressible too.

### Tests

461 → 477. New: `test_v424_vpn_column.py` (12).

---

## v4.23.0 — the Chapter 4-6 homework, and the four defects doing it uncovered

The learning guide ends each chapter with exercises. Working through them was
supposed to produce notes; it produced four defects instead, three of which
no test in the 381-test suite could see.

**A NAT rule sent in singular form was skipped in silence.** Access rules
always send `source` as a list, so `ObjectResolver.uids()` returns `[]` for
anything else — and `correlate_nat()` fed it `original-source` straight from
the API, which for a NAT rule can be a bare uid. The rule matched nothing and
was passed over without a word. This is the `_as_list()` lesson Chapter 5
teaches, in the one file that had not learned it. Reproduced before the fix:

```
singular form -> []
list form     -> [{'rule': 1, 'name': 'Hide lab out', ...}]
```

**NAT correlation was boolean, so it could name the wrong rule.** A NAT rule
built on an object with no static model answered "does not match", and since
NAT is first-match-wins, the next rule down became the answer. Not a partial
answer — a different rule, shown with no warning. Correlation moved to
`app/nat_correlate.py` and is now tri-state on the same rule as the Access
side: an unevaluable rule ABOVE a proven one is returned first, and the proven
rule carries `blocked_by`. Where every object resolves, every field of the
result is byte-for-byte what it was.

**An unmodellable object listed first hid a real match.** Chapter 4's exercise
(a) asks you to make `address_match_state()` return `unknown` on the first
object it cannot model, then explain what breaks. What broke was one test, and
it was about how a blocker is *named*, not about a verdict. The behaviour the
rule exists to protect was uncovered:

```
field ["InternalZone", "LAB-VLAN10"] vs 192.168.10.50 -> unknown
field ["LAB-VLAN10", "InternalZone"] vs 192.168.10.50 -> match
```

Same rule, same packet, different answer depending on the order the API listed
the objects. `tests/test_v423_match_order.py` closes that for addresses and
services both.

**A secondary management server with no primary rendered as a standalone
one.** `network_map()` handled one primary with N secondaries, and two
primaries, and fell out of the `if` chain for the third case saying nothing —
so a secondary whose primary the API did not return was drawn exactly like a
lone management server, which is a different estate. Pairing is now done one
domain at a time (`domain` is a field the API already sends, and a
Multi-Domain payload's "two primaries" is two domains, not an ambiguity), and
all three shapes state themselves in `limitations`.

### Added

- **Traffic Path on the network map** (`app/path_map.py`, Chapter 6 exercise d).
  The join between the two models is the only thing in both: the addresses,
  tested against the subnets the map derived from interface addresses. Past
  that join the overlay carries *two* confidences, because they fail
  independently — `policy_confidence` (does the rulebase decide this flow) and
  `topology_confidence` (does the packet pass through this box). An exact
  `accept` to 8.8.8.8 is a certain verdict on a path the map cannot see. What
  is drawn is the weaker of the two, and the three styles differ by dash
  pattern as well as colour so a colour-blind reader and a greyscale
  screenshot both keep the distinction. A failing `show-gateways-and-servers`
  costs the overlay and nothing else.
- **NAT install-on validation** (Chapter 5 exercise d). Each rule's install-on
  target compared with the live gateway list, with its own UI tab. Two traps
  kept by tests: `Policy Targets` means every gateway and is never a finding,
  and without the gateway list the result says the check *did not run* —
  `install_on_checked: false` and `install_on_unknown_rules: null`, never `0`.
- **Ambiguous service-name warnings** (Chapter 4 exercise d). The lab's own
  trap: Check Point ships an object called `RDP` which is UDP/259, while
  Remote Desktop is `Remote_Desktop_Protocol`. Resolution is unchanged — the
  rulebase is written in object names — but a protocol mismatch, or a policy
  object shadowing a standard service name, is now stated instead of left in a
  small display string.
- **ICMP end to end** (found while doing Chapter 4 exercise c). The resolver
  has modelled ICMP since v4.10, but the protocol selector offered tcp and udp
  only, so no ICMP rule in any policy could be traced from the UI, and an ICMP
  query displayed as `ICMP/8` — port notation for a protocol with no ports.
- **`tools/suggest_cases.py`** (Chapter 4 exercise c). Derives one flow from
  each rule's own objects and prints what the application says today. It does
  not write `acceptance_cases.json`, and every case it emits carries
  `expect: null`: promoting one is a human decision made against SmartConsole.
  Hand-written cases would need invented addresses, and an invented address
  falls through to the cleanup rule, so the case passes while testing nothing.
- **`docs/Firewall-Insight-Learning-Guide-Ch4-6-Answers.md`** — the worked
  answers, with the measurements each one rests on, and the two questions that
  need the lab still marked unanswered rather than guessed.

### Changed

- `describe_uid()` reads `ipv4-address` / `ipv6-address`, not only the generic
  `ip-address`. Real `show-object` payloads use the former, so host objects
  had been rendering without their address throughout the NAT table.
- NAT duplicate signatures resolve a name-only reference to its uid when the
  objects-dictionary names exactly one such object (Chapter 5 exercise c).
  An ambiguous name is left as written: announcing a duplicate that cannot be
  proven is the more expensive mistake.
- `tools/diag_topology.py` prints each management host's domain.
- README: the "Known limitations" paragraph claiming `app/main.py` embeds the
  frontend as a Python string was three releases out of date. Replaced with
  the map and NAT-correlation limits that are actually true.

### Tests

381 → 461. New files: `test_v420_nat_tristate.py`, `test_v420_service_names.py`,
`test_v421_nat_install_on.py`, `test_v422_multi_management.py`,
`test_v423_trace_on_map.py`, `test_v423_route_overlay.py`, `test_v423_icmp.py`,
`test_v423_suggest_cases.py`, `test_v423_match_order.py`,
`test_v423_nat_signature.py`.

`test_v44_source.py` had one assertion pinning the whole Port/Service
placeholder string, which its own docstring says it avoids doing. Adding ICMP
to that field made a true statement about the UI fail; the assertion now
checks the meaning, as intended.

### Still open

- Chapter 5 exercise a — `External-FW` has 11 NAT rules and `Internal-FW` 10.
  Both numbers are in the acceptance evidence; which rule differs is not, and
  answering it needs the lab.
- The cases for `External-FW` rules 1, 2, 3 and 7 exist as a generator, not as
  expectations. `expect` stays `null` until a human confirms each verdict.

---

## v4.19.1 — the runner was judging the policy it said it would not judge

`tools/acceptance.py` opens with "it does not judge whether the POLICY is good
— that is what the Analyze page is for", and then three of its checks did
exactly that. Running it against `Internal-FW` (one `Allow-Any` rule) produced
**16/19 with 3 failures**, of which only one was about the policy at all:

| reported as a tool failure | what it actually was |
|---|---|
| `inline layers discovered: 0` | the package has none, which is allowed |
| `cleanup rule recognised: cleanup=0` | no trailing Drop, which is a policy choice |
| `no Any/Any/Any permit rule` | a genuine policy finding, in the wrong place |

A run that cannot be green until the estate is perfect is a run nobody looks at
twice. The checks are now split:

- **Checks** answer *does this application report the estate correctly* — they
  must pass on any package. Where a feature has nothing to exercise (no inline
  layers, no cleanup rule) the check reports INFO instead of inventing a
  requirement out of how one package happens to be written.
- **Findings** answer *what did the application find* — permit-all rules,
  missing cleanup, shadowed and duplicate rules, disabled and zero-hit rules.
  Printed and stored in `policy_findings`, never counted as failures.

First run after the split: **External-FW 26/26**, `Internal-FW` green on the
tool with the permit-all rule reported as a finding.

---

## v4.19.0 — three policy packages, and a permit-all rule is a finding

The lab grew from one policy package to three (`External-FW`, `Internal-FW`,
`Standard`), which the acceptance run only discovered by listing them. Two
consequences:

**Cases are now keyed by package.** One flat list of flows cannot describe
three different rulebases. `acceptance_cases.json` takes a `packages` map;
a flat `cases` list still works. Running against a package with no cases
defined says so rather than reporting a clean run — zero cases and zero
failures otherwise look identical to a pass.

**An Any/Any/Any *permit* rule now fails the run.** `Internal-FW` is a single
`Any → Any → Any → Accept`. The existing check only confirmed that a trailing
Drop was recognised as a cleanup rule; nothing said anything about a rule that
permits everything. A tool that scores that 100 and moves on is not worth
running.

### Fixed — the first run's failure was my case file, not the policy

`VLAN10 client reaches RDP server on VLAN20` used `192.168.20.10`. The real
object is `RDP-Server_192.168.20.100`, and `Web-Server` is `192.168.20.20`.
The cases are now transcribed from the live rulebase, with a `why` field on
each naming the rule it exercises, and they include the negative direction of
every permit: VLAN20 must *not* reach RDP, VLAN10 must *not* reach AD over
LDAP. A matrix of permits alone cannot tell a working firewall from an open one.

---

## v4.18.1 — a failing check names the rule that decided

First run against the live lab: **21/22**, and the one failure was a real
finding — `VLAN10 client reaches RDP server on VLAN20` came back `drop`.

The report said what happened and not why, which sends you back to
SmartConsole to work out which rule did it. Each traffic case now records the
walked path — layer, display rule number, rule name, action — so the failure
line reads `expected accept, got drop via Network rule 5 (Access-to-RDP)`
instead of stopping at the verdict.

`acceptance-report.json` gains `decided_by`, `path` and `reason` per case.

375 tests.

---

## v4.18.0 — an acceptance run, so "is it tested?" has an answer

"ทดสอบให้เสร็จ" had no pass criteria, so the honest answer to *is Project Dev
tested?* was "somewhat". `tools/acceptance.py` replaces that with a number:
22 checks against the live lab, one line each, a total, and a non-zero exit
code when anything fails. It also writes `acceptance-report.json`, so a
screenshot of a green run is backed by something a reviewer can open.

```
1. Safety        no mutating Management command anywhere in app/
2. Connection    login · the named policy package exists
3. Access        rulebase loaded · inline layers found · cleanup rule
                 recognised and not counted as Any/Any/Any · score computed
4. Data quality  hydration not truncated · every inline layer loaded ·
                 result reports itself complete
5. Traffic Path  one check per flow in tools/acceptance_cases.json
6. NAT           rulebase loaded · show-hits probed rather than assumed
7. Topology      objects → nodes · cluster membership from the API ·
                 management HA pair · subnets derived · limitations stated
```

Expected traffic verdicts live in `tools/acceptance_cases.json` — editable
without touching the runner, seeded from the documented lab. A case with
`"expect": null` is recorded but never judged, for a flow you want on the
record before deciding what it should do. **Rule numbers are deliberately not
asserted**: they shift whenever a rule is inserted, and a test that breaks on
renumbering teaches you to ignore it.

The traffic checks call `trace_access_tree` through the same resolver
construction `app/api/traffic.py` uses. Calling the single-layer
`trace_access()` would have tested a different code path from the one the UI
walks, which is worse than not testing at all.

### Tests

`tests/test_v418_acceptance.py` (13) drives the whole runner against a fake
Management Server. It cannot prove the lab is healthy — nothing offline can —
but it proves the runner *runs*: every signature it calls, every result key it
reads, and the inline-aware trace it walks. A tool that dies on
`TypeError: package_access_tree() takes 2 positional arguments` the first time
it meets a real server is worse than no tool, because it fails exactly when
you were relying on it. Two of the tests exist to stop the matrix becoming
decoration: one asserts a wrong expectation actually fails the run, another
that the defaults cover both an allow and a deny.

372 tests.

---

## v4.17.0 — an empty rule dimension is unknown, not covered

Found while writing Chapter 3 of the learning guide, by reading
`_dimension_cover` line by line rather than by hitting it in the lab.

Both containment shortcuts are vacuously true against an empty list:

```python
set([]).issubset(anything)            # True
_intervals_cover(earlier, later=[])   # True - the loop never runs
```

So a rule whose `source`, `destination` or `service` came back as `[]` was
reported as **shadowed by the first earlier rule it was compared against** — a
confident finding derived from no data at all, which is the one thing this tool
must never produce. `_dimension_cover` now returns
`False, "No values on this dimension"` for an empty side.

A real Check Point rule always carries all three fields, which is why this
never appeared against the lab. It is the kind of defect that only shows up on
someone else's estate, in the payload nobody thought to test.

`tests/test_v417_empty_dimension.py` (7 tests) pins it, including that a normal
shadow is still detected — a guard that switches the feature off would pass a
"no false positives" test perfectly.

### Added — `tools/ch3_demo.py`

Runs every claim Chapter 3 makes against the real modules and prints the
result. The chapter quotes its output verbatim, so if the code changes and the
output stops matching, the guide is visibly out of date rather than quietly
wrong. Read-only, no `.env` and no network needed.

### Fixed — the suite was testing the HTML formatter's settings

Commit `a5db12b` ("fix index.html", 24 Aug) ran an HTML formatter over the
template. It changed nothing about the page, but it rewrapped long lines, and
**five tests had been failing ever since**:

```
>&#9642; Access Policy</button>        became        >&#9642; Access
                                                       Policy</button>
```

Every one of those assertions was about the *words on a button* or the *text of
a hint*, not about where the line broke — so they were pinning the editor's
formatting settings, not the application. `conftest.ui_text()` now returns
`ui_source()` with runs of whitespace collapsed, and assertions about visible
text use it. Assertions about structure (ids, attributes, CSS, JS) still use
`ui_source()`, where the exact characters really are the contract.

`test_header_has_no_phase_subtitle` was the same mistake twice over — it pinned
`</h1></div>` with no space. It now asserts "nothing but the closing tag
follows the title", which is what it always meant.

Verified against three different formattings of the same page — unformatted,
the formatter's output, and a deliberate one-tag-per-line rewrap: **359 passed**
in all three.

359 tests.

---

## v4.16.1 — five defects the live lab showed

### Fixed — cluster cards rendered as empty rectangles

v4.16 split the `gateway` role into `gateway` / `cluster` / `cluster-member`.
Cards mode styles by role, so the two new roles had no rule at all and drew
unfilled, unstroked boxes — External-Cluster, External-GW01 and External-GW02
all appeared as black rectangles while Internal-GW01 stayed purple. Both roles
now have card fills in light and dark, and a test asserts every role the map
emits is styled **in both modes**, so the next role split cannot repeat this.

### Fixed — the map used half the panel

Component packing guessed one shelf width, and on a panel twice as wide as it
was tall that put the management pair *below* the firewall estate. The tall
result then had to be scaled down to fit: the lab rendered at **0.6×**. Instead
of tuning the constant, it now lays the shelves out at six widths and keeps
whichever renders largest — which is what "best" means here. Same lab, same
panel: **1.26×**, and the HA pair sits beside the estate.

Components are also padded by their own nodes' radii rather than a constant.
A radius already tracks label width, so a fixed pad let `192.168.20.0/24` in
one component print over `CP-MGMT-01`'s address in the next. Measured on the
lab at 1920px and at 1500px: **0 overlapping labels** in every state.

### Fixed — a merged subnet was a dead end

Auto Merge answers "how many subnets sit behind these devices". There was no
way to ask "which ones" — the node was not clickable. A merged node is now
expandable: clicking it opens that one group back into its members without
turning merging off everywhere else.

### Fixed — a node added later started in the middle of the map

Unmerging a group creates a node in an arrangement that already exists. It was
seeded on the golden-angle spiral, i.e. in the centre of everything, and
dragged its links across the picture. A node that is new to an existing layout
now starts at the centroid of the neighbours it connects to.

### Fixed — Save Map underlined every label, one interaction late

Save pins all nodes, and the "placed" marker was a dotted underline, so after
saving all eleven names looked like links. It is now a small dot in the node's
corner. Save also re-renders, so the markers appear when you press it rather
than on the next unrelated click.

---

## v4.16.0 — clusters are one firewall, and Management HA is on the map

Two questions from the lab: *should External-Cluster, External-GW01 and
External-GW02 be merged?* and *how are CP-MGMT-01 and CP-MGMT-02 linked?*
`tools/diag_topology.py` (new, read-only) answered both against the live R82.

### Added — cluster membership, from the cluster's own member list

```
External-Cluster  [CpmiGatewayCluster]
  cluster-member-names: ['External-GW01', 'External-GW02']
External-GW01  cluster-member  back-reference: NONE
```

`show-gateways-and-servers` returns the cluster **and** its members as
top-level objects, and the members carry no pointer back, which is why the map
drew three peers. It is now one cluster node with a second plate behind it, its
members attached by a dashed membership link, and Collapse folds the members
into it. Roles split: `cluster`, `cluster-member`, `gateway`, `management`.

**Membership is never inferred from addresses.** A /30 with .1 and .2 looks
like sync, and a third address on a member's subnet looks like a VIP — those
readings are right most of the time, and a map that is "usually right" about
which boxes are one firewall is worse than one that says it does not know.
Strip `cluster-member-names` from the payload and the app draws no membership
at all; if a named member is missing from the response, it says so in
`limitations` rather than quietly showing a smaller cluster.

What *is* read off the graph: a subnet no cluster interface touches, reached
only through members of one cluster, is internal to it. `10.99.99.0/30` is
marked accordingly, and the tooltip gives the evidence before the conclusion —
"No interface of External-Cluster is on this network, only its members are. On
a ClusterXL deployment that is the sync network."

### Added — Management HA

I was wrong when I said the API does not expose this. It does, in a field I had
not checked:

```
CP-MGMT-01  management-blades: [logging-and-status, network-policy-management]
CP-MGMT-02  management-blades: [logging-and-status, network-policy-management,
                                secondary]
```

`management-blades.secondary` marks the standby, and a domain has exactly one
primary — so primary + secondary *is* the pair, by definition rather than by
inference. Both are labelled with their role and joined by a green dashed HA
link. Two primaries, or a log-only server, draws nothing and says why.

The map says HA is **configured**. It never says it is healthy: whether the
peers are currently synchronised is not in the object model, and that caveat
is in `limitations` and in the node tooltip.

### Added — internet-facing subnets

Cluster interface 2 reports `topology.leads-to-internet: true`, so
`172.23.34.0/24` is marked as facing outside. Only that flag marks it; nothing
is guessed from address ranges.

### Changed — traffic.py split

`traffic.py` held four concerns and this work pushed it past the 700-line guard
that `test_v413_structure.py` enforces — the split flagged as deferred in
v4.13. The graph builder moved to `app/topology_map.py` (182 lines);
`traffic.py` re-exports `network_map` so existing imports keep working.

### Fixed — layout, for the shape this created

- The HA pair has no interface to the estate, so it is a second connected
  component. Fruchterman-Reingold assumes one graph: gravity pulled both to the
  middle while repulsion shoved them apart, compressing one and flinging the
  other. Components are now laid out together and then shelf-packed as rigid
  bodies — deterministic, and skipped entirely once the user has placed a node
  by hand.
- A member link is pulled to 0.78× a subnet link, so members sit with their
  cluster.
- Spacing now clears the widest label (`max(panel-derived k, widest × 1.35)`);
  a panel-derived k could come out smaller than the labels it had to separate.
- Collapsing a cluster used to strand `10.99.99.0/30` with no links at all.
- `topoDeclutter()`: geometry keeps an edge label clear of its own two
  endpoints, but nothing cheap predicts it landing on a *third* node's label.
  After the layout settles, measure what rendered and drop the few that
  collide — the interface label gives way, never the node name. Measured on
  the lab: **8 overlapping labels → 0**.

### Tests

`tests/test_v416_cluster_ha.py` (28). 340 total.

---

## v4.15.1 — graph view polish, after seeing it against the live lab

Rendering the real 7-firewall lab (22 objects → 11 nodes, 11 links) exposed
five things the synthetic fixture did not.

### Fixed — the map used a third of the panel

The SVG had a fixed `1600×1000` viewBox with `preserveAspectRatio`, so on a
1540×600 panel the whole graph was letterboxed into a centred 1.6:1 box with
empty panel either side. The viewBox is now the container's own pixel size —
one world unit is one CSS pixel — and it is re-set on resize (trailing edge
only; a resize fires continuously and the layout must not thrash).

### Fixed — a bigger screen bought you smaller labels

Edge length was a constant 150 units, which laid 11 nodes out over ~1300×850.
That had to be fitted into the panel at **67%**, so 12.5px labels rendered at
8.4px. Spacing now scales to the panel (`√(area/n) × 0.45`, clamped to 90–170)
and gravity is anisotropic — pulling harder on one axis compresses it, so a
`√aspect` split makes the settled cloud roughly the panel's shape rather than a
tall column. Same lab now fits at **~0.9–1.1×**. A dense estate still overflows
and is explored by zooming, which is correct.

### Fixed — labels printed on top of each other

`3 connections` and `if2` landed in the same place in the lab: an edge label
sat exactly on the midpoint, which is also where a short edge passes under a
node's sub-label. Labels now sit 9px off to the side of the line, are dropped
entirely on edges shorter than half the ideal length, and are painted with a
background-coloured outline (`paint-order: stroke`) so they stay readable
wherever they land. Node repulsion radius now follows the *label* width, not
the chip — two 14-character subnet names need more room than two 18px boxes.
Measured: **0 overlaps** between edge labels and node sub-labels.

### Fixed — a node could settle behind the pan/zoom pad

`CP-MGMT-01` did. The pad floats over the canvas, so fit now treats its
footprint as unusable space. Measured: **0 nodes intersecting the pad**.

### Fixed — clicking some devices did nothing

Every device was marked expandable, but a management server has no subnets
behind it and a gateway whose subnets are all shared has no leaves either — so
the click toggled an empty set. Only a device with something to hide is
expandable now; the rest isolate on a single click. **Double-click isolates
anything** (on an expandable device the two single clicks toggle it there and
back first, so the net effect is just the focus).

### Changed — no more emoji in the chrome

The Export buttons were 📷 and 📄, which render at the font's own colour and
weight and looked pasted on next to the app's SVG icon set. Export, the search
step arrows, and the pad's five controls are now inline SVG line art that
inherits the button colour. Only `−` and `+` remain as text, where a glyph is
the right answer.

### Tests

`tests/test_v415_graph_map.py` grows to 63. 312 total.

---

## v4.15.0 — Network Mapping gets a graph view

### Added — a physics layout, the way AlgoSec's Discover and Map reads

v4.14's two-column layout answers "which port on this gateway reaches which
subnet" well, and answers "what does this network actually look like" badly:
the shape of an estate is not visible in a bundle of parallel edges. Network
Mapping now has **two layouts**, switched in the toolbar:

| | Graph (default) | Cards |
|---|---|---|
| Shape | gateways as hubs, subnets orbiting | two columns |
| Best for | what sits between A and B | which interface reaches which subnet |
| Interfaces | edge labels (`if1`, `if2`) | rows inside the device card |

The graph runs a **Fruchterman-Reingold** simulation in plain JavaScript — no
library, no build step, works offline. It is seeded on a golden-angle spiral
rather than `Math.random()`, so the same topology lays out identically every
time; without that a saved arrangement would be meaningless. Repulsion is
`k²/d` plus a hard shove that only applies while two nodes actually overlap,
which is what keeps labels off each other. Unlinked nodes (a management server
with no modelled interfaces) get gravity 3.2 instead of 0.9, so they sit
beside the estate instead of defining its bounding box.

### Added — the controls that make a big map usable

- **Save Map / Reset Map** — drag any node to place it, then save. Positions
  are keyed to a hash of the node set, so one topology's coordinates are never
  reapplied to a different estate. Reset clears them and re-runs the physics.
- **Auto Merge** — subnets reached through exactly the same set of devices
  share one node. It is a presentation grouping: nothing is dropped, the count
  is shown, hovering lists the members, and clicking it again undoes it. On a
  40-gateway estate this took the map from 241 nodes to 81.
- **Collapse all** — hides the subnets that hang off exactly one device, which
  leaves the backbone. A subnet reached by two gateways is never hidden: it is
  part of the path between them, so hiding it would change what the map says.
  A collapsed device carries a `+N` badge for what is behind it.
- **Search IP / Subnet / Name** with ▲ ▼ to step through matches — each hit is
  centred and flashed; non-matches dim rather than disappear.
- **Show / Hide Legend**, and **Export** to PNG and CSV. The PNG re-attaches
  the topology CSS rules and resolves their custom properties into the
  serialised SVG, because a detached SVG leaves the page stylesheet behind and
  would otherwise export as black shapes on a transparent field.
- **Pan/zoom pad** bottom-right: D-pad, −/+, fit-to-screen and a slider, plus
  scroll-to-zoom and drag-to-pan on the canvas itself.

### Fixed

- `topoBindEvents()` runs on every render, and it registered a `window` mouseup
  listener each time without removing the old one — one leaked handler per
  render for the life of the session. Drag state moved onto a module-level
  object and the listener is now registered once.
- A re-render (filter, focus, collapse) re-ran the whole simulation and threw
  away the user's arrangement and zoom. Positions now persist across renders;
  only genuinely new nodes trigger physics.

### Verified in headless Chromium

Against a fixture reproducing the lab (20 objects) and a synthetic 40-gateway
estate (481 objects):

```
lab      : 11 nodes / 9 links, min node separation 180 units, 0 overlaps
           layout identical across two independent runs
collapse : 8 nodes, 3 hidden      merge: 10 nodes, 2 subnets merged
focus    : 6 dimmed               search "192.168": 2 hits, 9 dimmed
step     : hit centred to (0,0) offset, flash applied
drag     : node pinned, status reads "1 placed"
save     : 11 positions stored -> reload -> all nodes fixed -> reset clears
export   : 7.9 KB of style inlined, 7,366 non-background pixels rasterised
40 GW    : 481 objects -> 241 nodes / 240 links, 0 overlaps, 6.2 s to settle
           Auto Merge -> 81 nodes (200 merged); Collapse all -> 41 nodes
390 px   : no horizontal overflow, pad reachable
0 page errors in any state
```

### Tests

`tests/test_v415_graph_map.py` (46 tests). 295 total.

---

## v4.14.0 — Network Mapping redesign

### Changed — interfaces are no longer nodes

The old view drew every interface as its own node in a middle column. In the
lab that is 4 gateways + 2 management hosts + 5 subnets = 11 real things, but
the view rendered **22 nodes across 3 columns**, and every subnet edge had to
cross the interface column. The result was a hairball that told you less than
the raw JSON did.

An interface is not a peer of a gateway — it is a *part* of one. So it is now
a row inside the gateway card:

```
before                                  after
  [GW01] ── [interface 1] ── [10.99.99.0/30]     [GW01        2 ports ›] ── [10.99.99.0/30]
        └── [interface 2] ── [172.23.31.0/24]      interface 1  10.99.99.1/30
                                                   interface 2  172.23.31.177/24
  22 nodes, 3 columns                            11 nodes, 2 columns
```

- **Click a gateway** to open or close its interface rows. Collapsed, edges
  leave the card edge; expanded, each edge leaves the row it belongs to and is
  labelled with the interface, so you can see *which* port reaches a subnet.
- **Click a network** to isolate it — everything not connected to it dims,
  rather than disappearing, because the context is what makes the hit useful.
- **Filter box** dims non-matching nodes by name or address.
- **Expand all / Collapse all / zoom / Reset**, plus scroll-to-zoom and
  drag-to-pan. A drag of more than 4px is not treated as a click, so panning
  across a card no longer toggles it.
- Networks are ordered by the mean Y of what connects to them, which removes
  most edge crossings without a full layout solver.
- Cards are keyboard reachable (`Tab`, then `Enter`/`Space`) and report
  `aria-expanded`.

Honesty is unchanged: the banner still says the topology is logical only, and
an interface with no CIDR renders as `—` rather than a guess.

### Fixed

- The port-count pill clipped the trailing "s" of "ports" at some zoom levels;
  it is now sized for the widest label with the chevron parked clear.
- `topoExpandAll()` rebuilt the entire topology model once *per device*.
- `@app.on_event("shutdown")` is deprecated in FastAPI; the Management API
  logout now runs from a `lifespan` context manager.

### Tests

`tests/test_v414_topology.py` (26 tests) pins the contract of the redesign —
interfaces never emitted as nodes, expand/focus/search reachable, drag is not
a click, every emitted CSS class actually has a rule. Three test files pinned
the version as a literal string, so every release edited unrelated files; they
now assert what they meant (`version.py` defines it exactly once, the UI
reports the same version the app declares, the version never goes backwards).

Verified in headless Chromium against a fixture reproducing the lab exactly:
11 nodes / 9 links collapsed, 9 interface rows when fully expanded, 6 nodes
dimmed on network focus, 9 on a filter, no page errors.

---

## v4.13.0 — project structure, and UI fixes from the lab

### Changed — main.py was 2,473 lines, 83% of it an embedded frontend

`app/main.py` held the routes, the policy orchestration, the cache, the
progress registry **and** 100KB of HTML + CSS + JavaScript as a single Python
string. That meant no syntax highlighting or linting for the frontend, no
browser caching of assets, and one file that every change had to touch.

```
app/
  main.py            42 lines  — app factory and router include, nothing else
  version.py                   — single source of truth for APP_VERSION
  runtime.py                   — Management client, cache, HTTP error mapping
  progress.py                  — live phase registry for long requests
  policy.py                    — fetch -> hydrate -> analyse orchestration
  api/  meta access nat traffic topology export ui
  templates/index.html
  static/css/app.css
  static/js/app.js
  (analysis modules unchanged: checkpoint, resolver, analyzer,
   nat_analyzer, inline_layers, policy_browser, traffic)
```

**Deliberately not done:** the analysis modules were not moved into a
`services/` package. They are already single-responsibility and 90–650 lines
each; renaming them would have churned twelve test files for no structural
gain. `traffic.py` (651 lines) does deserve a split — matching, tracing, NAT
correlation and the topology graph are four concerns — but that is a behaviour
change worth landing separately and re-validating against the lab.

`tests/conftest.py` now exposes `app_source()`, which concatenates every file
the application is built from. Twenty test files asserted "this string exists
in app/main.py"; they now assert "this exists in the application", which is
what they always meant.

New `tests/test_v413_structure.py` keeps the structure from collapsing back:
main.py under 60 lines, no module over 700, no markup inside a `.py`, routers
that do not import each other, one home for the version — and, still
structural, **every route is a GET and no mutating Management command appears
anywhere in the source**.

### Fixed — five things the lab screenshots exposed

**Monospace applied to words.** `.metric` was styled with JetBrains Mono for
tabular figures, but metric *values* include `Access Control` and `Standard`,
which rendered as if broken. `metricCards()` and `setDashboardMetric()` now add
`.num` only for numeric values, and only `.metric.num` is monospaced.

**A bright bar under every wide table.** `::-webkit-scrollbar-thumb` was styled
but the *track* was not, so it fell back to light grey against a dark table.
Track and corner are now transparent and the thumb is inset.

**A bare strip below the sidebar.** The sidebar is `position:sticky` with
`height:100vh`, so on a page taller than the viewport its grid cell continued
below it and showed the page background. The column is now painted by a fixed
layer on `.app` that animates with the rail.

**A legacy media query fighting the new one.** The old `max-width:1100px` block
turned the sidebar into a horizontal strip, which collided with the collapsible
rail between 900px and 1100px. Reduced to the card reflow it was actually for.

**Four unlabelled inputs.** Traffic Path showed four bare boxes; you had to
click into each one to learn which was source, destination or service. They now
have visible labels, and the panel states up front that no packet is sent.

### Fixed — the collapsed rail, and two features that were built but unreachable

**The rail was still wrong after collapsing.** `.menu button` sets
`justify-content:flex-start` for the expanded layout and the rail rules never
overrode it, so every icon hugged the left edge of the 74px column. All six now
centre at offset 0.0px, verified in Chromium.

**Static assets had no cache-busting — a bug the refactor itself created.**
While the CSS and JS were inline in the HTML, every reload picked up the newest
version automatically. As separate files under `/static/` the browser caches
them, so upgrading left new markup running against stale styles: the theme
button rendered **both** the sun and the moon, and the collapse button still
said "Collapse". That looks like a broken UI, not a stale cache, which is the
worst kind of failure to hand a user. Asset URLs now carry
`?v={APP_VERSION}-{newest static mtime}` — the version makes an upgrade visible
to every existing user, the mtime makes an edit visible on the next reload
under `--reload`.

**The sidebar footer was louder than the navigation.** A full-width "Collapse"
pill and a "Light Mode" label with a toggle switch drew more attention than the
menu above them. Both are now quiet icon buttons: a sun/moon that shows the
theme you will switch *to*, and a collapse arrow that flips direction. `Ctrl+B`
collapses, `Ctrl+J` switches theme.

The icons are **inline SVG, not font glyphs**. `☀` and `☾` render differently in
every font stack and looked wrong in the fallback face; SVG is crisp at any size
and inherits `currentColor` like text does.

Two defects in that footer were caught by measuring it in Chromium rather than
looking at it:

- `.icon-btn .ico` is specificity (0,2,0) and silently beat a bare
  `.ico-moon{display:none}` at (0,1,0), so **both** icons rendered in dark mode.
  The show/hide pair now matches that weight.
- `flex:1 1 0` sizes the *main* axis, so stacking the row into a column in the
  rail made flex-basis apply to height and the buttons collapsed from 36px to
  19px. The rail gives them an explicit 44×38.

The rail also drops the 3px inset active bar: it is an edge marker for a
full-width row, and on a centred 44px square it read as a stray line. The brand
becomes a gradient badge rather than two letters floating in a gap.

**"Export Raw CSV" exported nothing.** It printed *"Package-level CSV export
will be added after package/inline validation"* — a stub left behind when the
UI became package-first in v4.2 while the CSV endpoint stayed layer-first. New
`GET /api/package-policy-browser.csv?package=` exports the whole package with
`Display Rule` and `Layer Path`, so an inline row reads `7.1` under
`Network → InternetLayer` rather than an ambiguous `1`. The package name is
sanitised before it reaches `Content-Disposition`.

**Zero-hit and disabled rules were computed and never shown.** `analyzer.py`
has produced `zero_hit_rules` and `disabled_rules` since v4.0 — with layer,
display rule and hit counts — and no view rendered them. The lab had **9 of
them invisible**. Analyze now has an **Unused Rules** tab merging both
(disabled wins the label, so a rule is never listed twice), with the Dashboard
linking to it.

It carries an explicit caveat rather than a recommendation: hit counters reset
on policy install and on gateway restart, and a rule can protect a path that is
simply idle. "Unused" is a review candidate, never a delete instruction — the
same reason Traffic Path says `UNVERIFIED` instead of guessing.

### Tests

191 → 223. New: `tests/test_v413_structure.py`, `tests/test_v413_ui_polish.py`.
Two assertions were rewritten
to test intent rather than an exact string, for the same reason as in v4.12:
`test_v44_source` pinned four placeholder strings that moved into labels.

Verified after the move: all 17 routes answer 200 against a fake Management
client, the page loads from a real uvicorn with both assets served, no console
errors, and the font stack still renders correctly **with fonts.googleapis.com
blocked** — the air-gapped case.

---

## v4.12.0 — real progress, collapsible rail, typography

### Fixed — the step indicator was decoration that lied

v4.11 showed Traffic Path a four-step list, but the browser makes **one**
request and cannot see server-side phases, so the list advanced on a
client-side guess. Observed behaviour: it sat on step 1 for 27 s and then
jumped straight to done.

The steps were not merely mistimed — they were the same class of dishonesty
this project keeps fixing elsewhere: a display that asserts more than the code
actually knows.

Now the backend records its phase against a client-supplied request id
(`?rid=`), and the UI polls `GET /api/progress?rid=`:

```
phase 0  Loading package / inline layer tree
phase 1  Resolving objects and service
phase 2  Walking the ordered rulebase
phase 3  Correlating NAT
```

Measuring it exposed the real cause of the "stuck" feeling: **phase 0 takes
tens of seconds while phases 1–3 finish in microseconds.** Since v4.9, first
load issues one `show-object` per thin object at 0.55 s pacing, and that is
virtually the whole runtime. Balanced-looking steps would have been a second
lie, so `hydrate_objects()` now takes an `on_progress` callback and the overlay
shows a moving counter:

```
Network: resolving object 34/49
```

A cached result reports `done` with label `Served from cache` immediately, so
the overlay can never hang on step 1 for a request that already finished.
Progress is best-effort throughout: a failure in the progress channel never
fails the real request, and a request without `rid` is unaffected.

### Changed — toasts moved to the top right

### Added — collapsible sidebar

`Ctrl/Cmd+B` or the Collapse button shrinks the sidebar to a 74px icon rail
with hover tooltips; the state persists in `localStorage`. The active marker
moved from `::before` to an inset shadow because a button has only two
pseudo-elements and the rail needs `::before` for the icon and `::after` for
the tooltip. Icons come from an explicit `data-icon` attribute — `::first-letter`
does not apply to buttons, so the first attempt rendered a blank rail. The
sidebar also gets `z-index` in rail mode, or the tooltip draws behind the
panels.

### Added — typography

`Nunito` for Latin (rounded, blunt terminals), `Anuphan` for Thai
(loopless — ไม่มีหัว — geometric, pairs with Nunito), `JetBrains Mono` with
tabular figures for rule numbers, IPs, ports, scores and elapsed time, so
columns of data line up. The stack falls back to `system-ui` and
`Noto Sans Thai`; **air-gapped installs should self-host the three families and
replace the `<link>` with local `@font-face`**, since a Management network
usually cannot reach fonts.googleapis.com. Noted inline in the CSS.

### Added — motion polish

Metric scale on card hover, alert badges pulse on drill hover, pill lift on row
hover, input focus rings, animated sidebar width. All still disabled under
`prefers-reduced-motion`.

### Changed — one test now asserts intent instead of a literal

`test_phase310` pinned the exact string
`data-page="browser" onclick="…">▤ Access Policy</button>`. Adding `data-label`
for the rail tooltip broke it, while the property it exists to protect —
Access Policy ordered before Analyze — still held. It now compares attribute
positions and checks the labels separately.

### Tests

165 → 190. New: `tests/test_v412_progress.py`, including a spy that asserts the
per-object counter strictly increases and that traffic phases are emitted in
order.

---

## v4.11.0 — feedback, status and responsive shell

Reported symptom: after clicking an action the app looked frozen, and telling
"working" from "finished" from "crashed" meant opening DevTools → Network.

That was accurate. The only feedback channel was one line of text
(`S.textContent = …`), and eight code paths ended in
`catch(e){S.textContent=e.message}` — a raw string with no cause, no remedy and
no way to report it. Since v4.9 a first package load also issues one
`show-object` per thin object at 0.55 s pacing, so 10–20 s of apparent silence
became normal.

### Added — activity is always visible

- **Top progress bar** driven by a global in-flight request counter, so *any*
  request shows activity without each call site opting in. `aria-busy` is set
  on `<body>` for assistive tech.
- **Blur overlay** for blocking work: translucent glass
  (`backdrop-filter: blur(9px)`, `rgba(…,.62)`, with a light-theme variant),
  a spinner, an **elapsed-time counter**, and named **step progress** so a long
  run shows which phase it is in rather than one opaque spinner.
- After 6 s the overlay explains *why* it is slow — per-object hydration paced
  under the API rate limit, cached for 5 minutes afterwards — so expected
  slowness stops reading as a hang.
- **Per-button busy state**: the clicked button shows its own spinner and is
  disabled, and `task()` refuses to start a job whose key is already running,
  so double-clicking can no longer fire two analyses.
- Requests now have an `AbortController` timeout instead of hanging forever.

### Added — failures reach the user, not the console

`describeError()` maps a failure to a cause and a remedy:

| Symptom | Reported as |
|---|---|
| `Failed to fetch` | Cannot reach Firewall Insight — uvicorn looks stopped |
| `HTTP 429` | Management API rate limit — raise `CHECKPOINT_MIN_REQUEST_INTERVAL` |
| `HTTP 502` | Management Server unreachable — check `CHECKPOINT_MGMT` |
| `AbortError` | Request timed out — raise `CHECKPOINT_TIMEOUT` |
| login/credential | Authentication failed — check `.env` |

Each failure now produces a colour-coded status bar, a toast with a **Copy
details** action, *and* an inline error panel with a **Retry** button in the
affected view. `window.onerror` and `unhandledrejection` handlers mean a script
bug surfaces instead of silently doing nothing — the exact class of problem that
sent the user to DevTools. Offline/online transitions are detected too.

### Added — toasts, skeletons, empty states

Four toast kinds (success / info / warn / error) with a life-bar countdown;
**error toasts are sticky** and announce as `role="alert"`. Tables render a
shimmer skeleton while loading instead of collapsing to blank space. Each page
opens with an empty state saying what to do next; the Traffic Path one notes
that the simulation never sends a packet, so the hosts need not exist.

### Added — incomplete results are labelled incomplete

New backend `data_quality()` reports `failed_inline_layers`,
`object_hydration_truncated` and human-readable warnings on
`/api/package-analyze`, `/api/package-policy-browser` and `/api/traffic-path`.
The UI renders a banner plus a toast. Previously a partially-loaded policy was
presented identically to a complete one — the same failure mode as the v4.9
bug, one layer up.

Traffic Path feedback now follows confidence rather than flattening it:
`exact` → success, `inferred` → warning that the gateway log is authoritative,
`UNVERIFIED` → a sticky warning explaining that guessing here risks being
confidently wrong. NAT reports whether the build supports hit counts.

### Fixed — horizontal overflow on mobile

`1fr` is shorthand for `minmax(auto,1fr)`, and `auto` will not shrink below its
content's min-width. One table with `min-width:650px` stretched its grid column
to 688px and forced the whole document to scroll sideways at 390px.
`minmax(0,1fr)` plus `min-width:0` down the chain lets `.table-wrap` scroll
instead of the page, so wide tables stay readable and the layout fits.

### Fixed — status bar nested inside itself

`#status` keeps its legacy `.status` class so every existing `S.textContent`
assignment still works, but that class carried its own background and border,
which rendered as a box inside the new status bar. Neutralised in context.

### Added — responsive and motion

Sidebar becomes an off-canvas drawer under 900px with a scrim and a Menu
button; controls, cards and grids reflow; sticky table headers; touch
scrolling. Page changes, hovers and cards animate on a shared easing scale,
all of it disabled under `prefers-reduced-motion`. `:focus-visible` rings for
keyboard users, `Escape` dismisses toasts and closes the drawer.

### Tests

119 → 165. New: `tests/test_v411_ux.py`. Behaviour was additionally verified in
headless Chromium: blur applied, overlay reference-counted and dismissed,
failure reaching the UI, `scrollWidth == 390` at 390px, double-submit blocked,
no page errors, dark and light themes.

---

## v4.10.0

Follow-up to v4.9. With hydration fixed, `tools/diag_resolver.py` narrowed the
live lab's remaining unresolvable objects from 10 to 2 — and both turned out to
be wrong for reasons that had nothing to do with missing data.

```
AD-Services [service-group]    member count: 10
    ldap [service-tcp]  ldap-ssl [service-tcp]  microsoft-ds [service-tcp]
    Kerberos_v5_UDP [service-udp]  ...  ALL_DCE_RPC [service-dce-rpc]

icmp-requests [service-group]  member count: 4
    echo-request / info-req / timestamp / mask-request  [service-icmp]
```

### Fixed — one unmodellable member discarded the whole group

`service_atoms()` and `address_atoms()` bailed out on the first member they
could not model:

```python
part = self.service_atoms(cu, seen.copy())
if part is None: return None
```

`ALL_DCE_RPC` has no fixed port, so `AD-Services` answered `unknown` even to a
TCP/389 query that plainly matches its `ldap` member.

The two callers were asking different questions with the same strictness:

| Question | Caller | Needs |
|---|---|---|
| "is this port in the set?" | traffic matching | **one** hit — positive evidence |
| "does set A cover set B?" | shadow analysis | **every** atom |

Added `address_atoms_partial()` / `service_atoms_partial()`, returning
`(atoms, complete)`. The matchers use them: a hit on a modelled member is a
definite `match`; failing to hit while something is unmodelled stays `unknown`.
`address_atoms()` / `service_atoms()` remain strict wrappers returning `None`
unless complete, so containment analysis is unchanged and still conservative.

### Fixed — ICMP-only services answered `unknown` to TCP queries

`service_atoms()` understood only TCP and UDP, so an ICMP service was
unmodellable rather than simply non-matching. This was a live hazard, not a
cosmetic one: an `unknown` earlier rule blocks every later definitive verdict,
so rule 6 (`Lab-Troubleshoot-ICMP`, service `icmp-requests`) would have turned
otherwise-exact traces into `UNVERIFIED` for any query whose source and
destination matched it. The lab avoided this only because the tested
destination fell outside rule 6.

`_leaf_service_atoms()` now models:

- `service-icmp` / `service-icmp6` → atom on `icmp-type` (0–255 if absent)
- `service-sctp` → port range, proto `sctp`
- `service-other` → proto `ip-<ip-protocol>`

so a TCP/443 query against an ICMP or GRE service is now a confident
`no-match`. `service-dce-rpc` and `service-rpc` stay unmodelled deliberately —
they negotiate ports at runtime, so `no-match` would be a lie.

### Changed — unknown reasons name the blocking leaf

"Static match unavailable for AD-Services [service-group]" did not say what to
look at. `resolver.unmodelled_names()` walks to the leaves, so the message is
now:

```
Static service match unavailable for AD-Services → ALL_DCE_RPC [service-dce-rpc]
Static match unavailable for Mixed-Nets → DynamicObj [dynamic-object]
```

`tools/diag_resolver.py` reports partially-modelled objects separately from
unusable ones, and no longer claims a service group failed because of
`address_atoms()`.

### Tests

100 → 119. New: `tests/test_v410_partial_resolution.py`.

---

## v4.9.0

### Fixed — objects-dictionary presence mistaken for completeness

`tools/diag_resolver.py` (added this release) reported **10 objects** in a live
lab's root Access layer that the resolver could not turn into comparable
ranges, every one of them marked `in dictionary: True` with `member count: 0`:

```
LAB-Internal-Nets [group]        Admin-Networks [group]
AD-Services [service-group]      dns / ntp / icmp-requests [service-group]
External-Cluster [simple-cluster]
External-GW01 / External-GW02 [cluster-member]
Internal-GW01 [simple-gateway]
```

`show-access-rulebase` is called with `details-level: standard`, so its
`objects-dictionary` entries carry only `uid`, `name` and `type` — no group
members, no gateway or cluster address. `hydrate_objects()` decided whether to
fetch full detail with a single test:

```python
for uid in [x for x in uids if x and x not in existing]:
```

Present was treated as complete, so all ten were skipped and stayed as stubs.

Consequences, both observed:

- **Traffic Path** returned `UNVERIFIED` for a flow whose real configured path
  is `Rule 7 → InternetLayer → Rule 7.1 → Accept`, because
  `address_atoms()` returned `None` for `LAB-Internal-Nets` and the tri-state
  matcher — correctly — refused to guess.
- **Shadow analysis** silently under-reported: `_dimension_cover()` answers
  `"Unsupported object type"` for an unresolvable object, so any rule using a
  group was skipped instead of compared.

`resolver.needs_detail()` now decides completeness from the fields the resolver
actually consumes — an address, a port, or members — rather than from presence.
`hydrate_objects()` re-fetches thin entries, and the hydration loop in
`hydrate_rulebase()` re-checks nested members for completeness too (a group
member can itself be a stub), over at most `MAX_HYDRATION_ROUNDS = 6` passes.

Action and track objects (`Accept`, `Drop`, `Log`) reach hydration because
`action` is in `RULE_FIELDS`; `needs_detail()` excludes them so they do not
each cost a paced, rate-limited round trip.

**Cost:** first load of a package now issues one `show-object` per thin object.
At the default 0.55 s pacing that is roughly 10–20 s extra on a small policy,
then served from the 300 s cache. Requesting `details-level: full` on
`show-access-rulebase` would trade those N calls for one larger response and is
worth measuring, but was not changed here.

### Fixed — rate-limited hydration failed silently

`hydrate_objects()` caught `CheckPointRateLimitError` and `break`, leaving a
partly-resolved dictionary indistinguishable from a complete one. It now sets
`CheckPointClient.hydration_truncated` so reduced confidence can be reported.

### Changed

- `disabled_rules` and `zero_hit_rules` findings now carry `display_rule`, so
  an inline finding reads `7.1` instead of the ambiguous `1`.
- Added `tools/diag_resolver.py`: read-only, prints every referenced object the
  resolver cannot evaluate and distinguishes "no members returned" from
  "members not hydrated".

### Tests

78 → 100. New: `tests/test_v49_hydration.py`.

---

## v4.8.0

Two fixes driven by validation against a live lab Management Server running
Management API **2.0.1** (the earlier baseline was validated against 1.9).

### Fixed — cleanup rule reported as an Any/Any/Any finding

Every Check Point policy ends with an implicit-deny cleanup rule, which is
Any/Any/Any/Drop by design. The analyzer counted it as an optimization finding,
so a healthy policy scored 92 instead of 100 and the dashboard showed a yellow
alert badge for a rule that was correct.

`analyzer.is_cleanup_rule()` now identifies the layer's cleanup rule
**positionally** — the last ordered rule in the layer with a `Drop` or `Reject`
action — and reports it under `cleanup_rules` instead of `any_any_any_rules`.
Detection deliberately ignores the rule name, because names vary by
administrator and language.

Still reported as genuine findings:

- a trailing Any/Any/Any **Accept** rule
- an Any/Any/Any Drop rule that is **not** last in its layer

The Analyze → Any Rules view now states which cleanup rules were excluded and
why, so the exclusion is visible rather than silent.

### Fixed — NAT hit counts permanently disabled

v4.0 hardcoded "no NAT hits" after one lab on Management API 1.9 answered
`HTTP 400: Unrecognized parameter [show-hits]` to `show-nat-rulebase`. Newer
Management builds accept the parameter, so the workaround was suppressing real
data everywhere.

`CheckPointClient` now **probes** the capability once per session:
`show-nat-rulebase` is called with `show-hits`, and only if the server rejects
it with an unrecognised-parameter error does the client fall back and remember
not to ask again. Rate-limit errors and unrelated API errors propagate normally
instead of being mistaken for an unsupported parameter.

`analyze_nat_rulebase()` reads the returned hit values instead of returning
`None`, and reports `summary.nat_hits_available`.

### Changed

- Version is now a single `APP_VERSION` constant, surfaced in `GET /health`.
- Application title is `Firewall Insight - Check Point Firewall Analysis Platform`.
- Added `pytest.ini` (`pythonpath = .`) so a bare `pytest` works. Previously only
  `python -m pytest` collected, because the plain `pytest` entry point does not
  put the working directory on `sys.path`.
- README rewritten as project documentation; release history moved here.

### Tests

63 → 78. New: `tests/test_v48_cleanup_rule.py`, `tests/test_v48_nat_hits.py`.

---

## v4.7 — Tri-state traffic matching

- Access matching distinguishes Match / No Match / Unknown.
- Security Zone, dynamic-style, negated and otherwise unsupported static
  conditions are no longer incorrectly treated as No Match.
- An uncertain parent rule can still be followed into its Inline Layer; when the
  child rule matches exactly the result is returned with `confidence = inferred`.
- A later cleanup rule is no longer reported as definitive when an earlier rule
  cannot be statically evaluated; the result becomes `UNVERIFIED`.
- Parent rows are neutral/green-accented, Inline rows blue-accented.

Driven by a real mismatch: expected `Rule 60 → InternetLayer → Rule 60.35 →
Accept`, incorrectly reported as `Cleanup Rule 132`.

## v4.6 — Tri-state groundwork

- `MATCH` / `NO MATCH` / `UNKNOWN` states introduced in the traffic matcher.
- Protection against returning Cleanup when an earlier rule is unevaluable.

## v4.5 — Inline-aware Traffic Path

- Traffic Path reads rules inside Access Sections recursively.
- When a matching parent rule references an Inline Layer, the trace follows the
  child layer until a terminal Accept/Drop/Reject rule is found.
- Result includes the complete matched path, e.g.
  `Rule 60 → InternetLayer → Rule 60.35 → Accept`.
- Inline rows use a neutral dark background with blue accents.

## v4.4 — Hierarchical rule numbering + flexible traffic inputs

- Inline rule numbers follow the parent path: `30 → 30.1, 30.2, 30.3`, nested `30.2.1`.
- Traffic Path accepts source and destination as IP address or domain/FQDN.
- Domain input is matched against Check Point domain objects and locally resolved
  DNS A/AAAA addresses.
- Service input accepts a numeric port, a standard service name, or an exact
  Check Point service object name including custom TCP/UDP services.

## v4.3.1 — Drill-down fixes

- Dashboard alert counts became clickable and route to the related analysis view.

## v4.3 — Inline hierarchy and dashboard findings

- Inline Layer rules render immediately below their parent rule.
- Parent rows show how many inline rules are attached.
- Dedicated Inline Layer Analysis panel on the dashboard.
- Shadow, duplicate and Any findings broken down into top-level vs inline counts.

## v4.2 — Package-first / SmartConsole count compatibility

- Policy Package became the primary selector; the ordered Access Control layer is
  resolved from the package.
- **Pagination fixed** for Access and NAT rulebases using the API collection `to`
  boundary instead of the number of returned top-level section wrappers.
- Section wrappers repeated across pages are de-duplicated.
- `Access Rules` is the SmartConsole-style top-level count; inline rules are
  loaded and analysed but displayed separately.
- Added `Total Rules Inspected`.

This is where inflated counts (1440 Access / 440 NAT against a real 132 / 116)
were traced to pagination plus section handling and corrected.

## v4.1 — Inline Layer compatibility

- Recursive discovery and loading of Inline Layers referenced by Access rules.
- Layer column, layer path and parent-rule context in the raw Access Policy.
- Analyzer runs independently inside each Access Layer to avoid false cross-layer
  shadow and duplicate findings.
- Access tree responses cached to reduce repeated Management API calls.
- Inline-layer fetch failures are tracked rather than silently treated as complete.

## v4.0 Final.1

- Dashboard `Analyze Selected Policies` also loads the raw Access Policy rulebase,
  so Access Policy, Analyze and NAT Policy are all populated after one action.

## v4.0 Final

- NAT `show-hits` disabled for Management API v1.9 compatibility
  (`HTTP 400: Unrecognized parameter [show-hits]`). *Revisited in v4.8.*
- Dashboard became a useful overview with Access/NAT metrics, finding summary,
  quick actions and selected context; cards support drill-down.
- Access workflow split into **Access Policy** (raw configured rulebase) and
  **Analyze** (optimizer findings and score).
- NAT parser supports scalar UID/string/object fields as well as lists, fixing
  blank Original/Translated NAT columns.
- NAT drill-down tabs for Disabled NAT and Possible No-Translation.
- Firewall and Management Server topology icons.
- Settings menu removed; Network Mapping no longer shows policy selectors.
- Non-zero finding counts highlighted with a yellow circular badge.
- API request pacing, cache, retry/backoff and persistent read-only session.
- CSV export for both raw policy and analysis.
