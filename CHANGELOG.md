# Changelog

All notable changes to Firewall Insight.

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
