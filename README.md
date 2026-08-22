# Firewall Insight

Read-only analysis and visualisation layer for Check Point Security Management.

Firewall Insight connects to a Check Point Management Server over the Management API,
retrieves Access Control and NAT policy, and presents an analytical view that
SmartConsole does not provide out of the box: shadowed and duplicate rules, overly broad
rules, Inline Layer hierarchy, a configuration-based traffic-path simulator, and a
topology map.

**It is not a SmartConsole replacement, and it never modifies policy.**

---

## Contents

- [Safety model](#safety-model)
- [Requirements](#requirements)
- [Setup](#setup)
- [Configuration](#configuration)
- [Features](#features)
- [Architecture](#architecture)
- [API reference](#api-reference)
- [Testing](#testing)
- [Known limitations](#known-limitations)
- [Contributing / development rules](#contributing--development-rules)

---

## Safety model

The application issues **only** these Management API commands:

```
login  logout  show-packages  show-package  show-access-layers
show-access-rulebase  show-nat-rulebase  show-object
show-gateways-and-servers
```

There is no `add-*`, `set-*`, `delete-*`, `publish`, or `install-policy` code path.
Every HTTP route is a `GET`. This is deliberate and should be preserved: the tool is
intended to be safe to point at a production Management Server.

`.env` holds Management credentials and is excluded by `.gitignore`. **Never commit it.**

---

## Requirements

- Python 3.12+ (tested on 3.12 and 3.13)
- Network reachability to a Check Point Management Server on TCP/443
- A Management API user with read permissions
- Management API enabled for the relevant clients (`api status` on the Management Server)

---

## Setup

```powershell
python -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass   # Windows PowerShell only
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

copy .env.example .env      # then edit .env with your Management details
pytest -q                   # expect: 352 passed
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Linux / macOS:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
pytest -q
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Open <http://localhost:8000>.

Docker:

```bash
docker compose up --build      # reads .env via env_file
```

### Verifying the install

| Check | Expected |
|---|---|
| `pytest -q` | `352 passed` |
| `GET /health` | `{"status":"ok","version":"4.16.1","mode":"read-only",...}` |
| `GET /api/checkpoint/test` | `{"connected":true,"api_server_version":"...","read_only":true}` |
| `GET /api/bootstrap` | lists your access layers and policy packages |

---

## Configuration

All settings come from `.env` (see `.env.example`), loaded by `app/config.py`.

| Variable | Default | Purpose |
|---|---|---|
| `CHECKPOINT_MGMT` | `https://127.0.0.1` | Management Server base URL |
| `CHECKPOINT_USER` | — | API user |
| `CHECKPOINT_PASSWORD` | — | API password |
| `CHECKPOINT_DOMAIN` | empty | MDS domain, leave empty for SMC |
| `CHECKPOINT_VERIFY_SSL` | `false` | TLS verification |
| `CHECKPOINT_TIMEOUT` | `90` | Per-request timeout (seconds) |
| `CHECKPOINT_MIN_REQUEST_INTERVAL` | `0.55` | Client-side pacing between API calls |
| `CHECKPOINT_RATE_LIMIT_RETRIES` | `4` | Retries on HTTP 403 rate limiting |
| `CHECKPOINT_RATE_LIMIT_BASE_DELAY` | `2` | Exponential backoff base (seconds) |
| `CHECKPOINT_CACHE_TTL` | `300` | In-memory cache lifetime (seconds) |

If you hit `HTTP 403: too many requests`, raise `CHECKPOINT_MIN_REQUEST_INTERVAL`.

---

## Features

**Dashboard** — package-level summary with Access rules, Inline rules, Inline Layers,
total rules inspected, findings counts and an optimizer score. Non-zero finding counts
render as clickable alert badges that drill into the matching result view.

**Access Policy** — the configured rulebase exactly as returned by the Management API,
with no optimizer analysis applied. Inline Layer rules render indented directly beneath
their parent rule and keep layer, layer-path and parent-rule context. CSV export.

**Analyze** — optimizer findings across four tabs: shadowed/redundant rules, exact
duplicate groups, Any/Any/Any rules, and **Unused Rules** (zero-hit plus disabled,
with hit counts and last-hit dates). Unused is reported as a review candidate, not a
delete instruction: hit counters reset on policy install and on gateway restart.
Analysis is isolated per layer, so rules in different Inline Layers are never compared
as siblings.

**NAT Policy** — NAT rulebase, duplicate NAT detection, broad NAT rules, disabled NAT
and possible no-translation drill-downs. NAT hit counts are shown when the Management
API build supports `show-hits` on `show-nat-rulebase`.

**Traffic Path** — configuration-based simulation of which rule a flow would match.
Accepts source/destination as IP or FQDN, and service as a port number, a standard
service name (`https`, `ssh`, `smtp`, `ntp`, `domain`) or an exact Check Point service
object name. Follows Parent Rule → Inline Layer → child rule → terminal action, and
reports a confidence level (`exact`, `inferred`, `unknown`).

**Network Mapping** — topology derived from `show-gateways-and-servers`, in two layouts.

*Graph* (default) is a Fruchterman-Reingold force layout: gateways become hubs and the
subnets behind them orbit as leaves, so the shape of the estate is visible at a glance.
Drag any node to place it and **Save Map** to keep the arrangement (positions are keyed
to a hash of the node set, so they are never reapplied to a different estate);
**Auto Merge** gives subnets reached through the same devices one node; **Collapse all**
hides single-homed subnets and leaves the backbone; search steps through matches with
▲ ▼; export to PNG or CSV. Pan/zoom pad bottom-right, plus scroll-to-zoom and
drag-to-pan. The layout is seeded deterministically, so the same topology always looks
the same.

*Cards* is the two-column view: interfaces are rows inside the device card, which
answers "which port reaches which subnet" better than the graph does. A four-gateway lab
is 11 nodes in either layout, not the 22 the pre-4.14 view drew.

A ClusterXL cluster is drawn as one enforcement point with its members attached by a
dashed membership link (from the cluster object's `cluster-member-names`), and a
Management HA pair is joined by a dashed HA link (from `management-blades.secondary`).
Subnets a gateway reports as internet-facing are marked, as are subnets only one
cluster's own members reach.

Both layouts are logical only — physical cabling, switching, routing protocols and live
routes are not discovered, and an interface with no CIDR shows `—` rather than a guess.
Membership is never inferred from addressing: if the API does not name the members, none
are drawn. Management HA is reported as *configured*; whether the peers are currently
synchronised is not exposed by the object model and is never implied.

**Feedback layer** — every request drives a top progress bar; blocking work shows a
translucent blur overlay with elapsed time and named steps, and explains itself once it
passes 6 s. Failures produce a cause-and-remedy status line, a toast with copyable
details, and an inline retry panel — never a silent console error. Loading shows
skeletons, empty views say what to do next, and an incomplete result is labelled
incomplete rather than presented as complete. The interface is responsive down to
390px, with an off-canvas nav drawer, sticky table headers, and all motion disabled
under `prefers-reduced-motion`.

---

## Architecture

```
app/
  main.py               app factory + lifespan + router include (~45 lines)
  version.py            APP_VERSION, single source of truth
  config.py             .env settings
  runtime.py            Management client, response cache, HTTP error mapping
  progress.py           live phase registry polled by the UI
  policy.py             fetch → hydrate → analyse orchestration, data_quality
  api/
    meta.py             /health, connection test, bootstrap, progress
    access.py           package analysis and raw rulebase
    nat.py              NAT analysis
    traffic.py          traffic-path simulation
    topology.py         network map
    export.py           CSV
    ui.py               serves the single-page UI
  checkpoint.py         Management API client: session, pacing, retry/backoff,
                        pagination, Inline Layer tree discovery
  inline_layers.py      layer-tree traversal, display numbering, aggregation
  resolver.py           UID → name / IP interval / port interval
  analyzer.py           Access findings
  nat_analyzer.py       NAT findings
  policy_browser.py     raw rulebase → table rows
  traffic.py            tri-state matcher, path trace, NAT correlation
  topology_map.py       gateways/servers -> nodes and edges, cluster and HA links
  templates/index.html
  static/css/app.css
  static/js/app.js
```

Every route is a `GET`, and `tests/test_v413_structure.py` asserts that no
router declares a mutating verb and that no mutating Management command appears
anywhere in the source. The read-only guarantee is structural, not a promise.

### Concepts you must understand before changing anything

1. **Policy Package is the primary context**, not Access Layer. The package's ordered
   Access Control layer is resolved from `show-package`, falling back to the
   `"<package> Network"` naming convention.
2. **Access policy is a tree.** An Inline Layer is a real child policy, not a flat rule.
   `show_rulebase_tree()` walks it recursively; every node keeps `depth`, `path`,
   `parent_layer`, `parent_rule` and `display_prefix`.
3. **Rule count and analysed rule count are different numbers.** `Access Rules` is the
   SmartConsole-style top-level count. `Inline Rules` and `Total Rules Inspected` are
   reported separately and must never be folded into the headline Access count.
4. **Pagination advances on the API's `to` boundary**, not `len(batch)`. A page can
   contain section wrappers rather than rules, and the same section wrapper can repeat
   across pages; `_merge_rulebase_page()` merges and de-duplicates them.
5. **`display_rule` is presentation only.** Parent rule 30 renders its inline children as
   `30.1`, `30.2`, nested as `30.2.1`. The Check Point native `rule-number` is never
   rewritten.
6. **Traffic matching is tri-state:** `match` / `no-match` / `unknown`. Security Zones,
   dynamic objects, negation and Identity Awareness are `unknown`, never `no-match`.
7. **An `unknown` earlier rule blocks a definitive later verdict.** If rule 60 cannot be
   statically evaluated and rule 132 (cleanup) matches exactly, the result is
   `UNVERIFIED`, not `Drop`. Reporting a confident wrong answer about a firewall is
   worse than reporting uncertainty.
8. **A dictionary entry being present does not make it usable.**
   `objects-dictionary` from `details-level: standard` carries only uid, name
   and type — groups arrive with no members, gateways with no address.
   `resolver.needs_detail()` decides completeness from the fields the resolver
   consumes, and hydration re-fetches anything thin. Skip this and every rule
   using a group silently becomes statically unevaluable.
9. **Matching and containment need different strictness.** Proving a match
   needs one hit, so the traffic matchers use `*_atoms_partial()` and can
   answer through the members of a group they understand. Proving coverage
   needs every atom, so the analyzer uses the strict `address_atoms()` /
   `service_atoms()`, which return `None` unless the object is fully modelled.
   Do not make one of them use the other's resolver.
10. **The UI must never present a partial result as a complete one.**
    `data_quality()` reports failed inline layers and truncated object
    hydration; the frontend turns that into a visible banner and a toast. The
    same applies to traffic confidence: `exact`, `inferred` and `UNVERIFIED`
    get visually different treatment, because flattening them is how a user
    ends up trusting a guess.
11. **Real SmartConsole and gateway logs are the oracle.** Validate counts and traffic
   results against the live environment. Never hardcode expected numbers to make output
   look right.

---

## API reference

| Method | Path | Description |
|---|---|---|
| GET | `/` | Single-page UI |
| GET | `/health` | Liveness + version |
| GET | `/api/checkpoint/test` | Log in, return Management API version |
| GET | `/api/bootstrap` | List access layers and policy packages |
| GET | `/api/package-analyze?package=` | Full analysis for a policy package |
| GET | `/api/package-policy-browser?package=` | Raw rulebase for a policy package |
| GET | `/api/package-context?package=` | Access layers belonging to a package |
| GET | `/api/nat-analyze?package=` | NAT analysis for a policy package |
| GET | `/api/traffic-path?src=&dst=&protocol=&service=&layer=&package=` | Traffic simulation |
| GET | `/api/network-map` | Topology nodes and edges |
| GET | `/api/progress?rid=` | Live phase of a long request (polled by the UI) |
| GET | `/api/analyze?layer=` | Legacy layer-first analysis |
| GET | `/api/policy-browser?layer=` | Legacy layer-first raw rulebase |
| GET | `/api/export.csv?layer=` | Analysis CSV |
| GET | `/api/policy-browser.csv?layer=` | Raw policy CSV |
| GET | `/api/package-policy-browser.csv?package=` | Raw policy CSV for a whole package, inline rules included |

Add `&force=true` to `bootstrap`, `policy-browser`, `package-policy-browser` or
`network-map` to bypass the cache.

---

## Testing

```bash
pytest -q          # 352 tests, no Management Server required
```

Tests use fixture payloads shaped like real Management API responses; nothing in the
suite touches a live server. `pytest.ini` sets `pythonpath = .` so `pytest` works
without the `python -m` prefix.

### Diagnosing a live environment

```bash
python -m tools.diag_resolver <policy-package-name>
```

Read-only. Prints every object referenced by a rule that the resolver cannot
turn into an IP or port range, and says whether the cause is "no members
returned" (a thin dictionary entry) or "members not hydrated". Run this first
whenever Traffic Path answers `UNVERIFIED` or shadow analysis looks empty.

When a bug is found against a real environment:

1. Reproduce it and capture a minimal fixture from the real API response.
2. Add a failing regression test.
3. Fix the code.
4. Run the full suite.
5. Re-validate against SmartConsole.
6. Bump the version.

---

## Known limitations

Traffic Path is a **configuration-based simulation**, not a Check Point kernel
emulation. Live gateway behaviour can differ because of Identity Awareness, Security
Zones, dynamic objects, time objects, implied rules, routing, NAT ordering, VPN
processing and gateway state. The UI reports `exact` / `inferred` / `unknown`
confidence for this reason — treat SmartConsole and gateway logs as authoritative.

The optimizer score is an application-side heuristic, not a Check Point feature. Its
current formula penalises Any/Any/Any rules, duplicate groups, shadow findings and
disabled rules, each with a cap. Document any change to it.

Domain-based traffic queries resolve DNS from the machine running Firewall Insight,
which may differ from what the gateway resolves under split DNS.

`app/main.py` embeds the entire frontend (HTML, CSS, JavaScript) as a Python string.
This is known technical debt; splitting it into `templates/` and `static/` is the
recommended next refactor, but only once behaviour is stable.

---

## Contributing / development rules

Do **not**:

- add any mutating Management API call
- flatten Inline Layer rules into the top-level Access Rules count
- compare rules across unrelated layers by rule number alone
- treat an unevaluable condition as "no match"
- report a cleanup rule as definitive when an earlier rule is `unknown`
- hardcode expected SmartConsole rule counts
- assume NAT accepts every parameter Access accepts
- return to a layer-first selection model
- strip layer / layer-path / parent-rule metadata from findings or UI rows

Versioning: `x.y.Z` bugfix, `x.Y.0` feature, `X.0.0` architecture change. Keep
experimental UI work out of the stable baseline.

---

See [CHANGELOG.md](CHANGELOG.md) for release history.
