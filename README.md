# Firewall Insight

Read-only analysis and visualisation layer for Check Point Security Management.

Firewall Insight connects to a Check Point Management Server over the Management API,
retrieves Access Control and NAT policy, and presents an analytical view that
SmartConsole does not provide out of the box: shadowed and duplicate rules, overly broad
rules, Inline Layer hierarchy, a configuration-based traffic-path simulator, a topology
map, compliance profiles, policy diffs between snapshots, gateway health over the Gaia
API, reviews that run on a schedule and send alerts, object hygiene, rule usage from the
firewall logs, trends over time, cleanup scripts for a person to run, and traffic questions
asked in Thai or English.

**It is not a SmartConsole replacement, and it never modifies policy.**

The current version is in [`app/version.py`](app/version.py) and reported by `GET /health`.
Release history is in [CHANGELOG.md](CHANGELOG.md).

---

## Contents

- [Safety model](#safety-model)
- [Signing in](#signing-in)
- [Requirements](#requirements)
- [Setup](#setup)
- [Configuration](#configuration)
- [Features](#features)
- [Architecture](#architecture)
- [API reference](#api-reference)
- [Command-line tools](#command-line-tools)
- [Testing](#testing)
- [Acceptance run](#acceptance-run)
- [Known limitations](#known-limitations)
- [Contributing / development rules](#contributing--development-rules)

---

## Safety model

### Nothing is ever written to a Check Point host

The application issues **only** these Management API commands:

```
login  logout  show-packages  show-package  show-access-layers
show-access-rulebase  show-nat-rulebase  show-object
show-gateways-and-servers
show-unused-objects  show-hosts  show-networks  show-address-ranges
show-groups  where-used  show-logs
```

The second group arrived in v4.39 and lives in one module, `app/estate_reads.py`, whose
`READ_COMMANDS` set a test holds the module to. `where-used` does not start with `show-`,
which is why the set is written out rather than trusted to a prefix.

There is no `add-*`, `set-*`, `delete-*`, `publish`, or `install-policy` code path.
`tests/test_v413_structure.py` scans the source for mutating Management commands and
fails if one appears. This is deliberate and should be preserved: the tool is intended
to be safe to point at a production Management Server.

### The cleanup script is text the application cannot run

`app/remediation.py` turns findings into a `mgmt_cli` script or an Ansible playbook, so it
necessarily contains mutating commands - as text, for a person to read and run. It imports
nothing that can reach a network (no client, no httpx, no socket, no subprocess); a test
checks its imports rather than trusting this paragraph, and the acceptance runner exempts
that one file from its source scan by name while checking the same thing. The script
disables rather than deletes, never touches a layer's cleanup rule or a rule holding an
inline layer, refuses to build on an incomplete read, publishes only when the person running
it types `PUBLISH`, and never installs policy.

### The Gaia API needs its own guarantee

Routing, interfaces and cluster state come from the **Gaia API** on each gateway, which
is a different API with different credentials. It does not have the property that made
the Management API easy to audit: its reads sit in the same command space as
`set-static-route`, `add-license`, `run-script` and `run-reboot`, on the same session.

So `app/gaia.py` carries an explicit read allowlist that is **enforced at call time** —
a command outside it raises before any request is built, so it never reaches the
network, not even as an authentication attempt:

```
show-routes  show-static-routes  show-interfaces  show-interface
show-bond-interfaces  show-cluster-state  show-version  show-asset
show-lldp-status  show-physical-interfaces-xcvr
```

The integration is **off unless configured** (`GAIA_ENABLED=false`), and the map
distinguishes *routing was not read* from *there are no routes*.

### What the application does write — all of it local

Earlier versions of this README said every route was a `GET` and that a snapshot was
the only write. Neither has been true since v4.30. This is the complete list, and
every entry lands on the machine running the application:

| Written | By | Where |
|---|---|---|
| Encrypted Management / Gaia credentials | `POST /api/credentials` (Settings page) | `credentials.enc`, key in `.credential_key` |
| Session-signing key | first start | `.session_key` |
| Policy snapshot | `GET /api/snapshot`; every compliance run against a live package; every review | `snapshots/*.json` |
| Gateway health baseline | `GET /api/health` (unless `save=false`); every review that includes health | `health-baselines/*.json` |
| Review run | `POST /api/runs`, a schedule, or `tools/run_review.py` | `runs/*.json` |
| Schedules | `PUT` / `DELETE /api/schedules` | `schedules.json` |
| PDF report | a schedule with PDF enabled | `reports/*.pdf` (or the schedule's `pdf_dir`) |
| Alert destinations | `PUT` / `DELETE /api/alerts/destinations` | `alerts.json`; webhook URLs and SMTP passwords encrypted under `alerts` in `credentials.enc` |

All of these paths are in `.gitignore`. Note that three of the writes happen on a
`GET` — capturing a snapshot, recording a health baseline, and a compliance run that
saves its evidence. They change nothing on any Check Point host, and each response
names what it saved.

### What leaves this machine - only when you configure it

Alerts are the one feature that sends data somewhere other than a Check Point host: a POST
to a Slack, Teams or generic webhook URL, or an SMTP session. Nothing is sent until a
destination is saved. Summary alerts carry counts and verdicts - no rule contents and no
addresses; `findings` detail adds rule numbers, failed check titles and gateway addresses,
and is chosen per destination. Webhook URLs must be `https://` (plain `http://` only to this
machine, for testing).

`.env` holds Management **and** Gaia credentials and is excluded by `.gitignore`.
**Never commit it.**

---

## Signing in

Every route except `/`, `/health` and the three `/api/auth/*` routes requires a
session. The gate is one middleware in `app/main.py`, not a decorator per route, and
`tests/test_v413_structure.py` fails if the public list grows.

- **You sign in with Check Point Management API credentials.** A sign-in is one
  `login` immediately followed by `logout`, on a throwaway client. The password is not
  stored, cached or reused; the session cookie carries a username and two timestamps,
  signed with `.session_key`. If you may read the policy in SmartConsole, you may read
  it here.
- **Sessions last 12 hours**, or 30 days with *Keep me signed in*. Signing out ends
  one immediately.
- **Five failed attempts per username locks that username out here for five
  minutes.** The sixth attempt never reaches the Management Server, so this
  application cannot be used to trip an account lockout there.
- **Setup mode.** With no Management address and username configured there is nobody
  to check a sign-in against, so the application lets people in and says, in a banner
  that does not dismiss itself, that it is unauthenticated.
- **The cost, stated.** A page that asks for Check Point administrator credentials
  looks exactly like a phishing page. Serve it over HTTPS and tell people the address.
  The cookie is not marked `secure`, because the application is commonly served over
  plain HTTP on a LAN; `app/api/auth.py` marks the line to change once it is behind
  HTTPS.

### If nobody can sign in

A saved record in `credentials.enc` **overrides** `.env`. If the saved Management
address is wrong, every sign-in fails — and the Settings page, where it would be
corrected, is behind the sign-in. The sign-in error says where the address came from.
To get back in, on the machine running the application:

```bash
python -m tools.reset_credentials                      # what is used, and from where
python -m tools.reset_credentials --clear checkpoint   # remove the saved record; .env applies
```

then restart. If the address is right and the Management Server is simply unreachable
(a VPN that has dropped, for instance), a new sign-in cannot succeed until it is back —
but an existing session keeps working, because the cookie is checked locally.

---

## Requirements

- Python 3.12+ (tested on 3.12 and 3.13)
- Network reachability to a Check Point Management Server on TCP/443
- A Management API user with read permissions
- Management API enabled for the relevant clients (`api status` on the Management Server)
- Optional: Gaia API reachable on each gateway, for Gateway Health and routing
- Optional: Node.js, to run the frontend renderer harness (skipped without it)

---

## Setup

```powershell
python -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass   # Windows PowerShell only
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

copy .env.example .env      # then edit .env with your Management details
pytest -q                   # every test should pass; none needs a Management Server
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

Open <http://localhost:8000> and sign in with the Management API account.

Docker:

```bash
docker compose up --build      # reads .env via env_file
```

Reviews, snapshots, health baselines and PDF reports persist in named volumes.
`credentials.enc`, the key files, `schedules.json` and `alerts.json` do not: after a
rebuild, credentials fall back to `.env`, everyone signs in again, and schedules and alert
destinations have to be re-created. `docker-compose.yml` explains why they are not bind-mounted.

### Verifying the install

| Check | Expected |
|---|---|
| `pytest -q` | all pass |
| `GET /health` | `{"status":"ok","version":"<app/version.py>","mode":"read-only",...}` |
| `GET /api/auth/status` | `"required": true` once `.env` names a Management address and user |
| `GET /api/bootstrap` without signing in | `401` |
| `GET /api/checkpoint/test` after signing in | `{"connected":true,"api_server_version":"...","read_only":true}` |

---

## Configuration

Settings come from `.env` (see `.env.example`), loaded by `app/config.py`. Credentials
saved on the Settings page are encrypted into `credentials.enc` and **override** the
`.env` values at startup.

| Variable | Default | Purpose |
|---|---|---|
| `CHECKPOINT_MGMT` | `https://127.0.0.1` | Management Server base URL |
| `CHECKPOINT_USER` | — | API user; also the account people sign in with |
| `CHECKPOINT_PASSWORD` | — | API password |
| `CHECKPOINT_DOMAIN` | empty | MDS domain, leave empty for SMC |
| `CHECKPOINT_VERIFY_SSL` | `false` | TLS verification |
| `CHECKPOINT_TIMEOUT` | `90` | Per-request timeout (seconds) |
| `CHECKPOINT_MIN_REQUEST_INTERVAL` | `0.55` | Client-side pacing between API calls |
| `CHECKPOINT_RATE_LIMIT_RETRIES` | `4` | Retries on HTTP 403 rate limiting |
| `CHECKPOINT_RATE_LIMIT_BASE_DELAY` | `2` | Exponential backoff base (seconds) |
| `CHECKPOINT_CACHE_TTL` | `300` | In-memory cache lifetime (seconds) |
| `GAIA_ENABLED` | `false` | Read routing, interfaces and cluster state from gateways |
| `GAIA_USER` / `GAIA_PASSWORD` | — | Gaia API credentials |
| `GAIA_HOSTS` | empty | Comma-separated gateway addresses |
| `GAIA_VERIFY_SSL` | `false` | TLS verification for Gaia |
| `GAIA_TIMEOUT` | `30` | Per-request timeout for Gaia (seconds) |

If you hit `HTTP 403: too many requests`, raise `CHECKPOINT_MIN_REQUEST_INTERVAL`.

---

## Features

Opening a page loads it. Nothing runs on a page nobody has opened, nothing runs twice,
and what a page already holds is rendered rather than re-read. Traffic Path is the
exception: it needs a source, a destination and a port.

**Dashboard** — on arrival, with a session, the package list and network map are read
and the dashboard fills from the most recent stored review. Hits over time (drawn only
from snapshots you took — nothing interpolated), where the hits are, a Policy Health
Score, a topology preview, what the last read found, optimization findings, Inline
Layer analysis, the last traffic trace and the selected context. Every card can be
folded away and stays folded. Non-zero findings drill into the matching view.

**Access Policy** — the configured rulebase exactly as returned by the Management API,
with no optimizer analysis applied. Inline Layer rules render indented directly beneath
their parent rule and keep layer, layer-path and parent-rule context. CSV export.

**Analyze** — optimizer findings: shadowed/redundant rules, exact duplicate groups,
Any/Any/Any rules, and **Unused Rules** (zero-hit plus disabled, with hit counts and
last-hit dates). Unused is a review candidate, not a delete instruction: hit counters
reset on policy install and on gateway restart. Analysis is isolated per layer, so rules
in different Inline Layers are never compared as siblings.

**NAT Policy** — NAT rulebase, duplicate NAT detection, broad NAT rules, disabled NAT
and possible no-translation drill-downs. NAT hit counts are shown when the Management
API build supports `show-hits` on `show-nat-rulebase`.

**Traffic Path** — configuration-based simulation of which rule a flow would match.
Accepts source/destination as IP or FQDN, and service as a port number, a standard
service name (`https`, `ssh`, `smtp`, `ntp`, `domain`) or an exact Check Point service
object name. Follows Parent Rule → Inline Layer → child rule → terminal action, and
reports a confidence level (`exact`, `inferred`, `unknown`).

**Network Mapping** — topology derived from `show-gateways-and-servers`, in two layouts,
with routing from the Gaia API overlaid when it is enabled.

*Graph* (default) is a force layout: gateways become hubs and the subnets behind them
orbit as leaves. Drag any node and **Save Map** to keep the arrangement (positions are
keyed to a hash of the node set, so they are never reapplied to a different estate);
**Auto Merge** gives subnets reached through the same devices one node; **Collapse all**
hides single-homed subnets; search steps through matches; export to PNG or CSV. The
layout is seeded deterministically, so the same topology always looks the same.

*Cards* is the two-column view: interfaces are rows inside the device card, which
answers "which port reaches which subnet" better than the graph does.

A ClusterXL cluster is drawn as one enforcement point with its members attached by a
dashed membership link, and a Management HA pair by a dashed HA link. Membership is
never inferred from addressing: if the API does not name the members, none are drawn.

**Policy Diff** — capture a snapshot of a package, then compare any two. Rules are
matched by uid, never by rule number, so inserting a rule does not report every rule
below it as rewritten. Reports added, removed, modified and moved rules, rules whose
*scope* changed because an object inside them grew or shrank, NAT changes, and — as its
own category, never counted as unchanged — rules whose reach **could not be compared**
because an object has no static model. Snapshots taken by different application
versions are flagged.

**Compliance** — a profile is a YAML file you own, listing the checks you have decided
apply to your estate. Two ship as starting points in `app/compliance_profiles/`
(`house-hygiene`, `nist-800-41-baseline`); every check reports the clause it came from,
or is labelled a house rule when it has none. Runs against a live package or a saved
snapshot. There is no compliance percentage: an unverifiable check is never counted as
a pass, and a run is not conformant while one remains. What a profile declares out of
scope is printed below the results.

**Gateway Health** — interface state, cluster roles and software build, read at one
instant over the Gaia API. It is not monitoring. A gateway that did not answer
produces no findings, which is not the same as producing none, so it is reported as a
high-severity finding of its own. Each reading can be saved as a baseline and compared
with a later one.

**Reviews** — one review composes the package analysis, what changed since the previous
snapshot, a compliance profile and optionally gateway health. Run it from the Reviews
page, from `tools/run_review.py`, or on a **schedule** (off by default; days and a local
time; a window missed while the machine was asleep is caught up within 7 days unless
turned off). Each run is stored and can be opened again; an unreachable section is
recorded as *not read*, never as an empty result. Runs can be exported as a PDF at three
detail levels — `summary` (the default, and deliberately free of rule identifiers,
because it is the file that gets forwarded), `findings`, and `full` — and the PDF prints
what the review does not cover.

**Cleanup script** (on Analyze) — the findings as a `mgmt_cli` script or an Ansible playbook
for the `check_point.mgmt` collection. Redundant rules and later copies of exact duplicates
are disabled; zero-hit rules (opt-in, since counters reset on install), deletion of disabled
rules (opt-in) and deletion of objects the server reports unused (opt-in) can be added. A rule
shadowed by one with a *different* action, and Any/Any/Any, are listed as decisions with no
command. Every command carries its reason and the rule's hits and tracking. The Ansible module
addresses rules by name, so unnamed rules are listed as not handled rather than risked.

**Objects** — what the Management Server itself reports as unused (`show-unused-objects`),
objects defined twice under different names, and groups whose members add nothing because
they sit inside another member, or that could be written as fewer blocks. A shorter form is
suggested only when it covers exactly the same addresses. `where-used` on demand.

**Rule Usage** — firewall log records counted per rule, beside the hit counter. This API
version cannot aggregate, so records are read newest first up to a limit, and the page says
what time span they covered. Each rule gets one verdict: *seen*, *no traffic* (the only one
that says a rule is unused - it logs, and the whole window was read), *not in sample*, *not
logged* (track None), *track unknown*, or *via inline*. Not loaded on arrival: reading the
logs takes a minute or more.

**Trends** — small multiples of the optimization score, compliance failures, rule changes,
gateway findings, rule count and zero-hit rules, drawn only from reviews, snapshots and health
readings that were taken. Time is to scale, a missing reading breaks the line, and a section
that could not be read is marked on the chart rather than drawn as zero. The same points as a
table.

**Ask** (on Traffic Path) — a traffic question in Thai or English, such as *ทำไม 192.0.2.10
เข้า 198.51.100.5 ด้วย rdp ไม่ได้*. The source, destination and service are read out of the
words and the same trace as the form runs; the verdict, UNVERIFIED and confidence are the
trace's, and the answer is never a yes or a no when the trace could not say. A network, range
or group where one address is needed gets a question back, not a guess. It is deterministic -
no language model, and the question never leaves this application.

**Alerts** (on Reviews) — Slack, Microsoft Teams (Workflows adaptive card), a generic JSON
webhook, or email with the summary PDF attached. Each destination fires on *needs attention*,
*could not be read*, *gateway problem*, *no change* or *every review*; the default includes
*could not be read*, because a review that failed to read is the one whose silence is misread.
A failed delivery is recorded on the run and never raised into it. Scheduled reviews send
automatically; a manual review sends when *send alerts* is ticked.

**Settings** — save, test and delete Management and Gaia credentials. Saved credentials
are encrypted at rest with Fernet and override `.env`.

**Feedback layer** — every request drives a progress bar; blocking work shows elapsed
time and named steps. Failures produce a cause-and-remedy status line, a toast with
copyable details and a retry — never a silent console error. An incomplete result is
labelled incomplete rather than presented as complete. Responsive down to 390px, with
motion disabled under `prefers-reduced-motion`.

---

## Architecture

```
app/
  main.py               app factory, lifespan, the session gate, PUBLIC_PATHS
  version.py            APP_VERSION, single source of truth
  config.py             .env settings
  auth.py               signed session cookie, per-username rate limit, setup mode
  credential_store.py   Fernet-encrypted credentials.enc
  runtime.py            Management client, response cache, HTTP error mapping
  progress.py           live phase registry polled by the UI
  policy.py             fetch → hydrate → analyse orchestration, data_quality
  api/
    auth.py             sign in / sign out / status
    credentials.py      save, test and delete credentials; address_source()
    meta.py             /health, connection test, bootstrap, progress
    access.py           package analysis and raw rulebase
    nat.py              NAT analysis
    traffic.py          traffic-path simulation
    topology.py         network map
    snapshot.py         capture, list and diff snapshots
    compliance.py       profiles and compliance runs
    health.py           gateway health readings and baselines
    jobs.py             reviews, PDF export, schedules
    alerts.py           alert destinations, test send
    remediation.py      the cleanup script route
    objects.py          object hygiene, where-used
    usage.py            rule usage from logs
    trends.py           trend series from stored history
    export.py           CSV
    ui.py               serves the single-page UI
  jobs/
    runner.py           run_review(): one review, trigger-agnostic
    store.py            run persistence in runs/
    report.py           reportlab PDF, three detail levels
    schedule.py         due_at()/next_due() and the in-app schedule loop
    alerts.py           destinations, messages, Slack/Teams/webhook/SMTP delivery
  checkpoint.py         Management API client: session, pacing, retry/backoff,
                        pagination, Inline Layer tree discovery
  inline_layers.py      layer-tree traversal, display numbering, aggregation
  resolver.py           UID → name / IP interval / port interval
  matching.py           tri-state address/service matching, DNS memoisation
  analyzer.py           Access findings
  nat_analyzer.py       NAT findings
  nat_correlate.py      NAT rules relevant to a traced flow
  policy_browser.py     raw rulebase → table rows
  traffic.py            path trace
  path_map.py           traffic path overlaid on the topology
  topology_map.py       gateways/servers → nodes and edges, cluster and HA links
  gaia.py               Gaia API client with the read allowlist
  gaia_topology.py      Gaia routing and interfaces merged into the map
  snapshot.py           snapshot capture and storage
  snapshot_diff.py      uid-matched diff, scope changes, unverifiable reach
  compliance.py         YAML profile evaluation
  compliance_profiles/  shipped starting-point profiles
  health.py             gateway health findings and baselines
  estate_reads.py       the v4.39 reads: unused objects, definitions, where-used, logs
  remediation.py        findings -> mgmt_cli / Ansible text; imports no network code
  object_hygiene.py     duplicates, redundant group members, exact merges
  log_usage.py          log records -> per-rule verdicts
  trends.py             stored runs, snapshots, baselines -> series with gaps
  ask.py                a question in words -> the trace's three inputs, and back
  templates/index.html
  static/css/app.css
  static/js/app.js
tools/                  command-line tools, see below
```

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
   `objects-dictionary` from `details-level: standard` carries only uid, name and type —
   groups arrive with no members, gateways with no address. `resolver.needs_detail()`
   decides completeness from the fields the resolver consumes, and hydration re-fetches
   anything thin.
9. **Matching and containment need different strictness.** Proving a match needs one
   hit, so the traffic matchers use `*_atoms_partial()`. Proving coverage needs every
   atom, so the analyzer uses the strict `address_atoms()` / `service_atoms()`, which
   return `None` unless the object is fully modelled. Do not make one of them use the
   other's resolver.
10. **"Could not be compared" is not "unchanged".** A diff, a review summary, a PDF
    headline and a scheduler exit code must all keep the undecided case separate.
    `REAL_CHANGE_KEYS` in `app/jobs/store.py` is the one list of what counts as a
    change, and `scope_unverifiable` is deliberately not in it. `store.outcome()` is the
    one meaning of a finished review - attention, undecided, clean - shared by the CLI exit
    code, alerts and trends.
11. **The UI must never present a partial result as a complete one.** `data_quality()`
    reports failed inline layers and truncated object hydration; the frontend turns that
    into a visible banner. Traffic confidence `exact`, `inferred` and `UNVERIFIED` get
    visually different treatment.
12. **A credential field that was not sent is not an empty one.** Request models default
    every credential field to `None`, and a save overlays only what was sent onto the
    stored record. A `str = ""` default once wiped the saved password (v4.31) and once
    blanked the Management address, which switched authentication off (v4.38).
13. **Real SmartConsole and gateway logs are the oracle.** Validate counts and traffic
    results against the live environment. Never hardcode expected numbers to make
    output look right.

---

## API reference

All routes except those marked *public* require a session.

| Method | Path | Description |
|---|---|---|
| GET | `/` | Single-page UI *(public)* |
| GET | `/health` | Liveness and version *(public)* |
| GET | `/api/auth/status` | Whether sign-in is required, and who is signed in *(public)* |
| POST | `/api/auth/login` | Sign in with Management API credentials *(public)* |
| POST | `/api/auth/logout` | Sign out *(public)* |
| GET | `/api/checkpoint/test` | Log in, return Management API version |
| GET | `/api/bootstrap?force=` | List access layers and policy packages |
| GET | `/api/progress?rid=` | Live phase of a long request (polled by the UI) |
| GET | `/api/credentials/status` | Which credentials are configured; never returns passwords |
| POST | `/api/credentials` | Encrypt and save credentials, then apply them |
| POST | `/api/credentials/test` | `login` → `logout` with the supplied credentials; saves nothing |
| DELETE | `/api/credentials` | Remove a saved credential record |
| GET | `/api/package-analyze?package=&rid=` | Full analysis for a policy package |
| GET | `/api/package-policy-browser?package=&force=` | Raw rulebase for a policy package |
| GET | `/api/package-context?package=` | Access layers belonging to a package |
| GET | `/api/nat-analyze?package=` | NAT analysis for a policy package |
| GET | `/api/traffic-path?src=&dst=&protocol=&service=&port=&layer=&package=&rid=` | Traffic simulation |
| GET | `/api/network-map?force=&routing=` | Topology nodes and edges |
| GET | `/api/snapshot?package=&rid=` | Capture a snapshot (writes `snapshots/`) |
| GET | `/api/snapshots` | List snapshots |
| GET | `/api/snapshot-diff?a=&b=` | Compare two snapshots |
| GET | `/api/compliance-profiles` | List compliance profiles |
| GET | `/api/compliance?profile=&package=&snapshot=&rid=` | Run a profile against a package or snapshot |
| GET | `/api/health?baseline=&save=` | Read gateway health over Gaia; optionally compare and save |
| GET | `/api/health-baselines` | List saved health baselines |
| GET | `/api/runs` | List stored reviews |
| POST | `/api/runs?package=&profile=&include_health=&notify=&rid=` | Run a review now; `notify` sends it to alert destinations |
| GET | `/api/runs/{run_id}` | One stored review |
| GET | `/api/runs/{run_id}/report.pdf?detail=` | The review as a PDF (`summary`, `findings`, `full`) |
| GET | `/api/schedules` | List schedules and when each is next due |
| PUT | `/api/schedules` | Create or replace a schedule |
| DELETE | `/api/schedules/{sid}` | Remove a schedule |
| GET | `/api/ask?q=&package=&rid=` | A traffic question in Thai or English, answered by the Traffic Path trace |
| GET | `/api/remediation-script?package=&format=&include_zero_hit=&include_disabled=&include_unused_objects=&download=` | The cleanup script and its plan; writes nothing, runs nothing |
| GET | `/api/objects/hygiene?cap=&force=&rid=` | Unused objects, duplicates, redundant group members, exact merges |
| GET | `/api/objects/where-used?uid=` | What refers to one object |
| GET | `/api/rule-usage?package=&time_frame=&cap=&rid=` | Per-rule usage from firewall log records |
| GET | `/api/trends?package=` | Series from stored reviews, snapshots and health readings |
| GET | `/api/alerts` | Alert destinations; never returns a URL or password |
| PUT | `/api/alerts/destinations` | Create or replace a destination (secrets beside it, stored encrypted) |
| DELETE | `/api/alerts/destinations/{did}` | Remove a destination and its secret |
| PUT | `/api/alerts/public-url?url=` | The address alerts link back to |
| POST | `/api/alerts/test?destination=&run_id=` | Send the latest (or a given) review to one destination |
| GET | `/api/analyze?layer=` | Legacy layer-first analysis |
| GET | `/api/policy-browser?layer=&force=` | Legacy layer-first raw rulebase |
| GET | `/api/export.csv?layer=` | Analysis CSV |
| GET | `/api/policy-browser.csv?layer=` | Raw policy CSV |
| GET | `/api/package-policy-browser.csv?package=` | Raw policy CSV for a whole package, inline rules included |

`tests/test_v438_docs.py` fails if a route exists that this table does not list.

---

## Command-line tools

All are read-only against Check Point hosts and take credentials the same way the
server does: the encrypted store if one exists, otherwise `.env`.

| Command | What it does |
|---|---|
| `python -m tools.run_review --package <name>` | One review with no browser and no server. Exit `0` nothing changed, `1` something changed or a check failed, `2` part of it could not be decided, `3` it could not start — so Task Scheduler or cron can act on the result |
| `python -m tools.reset_credentials [--clear checkpoint\|gaia\|all]` | Show which source each credential value comes from; clear a saved record so `.env` applies. Never prints a password |
| `python -m tools.acceptance --package <name>` | Acceptance run against the live Management Server (below) |
| `python -m tools.suggest_cases --package <name>` | Propose acceptance cases from the live rulebase |
| `python -m tools.diag_resolver <package>` | Objects the resolver cannot turn into IP or port ranges, and why |
| `python -m tools.diag_topology` | What the Management Server says about clusters and HA |
| `python -m tools.probe_gaia --host <address>` | Record what a real Gaia gateway answers |

Run `tools.diag_resolver` first whenever Traffic Path answers `UNVERIFIED` or shadow
analysis looks empty.

---

## Testing

```bash
pytest -q                          # no Management Server required
node tests/js/scope_check.mjs .    # the frontend renderer harness on its own
```

Tests use fixture payloads shaped like real Management API responses; nothing in the
suite touches a live server. The suite runs as a signed-in operator through one autouse
fixture in `tests/conftest.py`; tests of the gate itself opt out with
`@pytest.mark.anonymous`. A second autouse fixture points the credential store at a
temporary file for every test, so no test can read or write the real `credentials.enc`.

`tests/js/scope_check.mjs` runs the real renderers from `app.js` in a stubbed DOM,
including the page's own start-up handler, to catch identifier errors that
`node --check` does not. It runs as part of `pytest` when Node.js is installed.

When a bug is found against a real environment:

1. Reproduce it and capture a minimal fixture from the real API response.
2. Add a failing regression test.
3. Fix the code.
4. Confirm the test fails with the fix removed.
5. Run the full suite.
6. Re-validate against SmartConsole.
7. Bump the version and add a CHANGELOG entry.

---

## Acceptance run

`pytest` proves the code behaves; it says nothing about whether this application
reports *your* estate correctly. For that, point the acceptance runner at the
Management Server:

```powershell
python -m tools.acceptance --package Standard
```

Read-only checks across safety, connection, access policy, data quality, Traffic Path,
NAT and topology. Prints one line per check and a total, exits non-zero on any failure,
and writes `acceptance-report.json` as evidence. Expected traffic verdicts live in
`tools/acceptance_cases.json` and are meant to be edited as the policy changes.

---

## Known limitations

Traffic Path is a **configuration-based simulation**, not a Check Point kernel
emulation. Live gateway behaviour can differ because of Identity Awareness, Security
Zones, dynamic objects, time objects, implied rules, routing, NAT ordering, VPN
processing and gateway state. Treat SmartConsole and gateway logs as authoritative.

Both scores are application-side heuristics, not Check Point features, and neither is
validated against expert judgement. Use them to compare the same policy over time, not
as an absolute grade. They are also different formulas:

- the dashboard's **Policy Health Score** (`policyHealthScore()` in `app.js`) deducts in
  proportion to how much of the rulebase each finding touches — shadowed/redundant
  (up to 34), duplicate groups (22), Any/Any/Any (9 each, up to 26), never-hit rules
  (12) — and 6 more when any object could not be fully resolved;
- `optimization_score` in the analysis payload (`app/analyzer.py`) deducts per finding —
  Any/Any/Any (8 each, up to 24), duplicate groups (3, up to 15), shadows (2, up to 25),
  disabled rules (1, up to 10).

Domain-based traffic queries resolve DNS from the machine running Firewall Insight,
which may differ from what the gateway resolves under split DNS. Results are memoised
for 60 seconds.

The network map is logical: it knows nothing about cabling, switches or live routing
beyond what the Gaia API reports at one instant, and Management HA is reported as
*configured*, never as *currently synchronised*.

NAT correlation matches `original-source` and `original-destination` only;
`original-service` is not evaluated, so a service-specific NAT rule can be reported
where it would not fire.

Gateway Health is one reading at one instant. It is not monitoring, and a schedule that
includes it takes one reading per run.

**Check Point only.** Palo Alto, Fortinet and Cisco are not supported. The analysis model
(rules, objects, tri-state matching) is not tied to Check Point in principle, but an adapter
that has never been run against a real device would be a claim, not a feature.

**Rule usage is a sample, not a count.** This Management API rejects aggregate log queries
and returns nothing for a filter on rule uid, so records are read one page at a time - about
seven seconds per hundred on the lab, where 500 records covered six minutes. It is not
Splunk/Elastic/SIEM integration and it is not real-time.

**The cleanup script has not been run against a Management Server by this project.** Its
shell syntax is checked with `bash -n` and the playbook parses as YAML; the commands follow
`mgmt_cli` and `check_point.mgmt` documentation. Read it before running it.

**Alert delivery to real Slack, Teams and SMTP servers is not verified here** - no such
endpoints were available. It was tested against a local HTTP receiver and a fake SMTP class.

**Ask understands phrasing it was written for.** It is a deterministic parser, not a language
model; when it cannot find a source, destination or service it says which, rather than guessing.

**Sign-in depends on the Management Server.** While it is unreachable, nobody can start
a new session; existing sessions continue. A wrong address saved in `credentials.enc`
locks everyone out until it is cleared with `tools/reset_credentials.py`.

**Served over plain HTTP by default.** The sign-in form carries Check Point
administrator credentials; put the application behind HTTPS before exposing it beyond
a trusted LAN, and mark the session cookie `secure` when you do.

**Single process.** The Management session, the response cache, the sign-in rate
limiter and the schedule loop live in one process. Running several workers would give
each its own copy of all four.

---

## Contributing / development rules

Do **not**:

- add any mutating Management API call, or a Gaia command outside the allowlist
- add a route to `PUBLIC_PATHS` without a stated reason
- give a credential request field a value-typed default
- flatten Inline Layer rules into the top-level Access Rules count
- compare rules across unrelated layers by rule number alone
- treat an unevaluable condition as "no match", or "could not be compared" as "unchanged"
- report a cleanup rule as definitive when an earlier rule is `unknown`
- hardcode expected SmartConsole rule counts
- assume NAT accepts every parameter Access accepts
- return to a layer-first selection model
- strip layer / layer-path / parent-rule metadata from findings or UI rows
- let `app/remediation.py` import anything that can reach a network
- send an alert at more than summary detail by default
- count a capped log scan's silence as "no traffic"
- put a real address in a placeholder, `.env.example` or this README — use RFC 5737
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`)

Versioning: `x.y.Z` bugfix, `x.Y.0` feature, `X.0.0` architecture change. Keep
experimental UI work out of the stable baseline.
