# Firewall Insight — Project-Dev Handoff (v4.29.0, 8 ก.ย. 2569)

**เอกสารนี้แทนที่ฉบับ v4.19.1 ทั้งหมด** ฉบับก่อนหน้าอ้างอิง 381 เทสต์, ยังไม่มี Gaia API,
ยังไม่มี snapshot/compliance/health และยังบอกว่า "Diff นโยบายข้ามช่วงเวลา — ยังไม่มีในโค้ด"
ซึ่งตอนนี้มีแล้ว **อย่าใช้ฉบับเก่าเป็น context**

ใช้ไฟล์นี้เป็นข้อความเริ่มต้นเมื่อเปิดแชทใหม่ เพื่อไม่ต้องแบกประวัติแชทเดิม
งานถัดไปที่ตั้งใจไว้คือ **รื้อ frontend ใหม่ทั้งหมด — อ่านข้อ 12 ให้จบก่อนแตะไฟล์ใดๆ**

---

## 1. โปรเจกต์คืออะไร

**Firewall Insight** — เครื่องมือวิเคราะห์นโยบาย Check Point แบบ **อ่านอย่างเดียว**
(FastAPI + vanilla JS) ไม่ใช่ตัวแทน SmartConsole ต่อกับ Security Management Server จริง
ผ่าน Management API และต่อกับ gateway ผ่าน Gaia API แล้ววิเคราะห์สิ่งที่ SmartConsole
ไม่ได้ให้ตรงๆ: กฎซ้อนทับ/ซ้ำ, Inline Layer hierarchy, จำลองเส้นทางทราฟฟิกแบบ tri-state,
วิเคราะห์ NAT, แผนผังเครือข่ายพร้อม routing ที่อ่านมาจริง, เทียบ snapshot ข้ามเวลา,
ตรวจ compliance แบบ policy-as-code, และอ่านสถานะ gateway เทียบ baseline

พัฒนาโดยนักศึกษาสหกิจศึกษาที่ Netpoleon Thailand แล็บเป็นของจริงในบริษัท ไม่ใช่ mock
โปรเจกต์รับช่วงต่อจากพี่ไซ ("เอาไปศึกษาเอาเองนะน้อง") — ไม่มีสเปกตั้งต้น

---

## 2. กฎความปลอดภัยที่ห้ามละเมิด (ไม่ต่อรอง)

### 2.1 Management API

เรียกได้เฉพาะกลุ่ม `show-*` เท่านั้น:

```
login  logout  show-packages  show-package  show-access-layers
show-access-rulebase  show-nat-rulebase  show-object
show-gateways-and-servers
```

### 2.2 Gaia API (เพิ่มมาใน v4.27 — คนละ API คนละ credential)

`app/gaia.py` บังคับ allowlist **ใน `call()` ก่อน network I/O ใดๆ**:

```
show-routes  show-static-routes  show-interfaces  show-interface
show-bond-interfaces  show-cluster-state  show-version  show-asset
show-lldp-status  show-physical-interfaces-xcvr
```

`login` / `logout` / `keepalive` แยกไว้ใน `SESSION` ต่างหาก เพื่อให้ allowlist เป็น
"การอ่าน" ล้วนๆ อย่าเอาไปรวมกัน

### 2.3 กฎที่บังคับด้วยเทสต์ ไม่ใช่ด้วยความจำ

**ห้ามเพิ่ม** `add-*`, `set-*`, `delete-*`, `publish`, `install-policy`, `run-script`,
`run-reboot`, `add-license` หรือเทียบเท่า โดยเด็ดขาด **ทุก HTTP route ต้องเป็น `GET`**

`tests/test_v413_structure.py` ตรวจซ้ำ 3 ชั้น:
- ไม่มี router ประกาศ verb ที่แก้ไขข้อมูล (วัดได้ตอนนี้: **0 ตัว**)
- ไม่มีสตริงคำสั่งกลุ่มแก้ไขปรากฏใน `app/` เลย
- allowlist ของ Gaia มีแต่คำสั่งอ่าน

> การเพิ่มความสามารถต้อง **รัดการรับประกันให้แน่นขึ้น ไม่ใช่คลายลง** — นี่คือทิศทางเดียว
> ที่ยอมรับได้สำหรับเครื่องมือที่เราจะขอให้คนเอาไปชี้ที่ production

### 2.4 ความลับ

`.env` เก็บรหัสผ่านจริงของ Management Server **และ** Gaia ในแล็บ อยู่ใน `.gitignore`
**ห้าม commit เด็ดขาด** รันก่อน commit ทุกครั้ง:

```powershell
git status --short   # ต้องไม่เห็น .env
```

ไฟล์ที่ ignore ไว้แล้วและต้องคงไว้: `.env`, `snapshots/`, `health-baselines/`,
`gaia-probe.json`, `internal-fw.json`

### 2.5 การเขียนลงดิสก์

ระบบนี้เขียนไฟล์ที่เดียว และเป็น **local ทั้งหมด**: snapshot กับ baseline ใต้โฟลเดอร์
โปรเจกต์ ซึ่ง gitignore ไว้แล้ว ไม่มีการเขียนอะไรกลับไปที่ Management Server หรือ gateway
ชื่อไฟล์ผ่าน `SAFE_ID = ^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$` (ตัวแรกเป็น alphanumeric
จึงตัด `..` และ dot-file ออกโดยปริยาย)

---

## 3. สถานะปัจจุบัน (v4.29.0, วัดจริง 8 ก.ย. 2569)

```
python -m pytest -q                                 687 passed, ~2.2s (ไม่ต้องต่อ server)
node tests/js/scope_check.mjs .                     22 renderer checks (รันผ่าน pytest ด้วย)
python -m tools.acceptance --package External-FW    26/26, 0 failed
python -m tools.acceptance --package Internal-FW    17/17, 0 failed
python -m tools.probe_gaia                          3/3 gateway PASS
git log --oneline -1                                fc4388f (tag v4.29.0)
git status --short                                  สะอาด
```

ขนาดโค้ด (วัดจริง ไม่ใช่ประมาณ):

```
backend   6,398 บรรทัด   Python 35 ไฟล์ใต้ app/
frontend  4,521 บรรทัด   app.js 2,912 · app.css 991 · index.html 618
tests        66 ไฟล์      687 เทสต์ + 22 JS renderer checks
routes       23 path      ประกาศ 24 ครั้ง ทุกตัว GET  (ดูข้อ 8.1 — มี 1 ตัวซ้ำ)
```

**ประวัติเวอร์ชัน**: v4.20 tri-state NAT → v4.21 install-on → v4.22 multi-management →
v4.23 ICMP/match order/trace on map → v4.24 VPN column → v4.25 snapshot/diff →
v4.26 compliance-as-code → v4.27 Gaia API + routing → v4.28 gateway health →
v4.29 health diff readability รายละเอียดต่อเวอร์ชันอยู่ใน `CHANGELOG.md` (1,826 บรรทัด)
ซึ่งเป็น record จริง — commit `fc4388f` กินงาน v4.20–v4.29.0 รวดเดียวเพราะไม่เคย commit
ระหว่างทาง อย่าไปย้อนแตกทีหลัง

---

## 4. Lab จริงที่ใช้ทดสอบ (สถานะ 8 ก.ย. 2569)

```
CP-MGMT-01 / 02      R82 JHF T122        172.23.31.180 / .181   Management HA (primary/secondary)
External-GW01        Check Point 5800    172.23.31.177          cluster member ACTIVE
External-GW02        Check Point 5800    172.23.31.178          cluster member STANDBY
External-Cluster     ClusterXL           .31.179 / .34.179 VIP
Internal-GW01        Check Point 5800    172.23.31.176          bond1 = eth2+eth3, standalone
                                                                 bond1.10 = 192.168.10.254/24
                                                                 bond1.20 = 192.168.20.254/24
VDX-LAB              Brocade VDX6710     172.23.31.199
ICX6450-48           core switch         ve31 .254 / ve34 .254
esxi-nuc01           Intel NUC ESXi      192.168.10.2           รัน VM 4 ตัว (nsth.lab)
```

Policy packages: **External-FW** (9 top-level rule + 1 Inline Layer/4 rule),
**Internal-FW** (Allow-Any ตัวเดียว — ของจริง ยังไม่ได้ทำ segmentation), **Standard**

**ตัวเลข "132 rule / 116 NAT" ในเอกสารรุ่น v4.7 ไม่เกี่ยวกับแล็บปัจจุบัน** อย่าใช้เป็น
oracle ใช้ `tools/acceptance_cases.json` ซึ่ง transcribe จาก live rulebase จริง

### 4.1 เรื่องที่ต้องรู้เรื่อง .176 (เกิดขึ้นจริง 8 ก.ย. อย่าไปแก้กลับ)

`Internal-GW01` เคยอ่านไม่ได้จาก workstation (172.23.10.35) ทั้งที่ default route
`0.0.0.0/0 via 172.23.31.179` มีอยู่และถูกต้อง สาเหตุจริงคือ **asymmetric route**:
SYN เข้าทาง .176 แต่ reply ออกคนละทาง External cluster จึงเห็นเป็น out-of-state แล้ว drop
พิสูจน์ด้วย tcpdump (เห็นทั้ง request และ reply) + SmartConsole drop log

**ทางแก้ที่ถูกและใส่ไปแล้ว** — บน .176:

```
set static-route 172.23.10.0/24 nexthop gateway address 172.23.31.254 on
save config
```

`172.23.31.254` คือ **ve31 ของ ICX core** ไม่ใช่ `.179` (VIP ของคลัสเตอร์ ซึ่ง default
ชี้ไปอยู่แล้ว และเป็นต้นเหตุ) — สมมติฐานแรกสองข้อ (default route หาย / allowed-clients)
**ผิดทั้งคู่** และถูกหักล้างด้วย `show route` กับ `show allowed-client all` ของผู้ใช้เอง
เรื่องเต็มอยู่ใน `docs/Case-Study-Asymmetric-Route-2026-09-08.md`

`show-cluster-state` บน .176 ตอบ `{"message": ...}` เปล่าๆ ไม่ error เพราะเป็น standalone
UI จะขึ้น **"No cluster state returned by this gateway"** ซึ่ง **ถูกต้องแล้ว** ไม่ใช่บั๊ก
และ finding `no-active-member` ถูกข้ามอย่างตั้งใจเพราะ guard ด้วย `if cluster["readable"]:`

---

## 5. สถาปัตยกรรมปัจจุบัน

```
app/
  main.py (52)          app factory + lifespan + router include
  version.py (3)        APP_VERSION แหล่งเดียว — v4.29.0
  config.py (27)        .env settings (รวม GAIA_*)
  runtime.py (67)       Management client, response cache, HTTP error mapping
  progress.py (45)      live phase registry ที่ UI poll
  policy.py (254)       fetch → hydrate → analyse orchestration, data_quality
  api/                  ทุกไฟล์ GET-only
    meta.py access.py nat.py traffic.py topology.py export.py ui.py
    snapshot.py compliance.py health.py
  checkpoint.py (511)   Management API client: session, pacing, retry/backoff,
                        pagination, Inline Layer tree discovery
  inline_layers.py (366) layer-tree traversal, display numbering, aggregation
  resolver.py (358)     UID → name / IP interval / port interval
  analyzer.py (141)     Access findings
  nat_analyzer.py (349) NAT findings
  nat_correlate.py (125) tri-state NAT correlation (แยกออกมาตอน traffic.py ชน guard)
  policy_browser.py (90) raw rulebase → table rows
  traffic.py (366)      path trace orchestration
  matching.py (386)     address/service/vpn matching, tri-state (แยกจาก traffic.py)
  topology_map.py (229) gateways/servers → nodes/edges, cluster + HA links
  path_map.py (240)     trace_overlay(): policy_confidence / topology_confidence แยกกัน
                        `draw` = อันที่อ่อนที่สุด
  snapshot.py (252)     build/save/list/load snapshot
  snapshot_diff.py (302) diff by rule uid, moved vs modified, scope by interval
  compliance.py (449)   7 check type + provenance บังคับ + ไม่มี percentage
  compliance_profiles/  nist-800-41-baseline.yaml, house-hygiene.yaml
  gaia.py (253)         Gaia client + ALLOWED enforced ก่อน I/O
  gaia_topology.py (369) read_routes(), add_routing(), HOP_DESCRIPTORS
  health.py (403)       interfaces/cluster/version, findings, baseline diff
  templates/index.html (618)
  static/css/app.css (991)
  static/js/app.js (2912)
tests/          66 ไฟล์ 687 เทสต์
  conftest.py           ui_source() / ui_text() / python_source()
  fixtures/gaia_r82_probe.py   payload R82 จริง ไม่แก้ — เป็น oracle
  js/scope_check.mjs           รัน app.js ใน node:vm พร้อม DOM stub
tools/
  acceptance.py + acceptance_cases.json   acceptance กับ server จริง
  probe_gaia.py         บันทึกว่า Gaia ของแล็บตอบอะไรจริง
  suggest_cases.py      เสนอเคสทดสอบจาก rulebase จริง
  diag_topology.py  diag_resolver.py  ch3_demo.py
docs/
  Firewall-Insight-Learning-Guide-Ch1..6.md
  Firewall-Insight-Learning-Guide-Ch4-6-Answers.md   การบ้าน Ch4-6 (429 บรรทัด)
  Project-Assessment-and-Market-Position.md          ประเมินแบบไม่อวย + เทียบตลาด
  Case-Study-Asymmetric-Route-2026-09-08.md          เคสจริงเต็มลูป
```

**Guard เชิงโครงสร้าง**: ไฟล์ Python ใต้ `app/` ต้อง **< 700 บรรทัด** เทสต์บังคับ
`traffic.py` ชน guard สองครั้ง จึงแตกเป็น `nat_correlate.py` แล้วก็ `matching.py`
ถ้าจะเพิ่มโค้ดจนไฟล์ยาวเกิน ให้แยกโมดูล **แล้วเพิ่มชื่อโมดูลใหม่ในลิสต์ของเทสต์ด้วย**

---

## 6. หลักการออกแบบที่ต้องเข้าใจก่อนแก้โค้ด

1. **Policy Package คือ context หลัก** ไม่ใช่ Access Layer เดี่ยวๆ
2. **Access policy เป็นต้นไม้** Inline Layer คือ policy ลูกจริง ไม่ใช่กฎแบน
   `show_rulebase_tree()` เดิน recursive เก็บ `depth`, `path`, `parent_layer`,
   `parent_rule`, `display_prefix`
3. **จำนวนกฎกับจำนวนกฎที่วิเคราะห์คนละตัวกัน** ห้ามรวมเป็นเลขเดียว
4. **Pagination เดินตาม `to` boundary ของ API** ไม่ใช่ `len(batch)`
5. **`display_rule` เป็นการแสดงผลเท่านั้น** (`30.1`, `30.2.1`) ไม่แก้ `rule-number` จริง
6. **Traffic matching เป็น tri-state**: `match` / `no-match` / `unknown` — Security Zone,
   dynamic object, negation, Identity Awareness = `unknown` เสมอ **ห้ามแปลงเป็น `no-match`**
7. **กฎก่อนหน้าที่ `unknown` บล็อกผลสรุปของกฎหลัง** ผลต้องเป็น `UNVERIFIED` ไม่ใช่ `Drop`
8. **มีข้อมูลใน dictionary ไม่ได้แปลว่าใช้ได้** `details-level: standard` มีแค่
   uid/name/type — `resolver.needs_detail()` ตัดสินจาก field ที่ resolver ใช้จริง แล้ว
   hydrate ซ้ำ (สูงสุด `MAX_HYDRATION_ROUNDS = 6`)
9. **Matching กับ Containment ต้องการความเข้มงวดต่างกัน** พิสูจน์ตรงใช้ `*_atoms_partial()`
   (∃ พอ) พิสูจน์ครอบคลุมใช้ `address_atoms()`/`service_atoms()` แบบเข้ม (ต้อง ∀, คืน
   `None` ถ้าไม่ครบ) **ห้ามสลับกันใช้**
10. **UI ห้ามแสดงผลบางส่วนเหมือนผลสมบูรณ์** `data_quality()` รายงาน inline layer ที่โหลด
    ไม่สำเร็จและ hydration ที่ถูกตัดตอน frontend ต้องแสดง banner/toast
11. **SmartConsole/gateway log จริงคือ oracle เดียว** ห้าม hardcode ตัวเลขที่ "ควรจะถูก"

### 6.1 หลักการที่เพิ่มมาระหว่าง v4.20–v4.29 (สำคัญไม่แพ้ 11 ข้อบน)

12. **unknown ห้ามถูกปัดขึ้นเป็นผ่าน และความเงียบไม่ใช่สุขภาพ** — gateway ที่ไม่ตอบต้อง
    ถูกรายงานเป็น finding ของตัวเอง ไม่ใช่หายไปเฉยๆ เป็นประโยคที่เขียนไว้ใน UI จริง:
    *"A gateway that did not answer produces no findings, which is not the same as
    producing none."*
13. **compliance ไม่ออกเป็นเปอร์เซ็นต์โดยเจตนา** คะแนนชวนให้ปัด unverifiable ขึ้นเป็นผ่าน
    `conformant` ต้อง failed = 0 **และ** unverifiable = 0 ทุก check ต้องมี provenance
    (`UNCITED` ถ้าไม่มี)
14. **หนึ่ง read ที่พังต้องเสียแค่ read นั้น** ทั้งระดับ gateway (gateway หนึ่งพังไม่ลาก
    ตัวอื่น) และระดับคำสั่ง (`show-cluster-state` พังไม่ลาก interfaces/version ไปด้วย)
15. **"อ่านไม่ได้" ≠ "ไม่มีอยู่"** — บทเรียน v4.29.0 `diff_health()` เคยอ่านแค่ครึ่งเดียว
    ของรายงาน gateway ที่บันทึกไว้เองว่า unreachable จึงกลับมาเป็น `gateway-added`
    ตอนนี้มี `gateway-became-readable` / `gateway-became-unreadable` ที่พก error ติดไปด้วย
16. **parsed ต้องแปลว่า "เข้าใจแล้ว" ไม่ใช่ "เห็นแล้ว"** — route reader เคยรายงาน 7/7
    ทั้งที่ทิ้ง next hop ทุกตัว เพราะ Gaia ซ้อน `next-hop.gateways[]`

**บทเรียนที่แพงที่สุด**: `_dimension_cover()` (v4.17) — เซตว่างเป็นสับเซตของทุกเซตในทาง
คณิตศาสตร์ ทำให้กฎที่มิติใดมิติหนึ่งไม่มีข้อมูล (`[]`) ถูกรายงานว่า "ถูกกฎก่อนหน้าบังไว้"
ทั้งที่ไม่มีข้อมูลจะพิสูจน์เลย **พบจากการอ่านโค้ดตอนเขียนคู่มือ ไม่ใช่จากการทดสอบ**

---

## 7. ข้อจำกัดที่ระบบประกาศไว้เอง

- **Traffic Path เป็นการจำลองจาก configuration** ไม่ใช่ kernel emulation ต่างจาก gateway
  จริงได้เพราะ Identity Awareness, Security Zone, dynamic object, routing, NAT ordering,
  VPN, gateway state — UI ต้องรายงานระดับความเชื่อมั่นเสมอ
- **Optimizer score เป็น heuristic ฝั่งแอป** ไม่ใช่ฟีเจอร์ Check Point ห้ามเรียกว่า
  "Check Point official score"
- **Domain-based query resolve DNS จากเครื่องที่รัน Firewall Insight** อาจต่างจาก gateway
  ภายใต้ split DNS
- **แผนผังเครือข่ายเป็น logical** — `Load with Routing` ไม่ได้เปลี่ยนข้อนี้ มัน **อ่าน**
  routing table ของแต่ละ gateway มาแทนการเดา และเป็น snapshot ณ เวลาที่อ่าน ไม่ใช่ live
- **Gateway Health ไม่ใช่ monitoring** เป็นการอ่านครั้งเดียว ณ วินาทีนั้น
- **Management HA = สถานะที่ตั้งไว้** ไม่ใช่สถานะซิงค์ปัจจุบัน (API ไม่เปิดเผย)

---

## 8. ยังไม่ได้ทำ / ทำต่อได้เลย

### 8.1 บั๊กที่รู้แล้วแต่ยังไม่แก้

- **`/api/analyze` ประกาศซ้ำสองครั้งแบบเหมือนกันเป๊ะ** ที่ `app/api/access.py:58` และ `:63`
  ตัวหลังเป็น dead code (FastAPI ใช้ตัวแรก) ไม่ทำให้พัง แต่ควรลบ และควรมี structure test
  ว่า "ไม่มี path ไหนถูกประกาศซ้ำ" กันไม่ให้กลับมา — งาน 10 นาที

### 8.2 งานที่ยังค้างจากคู่มือ/แล็บ

- **Ch5 ข้อ ก ยังไม่ได้ตอบ**: ทำไม External-FW มี NAT 11 rule แต่ Internal-FW มี 10
- **`acceptance_cases.json`**: External-FW rule 1/2/3/7 ยัง `expect: null` รอคนยืนยัน
  จาก log จริง (หลักการข้อ 11 — ห้ามเดาแล้วเขียนลงไป)
- **ทดสอบกับ policy ขนาดใหญ่** ตอนนี้มีแค่ 13 กฎที่วิเคราะห์รวม ยังไม่เคยพิสูจน์
  performance/ความถูกต้องกับ policy หลายร้อยกฎ
- **นโยบายในแล็บที่ acceptance ชี้เป็น finding ไม่ใช่บั๊กของแอป**: Internal-FW ยังเป็น
  Allow-Any ตัวเดียว, External-FW มี zero-hit rule — งาน SmartConsole ไม่ใช่งาน dev

### 8.3 ฟีเจอร์ที่ตัดสินใจ "ไม่ทำ" พร้อมเหตุผล

- **แปลง config Palo Alto → Check Point** — ตัดออกโดยตั้งใจ Check Point **SmartMove**
  รองรับ PAN-OS + Panorama อย่างเป็นทางการและฟรีอยู่แล้ว การเขียนใหม่ให้แย่กว่าไม่ใช่
  การเพิ่มคุณค่า ถ้าจะรื้อเรื่องนี้ ต้องตอบให้ได้ก่อนว่า *ดีกว่า SmartMove ตรงไหน*

---

## 9. คำสั่งที่ต้องรู้ (อ่านอย่างเดียวทั้งหมด)

```powershell
python -m pytest -q                                 # 687 เทสต์ ไม่ต้องต่อ server
node tests/js/scope_check.mjs .                     # 22 renderer checks
python -m tools.acceptance --package External-FW    # 26 check
python -m tools.acceptance --package Internal-FW    # 17 check
python -m tools.probe_gaia                          # Gaia ตอบอะไรจริง
python -m tools.suggest_cases --only 1,2,3,7        # เสนอเคสจาก rulebase จริง
python -m tools.diag_topology                       # cluster/HA ตาม API จริง
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

> ใช้ `python -m <tool>` เสมอ ถ้า `pytest`/`uvicorn` เรียกตรงแล้วไม่เจอ แปลว่า venv
> ไม่ได้ active จริง (`pip` ไปโดน Python global) — `python -m` เลี่ยงปัญหานั้นทั้งหมด

**Workflow เมื่อพบบั๊ก (ห้ามข้ามขั้น)**:
**reproduce → หาสาเหตุด้วยเครื่องมือ read-only ที่เขียนเฉพาะ → เขียน regression test →
แก้ → พิสูจน์ด้วยการวัดจริง (ไม่ใช่ดูสกรีนช็อต) → bump version → เขียน CHANGELOG.md**

---

## 10. Repo

```
remote:  https://github.com/IyolrymtnXmo/firewall-insight.git   (private — ต้องเคลียร์
                                                                 สิทธิ์ IP กับ Netpoleon
                                                                 ก่อนขาย/เปิด)
branch:  main
HEAD:    fc4388f  tag v4.29.0
โฟลเดอร์: A:\Co-Operation-NetpoleonTH\Project-Dev\Policy-Automation\Firewall-Insight-v4.7
```

---

## 11. ข้อความเปิดสำหรับแชทใหม่

> คุณคือ dev หลักของ Firewall Insight เครื่องมือวิเคราะห์นโยบาย Check Point แบบอ่านอย่างเดียว
> อยู่ที่ v4.29.0 (commit fc4388f) 687 เทสต์ + 22 JS renderer checks ผ่าน acceptance
> 26/26 + 17/17 กับแล็บจริง อ่าน handoff นี้ทั้งหมดก่อนแก้โค้ดใดๆ โดยเฉพาะข้อ 2
> (กฎความปลอดภัย), ข้อ 6 (หลักการออกแบบ 16 ข้อ) และข้อ 12 (บรีฟรื้อ frontend)
> ห้ามเพิ่มคำสั่งที่แก้ไขข้อมูลเด็ดขาด งานถัดไปคือ: **รื้อ frontend ใหม่ทั้งหมด**

---

## 12. บรีฟ: รื้อ frontend ใหม่ทั้งหมด ← งานถัดไป

### 12.1 โจทย์

หน้าตาปัจจุบัน "ดูเหมือน AI ทำ" และเจ้าของโปรเจกต์อยากได้ความรู้สึกแบบ **enterprise**
วินิจฉัยจาก `app/static/css/app.css` — สัญญาณชัดเจน:

| สิ่งที่เจอ | ทำไมมันฟ้อง |
|---|---|
| `--purple:#8b5cf6` | คือ Tailwind `violet-500` เป๊ะ เป็นสี default ที่ LLM หยิบบ่อยที่สุด |
| `--font-ui:'Nunito'` | ฟอนต์ปลายมน โทน friendly/consumer ตรงข้ามกับเครื่องมือ NetOps |
| `border-radius:15px`, pill `999px` ทุกที่ | มนหมดทั้งหน้า |
| `linear-gradient` บนเมนู active, `radial-gradient` เรืองแสงหลัง topology | gradient ตกแต่งคือลายเซ็นอีกอัน |
| metric `31px` / `font-weight:850` | ใหญ่เกินสำหรับความหนาแน่นข้อมูลระดับนี้ |
| icon เป็นอักขระ `◈ ▤ ◇ ⇄ ➜ ⌘ ⧗ ✓ ♥` | ชุด glyph ที่ไม่ได้มาจาก icon set เดียวกัน |

เครื่องมือ enterprise จริง (SmartConsole, AlgoSec, Tufin, FireMon) ไปคนละทาง: **พาเลตกลาง
(เทา/น้ำเงินเข้ม) สงวนสีไว้สื่อ state เท่านั้น, มุม 3–4px, ตัวอักษรเล็กลง, ข้อมูลต่อ
หน้าจอเยอะขึ้น, ไม่มี gradient ตกแต่ง** เพราะคนใช้จ้องมันวันละ 8 ชั่วโมงเพื่อหาความผิดปกติ

### 12.2 ทิศทางดีไซน์ — **ยังไม่ตัดสินใจ**

เจ้าของโปรเจกต์ขอ **ดูตัวอย่างก่อนเลือก** ดังนั้นงานแรกของ session ถัดไปคือ:

> ทำ preview 2–3 ทิศทางของ **หน้า Access Policy หน้าเดียว** (หน้าที่ข้อมูลหนาแน่นที่สุด
> จึงเป็นบททดสอบจริงของดีไซน์) ให้เลือก **ก่อน** ลงมือรื้อของจริง
> ตัวเลือกที่คุยกันไว้: (ก) เหมือน SmartConsole — แน่น มุมคม มุมมอง operator
> (ข) enterprise SaaS แบบ AlgoSec/Tufin — สะอาดกว่า whitespace บ้าง
> (ค) โมเดิร์นแต่สำรวม — โครงเดิม ทิ้งม่วง/gradient/มุมมน เปลี่ยนฟอนต์

### 12.3 สัญญาที่ห้ามผิด — **อ่านให้จบก่อนลบไฟล์ใดๆ**

การรื้อ frontend ที่นี่ไม่ใช่งาน CSS ล้วน เพราะเทสต์ผูกกับ **ข้อความจริงในไฟล์ frontend**

**วัดจริง: มี 102 ฟังก์ชันเทสต์ที่ assert กับ source ของ UI** (ผ่าน `ui_source()` /
`ui_text()` ใน `tests/conftest.py`) กระจายใน 18 ไฟล์ หนักสุดคือ
`test_v415_graph_map.py` (35), `test_v414_topology.py` (20), `test_v416_cluster_ha.py` (8)
**บวกอีก 22 renderer checks** ที่รัน JS จริงใน `node:vm`

สิ่งที่ถูกตรึงไว้:

1. **Element id** — `index.html` มี **101 id** และโค้ด JS อ้างถึงมันเป็น **global
   variable โดยตรง** (`natResults` ไม่ใช่ `document.getElementById('natResults')`)
   นี่คือพฤติกรรมของเบราว์เซอร์ที่ `scope_check.mjs` จำลองไว้ **เปลี่ยน id = พังเงียบ**
2. **ชื่อฟังก์ชัน** ที่ `scope_check.mjs` เรียกตรงๆ ต้องมีอยู่และเรียกได้:
   `renderNatSpecialViews` `showNatTab` `natTable` `complianceSource_cite`
   `complianceSourceChanged` `diffRows` `diffSection` `topoTraceClass` `topoTraceHops`
   `topoTraceBar` `clearTraceOnMap` `esc` `buildTopoGraph`
3. **global `TOPO`** พร้อม field `merge` `collapsed` `unmerged` `expanded` `focus`
   `query` `trace` `graph` `hits` `hitIdx` และ `buildTopoGraph()` ต้องคืน `{nodes, links}`
   ที่ **ยังมี** `role: 'routed-network'` และ `kind: 'route'` อยู่ (v4.28.2 พังตรงนี้มาแล้ว)
4. **สตริงที่ถูกตรึงแบบตัวอักษรต่อตัวอักษร ~57 ชิ้น** รวมถึง **CSS declaration เต็มบรรทัด**
   เช่น `.topo-g-edge.on-path.path-unverified line{stroke:var(--warn);stroke-dasharray:2 6`
   — เขียน CSS ใหม่แล้วเทสต์แดงแน่นอนถ้าไม่อ่านก่อน
5. **`<h1>Check Point Firewall Analysis Platform</h1>` ต้องตามด้วย `</div>` ทันที**
   (ห้ามมี subtitle ใต้ h1 — เคยมีแล้วเอาออก)
6. **ประโยคความซื่อสัตย์ที่ต้องรอด** เพราะมันคือคำสัญญาของเครื่องมือ ไม่ใช่ copy:
   - *"Physical cabling, switches and live routing are not inferred"*
   - *"A gateway that did not answer produces no findings, which is not the same as producing none."*
   - *"State is read at one instant over the Gaia API. It is not monitoring."*
   - *"whether the peers are currently synchronised is not exposed"*
   - เหตุผลของ dashed/warn บนเส้น trace: unverified ห้ามวาดเหมือน exact และ
     **ต้องอ่านออกทั้งในภาพขาวดำและสำหรับคนตาบอดสี** (มีเทสต์ตรงนี้จริง)

### 12.4 วิธีที่แนะนำ (และเหตุผลที่ไม่แนะนำ big-bang)

เจ้าของเลือก "รื้อทั้งหมด" ไว้ ซึ่งทำได้ แต่ **อย่าลบ `app.js` ทิ้งแล้วเขียนใหม่จากศูนย์**
— นั่นคือการทิ้งทั้ง 102 assertion ทิ้ง 22 renderer check และทิ้งบั๊กที่แก้ไปแล้ว 10 เวอร์ชัน
ในคืนเดียว วิธีที่ได้ผลลัพธ์เดียวกันแต่ไม่ทิ้งหลักฐาน:

1. **ชั้น token ก่อน** — เขียน `:root` ใหม่ทั้งชุด (สี ฟอนต์ radius spacing) โดยไม่แตะ
   selector อื่น รันเทสต์ ดูว่าแดงกี่ตัวและตัวไหน **นี่คือการวัดขนาดงานจริง**
2. **แก้เทสต์ที่ตรึง CSS declaration ให้ตรึง *เจตนา* แทน *ตัวอักษร*** เช่นเปลี่ยนจาก
   "ต้องมีสตริงนี้เป๊ะ" เป็น "เส้น unverified ต้องมี `stroke-  ` และสีต่างจาก
   เส้น exact" — เทสต์จะแข็งแรงขึ้นด้วย ทำทีละไฟล์ อย่ารวบ
3. **รื้อทีละหน้า** เรียงตามความเสี่ยงจากน้อยไปมาก:
   Compliance → Policy Diff → Gateway Health → Dashboard → NAT → Access Policy →
   Traffic Path → **Network Mapping ท้ายสุด** (มี 55 assertion และ SVG graph ทั้งชุด)
4. **`node tests/js/scope_check.mjs .` หลังแตะ JS ทุกครั้ง** ไม่ใช่แค่ตอนจบ — เครื่องมือนี้
   ถูกสร้างขึ้นเพราะ `d is not defined` หลุดถึงมือผู้ใช้ทั้งที่ 668 เทสต์เขียว
5. **bump version + CHANGELOG ทุกขั้น** เหมือนงาน backend ไม่มีข้อยกเว้นให้ UI

### 12.5 สิ่งที่ห้ามหายไปพร้อมกับดีไซน์เก่า

- toast/banner ของ `data_quality()` (หลักการข้อ 10)
- ป้าย confidence บน Traffic Path ทั้ง `policy_confidence` และ `topology_confidence`
- คำเตือน "gateway ไหนไม่ตอบ" บนหน้า Health
- legend ของแผนที่ที่แยก `Route (read at one instant)` ออกจาก edge ชนิดอื่น
- ปุ่ม/ป้าย **Read-only · Management API** ที่มุมล่างซ้าย — มันคือคำสัญญาหลักของเครื่องมือ
  ที่ผู้ใช้เห็นตลอดเวลา

> ถ้าดีไซน์ใหม่สวยขึ้นแต่พูดความจริงน้อยลง แปลว่าเรารื้อผิดทาง
