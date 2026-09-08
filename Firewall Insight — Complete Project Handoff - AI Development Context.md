# Firewall Insight — Project-Dev Handoff (v4.19.1, 7 ก.ย. 2569)

**เอกสารนี้แทนที่ฉบับเดิม** `Firewall Insight — Complete Project Handoff - AI Development Context.md`
ทั้งหมด ฉบับเดิมอ้างอิง baseline v4.7 (main.py ก้อนเดียว 132/116 rule, สี purple/blue,
tri-state ยังไม่มี) ซึ่งไม่ตรงกับสถานะจริงอีกต่อไป **อย่าใช้ฉบับเดิมเป็น context** —
ทุกตัวเลขและสถาปัตยกรรมในนั้นถูกแทนที่แล้ว

ใช้ไฟล์นี้เป็นข้อความเริ่มต้น (system/first message) เมื่อเปิดแชทใหม่สำหรับงาน Project-Dev
เพื่อไม่ต้องแบกประวัติแชทเดิมที่ยาวเกินไป

---

## 1. โปรเจกต์คืออะไร

**Firewall Insight** — เครื่องมือวิเคราะห์นโยบาย Check Point แบบ **อ่านอย่างเดียว**
(FastAPI backend + vanilla JS frontend) ไม่ใช่ตัวแทน SmartConsole เชื่อมต่อ
Check Point Security Management Server จริงผ่าน Management API แล้ววิเคราะห์/แสดงผล
สิ่งที่ SmartConsole ไม่ได้ให้ตรงๆ: กฎซ้อนทับ/ซ้ำ, Inline Layer hierarchy, จำลอง
เส้นทางทราฟฟิกแบบ tri-state, วิเคราะห์ NAT, แผนผังเครือข่าย

พัฒนาโดยนักศึกษาฝึกงาน (สหกิจศึกษา) ที่ Netpoleon Thailand แล็บทดสอบเป็นของจริงในบริษัท
ไม่ใช่ mock

---

## 2. กฎความปลอดภัยที่ห้ามละเมิด (ไม่ต่อรอง)

ระบบเรียกได้เฉพาะคำสั่งกลุ่ม `show-*` เท่านั้น:

```
login  logout  show-packages  show-package  show-access-layers
show-access-rulebase  show-nat-rulebase  show-object
show-gateways-and-servers
```

**ห้ามเพิ่ม** `add-*`, `set-*`, `delete-*`, `publish`, `install-policy` หรือเทียบเท่า
โดยเด็ดขาด ทุก HTTP route ต้องเป็น `GET` — `tests/test_v413_structure.py` ตรวจซ้ำว่า
ไม่มี router ประกาศ verb ที่แก้ไขข้อมูล และไม่มีคำสั่งกลุ่มแก้ไขปรากฏใน `app/` เลย

`.env` เก็บรหัสผ่านจริงของ Management Server ในแล็บ อยู่ใน `.gitignore` **ห้าม commit**
เด็ดขาด รันคำสั่งนี้ก่อน commit ทุกครั้ง:

```powershell
git status --short   # ต้องไม่เห็น .env
```

---

## 3. สถานะปัจจุบัน (v4.19.1, ยืนยัน 7 ก.ย. 2569)

```
pytest -q                                    381 passed, 1.18s (ไม่ต้องต่อ Management Server)
python -m tools.acceptance --package External-FW    25/25, 0 failed
python -m tools.acceptance --package Internal-FW    16/16, 0 failed
git log --oneline -1                         f87844c (tag v4.19.1) — ตรงกับ HEAD
git status                                   สะอาด (มีแค่ internal-fw.json ซึ่งเป็นไฟล์รายงานที่ generate ใหม่ทุกรัน ไม่ใช่ source)
origin/main                                  ตรงกับ HEAD ไม่มี commit ค้าง push
```

ปัญหาที่เคยค้าง — **แท็ก git ผิด (v4.17.0 ชี้คอมมิตเก่า)** — **แก้แล้ว**, ไม่มีแท็กนั้นในระบบ
อีกต่อไป v4.19.1 ชี้ commit ถูกต้อง

ขนาดโค้ด: backend 3,371 บรรทัด (21 ไฟล์) + frontend 3,765 บรรทัด (`app.js` 2,311,
`app.css` 942, `index.html` 512) รวม 7,136 บรรทัด, 16 API endpoint ทุกตัวเป็น GET

---

## 4. Lab จริงที่ใช้ทดสอบ (สถานะ 1 ก.ย. 2569 เป็นต้นไป — เปลี่ยน routing แล้ว)

```
CP-MGMT-01 / 02      R82 JHF T122        172.23.31.180 / .181   Management HA (primary/secondary)
External-GW01        Check Point 5800    172.23.31.177          cluster member ACTIVE
External-GW02        Check Point 5800    172.23.31.178          cluster member STANDBY
External-Cluster     ClusterXL           .31.179 / .34.179 VIP
Internal-GW01        Check Point 5800    172.23.31.176          bond1 = eth2+eth3
VDX-LAB               Brocade VDX6710    172.23.31.199
ICX6450-48            core switch        ve31 .254 / ve34 .254
esxi-nuc01            Intel NUC ESXi     192.168.10.2           รัน VM 4 ตัว (nsth.lab)
```

Policy packages ในแล็บ: **External-FW** (9 top-level rule, 1 Inline Layer/4 rule),
**Internal-FW** (1 rule: Allow-Any — ของจริง ยังไม่ได้ทำ segmentation), **Standard**

**ตัวเลข "132 rule / 116 NAT" ในเอกสารเก่าไม่เกี่ยวข้องกับแล็บปัจจุบัน** — เป็นเลขจาก
สภาพแวดล้อมทดสอบคนละชุดตอนต้นโปรเจกต์ (v4.0–v4.2) แล็บปัจจุบันมีกฎน้อยกว่ามาก
อย่าใช้ 132/116 เป็น oracle อีก — ใช้ `tools/acceptance_cases.json` ซึ่ง transcribe
จาก live rulebase จริงแทน

---

## 5. สถาปัตยกรรมปัจจุบัน (ไม่ใช่ main.py ก้อนเดียวอีกต่อไป — refactor เสร็จแล้ว)

```
app/
  main.py               app factory + lifespan + router include (~53 บรรทัด)
  version.py            APP_VERSION แหล่งเดียว
  config.py             .env settings
  runtime.py            Management client, response cache, HTTP error mapping
  progress.py           live phase registry ที่ UI poll
  policy.py             fetch → hydrate → analyse orchestration, data_quality
  api/
    meta.py    access.py   nat.py   traffic.py   topology.py   export.py   ui.py
  checkpoint.py          Management API client: session, pacing, retry/backoff,
                         pagination, Inline Layer tree discovery
  inline_layers.py       layer-tree traversal, display numbering, aggregation
  resolver.py            UID → name / IP interval / port interval
  analyzer.py            Access findings
  nat_analyzer.py        NAT findings
  policy_browser.py      raw rulebase → table rows
  traffic.py             tri-state matcher, path trace, NAT correlation
  topology_map.py        gateways/servers -> nodes/edges, cluster + HA links
  templates/index.html
  static/css/app.css
  static/js/app.js
tests/            46 ไฟล์ 381 เทสต์
tools/
  acceptance.py          ตัวรัน acceptance test กับ Management Server จริง
  acceptance_cases.json  เคสทดสอบต่อ package (แก้ไขได้โดยไม่แตะ runner)
  ch3_demo.py            พิสูจน์ทุกข้ออ้างในคู่มือบทที่ 3 ต่อโค้ดจริง
  diag_topology.py       diagnostic อ่านอย่างเดียว: cluster/HA ตาม API จริง
  diag_resolver.py       diagnostic: วัตถุที่ resolve ไม่ออก
docs/
  Firewall-Insight-Learning-Guide-Ch1..6.md   คู่มือ dev ต่อ (มีใน Project ด้วย)
```

> **README.md มีจุดที่ล้าสมัยอยู่ 1 จุด**: หัวข้อ "Known limitations" ยังบอกว่า
> `app/main.py` embed ทั้ง frontend เป็น Python string — **ไม่จริงแล้ว**, refactor
> เป็น `templates/`/`static/` เสร็จตั้งแต่ v4.13 ควรแก้ README ทิ้งประโยคนี้เป็นงานเล็กๆ
> ที่ทำได้ทันที

---

## 6. หลักการออกแบบที่ต้องเข้าใจก่อนแก้โค้ด (11 ข้อ จาก README, สำคัญมาก)

1. **Policy Package คือ context หลัก** ไม่ใช่ Access Layer เดี่ยวๆ
2. **Access policy เป็นต้นไม้** Inline Layer คือ policy ลูกจริง ไม่ใช่กฎแบน
   `show_rulebase_tree()` เดินแบบ recursive เก็บ `depth`, `path`, `parent_layer`,
   `parent_rule`, `display_prefix`
3. **จำนวนกฎกับจำนวนกฎที่วิเคราะห์คนละตัวกัน** `Access Rules` = top-level แบบ
   SmartConsole, `Inline Rules`/`Total Rules Inspected` แยกรายงาน ห้ามรวมเป็นเลขเดียว
4. **Pagination เดินตาม `to` boundary ของ API** ไม่ใช่ `len(batch)` — section wrapper
   อาจซ้ำข้ามหน้า `_merge_rulebase_page()` merge + dedupe
5. **`display_rule` เป็นการแสดงผลเท่านั้น** เช่น `30.1`, `30.2.1` — ไม่แก้
   `rule-number` จริงของ Check Point
6. **Traffic matching เป็น tri-state**: `match` / `no-match` / `unknown` — Security
   Zone, dynamic object, negation, Identity Awareness = `unknown` เสมอ **ห้ามแปลงเป็น
   `no-match`**
7. **กฎก่อนหน้าที่ `unknown` บล็อกผลสรุปของกฎหลัง** ถ้ากฎ 60 ประเมินไม่ได้ และกฎ 132
   (cleanup) ตรงเป๊ะ ผลต้องเป็น `UNVERIFIED` ไม่ใช่ `Drop`
8. **มีข้อมูลใน dictionary ไม่ได้แปลว่าใช้ได้** `objects-dictionary` จาก
   `details-level: standard` มีแค่ uid/name/type — group ไม่มีสมาชิก, gateway ไม่มี
   address `resolver.needs_detail()` ตัดสินจาก field ที่ resolver ใช้จริง แล้ว hydrate
   ซ้ำสิ่งที่ยังบาง (สูงสุด `MAX_HYDRATION_ROUNDS = 6` รอบ)
9. **Matching กับ Containment ต้องการความเข้มงวดต่างกัน** พิสูจน์ตรงใช้ `*_atoms_partial()`
   (∃ พอ) พิสูจน์ครอบคลุมใช้ `address_atoms()`/`service_atoms()` แบบเข้ม (ต้อง ∀,
   คืน `None` ถ้าไม่ครบ) **ห้ามสลับ resolver กันใช้**
10. **UI ห้ามแสดงผลบางส่วนเหมือนผลสมบูรณ์** `data_quality()` รายงาน inline layer ที่โหลด
    ไม่สำเร็จและ object hydration ที่ถูกตัดตอน แล้ว frontend ต้องแสดง banner/toast
11. **SmartConsole/gateway log จริงคือ oracle เดียว** ห้าม hardcode ตัวเลขที่ "ควรจะถูก"

**บทเรียนที่แพงที่สุดที่เจอจริง**: `_dimension_cover()` (v4.17) — เซตว่างเป็นสับเซต
ของทุกเซตในทางคณิตศาสตร์ ทำให้กฎที่มิติใดมิติหนึ่งไม่มีข้อมูล (`[]`) ถูกรายงานว่า
"ถูกกฎก่อนหน้าบังไว้" ทั้งที่ไม่มีข้อมูลจะพิสูจน์เลย พบจากการอ่านโค้ดตอนเขียนคู่มือ
ไม่ใช่จากการทดสอบ — เป็นเหตุผลที่คู่มือ (docs/Ch1-6) มีค่าจริง ไม่ใช่แค่เอกสารประกอบ

---

## 7. ข้อจำกัดที่ระบบประกาศไว้เอง (จริง ไม่ใช่ของเก่า)

- **Traffic Path เป็นการจำลองจาก configuration** ไม่ใช่ kernel emulation ต่างจาก
  gateway จริงได้เพราะ Identity Awareness, Security Zone, dynamic object, routing,
  NAT ordering, VPN, gateway state — UI ต้องรายงานระดับความเชื่อมั่นเสมอ
- **Optimizer score เป็น heuristic ฝั่งแอป** ไม่ใช่ฟีเจอร์ Check Point ห้ามเรียกว่า
  "Check Point official score"
- **Domain-based query resolve DNS จากเครื่องที่รัน Firewall Insight** อาจต่างจาก
  gateway ภายใต้ split DNS
- **แผนผังเครือข่ายเป็น logical เท่านั้น** ไม่รู้จักสายสัญญาณ/สวิตช์/routing จริง
  Management HA = สถานะที่ตั้งไว้ ไม่ใช่สถานะซิงค์ปัจจุบัน (API ไม่เปิดเผย)

---

## 8. ยังไม่ได้ทำ / ทำต่อได้เลย (จาก docs/Ch6 "การบ้าน" + ช่องว่างจริงที่เจอ)

เรียงตามคุณค่า/ความยากโดยประมาณ:

1. **เชื่อม Traffic Path เข้ากับ Network Mapping** (Ch6 ข้อ ง, "ท้าทาย") — ไฮไลต์
   เส้นทางที่ trace ได้บนแผนผัง จุดยากคือแผนผังรู้จัก gateway/subnet แต่ trace รู้จัก
   rule/layer ต้องหาจุดเชื่อมสองโมเดล และ **ห้ามวาดเส้นทางที่ตอบ `unknown` เหมือนกับ
   ที่ตอบ `exact`** — สอดคล้องกับหลักการข้อ 10 ใน README โดยตรง เป็นงานที่ยังไม่มีใคร
   เริ่มเขียนโค้ดเลย
2. **แก้ README "Known limitations"** ตัดประโยค main.py monolith ที่ล้าสมัยออก (งานเล็ก
   5 นาที)
3. **นโยบายในแล็บที่ acceptance runner ชี้ไว้เป็น finding ไม่ใช่ bug ของแอป** — ถ้าจะ
   ปรับแล็บ (ไม่ใช่โค้ด): Internal-FW ยังเป็น Allow-Any ตัวเดียว (ควรมี segmentation
   จริง), External-FW มี 1 zero-hit rule ที่ควรพิจารณาทบทวน — พวกนี้เป็นงานปรับ
   SmartConsole ไม่ใช่งาน dev
4. **ทดสอบกับนโยบายขนาดใหญ่กว่านี้** ตอนนี้มีแค่ 13 กฎที่วิเคราะห์รวม (External-FW)
   ยังไม่เคยพิสูจน์ performance/ความถูกต้องกับ policy หลายร้อยกฎ
5. **Multiple Management Server / หลาย primary** — `topology_map.py::_mgmt_role()`
   มี `limitations` ที่ยังไม่ครอบคลุมกรณี 3 management server หรือ primary ซ้ำ (Ch6
   ข้อ ข ถามไว้ตรงๆ แต่ยังไม่มีคำตอบเป็นโค้ด)
6. **Diff นโยบายข้ามช่วงเวลา** — ยังไม่มีฟีเจอร์เทียบ snapshot สองครั้ง เพื่อดูว่ากฎ
   ไหนเปลี่ยนระหว่างสองรอบตรวจ (ไม่มีในโค้ด ไม่มีใน backlog ที่ไหน แต่เป็นคำถามที่
   งานตรวจสอบตามรอบมักต้องการ)

---

## 9. คำสั่งที่ต้องรู้ (อ่านอย่างเดียวทั้งหมด)

```powershell
pytest -q                                           # 381 เทสต์ ไม่ต้องต่อ Management Server
python -m tools.acceptance --package External-FW    # 25 check + acceptance-report.json
python -m tools.acceptance --package Internal-FW    # 16 check + internal-fw.json
python -m tools.diag_topology                       # cluster/HA ตาม API จริง (debug เท่านั้น)
python -m tools.diag_resolver Standard               # object ที่ resolve ไม่ออก
python -m tools.ch3_demo                             # พิสูจน์ข้ออ้างในคู่มือบทที่ 3
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Workflow เมื่อพบบั๊ก (ใช้ตลอดทั้งโปรเจกต์ อย่าข้ามขั้นตอน):
**reproduce → หาสาเหตุด้วยเครื่องมือ read-only ที่เขียนเฉพาะ → เขียน regression test →
แก้ → พิสูจน์ด้วยการวัดจริง (ไม่ใช่แค่ดูสกรีนช็อต) → bump version → เขียน CHANGELOG.md**

---

## 10. Repo

```
remote: https://github.com/IyolrymtnXmo/firewall-insight.git   (private — ต้องเคลียร์สิทธิ์
                                                                  ความเป็นเจ้าของ IP กับ
                                                                  Netpoleon Thailand ก่อนขาย/เปิด)
branch: main, sync กับ origin แล้ว ไม่มี commit ค้าง push
โฟลเดอร์บนเครื่อง: A:\Co-Operation-NetpoleonTH\Project-Dev\Policy-Automation\Firewall-Insight-v4.7
```

---

## 11. ข้อความเปิดสำหรับแชทใหม่ (วางเป็นข้อความแรก)

> คุณคือ dev หลักของ Firewall Insight เครื่องมือวิเคราะห์นโยบาย Check Point แบบอ่านอย่างเดียว
> อยู่ที่ v4.19.1 381 เทสต์ผ่าน acceptance 25/25 + 16/16 กับแล็บจริง อ่านเอกสาร handoff นี้
> ทั้งหมดก่อนแก้โค้ดใดๆ โดยเฉพาะข้อ 6 (หลักการออกแบบ 11 ข้อ) และข้อ 8 (สิ่งที่ยังไม่ได้ทำ)
> ห้ามเพิ่มคำสั่ง Management API ที่แก้ไขข้อมูลเด็ดขาด — อ่านข้อ 2 ก่อนเสมอ งานถัดไปที่
> เลือกทำคือ: [ระบุที่นี่ เช่น "เชื่อม Traffic Path เข้ากับ Network Mapping"]
