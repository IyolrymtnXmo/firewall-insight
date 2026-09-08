# Firewall Insight — เฉลยการบ้านบทที่ 4–6

> เขียนที่ v4.23.0 (8 ก.ย. 2569) โดยลงมือทำจริงกับโค้ด ไม่ใช่ตอบจากความจำ
> ทุกข้อที่บอกว่า "วัดแล้ว" คือรันจริงและคัดผลมาวาง
> ข้อที่ **ต้องใช้แล็บ** และยังไม่ได้รัน เขียนไว้ว่ายังไม่ได้คำตอบ พร้อมคำสั่งที่ต้องรัน —
> ไม่เดาแทน (หลักการข้อ 11: SmartConsole/gateway log คือ oracle เดียว)

สภาพแวดล้อมที่ใช้ตอบ: pytest ทั้งชุดรันได้โดยไม่ต้องต่อ Management Server
ส่วน `python -m tools.acceptance` ต่อแล็บไม่ได้จากเครื่องที่เขียนเฉลยนี้
ข้อที่ต้องใช้แล็บจึงถูกทำเป็นเทสต์ที่พิสูจน์ได้แบบ offline แทน เท่าที่ทำได้

---

## บทที่ 4

### ก) สลับลำดับใน `address_match_state()` ให้ `return "unknown"` ทันที

**ทำแล้ว วัดแล้ว และผลออกมาน่าสนใจกว่าที่โจทย์คาด**

แก้ให้ return ทันทีที่เจอ `not complete` แล้วรัน pytest ทั้งชุด:

```
1 failed, 449 passed
FAILED tests/test_v410_partial_resolution.py::TestPartialAddressGroup::test_ip_outside_known_members_is_unknown
```

และเทสต์ที่พังนั้น **ไม่ได้พังเพราะคำตอบเปลี่ยน** — มันพังเพราะ *ชื่อตัวที่บล็อก* เปลี่ยน:

```
assert "DynamicObj" in detail
AssertionError: assert 'DynamicObj' in 'Static match unavailable for Mixed-Nets [group]'
```

แปลว่าพฤติกรรมที่กฎข้อนี้มีไว้ป้องกัน — "เช็ค match ให้ครบทุก object ก่อนสรุป unknown" —
**ไม่มีเทสต์ตัวไหนคุมอยู่เลย** ทั้งที่มี 450 เทสต์

พิสูจน์ตรง ๆ ว่ามันพังจริง (รันตอนที่ยังใส่ experiment อยู่):

```
field ["InternalZone", "LAB-VLAN10"] vs 192.168.10.50 -> unknown
field ["LAB-VLAN10", "InternalZone"] vs 192.168.10.50 -> match
```

**กฎเดียวกัน แพ็กเก็ตเดียวกัน คำตอบต่างกันเพราะลำดับที่ Management API บังเอิญเรียง object มา**
ในแล็บนี่คือการตอบ "drop" ให้ทราฟฟิกที่นโยบายอนุญาตจริง และไม่มีอะไรในระบบเตือนเลย

> ทำไมลำดับเดิมถึงจำเป็น: `match` เป็น **หลักฐานบวก** — เจอชิ้นเดียวก็จบ ไม่ต้องรู้ครบ
> ส่วน `unknown` เป็น **การยอมแพ้** — จะยอมแพ้ได้ก็ต่อเมื่อดูครบทุกช่องแล้วว่าไม่มีชิ้นไหนตรง
> การ return ตอนเจอ unknown ตัวแรกคือการยอมแพ้ทั้งที่ยังไม่ได้ดูให้ครบ

**สิ่งที่ทำต่อ (ไม่ใช่แค่ revert):** เขียน `tests/test_v423_match_order.py` ปิดช่องนี้
ทั้งฝั่ง address และ service — 7 เทสต์ ล็อกไว้ว่าสลับลำดับ object แล้วคำตอบต้องเท่าเดิม
experiment revert แล้ว (`git diff app/traffic.py` ไม่มีร่องรอย early-return เหลือ)

---

### ข) `correlate_nat()` ใช้ boolean ไม่ใช่ tri-state

**ทำเป็นโค้ดแล้วใน v4.23.0** และระหว่างทางเจอบั๊กที่แรงกว่าที่โจทย์ถามอีก 2 ตัว

*จะเกิดอะไรขึ้น:* NAT rule ที่ใช้ object ซึ่งโมเดลไม่ได้ จะถูกตอบว่า "ไม่ตรง" เงียบ ๆ
NAT เป็น first-match-wins เพราะฉะนั้น rule ถัดไปจะถูกรายงานเป็นคำตอบแทน
**ไม่ใช่คำตอบที่ไม่ครบ แต่เป็นคนละ rule** และผู้ใช้ไม่มีทางรู้เลย — UI แสดง
"NAT Rule 7 → แปลงเป็น X" เหมือนกรณีปกติทุกประการ

*บั๊กที่เจอเพิ่มระหว่าง reproduce* (รันจริงก่อนแก้):

```
singular form -> []
list form     -> [{'rule': 1, 'name': 'Hide lab out', ...}]
```

1. **NAT field แบบค่าเดี่ยวถูกทิ้งทั้งกฎ** — `ObjectResolver.uids()` คืน `[]` ถ้า input ไม่ใช่ list
   ซึ่งคือบทเรียน `_as_list()` ของบทที่ 5 เป๊ะ ๆ ในไฟล์เดียวที่ยังไม่ได้เรียนมัน
2. **`"Original"` แสดงเป็น `—`** เพราะ `describe_list()` ก็รับแต่ list เหมือนกัน
   "ไม่ได้ตั้งค่าแปลง" กับ "แปลงกลับเป็นค่าเดิม" คนละเรื่องกัน

*แก้ยังไงโดยไม่ให้ผลเดิมเปลี่ยน:* ย้ายออกมาเป็น `app/nat_correlate.py` แล้วใช้
`address_match_state()` ตัวเดียวกับฝั่ง Access เกณฑ์คือ

| ผล | ความหมาย |
|---|---|
| `match` | พิสูจน์ได้ทั้ง original-source และ original-destination → `confidence: exact` |
| `unknown` | มีข้างใดข้างหนึ่งใช้ object ที่โมเดลไม่ได้ → `confidence: unverified` |
| `no-match` | พิสูจน์ได้ว่าไม่ตรง → ข้ามเงียบ ๆ เหมือนเดิม |

และกฎ `unknown` ที่อยู่ **เหนือ** กฎที่ตรงเป๊ะ จะถูกคืนมาเป็นตัวแรก
ส่วนกฎที่ตรงจะติดธง `blocked_by` — เหมือน `first_uncertain_terminal` ฝั่ง Access ทุกประการ

เคสที่ผลเดิมถูกอยู่แล้ว (ทุก object resolve ได้) คืนค่าเท่าเดิมทุก field —
มีเทสต์ `test_provable_match_is_unchanged_and_marked_exact` ล็อกไว้

*สิ่งที่ยัง**ไม่**ทำ และบอกไว้ในหน้าเว็บ:* `original-service` ยังไม่ถูกเทียบ (เดิมก็ไม่เทียบ)
การเพิ่มเข้าไปจะเปลี่ยนคำตอบเดิมเงียบ ๆ ซึ่งเป็นสิ่งที่รีลีสนี้สัญญาว่าจะไม่ทำ
จึงประกาศเป็น limitation ใน `/api/traffic-path` แทนการซ่อนไว้

---

### ค) เพิ่มเคสครอบ rule 1 (VPN), 2 (Admin-Access), 3 (Lab-Device-Mgmt), 7 (ICMP)

**ยังไม่ใส่เคสจริง — และนี่คือคำตอบ ไม่ใช่การหลบ**

เขียนเคสเองแปลว่าต้องแต่ง IP ขึ้นมา และ IP ที่แต่งขึ้นมักตกไปโดน cleanup rule
→ เคสผ่านทั้งที่ไม่ได้ทดสอบอะไรเลย ซึ่งแย่กว่าไม่มีเคส และขัดหลักการข้อ 11 ตรง ๆ

**สิ่งที่ทำแทน:** `tools/suggest_cases.py` (read-only) — อ่าน object ของแต่ละ rule จริง
แล้วดึงหนึ่งโฟลว์ที่ rule นั้นพูดถึงจริง ๆ ออกมา:

```powershell
python -m tools.suggest_cases --package External-FW --only 1,2,3,7
```

มันพิมพ์เคสพร้อม `expect: null` (บันทึกไว้ ไม่ตัดสิน) + บอกว่า *วันนี้* แอปตอบว่าอะไร
+ เตือนถ้าโฟลว์นั้นถูก rule ก่อนหน้าตัดสินไปแล้ว (แปลว่าเคสไม่ได้ทดสอบ rule ที่ตั้งใจ)
มัน **ไม่เขียนทับ** `acceptance_cases.json` — การเลื่อน `expect` จาก null เป็นค่าจริง
เป็นการตัดสินใจของคน หลังยืนยันกับ SmartConsole เครื่องมือตัดงานพิมพ์ ไม่ตัดการตัดสินใจ

ส่วนที่พิสูจน์ได้แบบ offline ทำเป็นเทสต์แล้ว (`tests/test_v423_suggest_cases.py`):
network /24 ต้องได้ `.1` ไม่ใช่ `.0` (network address ไม่มีเครื่องไหนถือ),
`Any` ต้องถูกข้ามเพื่อให้คนมาใส่เอง, object ที่โมเดลไม่ได้ต้องข้าม ไม่ใช่เดา

**เรื่อง ICMP — คำเตือนในโจทย์พาไปเจอช่องโหว่จริง**

resolver รองรับ ICMP มาตั้งแต่ v4.10 (`_leaf_service_atoms()` ให้ `PortAtom` ติดแท็ก `icmp`)
แต่ชั้นบนไม่รองรับ:

* `<select id="proto">` มีแค่ `tcp` / `udp` → **ไม่มีทางเทรซ rule ICMP จากหน้าเว็บได้เลย**
* query ICMP ถูกแสดงเป็น `ICMP/8` — ยืมสัญกรณ์พอร์ตมาใช้กับโปรโตคอลที่ไม่มีพอร์ต
  ซึ่งคือวิธีทำให้คนไปนั่งหา "port 8" ใน gateway log

แก้ทั้งสองข้อใน v4.23.0 + เทสต์ `tests/test_v423_icmp.py` ที่ล็อกไว้ด้วยว่า
query TCP ที่เจอ rule ICMP ต้องได้ `no-match` แบบมั่นใจ ไม่ใช่ `unknown`
(นี่คือเหตุผลที่ resolver ติดแท็กโปรโตคอลตั้งแต่แรก)

---

### ง) ถาม Traffic Path ด้วย service ชื่อ `RDP`

**ได้ผลต่างกัน และต่างแบบอันตราย**

`_service_object_by_name()` หา object จากชื่อจริงในนโยบาย **ก่อน** ฐานข้อมูล service มาตรฐาน
ซึ่งถูกต้อง — rulebase เขียนด้วยชื่อ object ไม่ใช่ชื่อสามัญ
แต่ Check Point มี object ชื่อ `RDP` = **UDP/259** (โปรโตคอลควบคุมของ Check Point เอง)
ส่วน Remote Desktop คือ `Remote_Desktop_Protocol` = TCP/3389

ผู้ใช้ที่ไม่รู้เรื่องนี้จะ:

1. เลือก protocol = **tcp** พิมพ์ `RDP` แล้วกด Analyze
2. ได้คำตอบเรื่อง **UDP/259** ซึ่งไม่มีใครใช้
3. เห็น `drop · exact` แล้วสรุปว่า "RDP เข้าไม่ได้ ปลอดภัยแล้ว"
4. ทั้งที่ TCP/3389 อาจเปิดโล่งอยู่

`drop` ของโฟลว์ผิด หน้าตาเหมือน `drop` ของโฟลว์ถูกทุกประการ — และมันเป็น `exact` ด้วย
เพราะการประเมิน UDP/259 นั้น *ถูกต้องจริง ๆ* ความมั่นใจไม่ได้ผิด แต่คำถามผิด

**แก้ยังไง (v4.23.0):** ไม่เปลี่ยนวิธี resolve — เปลี่ยนเป็นพูดออกมา
`_service_name_warnings()` เตือน 2 กรณี

* **โปรโตคอลไม่ตรง** — เลือก TCP แต่ object เป็น UDP → บอกว่ากำลังตอบคนละโฟลว์
* **ชื่อทับ standard service** — policy มี object ชื่อ `https` ที่เป็น TCP/8443
  → บอกว่าชื่อนี้ปกติคือ 443 แต่ในนโยบายนี้คือ 8443 และ object ชนะเพราะ rulebase อ้างชื่อ object

โผล่ทั้งใน `query.service_warnings`, แถวตาราง Service และเป็น toast

---

## บทที่ 5

### ก) External-FW มี 11 NAT rule แต่ Internal-FW มี 10 ต่างกันตรงไหน

**ยังไม่ได้คำตอบ — ต้องรันกับแล็บ และเครื่องที่เขียนเฉลยนี้ต่อ 172.23.31.180 ไม่ได้**

หลักฐานเท่าที่มีในรีโป ยืนยันแค่ตัวเลข ไม่ได้บอกว่าต่างที่กฎไหน:

```
acceptance-report.json  nat_rules: 11     (External-FW)
internal-fw.json        nat_rules: 10     (Internal-FW)
```

ขั้นตอนหาคำตอบ (read-only ทั้งหมด):

```powershell
python -m tools.acceptance --package External-FW --json ext.json
python -m tools.acceptance --package Internal-FW --json int.json
# แล้วเทียบ rules[] จาก /api/nat-analyze ของสอง package
```

สมมติฐานที่ควรตรวจตามลำดับ — **อย่าเพิ่งเชื่อข้อใดข้อหนึ่งก่อนดูของจริง**

1. Automatic NAT: object ที่มี NAT ตั้งไว้ในตัว object เอง จะโผล่เป็น NAT rule เฉพาะใน
   package ที่ install บน gateway ที่เห็น object นั้น → 1 rule ต่างเพราะ install target ต่าง
2. NAT exemption rule ที่มีใน package เดียว (ดูข้อ ข)
3. rule ที่ `install-on` ชี้ gateway คนละตัว — **v4.23.0 ตรวจข้อนี้ให้แล้ว**
   `python -m tools.acceptance --package External-FW` จะรายงานเป็น finding ถ้ามี

ถ้าต่างเพราะข้อ 1 = ปกติ ไม่ต้องแก้ ถ้าต่างเพราะข้อ 2 หรือ 3 = ต้องมีคนอธิบายได้ว่าทำไม

---

### ข) สร้าง NAT rule ที่ translated ทุกช่องเป็น `Original` แล้วใส่ comment ว่าเป็น exemption
### โปรแกรมควรเลิกรายงานมั้ย

**คำใบ้บอกว่าอย่ารีบตอบว่าควร — และคำตอบคือ ไม่ควร**

เหตุผล 3 ชั้น:

1. **comment ไม่ใช่หลักฐานว่าเป็น exemption — เป็นหลักฐานว่ามีคนพิมพ์คำนั้น**
   `"NAT exemption"` ในช่อง comment กับ rule ที่ลืมใส่ค่า translated แล้วพิมพ์ comment ไว้
   แยกกันไม่ออกทางโปรแกรม การเชื่อ comment คือการรับ input ที่ไม่มีใครตรวจ
   มาเป็นเกณฑ์ตัดสินความปลอดภัย
2. **finding นี้ตั้งชื่อตามสิ่งที่พิสูจน์ได้อยู่แล้ว** — "**Possible** No-Translation"
   ไม่ได้แปลว่า "ผิด" มันแปลว่า "rule นี้ไม่แปลงอะไรเลย ไปดูหน่อยว่าตั้งใจไหม"
   ซึ่งเป็นข้อความที่ยังจริง 100% แม้ rule นั้นจะตั้งใจ การซ่อนมันคือการลบข้อความจริงทิ้ง
3. **ถ้ายอมให้ comment ปิด finding ได้ วิธีทำให้รายงานเขียวคือพิมพ์ comment**
   ไม่ใช่แก้นโยบาย — เครื่องมือตรวจสอบที่ปิดปากตัวเองได้ด้วย input ของสิ่งที่มันตรวจ
   ไม่ใช่เครื่องมือตรวจสอบ

**สิ่งที่ควรทำแทน:** เอา comment ไป *แสดง* ข้าง finding เพื่อให้คนอ่านตัดสินเร็วขึ้น
— แสดงเหตุผล ไม่ใช่ยอมรับเหตุผล คนตัดสิน โปรแกรมรายงาน

---

### ค) `{"name": "X"}` กับ `{"uid": "abc", "name": "X"}` ถูกนับเป็น duplicate กันมั้ย ถูกต้องหรือไม่

**วัดก่อนแก้ คำตอบคือ ไม่** — และ **ไม่ถูกต้อง**

```
duplicate groups: 0
```

`_uid_values()` fallback ไป `name` เมื่อไม่มี `uid` → signature เป็น `("X",)` กับ `("abc",)` → ต่างกัน

fallback นั้น **ถูกแล้ว** ถ้าไม่มีมัน entry จะกลายเป็นสตริงว่างแล้วโดนกรองทิ้ง
ซึ่งทำให้ rule ที่ต่างกันจริงมี signature เท่ากัน — พังหนักกว่าเยอะ
แต่หยุดแค่นั้นคือ **false negative**: สองอันนี้คือ object เดียวกัน และ objects-dictionary รู้

**แก้แล้วใน v4.23.0:** เพิ่ม `_name_index()` — map ชื่อ → uid **เฉพาะชื่อที่มี object เดียวถืออยู่**
ถ้ามี object 2 ตัวชื่อ `X` แปลว่า dictionary พิสูจน์ไม่ได้ว่าหมายถึงตัวไหน → ปล่อยชื่อไว้ตามเดิม
และสอง rule ยังนับเป็นคนละอัน

> การรายงาน duplicate ที่พิสูจน์ไม่ได้ แพงกว่าการพลาด duplicate ไปหนึ่งอัน
> เพราะ finding ปลอมทำให้คนเลิกอ่านรายงานทั้งฉบับ

เขียนไว้ใน `notes` ของผลลัพธ์ด้วย เพื่อให้คนอ่านรู้ว่า signature ทำงานยังไง

---

### ง) เพิ่มการตรวจ "NAT rule ที่ install-on ไม่ตรงกับ gateway ที่มีอยู่จริง"

**ทำแล้วใน v4.23.0 เขียนเทสต์ก่อนเขียนโค้ด (8 เทสต์แดงก่อน แล้วค่อยเขียน)**

กับดัก 2 อันที่โจทย์เตือน และเทสต์ล็อกไว้ทั้งคู่:

1. **`Policy Targets` ไม่ใช่ชื่อ gateway** — มันคือ marker ว่า "ทุก gateway ใน package นี้"
   ถ้าไปรายงานมัน จะได้ finding บนเกือบทุก rule ของเกือบทุก policy
   ซึ่งเป็นวิธีสอนคนให้เลิกอ่านรายงานที่เร็วที่สุด (`ALL_GATEWAY_MARKERS` คุมไว้)
2. **ถ้าไม่มีรายชื่อ gateway ก็ไม่มีอะไรให้เทียบ** — ต้องรายงานว่า **"ไม่ได้ตรวจ"**
   ไม่ใช่ "ตรวจแล้วไม่เจอปัญหา" สองอย่างนี้หน้าตาเหมือนกันใน summary แต่มีอย่างเดียวที่เป็นข่าวดี
   → `install_on_checked: false`, `install_on_unknown_rules: null` (ไม่ใช่ `0`)
   และแท็บบน UI ขึ้น `(n/a)` ไม่ใช่ `(0)`

รายละเอียดอื่น: จับคู่ด้วย uid ก่อน แล้วค่อย name (objects-dictionary แบบบางให้แค่ uid),
รับ field ทั้งแบบ list และค่าเดี่ยว, และถ้า `show-gateways-and-servers` fail (สิทธิ์ไม่ถึง)
การวิเคราะห์ NAT ที่เหลือต้องไม่ล้มไปด้วย — มีเทสต์
`test_a_failing_gateway_call_does_not_fail_the_nat_analysis` ล็อกไว้

acceptance runner แยกสองเรื่องตามหลักเดิม: **"ตรวจได้ไหม" = check (นับคะแนน)**,
**"เจออะไร" = finding (รายงาน ไม่นับคะแนน)**

---

## บทที่ 6

### ก) ลบ `?v=` ออกจาก `asset_version()`

**วัดกลไกจริงแล้ว**

```
stamp before touch: 4.19.1-1788836922
stamp after touch : 4.19.1-1788837343
changed: True
```

`asset_version()` = `APP_VERSION` + mtime ล่าสุดของไฟล์ใน `static/` และ `index()`
เอาไปต่อท้าย URL ทุกครั้งที่ serve หน้าเว็บ

ถ้าลบ `?v=` ออก URL ของ CSS จะเป็น `/static/css/app.css` เป๊ะ ๆ **ทุกครั้ง ตลอดไป**
เบราว์เซอร์แคชตาม URL → แก้สีแล้วรีเฟรช (F5) จะ **ไม่เห็นอะไรเปลี่ยน**
ต้อง Ctrl+F5 (hard reload ข้ามแคช) ถึงจะเห็น และต้องทำ **ทุกครั้งที่แก้ CSS**

นี่คือบั๊กที่ผู้ใช้เจอจริงตอน v4.13: อัปเกรดแล้ว UI ยังหน้าตาเดิม ซึ่งอาการเหมือน
"อัปเกรดไม่สำเร็จ" ทุกประการ ทั้งที่ Python รันโค้ดใหม่อยู่ — ส่วนที่ค้างคือฝั่งเบราว์เซอร์

ทำไมต้องมีทั้งสองส่วนใน stamp:

* **version อย่างเดียว** — ถูกสำหรับ release แต่ระหว่าง dev ที่ `--reload` restart Python
  โดยที่เลข version ไม่ขยับ เบราว์เซอร์ก็ยังกิน CSS ของเมื่อวาน
* **mtime อย่างเดียว** — ใช้ได้ตอน dev แต่ deploy ที่ checkout ใหม่แล้ว mtime บังเอิญเท่าเดิม
  จะไม่ล้างแคชให้ user ที่มีอยู่

### ข) `_mgmt_role()` กับ management server 3 ตัว และกรณี primary 2 ตัว

**อ่านโค้ดแล้วเจอ 3 กรณี และมีกรณีหนึ่งที่พังเงียบ — แก้แล้วใน v4.23.0**

| สภาพ | v4.19.1 ทำอะไร | ถูกไหม |
|---|---|---|
| 1 primary + N secondary | วาดดาว primary → secondary ทุกตัว + เขียน limitation | ใช่ |
| primary 2 ตัว | ไม่วาดอะไร + บอกเหตุผล | ใช่ |
| **secondary ที่ไม่มี primary** | **ไม่วาด และ ไม่พูดอะไรเลย** | **ไม่** |

กรณีที่ 3 คือกรณีที่สำคัญ: `len(primaries) == 1` เป็นเท็จ, `len(primaries) > 1` ก็เท็จ
→ ตกท้าย if ไปเฉย ๆ ผลคือ management server ที่เป็น secondary จะถูกวาดเหมือน
**management server เดี่ยว ๆ ที่ไม่มี HA เลย** ทั้งที่ความจริงคือ "มี HA แต่เรามองไม่เห็นคู่ของมัน"
(สิทธิ์ของ API user ไม่ถึง หรือ primary ไม่อยู่ใน estate นี้)
แผนที่แยกสองสถานการณ์นี้ไม่ออก — เพราะฉะนั้นมันต้องบอกว่ามันแยกไม่ออก

**และปัญหาที่ใหญ่กว่าที่โจทย์ถาม:** โค้ดเดิมนับ primary/secondary **ทั้ง payload รวดเดียว**
Multi-Domain (MDS) ตอบ `show-gateways-and-servers` มาพร้อมกันหลายโดเมน
→ "primary 2 ตัว" ที่นั่นไม่ใช่ความกำกวมที่ต้องขอโทษ มันคือสองโดเมน แต่ละโดเมนมี primary ของตัวเอง
และการจับคู่ข้ามโดเมนคือการวาด HA ระหว่างเครื่องที่ไม่เคยคุยกัน

`domain` เป็น field ที่ API ส่งมาอยู่แล้ว → v4.23.0 จับคู่ **ภายในโดเมน**
ถ้าไม่มี field นี้ (SMC ปกติ) ทุกเครื่องตกอยู่ในกลุ่มไร้ชื่อกลุ่มเดียว = พฤติกรรมเดิมเป๊ะ

`tools/diag_topology.py` พิมพ์ domain ของแต่ละ management host ให้แล้ว ใช้ยืนยันกับแล็บจริงได้

### ค) ทำไม 3 check ของ Internal-FW ถึงเป็น INFO ไม่ใช่ FAIL

จาก `internal-fw.json` ของรันจริงล่าสุด (16/16 passed, 0 failed) มี 4 บรรทัดที่เป็น INFO:

```
INFO access   inline layer discovery                               this package has no inline layers
INFO access   cleanup rule told apart from an Any/Any/Any finding  no trailing Drop rule in this package
INFO findings 1 rule(s) permit Any -> Any -> Any
INFO findings no explicit cleanup rule; the layer relies on the implicit drop, which is not logged
```

สองกลุ่ม เหตุผลคนละแบบ:

**กลุ่ม `access` — ไม่มีอะไรให้ทดสอบ ไม่ใช่ทดสอบแล้วตก**
Internal-FW มี rule เดียว (`Allow-Any`) ไม่มี inline layer ไม่มี cleanup rule
ถ้าฟันธงว่าต้องมี ก็เท่ากับทดสอบว่า "policy นี้เขียนแบบเดียวกับ External-FW ไหม"
ไม่ใช่ "แอปอ่าน policy ถูกไหม" — Internal-FW จะตกเพราะมันเล็ก ซึ่งไม่ใช่บั๊กของแอป
โค้ดเขียนคอมเมนต์ไว้ตรงนี้ชัดเจน: มีฟีเจอร์ให้ใช้ → assert ว่าใช้ได้;
ไม่มีอะไรให้ใช้ → บอกไปตรง ๆ

**กลุ่ม `findings` — เป็นข้อความเกี่ยวกับ *นโยบาย* ไม่ใช่เกี่ยวกับ *เครื่องมือ***
"มี 1 rule ที่ Any/Any/Any" เป็นความจริงเกี่ยวกับแล็บ ไม่ใช่ความล้มเหลวของ Firewall Insight
แอปทำงานถูกต้องสมบูรณ์แบบตอนที่มันตรวจเจอ

**ทำไมการแยก "check" ออกจาก "finding" ถึงสำคัญ** (คำใบ้ในโจทย์):
ถ้ารวมกัน `python -m tools.acceptance` จะ **ไม่มีวันเขียวจนกว่า estate จะสมบูรณ์แบบ**
ซึ่งไม่มีวันเกิดขึ้น ผลคือ:

1. รันแล้วแดงทุกครั้ง → คนเลิกดู
2. พอเลิกดู ตอนที่แอปพังจริง ๆ ก็ไม่มีใครเห็น
3. เครื่องมือทดสอบที่ไม่มีใครดู = ไม่มีเครื่องมือทดสอบ

`16/16 passed` + `2 policy findings` บอกสองเรื่องที่ต่างกัน:
**"เครื่องมือนี้เชื่อถือได้"** และ **"นโยบายนี้มีเรื่องต้องคุย"**
ยุบเป็นเลขเดียวเมื่อไหร่ ก็เสียทั้งสองข้อความ

### ง) *(ท้าทาย)* ไฮไลต์เส้นทาง Traffic Path บนแผนที่

**ทำแล้วใน v4.23.0** — `app/path_map.py` + overlay บน SVG

**จุดเชื่อมของสองโมเดล:** แผนที่รู้จัก gateway/interface/subnet, trace รู้จัก rule/layer/action
ของอย่างเดียวที่อยู่ในทั้งสองโลกคือ **address** — src/dst ที่ผู้ใช้พิมพ์ เทียบกับ subnet
ที่แผนที่คำนวณจาก interface address การ contain เป็น **ข้อเท็จจริง** (IP อยู่ใน prefix หรือไม่อยู่)
เพราะฉะนั้นปลายทั้งสองข้างคือส่วนที่แข็งที่สุดของ overlay ที่เหลืออ่อนกว่านั้นหมด

**และมันอ่อนคนละแบบกับ verdict** จึงต้องแยกความมั่นใจเป็นสองตัว:

```
policy_confidence     rulebase ตัดสินโฟลว์นี้ได้ไหม        (tri-state ของบทที่ 4)
topology_confidence   แพ็กเก็ตวิ่งผ่านกล่องนี้จริงไหม       (ไฟล์นี้)
```

สองอันนี้พังอิสระจากกัน `accept` ที่พิสูจน์ได้เป๊ะ ปลายทาง 8.8.8.8 = **verdict แน่นอน
บนเส้นทางที่แผนที่มองไม่เห็น** เพราะ `show-gateways-and-servers` ไม่มี route ไปอินเทอร์เน็ต
มีแค่ interface ที่ gateway ติดธง `leads-to-internet` ไว้

`draw` = ตัวที่อ่อนกว่าในสองตัว (กฎ weakest-link เดียวกับบทที่ 4)

**"ห้ามวาดเส้นทางที่ตอบ unknown เหมือนที่ตอบ exact"** — บังคับด้วย CSS ที่มีเทสต์ล็อก:

| draw | เส้น |
|---|---|
| `exact` | ทึบ สีเขียว หนา 3.4 |
| `inferred` | **ประยาว** `9 5` สีเหลือง |
| `unverified` | **ประถี่จาง** `2 6` opacity .72 |
| `none` | ประถี่ สีแดง opacity .5 |

ความต่างไม่ได้อยู่ที่สีอย่างเดียว — dash pattern ต่างกันด้วย เพื่อให้คนตาบอดสี
และสกรีนช็อตขาวดำยังแยกออก และแถบเหนือแผนที่พูดเป็นคำด้วย
(`policy: exact · topology: inferred`) เทสต์ `test_the_difference_is_not_carried_by_colour_alone`
ล็อกข้อนี้ไว้

กรณีที่ต้องระวังและจัดการแล้ว:

* **ปลายทางไม่อยู่บนแผนที่ และไม่มี interface ไหนบอก leads-to-internet** → ไม่วาดเส้นทางไปหามัน
  `topology_confidence: unknown` และเขียนเหตุผลไว้ ไม่ประดิษฐ์ปลายทางขึ้นมา
* **subnet ต้นทางกับปลายทางอยู่คนละ gateway** → `inferred` + บอกชื่อทั้งสองตัว
  เพราะ hop ระหว่างกันคือ routing ซึ่งแผนที่ไม่รู้
* **แผนที่ merge subnet หรือ collapse cluster อยู่** → `topoTraceResolve()` ตามไปหา
  merged cell / cluster ที่กลืนโหนดนั้นไว้ เส้นทางจึงไม่หายตอนผู้ใช้กดย่อ
* **`/api/network-map` ล้ม** → overlay เป็น `null` + `map_path_error` แต่ **คำตอบ Access ยังส่งกลับปกติ**
  overlay ที่ลากคำตอบล้มไปด้วยจะแย่กว่าไม่มี overlay
  (`test_a_failing_gateway_call_costs_the_overlay_and_nothing_else`)

---

## สรุปสิ่งที่เปลี่ยนในโค้ดจากการทำการบ้านชุดนี้

ทั้งหมดออกเป็นรีลีสเดียว **v4.23.0** (457 → 461 เทสต์ผ่าน จาก 381 ตอน v4.19.1)

| มาจากข้อ | เปลี่ยนอะไร |
|---|---|
| Ch4 ก | `tests/test_v423_match_order.py` — ปิดช่องที่ 450 เทสต์เดิมไม่ได้คุม |
| Ch4 ข | `app/nat_correlate.py` — tri-state NAT correlation (+ singular field, `"Original"`) |
| Ch4 ค | `tools/suggest_cases.py` + ICMP ใช้งานได้ครบตั้งแต่ UI ถึง resolver |
| Ch4 ง | `_service_name_warnings()` — เตือน service ชื่อกำกวม (RDP / https ที่ทับ) |
| Ch5 ค | `_name_index()` — name→uid ใน NAT signature เมื่อ dictionary พิสูจน์ได้ |
| Ch5 ง | ตรวจ NAT `install-on` กับ gateway จริง + แท็บ Install-On Targets |
| Ch6 ข | จับคู่ Management HA รายโดเมน + ปิดกรณี secondary ไร้ primary ที่เคยเงียบ |
| Ch6 ง | `app/path_map.py` + overlay บนแผนที่ แยก policy / topology confidence |

**ข้อที่ยังค้างและต้องใช้แล็บ:** Ch5 ก (11 vs 10 NAT rule) และการเลื่อน `expect`
ของเคส rule 1/2/3/7 จาก `null` เป็นค่าจริง — ทั้งสองข้อต้องยืนยันกับ SmartConsole
