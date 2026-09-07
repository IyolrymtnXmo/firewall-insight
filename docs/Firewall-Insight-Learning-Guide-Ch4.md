# Firewall Insight — คู่มือเรียนรู้โปรเจกต์ (สำหรับ Dev ต่อ)

> **บทที่ 4: `traffic.py` — Tri-state matching และการเดินข้าม Inline Layer**
> เขียนโดยอ่านซอร์สจริงที่ v4.19.1 เมื่อ 7 ก.ย. 2569
> ผลลัพธ์ทุกอันในบทนี้มาจากการรัน `python -m tools.acceptance --package External-FW`
> กับ Lab จริง ไม่ใช่ตัวอย่างสมมติ

---

## 1. คำถามที่ฟีเจอร์นี้ตอบ

> "ถ้าเครื่อง `192.168.10.50` เปิด RDP ไปหา `192.168.20.100` มันจะโดน rule ไหน แล้วผลเป็นยังไง"

SmartConsole ตอบคำถามนี้ไม่ได้ตรง ๆ ต้องไล่อ่าน rule เอง ยิ่งมี Inline Layer ยิ่งไล่ยาก
เพราะ rule แม่ไม่ได้ตัดสินเอง มันส่งต่อให้ layer ลูก

**สิ่งที่ต้องระวังที่สุด:** นี่คือการจำลองจาก **configuration** ไม่ใช่การยิงแพ็กเก็ตจริง
มันไม่รู้เรื่อง routing, ไม่รู้ว่า interface ไหน up, ไม่รู้ session state
สิ่งที่มันตอบได้คือ "ตาม policy ที่เขียนไว้ ควรจะเป็นแบบนี้" — ซึ่งมีค่ามากตอนออกแบบ
และตอน review แต่ต้องไม่เอาไปอ้างแทนการทดสอบจริง

---

## 2. หัวใจ: ทำไมต้อง Tri-state

ระบบส่วนใหญ่ตอบได้แค่ **match / no-match** แต่โปรแกรมนี้ตอบ **3 แบบ**:

| สถานะ | ความหมาย | ตัวอย่าง |
|---|---|---|
| `match` | **พิสูจน์ได้ว่าตรง** | `192.168.10.50` อยู่ใน `LAB-VLAN10` (192.168.10.0/24) |
| `no-match` | **พิสูจน์ได้ว่าไม่ตรง** | `192.168.20.50` ไม่อยู่ใน `LAB-VLAN10` |
| `unknown` | **ประเมินไม่ได้** | rule ใช้ `ALL_DCE_RPC` ที่พอร์ตเจรจาตอน runtime |

### ทำไม `unknown` ต้องแยกจาก `no-match`

นี่คือจุดที่ผิดง่ายที่สุดและอันตรายที่สุด สมมติมี rule:

```
rule 4  VLAN20-to-AD:  LAB-VLAN20 → AD-Server → AD-Services → Accept
rule 9  Cleanup rule:  Any → Any → Any → Drop
```

`AD-Services` เป็น group ที่มีสมาชิกตัวหนึ่งคือ `ALL_DCE_RPC` (service-dce-rpc)
พอร์ตของมันเจรจากันตอน runtime — โปรแกรมบอกไม่ได้ว่าคือพอร์ตอะไร

ถ้ามีคนถามว่า **VLAN20 → AD ผ่าน TCP/9999 ได้มั้ย**:

- ถ้าเราตอบ `no-match` ที่ rule 4 → มันจะไหลไปถึง rule 9 → ตอบ **"Drop"** อย่างมั่นใจ
- แต่ความจริงคือ **เราไม่รู้** ว่า DCE-RPC จะเจรจาไปโดนพอร์ต 9999 หรือเปล่า

การตอบ "Drop" ในกรณีนี้คือการโกหกที่ฟังดูน่าเชื่อ — และถ้าคนเอาไปตัดสินใจว่า
"ไม่ต้องกังวล มัน drop อยู่แล้ว" ก็จะพลาดช่องโหว่จริง

ผลรันจริงจาก Lab:

```
[INFO] VLAN20 to AD on an unmodelled high port
       unverified · unknown  via External-FW Network rule 4 (VLAN20-to-AD)
```

ตอบว่า **unverified** และบอกด้วยว่าติดที่ rule ไหน — ผู้ใช้รู้ทันทีว่าต้องไปดู
`AD-Services` เอง ไม่ใช่ได้คำตอบผิดแล้วเชื่อไปเลย

---

## 3. `address_match_state()` — เดินยังไง

```python
def address_match_state(values, address_text, res) -> tuple[str, str]:
    """
    match    = พิสูจน์ได้ว่าตรง
    no-match = พิสูจน์ได้ว่าไม่ตรง
    unknown  = rule ใช้ object ที่ simulator นี้ประเมินไม่ได้
    """
```

ลำดับการทำงาน:

**ขั้น 1 — แปลง input** ถ้าเป็น IP ก็ใช้เลย ถ้าไม่ใช่ ถือว่าเป็น domain แล้วไป resolve
(`_domain_candidates`) ได้ IP กี่ตัวก็เก็บมาหมด

**ขั้น 2 — วนทุก object ในช่อง source/destination**

```python
if res.is_any_uid(uid):
    return "match", "Any"                      # ทางลัด จบเลย
```

**ขั้น 3 — เทียบแบบ partial** (นี่คือของจากบทที่ 3)

```python
atoms, complete = res.address_atoms_partial(uid)
for ip in ips:
    n = int(ip)
    if any(a.version == ip.version and a.start <= n <= a.end for a in atoms):
        return "match", res.describe_uid(uid)   # ∃ — เจอตัวเดียวก็พอ
```

ใช้ **partial** เพราะนี่คือคำถามแบบ matching ต้องการหลักฐานบวกชิ้นเดียว
(ถ้าใช้ strict `address_atoms()` group ที่มีสมาชิกพังตัวเดียวจะตอบไม่ได้เลย)

**ขั้น 4 — จำไว้ว่ามีชิ้นที่มองไม่เห็น**

```python
if not complete:
    saw_unknown = True
    blockers = res.unmodelled_names(uid, "address")
```

**ขั้น 5 — สรุป**

```python
if saw_unknown:
    return "unknown", "Static match unavailable for " + ", ".join(unknown_names[:4])
return "no-match", "No matching object"
```

> **ลำดับสำคัญมาก:** เช็ค `match` ให้ครบทุก object **ก่อน** แล้วค่อยดู `saw_unknown`
> ถ้ากลับลำดับ — เจอ unknown แล้ว return ทันที — object ตัวถัดไปที่ตรงจริงจะไม่มีโอกาสตอบ
> คำตอบจะกลายเป็น unknown ทั้งที่ตอบ match ได้

`service_match_state()` ทำงานเหมือนกันเป๊ะ ต่างแค่เทียบ `PortAtom` และต้องเช็ค proto ด้วย:

```python
proto_ok = a.proto == "any" or qp == "any" or a.proto == qp
if proto_ok and not (qe < a.start or qs > a.end):   # ช่วงซ้อนทับกัน
```

`not (qe < a.start or qs > a.end)` คือการเช็ค **overlap** ไม่ใช่ containment —
ถ้า query เป็นช่วง (เช่น `1024-2048`) แล้ว rule ครอบบางส่วน ก็ถือว่าตรง

---

## 4. `trace_layer_candidates()` — คัด rule ใน layer เดียว

```python
for r in _rules(payload.get("rulebase", [])):
    if not r.get("enabled", True):
        continue                                   # rule ปิดไม่มีผล

    if r.get("source-negate") or r.get("destination-negate") or r.get("service-negate"):
        candidates.append({... "state": "unknown", ...})
        continue                                   # negate = ยอมแพ้อย่างซื่อสัตย์

    ss, so = address_match_state(r.get("source"), src, res)
    if ss == "no-match": continue                  # ตัดกิ่งเร็ว
    ds, do = address_match_state(r.get("destination"), dst, res)
    if ds == "no-match": continue
    vs, vo = service_match_state(r.get("service"), service_query, res)
    if vs == "no-match": continue

    overall = "match" if all(x == "match" for x in (ss, ds, vs)) else "unknown"
```

จุดออกแบบ 3 อย่าง:

**ก) `no-match` แค่มิติเดียวก็ตัดทิ้งได้** เพราะ rule จะโดนต้องตรงครบทั้ง 3 มิติ

**ข) `overall` เป็น `match` ต่อเมื่อ**ทั้งสามมิติ**เป็น match**
มิติไหนเป็น unknown ทั้ง rule ก็ unknown — ระมัดระวังไว้ก่อน

**ค) rule ที่มี negate ถูกใส่เป็น `unknown` ไม่ใช่ข้ามทิ้ง**
เพราะการข้ามทิ้ง = แกล้งทำเป็นว่า rule นั้นไม่มีอยู่ ซึ่งอาจทำให้คำตอบสุดท้ายผิด
ใส่เป็น unknown = บอกตรง ๆ ว่า "มี rule นี้อยู่ตรงนี้ แต่ประเมินไม่ได้"

> `NOT LAB-VLAN10` ต้องประเมินแบบ gateway ทำ ซึ่งต้องรู้ทุก object ที่เป็นไปได้
> ในระบบ — static simulator ทำไม่ได้ จึงบอกว่าทำไม่ได้

---

## 5. `trace_access_tree()` — เดินข้าม Inline Layer

นี่คือส่วนที่ยากที่สุดของไฟล์ และเป็นเหตุผลที่ฟีเจอร์นี้มีค่า

### โครงสร้างที่ต้องเดิน

```
Network layer
 ├─ rule 5  Access-to-RDP        → Accept        ← terminal
 ├─ rule 8  Lab-Outbound         → InternetLayer ← ส่งต่อ ไม่ตัดสินเอง
 │            └─ InternetLayer
 │                 ├─ 8.1 Allow-Web   → Accept   ← terminal
 │                 ├─ 8.2 Allow-DNS   → Accept
 │                 ├─ 8.3 Allow-NTP   → Accept
 │                 └─ 8.4 Block-Rest  → Drop
 └─ rule 9  Cleanup rule         → Drop
```

**rule 8 ไม่ใช่คำตอบ** ถึงจะตรงเงื่อนไขก็ตาม มันแค่บอกว่า "ไปถามต่อที่ InternetLayer"

### ผลรันจริง

```
[PASS] Lab hosts browse the internet   got accept · exact
```

เส้นทางที่เดินคือ `rule 8 (Lab-Outbound) → InternetLayer → rule 8.1 (Allow-Web) → Accept`

### กฎการรวมความมั่นใจ

```python
child_unknown = child_result.get("confidence") != "exact"
child_result["confidence"] = "inferred" if (parent_unknown or child_unknown) else "exact"
```

อ่านเป็นภาษาคน: **ความมั่นใจของผลลัพธ์ = ความมั่นใจของจุดที่อ่อนที่สุดบนเส้นทาง**

| แม่ | ลูก | ผลรวม |
|---|---|---|
| exact | exact | `exact` |
| unknown | exact | `inferred` |
| exact | unknown | `inferred` |

ตรงกับสามัญสำนึก: ถ้าไม่แน่ใจว่าจะเข้า layer นี้จริงมั้ย ต่อให้ในนั้นชัดเจนแค่ไหน
คำตอบรวมก็ยังไม่ชัดเจน

### เคสที่ต้องระวังเป็นพิเศษ

**ก) แม่ตรงเป๊ะ เข้า layer แล้วไม่มีลูกตรงเลย**

```python
return {
    "matched": False,
    "reason": f"Parent Rule {display_rule} matched exactly and entered "
              f"Inline Layer {child.get('name')}, but no child rule matched.",
}
```

ไม่ใช่ "ไม่เจอ rule" เฉย ๆ แต่บอกว่า **เข้าไปแล้วแต่ข้างในไม่มีอะไรรับ** —
คนละสาเหตุ คนละวิธีแก้

**ข) มี rule ที่ตรงแบบ unknown อยู่ก่อนหน้า rule ที่ตรงเป๊ะ**

```
Earlier Rule 4 ... Later Rule 6 matches, but cannot be declared final.
```

เพราะ rule ที่มาก่อนอาจจะรับ traffic ไปแล้วก็ได้ — เราไม่รู้
จะบอกว่า "rule 6 คือคำตอบ" ไม่ได้ ต้องบอกว่า "rule 6 ตรง แต่ฟันธงไม่ได้"

**ค) กันวนไม่รู้จบ**

```python
"result": "Trace depth exceeded", "confidence": "none"
```

Inline Layer อ้างวนกันเองได้ (Check Point ยอม) ต้องมีเพดานความลึก

---

## 6. `resolve_service_query()` — แปลงสิ่งที่ผู้ใช้พิมพ์

ผู้ใช้พิมพ์ได้ 3 แบบ และต้องรองรับหมด:

| พิมพ์ | ตีความ |
|---|---|
| `443` | เลขพอร์ตตรง ๆ |
| `https` | ชื่อ service มาตรฐาน |
| `Remote_Desktop_Protocol` | **ชื่อ object จริงใน Check Point** |

แบบที่ 3 สำคัญ เพราะ Lab คุณมีบทเรียนอยู่: Check Point มี object ชื่อ **`RDP`**
ซึ่ง **ไม่ใช่** Microsoft Remote Desktop — มันคือ UDP 259 (โปรโตคอลของ Check Point เอง)
ตัวที่ใช่คือ `Remote_Desktop_Protocol` (TCP 3389)
`_service_object_by_name()` จึงหา object จากชื่อจริงในนโยบายก่อน

ถ้าแปลงไม่ได้เลย → `raise ValueError` → route ตอบ **HTTP 400 พร้อมข้อความ**
ไม่ใช่เดาว่าเป็นพอร์ตอะไรสักอย่างแล้วให้คำตอบผิด

---

## 7. `correlate_nat()` — NAT เข้ามาเกี่ยวตรงไหน

```python
for r in _nat_rules(payload.get("rulebase", [])):
    if not r.get("enabled", True): continue
    sm, so = address_matches(r.get("original-source"), src, res)
    dm, do = address_matches(r.get("original-destination"), dst, res)
    if not (sm and dm): continue
    findings.append({...})
    break                      # NAT rule แรกที่ตรง = ตัวที่ทำงาน
```

`break` สำคัญ: NAT ใน Check Point ทำงานแบบ **first match wins** เหมือน Access
รายงานทุกตัวที่ตรงจะทำให้เข้าใจผิดว่ามีหลาย NAT ทำงานพร้อมกัน

> **ข้อจำกัดที่ต้องรู้:** ตรงนี้ใช้ `address_matches()` แบบ boolean ไม่ใช่ tri-state
> ถ้า NAT rule ใช้ object ที่โมเดลไม่ได้ มันจะถือว่า "ไม่ตรง" เงียบ ๆ
> **นี่เป็นจุดที่ควรอัปเกรดเป็น tri-state เหมือนฝั่ง Access** (ดูการบ้าน ข)

---

## 8. อ่านผลจริงจาก Lab ให้ออก

```
[PASS] VLAN10 reaches the RDP server          got accept · exact
[PASS] VLAN20 CANNOT reach the RDP server     got drop   · exact
[PASS] VLAN10 CANNOT reach AD over LDAP       got drop   · exact
[INFO] VLAN20 to AD on an unmodelled high port  unverified · unknown
```

- 3 อันแรก **`exact`** = ทุก object บนเส้นทางโมเดลได้หมด ฟันธงได้
- อันสุดท้าย **`unknown`** = ติด `ALL_DCE_RPC` ตอบไม่ได้ และ**บอกว่าติดที่ rule 4**

เคสด้านลบ (`CANNOT`) สำคัญไม่แพ้ด้านบวก — matrix ที่มีแต่ "อันนี้ต้องผ่าน"
แยกไม่ออกระหว่าง firewall ที่ทำงานถูกกับ firewall ที่เปิดหมด

---

## 9. สรุปสิ่งที่ต้องจำ

1. **Tri-state ไม่ใช่ของฟุ่มเฟือย** — `unknown` ที่ถูกยุบเป็น `no-match` จะกลายเป็น
   คำตอบผิดที่ฟังดูมั่นใจ ซึ่งอันตรายกว่าไม่ตอบ
2. **Matching ใช้ partial** (∃) — ต่างจาก containment ในบทที่ 3 ที่ใช้ strict (∀)
3. **เช็ค match ให้ครบก่อน แล้วค่อยสรุป unknown** — ลำดับผิด = เสียคำตอบที่ถูก
4. **rule ที่มี negate ใส่เป็น unknown ไม่ใช่ข้ามทิ้ง**
5. **ความมั่นใจ = จุดที่อ่อนที่สุดบนเส้นทาง**
6. **"ไม่เจอ rule" กับ "เข้า layer แล้วไม่มีลูกรับ" เป็นคนละเรื่อง** ต้องบอกให้ต่างกัน
7. **นี่คือการจำลองจาก config** ไม่ใช่การยิงจริง — ต้องพูดให้ชัดเสมอ

---

## 10. การบ้านบทที่ 4

**ก)** เปิด `address_match_state()` แล้วสลับลำดับ: ให้ `return "unknown"` ทันที
ที่เจอ `not complete` (ไม่ต้องวนต่อ) แล้วรัน `python -m tools.acceptance --package External-FW`
> เคสไหนพังบ้าง? อธิบายว่าทำไมลำดับเดิมถึงจำเป็น (**อย่าลืม revert**)

**ข)** `correlate_nat()` ใช้ boolean ไม่ใช่ tri-state
> ถ้า NAT rule ใช้ object ที่โมเดลไม่ได้ จะเกิดอะไรขึ้น แล้วผู้ใช้จะรู้ตัวมั้ย
> ลองร่างว่าจะแก้เป็น tri-state ยังไงโดยไม่ทำให้ผลลัพธ์เดิมเปลี่ยน

**ค)** เพิ่มเคสใน `tools/acceptance_cases.json` ให้ครอบคลุม rule ที่ยังไม่มีเคส
(rule 1 VPN, rule 2 Admin-Access, rule 3 Lab-Device-Mgmt, rule 7 ICMP)
> ข้อควรระวัง: rule 7 เป็น ICMP — ต้องใส่ `"protocol": "icmp"` ไม่ใช่ tcp

**ง)** ลองถาม Traffic Path ด้วย service ชื่อ `RDP` (ไม่ใช่ `Remote_Desktop_Protocol`)
> ได้ผลต่างกันมั้ย ทำไม แล้วถ้าเป็นผู้ใช้ที่ไม่รู้เรื่องนี้จะเข้าใจผิดยังไง

---

*บทที่ 5 จะเจาะ `nat_analyzer.py` — ทำไม NAT ถึงต้องมี analyzer แยกจาก Access
และ "Possible No-Translation" คืออะไร*
