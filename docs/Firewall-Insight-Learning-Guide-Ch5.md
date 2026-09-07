# Firewall Insight — คู่มือเรียนรู้โปรเจกต์ (สำหรับ Dev ต่อ)

> **บทที่ 5: `nat_analyzer.py` — ทำไม NAT ต้องมี analyzer ของตัวเอง**
> เขียนโดยอ่านซอร์สจริงที่ v4.19.1 เมื่อ 7 ก.ย. 2569
> Lab ปัจจุบัน: `External-FW` มี 11 NAT rule · `Internal-FW` มี 10

---

## 1. ทำไมไม่ใช้ `analyzer.py` ตัวเดิม

เพราะ **NAT rule ไม่ใช่ Access rule ที่มีช่องเพิ่ม** มันเป็นคนละเรื่อง:

| | Access rule | NAT rule |
|---|---|---|
| ถามว่า | อนุญาตหรือไม่ | แปลงเป็นอะไร |
| ช่อง | source / destination / service | **original**-source/dest/service **+ translated**-source/dest/service |
| Action | Accept / Drop / Reject | ไม่มี action — มีแต่ผลการแปลง |
| ซ้อนกัน | shadow ได้ (rule แรกกินหมด) | first-match-wins เหมือนกัน แต่ "ครอบ" ไม่ได้แปลว่าอะไรเลย |

**จุดที่สำคัญที่สุด:** ใน Access การที่ rule 1 ครอบ rule 5 = rule 5 ไม่มีวันทำงาน = ปัญหา
แต่ใน NAT การที่ rule แรกครอบอยู่**ไม่ได้แปลว่า rule หลังไร้ประโยชน์เสมอไป** เพราะผลการแปลง
อาจต่างกันโดยตั้งใจ การเอา shadow analysis ของ Access มาใช้ตรง ๆ จะได้ false positive เพียบ

`nat_analyzer.py` จึงตรวจแค่ 4 อย่างที่**พูดได้อย่างมั่นใจ**:

1. **Exact duplicate** — เหมือนกันทุกช่องจริง ๆ
2. **Broad NAT** — original ทั้ง 3 ช่องเป็น Any
3. **Possible No-Translation** — translated ทั้ง 3 ช่องไม่แปลอะไรเลย
4. **Disabled** — ปิดอยู่

ไม่มี shadow analysis เลย — **ตั้งใจไม่ทำ** เพราะทำแล้วจะผิดมากกว่าถูก

---

## 2. `_as_list()` — บทเรียนแรกที่เจ็บที่สุด

```python
def _as_list(value: Any) -> list[Any]:
    """
    Check Point NAT fields can be returned as a single UID/string/object
    rather than an Access-rule-style list. Normalize both forms.
    """
    if value is None:  return []
    if isinstance(value, list):  return value
    return [value]
```

Access rule ส่ง `source` มาเป็น **list เสมอ** แม้มีตัวเดียว
แต่ **NAT rule ส่งมาเป็นค่าเดี่ยวได้** — `"original-source": "uid-abc"` ไม่ใช่ `["uid-abc"]`

ถ้าเขียนโค้ดโดยสมมติว่าเป็น list เสมอ:

```python
for x in rule["original-source"]:   # ได้ตัวอักษรทีละตัว! 'u','i','d','-','a'...
```

ไม่ error แต่ผลลัพธ์มั่วหมด — เป็นบั๊กประเภทที่หายากที่สุดเพราะไม่มีอะไรพัง
**ทุกฟังก์ชันในไฟล์นี้จึงเรียก `_as_list()` ก่อนเสมอ ไม่มีข้อยกเว้น**

---

## 3. `_uid_values()` — signature ของ NAT rule

```python
def _uid_values(value: Any) -> tuple[str, ...]:
    out = []
    for item in _as_list(value):
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, dict):
            uid = item.get("uid")
            # Some API responses can embed a name without a uid.
            out.append(str(uid or item.get("name") or ""))
        elif item is not None:
            out.append(str(item))
    return tuple(sorted(x for x in out if x))
```

สามอย่างที่ต้องสังเกต:

- **`sorted()`** — `[A, B]` กับ `[B, A]` คือ rule เดียวกัน
- **fallback ไป `name`** — API บางเวอร์ชันฝัง name มาโดยไม่มี uid ถ้าไม่ fallback
  entry นั้นจะกลายเป็นสตริงว่างแล้วถูกกรองทิ้ง → signature เพี้ยน → นับซ้ำผิด
- **`tuple`** — ต้อง hashable เพราะเอาไปเป็น key ของ `defaultdict`

Signature ที่ใช้ตัดสิน duplicate ประกอบด้วย: original 3 ช่อง + translated 3 ช่อง +
install-on + method + enabled — ครบทุกอย่างที่ทำให้ NAT rule สองอันต่างกัน

---

## 4. `_method()` — ชื่อ field ไม่เหมือนกันในแต่ละเวอร์ชัน

```python
def _method(rule):
    for key in ("method", "nat-method", "translated-source-method"):
        value = rule.get(key)
        if isinstance(value, dict):
            return str(value.get("name") or value.get("uid") or "")
        if value:
            return str(value)
    return ""
```

Hide NAT กับ Static NAT เป็นคนละเรื่องกันโดยสิ้นเชิง แต่ Management API แต่ละ build
เรียก field นี้ไม่เหมือนกัน ลองทีละชื่อจนเจอ และรับได้ทั้งแบบ string และแบบ object

**ถ้าไม่มีเลยคืน `""`** ไม่ใช่เดาว่าเป็น hide — เพราะ method เป็นส่วนหนึ่งของ signature
ถ้าเดาผิด NAT rule ที่ต่างกันจริงจะถูกนับเป็นซ้ำ

---

## 5. Finding ที่ 1: Broad NAT

```python
if (_is_any(resolver, original_source)
        and _is_any(resolver, original_destination)
        and _is_any(resolver, original_service)):
    broad.append(rule_number)
```

NAT rule ที่ original เป็น `Any → Any → Any` = **แปลงทุกอย่างที่วิ่งผ่าน**
ไม่ผิดเสมอไป (Hide NAT ขาออกทั้งวงก็เขียนแบบนี้) แต่ควรตั้งใจ ไม่ใช่หลุดมา

ต่างจาก Access ตรงที่ **ไม่มีแนวคิด "cleanup rule" ใน NAT** — ไม่มีการยกเว้นให้ rule สุดท้าย

---

## 6. Finding ที่ 2: Possible No-Translation (อันที่น่าสนใจที่สุด)

```python
if all(x in {"—", "Original"} for x in translated_desc):
    no_translation.append(rule_number)
```

NAT rule ที่ทั้ง 3 ช่อง translated เป็น `Original` หรือว่างเปล่า = **rule ที่ไม่แปลงอะไรเลย**

มันมีอยู่ 2 เหตุผล:

**ก) ตั้งใจ — NAT exemption** เขียน rule ที่ไม่แปลงไว้ **ก่อน** rule ที่แปลง เพื่อยกเว้น
traffic บางเส้น (เช่น traffic ระหว่าง site ผ่าน VPN ไม่ต้อง NAT) เป็น pattern ปกติ

**ข) ไม่ตั้งใจ** — สร้าง rule ไว้แล้วลืมใส่ค่า translated

โปรแกรมแยกสองอย่างนี้ไม่ออก จึงตั้งชื่อว่า **"Possible"** No-Translation
ไม่ใช่ "Misconfigured NAT" — **ตั้งชื่อ finding ตามสิ่งที่พิสูจน์ได้ ไม่ใช่ตามข้อสรุปที่เดา**

> คำว่า `"Original"` เป็น **literal string** ที่ Check Point ส่งกลับมา ไม่ใช่ uid
> `_describe()` จึงมีบรรทัด `if item.lower() == "original": parts.append("Original")`
> ถ้าไม่ดักไว้ มันจะถูกส่งเข้า `describe_uid()` แล้วคืน uid ดิบออกมาให้ผู้ใช้อ่าน

---

## 7. Finding ที่ 3–4: Duplicate และ Disabled

Duplicate ใช้หลักเดียวกับ Access — signature ตรงกันเป๊ะเท่านั้น note ในผลลัพธ์เขียนไว้ชัด:

> *"Exact duplicate means original match, translated values, install-on, method,
> and enabled state are equal."*

ถ้ามีอย่างใดต่าง = **ไม่ใช่** duplicate แม้จะดูคล้ายกันแค่ไหน

---

## 8. `hits_available` — ไม่เดาว่า API รองรับอะไร

```python
hits_available = False
...
if hit_value is not None:
    hits_available = True
```

Management API เก่ากว่าบางเวอร์ชันตอบ HTTP 400 `Unrecognized parameter [show-hits]`
บน `show-nat-rulebase` — `checkpoint.py` จึง **probe ครั้งเดียวแล้วจำไว้**
(`_is_unsupported_parameter_error()` → `nat_show_hits_supported`)

ที่นี่เพิ่มอีกชั้น: ถึงจะขอ hits ไปแล้ว ถ้า**ไม่มี rule ไหนส่ง hit กลับมาเลย** ก็ยัง
รายงานว่าไม่มี — UI จะได้ไม่โชว์คอลัมน์ว่างเปล่าที่ดูเหมือน "0 hits ทุก rule"
ซึ่งเป็นคนละเรื่องกับ "ไม่มีข้อมูล hits"

ผลรันจริงจาก Lab: `nat_hits_available=True` (API 2.0.1 รองรับ)

---

## 9. ผลจริงจาก Lab

```
[PASS] NAT rulebase loaded  11 NAT rule(s)          ← External-FW
[PASS] NAT rulebase loaded  10 NAT rule(s)          ← Internal-FW
[PASS] show-hits support probed, not assumed  nat_hits_available=True
```

`External-FW` มี 11 rule `Internal-FW` มี 10 — ตัวเลขต่างกัน 1 ทั้งที่ NAT ควรเป็น
policy เดียวกัน **นี่คือสิ่งที่ควรไปดูต่อ** (ดูการบ้าน ก)

---

## 10. สิ่งที่ยังไม่มีในไฟล์นี้ — และเหตุผล

| ไม่มี | ทำไม |
|---|---|
| Shadow analysis | "ครอบ" ใน NAT ไม่ได้แปลว่าไร้ประโยชน์ จะได้ false positive เพียบ |
| ตรวจ NAT ชนกับ routing | ต้องรู้ routing table จริง ซึ่ง Management API ไม่ให้ |
| ตรวจว่า Hide NAT pool พอมั้ย | ต้องรู้จำนวน concurrent session จริง เป็น runtime ไม่ใช่ config |
| จับคู่ NAT กับ Access rule | ทำได้บางส่วนแล้วใน `correlate_nat()` (บทที่ 4) แต่ยังเป็น boolean ไม่ใช่ tri-state |

ทุกข้อคือ **"ทำไม่ได้อย่างซื่อสัตย์"** ไม่ใช่ "ยังไม่มีเวลาทำ" — ต่างกันมาก และควรเขียนไว้
ให้คนที่มาต่อรู้ ไม่งั้นเขาจะไปทำแล้วได้เครื่องมือที่โกหก

---

## 11. สรุปสิ่งที่ต้องจำ

1. **NAT ไม่ใช่ Access ที่มีช่องเพิ่ม** — ต้องมี analyzer แยก
2. **NAT field เป็นค่าเดี่ยวได้** — `_as_list()` ทุกครั้ง ไม่มีข้อยกเว้น
3. **ตั้งชื่อ finding ตามสิ่งที่พิสูจน์ได้** — "Possible No-Translation" ไม่ใช่ "Misconfigured"
4. **`"Original"` เป็น literal ไม่ใช่ uid**
5. **ไม่ทำ shadow analysis เป็นการตัดสินใจ ไม่ใช่ความขี้เกียจ** — และต้องเขียนไว้
6. **"ไม่รองรับ" กับ "รองรับแต่ค่าเป็นศูนย์" คนละเรื่อง**

---

## 12. การบ้านบทที่ 5

**ก)** `External-FW` มี 11 NAT rule แต่ `Internal-FW` มี 10
> ต่างกันตรงไหน เป็นความตั้งใจหรือหลุด?
> ใช้ `GET /api/nat-analyze?package=External-FW` เทียบกับ `Internal-FW`

**ข)** ลองสร้าง NAT rule ที่ translated ทุกช่องเป็น `Original` ใน Lab
> ขึ้นใน "Possible No-Translation" มั้ย แล้วถ้าใส่ comment อธิบายว่าเป็น NAT exemption
> โปรแกรมควรเลิกรายงานมั้ย? (คำใบ้: อย่ารีบตอบว่าควร)

**ค)** อ่าน `_uid_values()` แล้วตอบ
> ถ้า API ส่ง `{"name": "X"}` มาโดยไม่มี `uid` แล้วอีก rule ส่ง `{"uid": "abc", "name": "X"}`
> ทั้งสองจะถูกนับเป็น duplicate กันมั้ย? ถูกต้องหรือไม่?

**ง)** เพิ่มการตรวจ **"NAT rule ที่ install-on ไม่ตรงกับ gateway ที่มีอยู่จริง"**
> ข้อมูลมีครบแล้วจาก `show-gateways-and-servers` (บทที่ 6)
> เขียนเทสต์ก่อนเขียนโค้ด แล้วระวังว่า `Policy Targets` = ทุกตัว ไม่ใช่ชื่อ gateway

---

*บทที่ 6 จะเจาะ frontend + `topology_map.py` — physics layout, การแยก
"สิ่งที่ API บอก" ออกจาก "สิ่งที่เราอนุมาน" และเหตุผลที่ทุกอย่างเป็นไฟล์เดียวไม่ได้*
