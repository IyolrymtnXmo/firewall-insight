# Firewall Insight — คู่มือเรียนรู้โปรเจกต์ (สำหรับ Dev ต่อ)

> **บทที่ 6 (บทสุดท้าย): Frontend + `topology_map.py`**
> เขียนโดยอ่านซอร์สจริงที่ v4.19.1 เมื่อ 7 ก.ย. 2569
> Lab ปัจจุบัน: 6 objects → 22 map nodes → 11 graph nodes / 14 links

---

## 1. โครงสร้างที่มาถึงวันนี้

บทที่ 1 บอกว่า frontend ทั้งหมดฝังอยู่ใน `main.py` — **ไม่ใช่แล้ว**

| | v4.7 | v4.19 |
|---|---|---|
| `main.py` | 2,473 บรรทัด (83% เป็น HTML/CSS/JS ในสตริง Python) | 53 บรรทัด |
| frontend | สตริงใน Python | `templates/index.html` · `static/css/app.css` · `static/js/app.js` |
| routes | อยู่ใน main.py หมด | `app/api/` 7 ไฟล์แยกตามหน้า |

**ทำไมต้องแยก** — ตอนอยู่ในสตริง Python: ไม่มี syntax highlight, ไม่มี lint,
browser cache ไม่ทำงาน (ทุก request โหลด 100KB ใหม่), และทุกการแก้ CSS ต้องแตะไฟล์เดียวกับ
ที่มี logic การเชื่อม API

**ราคาที่ต้องจ่าย** — พอ CSS/JS เป็นไฟล์แยก browser จะ cache ไว้ ผู้ใช้จึงเห็นของเก่า
หลังอัปเดต (เกิดขึ้นจริงตอน v4.13: เห็นทั้งดวงอาทิตย์และดวงจันทร์พร้อมกัน) แก้ด้วย:

```python
def asset_version() -> str:
    newest = max(p.stat().st_mtime for p in STATIC.rglob("*") if p.is_file())
    return f"{APP_VERSION}-{int(newest)}"          # -> /static/css/app.css?v=4.19.1-1788797695
```

ผูกกับ **mtime ไม่ใช่แค่เลขเวอร์ชัน** เพราะระหว่าง dev เราแก้ CSS โดยไม่ bump version ตลอด

---

## 2. `topology_map.py` — เส้นแบ่งที่สำคัญที่สุดในโปรเจกต์

ไฟล์นี้แปลง `show-gateways-and-servers` เป็น nodes + edges และเป็นที่ที่**หลักการของทั้งโปรเจกต์
ถูกบังคับใช้อย่างเข้มที่สุด**: แยก "สิ่งที่ API บอก" ออกจาก "สิ่งที่เราอนุมาน"

### 2.1 ปัญหาที่เจอจริง

`show-gateways-and-servers` คืน **cluster และสมาชิกเป็น object ระดับเดียวกัน** และ
**สมาชิกไม่มี back-reference กลับไปหา cluster**:

```
External-Cluster   CpmiGatewayCluster   cluster-member-names: ['External-GW01','External-GW02']
External-GW01      cluster-member       back-reference: NONE
External-GW02      cluster-member       back-reference: NONE
```

แผนที่จึงวาด ClusterXL 1 ชุดเป็น firewall 3 ตัวเท่ากัน — **เกินความจริง**

### 2.2 สิ่งที่ยั่วใจ (และเราไม่ทำ)

ดูจากเลข IP ก็เดาได้:

| | 172.23.31.0/24 | 172.23.34.0/24 | 10.99.99.0/30 |
|---|---|---|---|
| External-Cluster | **.179** | **.179** | — |
| External-GW01 | .177 | .177 | **.1** |
| External-GW02 | .178 | .178 | **.2** |

`/30` ที่มี `.1` กับ `.2` ต่อกันเอง = sync network · IP ที่สามบน subnet เดียวกัน = VIP
**ถูกเกือบทุกครั้ง** แต่ไม่เสมอไป

```python
def _cluster_member_names(o):
    """
    This is deliberately the ONLY source of membership. Reading it off the
    addresses ... is right most of the time and wrong some of the time, and
    a map that is "usually right" about which boxes are one firewall is
    worse than one that says it does not know.
    """
    for key in ("cluster-member-names", "cluster-members", "members"):
```

**หลักการ:** แผนที่ที่ "ถูกเกือบทุกครั้ง" เรื่องว่ากล่องไหนคือ firewall เดียวกัน
แย่กว่าแผนที่ที่บอกตรง ๆ ว่าไม่รู้ — เพราะคนจะเชื่อมันแล้วตัดสินใจผิดโดยไม่รู้ตัว

มีเทสต์คุมไว้: ลบ `cluster-member-names` ออกจาก payload → ไม่ลากเส้น membership เลย

### 2.3 สิ่งที่อ่านจากกราฟได้ (ต่างกัน)

```python
# A subnet no cluster interface touches, reached only through members of one
# cluster, is internal to that cluster - on a real deployment, the sync
# network. This is read off the graph, not off the addresses.
```

`10.99.99.0/30` ไม่มี interface ของ cluster อยู่เลย มีแต่สมาชิก — นี่เป็น**ข้อเท็จจริงของกราฟ**
ไม่ใช่การเดาจากเลข tooltip จึงเขียนแบบ **หลักฐานก่อน ข้อสรุปทีหลัง**:

> "No interface of External-Cluster is on this network, only its members are.
> On a ClusterXL deployment that is the sync network."

### 2.4 Management HA — บทเรียนเรื่องการยอมรับว่าเคยผิด

ตอนแรกผมสรุปว่า API ไม่บอกความสัมพันธ์ HA (ไปดูแต่ field ชื่อ `ha`/`peer` ระดับบนสุด)
แต่ `tools/diag_topology.py` พิสูจน์ว่าผิด:

```
CP-MGMT-01  management-blades: [logging-and-status, network-policy-management]
CP-MGMT-02  management-blades: [logging-and-status, network-policy-management, secondary]
```

`management-blades.secondary` = ตัว standby และ 1 domain มี primary ตัวเดียว
→ **primary + secondary คือคู่ HA โดยนิยาม** ไม่ใช่การอนุมาน

แต่สิ่งที่ยัง**ไม่รู้**คือทั้งคู่ sync กันอยู่จริงมั้ย — object model ไม่มี field นั้น:

```python
"""
What is NOT knowable is whether they are currently synchronised - the object
model has no such field. So the map may say HA is configured and must never
imply it is healthy.
"""
```

แผนที่จึงบอกได้แค่ **"HA configured"** เขียนไว้ทั้งใน `limitations` และ tooltip

> **บทเรียนสำหรับคนทำต่อ:** ถ้าคิดว่า API ไม่มีข้อมูล **เขียนเครื่องมือ diagnostic ไปถามมัน
> ก่อนจะสรุป** ผมเกือบทิ้งฟีเจอร์นี้เพราะเชื่อ doc แทนที่จะเชื่อ payload

---

## 3. Physics layout — Fruchterman-Reingold เขียนเอง

ไม่ใช้ library เพราะ: ต้องทำงาน offline (แล็บไม่มีเน็ต), ไม่มี build step,
และ CSP ของแอปบล็อก CDN

```js
const K = g.k || 150;                              // ระยะเส้นในอุดมคติ
// repulsion: k²/d ตามสูตร + แรงผลักพิเศษตอนซ้อนกันจริง
const f = (K * K / d) * a.w * b.w + (d < gap ? (gap - d) * 8 : 0);
// attraction: d²/k
const f = d * d / (K * (l.len || 1));
```

### 3.1 ทำไมห้ามใช้ `Math.random()`

```js
// No Math.random: the same topology must lay out the same way every time,
// or a saved arrangement would be meaningless and two runs of the same lab
// would never look alike.
const GA = Math.PI * (3 - Math.sqrt(5));           // golden angle
```

ถ้าสุ่ม: ผู้ใช้จัดวางแล้ว Save ไว้ → เปิดใหม่คนละที่ → screenshot ในรายงานไม่ตรงกับหน้าจอ
→ เทสต์ที่วัดตำแหน่งเชื่อไม่ได้ **determinism ตรงนี้เป็นข้อกำหนด ไม่ใช่ความสวยงาม**

### 3.2 บั๊กที่เจอจากการวัด ไม่ใช่จากการดู

ทั้งหมดนี้เจอเพราะ**วัดค่าใน headless Chromium** ไม่ใช่ดูรูป:

| อาการ | สาเหตุ | แก้ |
|---|---|---|
| แผนที่ใช้พื้นที่ 1/3 ของ panel | `viewBox` ตายตัว 1600×1000 + `preserveAspectRatio` → letterbox | viewBox = ขนาดจริงของ container |
| จอใหญ่ขึ้น ตัวหนังสือเล็กลง | ระยะเส้นคงที่ → layout ใหญ่กว่า panel → fit ย่อเหลือ 67% | ระยะปรับตาม panel + anisotropic gravity |
| HA pair กระเด็นไปมุมจอ | เป็น connected component ที่ 2 แต่ FR สมมติกราฟต่อกันหมด | แยก component แล้ว shelf-pack |
| ป้ายทับกัน 8 จุด | ไม่มีสูตรถูก ๆ ทำนายว่าป้ายจะตกบนป้ายโหนดที่สาม | `topoDeclutter()` วัดกล่องจริงหลัง layout นิ่งแล้วซ่อนตัวที่ชน |
| memory leak | `topoBindEvents()` รันทุก render แล้ว add `window` listener ใหม่ทุกครั้ง | ย้าย drag state ออกมา register ครั้งเดียว |

**บทเรียน:** screenshot บอกว่า "ดูโอเค" ได้ แต่บอกไม่ได้ว่า "ป้ายทับกัน 8 จุด"
หรือ "listener สะสม 40 ตัว" — สองอย่างนี้ต้องวัด

```python
# วัดจริง ไม่ใช่ดูรูป
OVERLAP = """() => { ... นับกล่องข้อความที่ตัดกัน ... }"""
# ผล: 8 -> 0
```

---

## 4. Auto Merge / Collapse — การจัดกลุ่มที่ไม่ทิ้งข้อมูล

```js
const sig = [...c.users.keys()].sort().join('|');   // subnet ที่ถึงได้ผ่าน device ชุดเดียวกัน
```

**Auto Merge** ยุบ subnet ที่ถึงได้ผ่าน device ชุดเดียวกันเป๊ะ ๆ เข้าเป็นโหนดเดียว
บน estate 40 gateway: 241 โหนด → 81 โหนด

สามอย่างที่ทำให้มัน**ไม่ใช่การซ่อนข้อมูล**:
1. บอกจำนวนที่ยุบ (`2 subnets merged`)
2. hover เห็นสมาชิกทุกตัว
3. **กดขยายกลับได้** — เดิมกดไม่ได้ ซึ่งเป็นทางตัน: ตอบได้ว่า "มีกี่อัน" แต่ถามต่อว่า "อันไหนบ้าง" ไม่ได้

**Collapse** ซ่อน subnet ที่ห้อยกับ device เดียว เหลือแต่โครงหลัก
แต่ subnet ที่ gateway 2 ตัวถึงได้จะ**ไม่ซ่อน**เด็ดขาด — มันคือเส้นทางระหว่างสองตัวนั้น
ซ่อนแล้วแผนที่จะเปลี่ยนความหมาย

---

## 5. Feedback layer — สิ่งที่ทำให้ใช้งานได้จริง

เดิมกดปุ่มแล้วต้องเปิด F12 → Network ดูเองว่ามันทำอะไรอยู่ ตอนนี้:

- **Progress bar** ทุก request
- **Blur overlay** พร้อมเวลาที่ผ่านไป + ชื่อขั้นตอน สำหรับงานที่บล็อก
- **ขั้นตอนที่รายงานจาก server จริง** — เดิมเป็นการเดาฝั่ง client ซึ่งค้างที่ขั้น 1 ตลอดแล้วกระโดดไป done
  วัดแล้วพบว่า phase 0 ใช้ 27 วิ ส่วน phase 1-3 ใช้ microsecond → แก้ด้วย `/api/progress` + ตัวนับรายอ็อบเจกต์
- **Toast** มุมขวาบน คัดลอกรายละเอียดได้
- **Empty state** บอกว่าต้องทำอะไรต่อ ไม่ใช่หน้าว่าง
- **ผลลัพธ์ที่ไม่ครบถูกติดป้ายว่าไม่ครบ** — `data_quality()` ส่ง warning ขึ้นเป็นแบนเนอร์

หลักการเดียวกับทั้งโปรเจกต์: **UI ห้ามอ้างเกินกว่าที่โค้ดรู้จริง** — progress bar ปลอม
ก็คือการโกหกแบบหนึ่ง

---

## 6. เทสต์ frontend ยังไงโดยไม่มี browser

380 เทสต์รันโดยไม่ต้องมี browser และไม่ต้องมี Management Server:

```python
def ui_source() -> str:
    """Markup, then CSS, then JavaScript - the served single-page UI."""

def ui_text() -> str:
    """ui_source() with every run of whitespace collapsed to one space."""
```

**บทเรียนที่แพงที่สุดของหัวข้อนี้:** เทสต์ 5 ตัวพังเงียบ ๆ ตั้งแต่ 24 ส.ค. เพราะ
HTML formatter รันทับ `index.html` แล้วตัดบรรทัดใหม่:

```
>▤ Access Policy</button>     กลายเป็น     >▤ Access
                                              Policy</button>
```

เทสต์เหล่านั้นเช็ค *คำบนปุ่ม* แต่ไป pin *ตำแหน่งที่บรรทัดตัด* = กลายเป็นเทสต์การตั้งค่า
formatter ของ editor ไม่ใช่เทสต์ตัวแอป

แก้ด้วย `ui_text()` สำหรับ assertion เรื่องข้อความที่มองเห็น ส่วน assertion เรื่อง
โครงสร้าง (id, attribute, CSS, JS) ยังใช้ `ui_source()` เพราะตรงนั้นตัวอักษรเป๊ะ ๆ คือสัญญาจริง

**ทดสอบว่าแก้ถูกจริงด้วยการรันกับ index.html 3 แบบ** — ไม่ format, format แบบ formatter,
และจงใจตัดทุก tag ขึ้นบรรทัดใหม่ → ผ่านทั้ง 3 แบบ

ส่วนที่เทสต์แบบอ่านซอร์สไม่ได้ (physics แยกโหนดจริงมั้ย, drag ปักหมุดจริงมั้ย,
PNG export ได้ pixel จริงมั้ย) ใช้ **headless Chromium วัดค่า** แล้วบันทึกตัวเลขไว้ใน CHANGELOG

---

## 7. สรุปหลักการที่ใช้ทั้งโปรเจกต์

ถ้าจำอะไรจากคู่มือทั้ง 6 บทได้แค่อย่างเดียว ให้จำอันนี้:

> ## UI ห้ามอ้างเกินกว่าที่โค้ดรู้จริง

มันปรากฏซ้ำในทุกบท:

| บท | รูปแบบที่มันปรากฏ |
|---|---|
| 2 | pagination ใช้ขอบ `to` จาก API ไม่ใช่ `len(batch)` |
| 3 | matching ใช้ partial (∃) · containment ใช้ strict (∀) · `unknown` ต้องมีให้น้อยที่สุดแต่ต้องมี |
| 4 | tri-state — `unknown` ที่ยุบเป็น `no-match` คือคำตอบผิดที่ฟังดูมั่นใจ |
| 5 | "Possible No-Translation" ไม่ใช่ "Misconfigured" |
| 6 | cluster membership เอาจาก API เท่านั้น · HA บอกได้แค่ configured ไม่ใช่ healthy |
| ทุกบท | `data_quality()` · `limitations[]` · progress bar ที่รายงานของจริง |

**อีกอันที่ควรจำ:** false negative ปลอดภัยกว่า false positive ในเครื่องมือประเภทนี้เสมอ
พลาดการตรวจพบ = คนไปหาเจอเอง แต่รายงานผิด = คนตัดสินใจผิดโดยเชื่อเรา

---

## 8. งานที่เหลือ (สำหรับคนที่มาต่อ)

| ลำดับ | งาน | ทำไม |
|---|---|---|
| 1 | `correlate_nat()` เป็น tri-state | ตอนนี้เป็น boolean — NAT object ที่โมเดลไม่ได้ถูกมองว่า "ไม่ตรง" เงียบ ๆ |
| 2 | Cards mode ยังไม่วาดความสัมพันธ์ cluster/HA | มีแค่สีการ์ด โหมดนั้นวาดแค่ interface → subnet |
| 3 | ผูก Traffic Path เข้ากับแผนที่ | query แล้วไฮไลต์เส้นทางบนแผนที่ ข้อมูลมีครบแล้ว |
| 4 | เปิดเผยสูตรคะแนน optimizer บน UI | ตอนนี้อยู่แต่ในบทที่ 3 — เป็นตัวเลขที่เราตั้งเอง ไม่ใช่มาตรฐาน |
| 5 | CI workflow | ตอนนี้ต้องรัน pytest เอง |
| 6 | แยก `traffic.py` ต่อ | ยังมี 3 concern (matcher / trace / NAT correlation) |
| 7 | ruff lint | ยังไม่มี |

---

## 9. การบ้านบทที่ 6 (บทสุดท้าย)

**ก)** ลบ `?v=` ออกจาก `asset_version()` แล้วแก้สี CSS อะไรก็ได้ รีเฟรชหน้า
> เห็นการเปลี่ยนแปลงมั้ย ต้องกด Ctrl+F5 กี่ครั้ง — นี่คือบั๊กที่ผู้ใช้เจอจริงตอน v4.13

**ข)** เปิด `topology_map.py` หา `_mgmt_role()`
> ถ้า Lab มี management server 3 ตัว (1 primary 2 secondary) แผนที่จะวาดยังไง
> แล้วถ้ามี primary 2 ตัวล่ะ (คำใบ้: อ่าน `limitations` ที่มันเพิ่มเข้าไป)

**ค)** รัน `python -m tools.acceptance --package Internal-FW`
> ทำไม 3 check ถึงเป็น INFO ไม่ใช่ FAIL แล้วทำไมการแยก "check" ออกจาก "finding"
> ถึงสำคัญ (คำใบ้: ถ้ารันไม่มีวันเขียวจนกว่า estate จะสมบูรณ์แบบ จะเกิดอะไรขึ้น)

**ง)** *(ท้าทาย)* ทำงานข้อ 3 ในตาราง — ไฮไลต์เส้นทาง Traffic Path บนแผนที่
> ระวัง: แผนที่รู้จัก gateway/subnet แต่ trace รู้จัก rule/layer ต้องหาจุดเชื่อม
> และห้ามวาดเส้นทางที่ trace ตอบ `unknown` เหมือนกับที่ตอบ `exact`

---

## 10. จบคู่มือ

| บท | หัวข้อ | ไฟล์ |
|---|---|---|
| 1 | Setup + ภาพรวม + request flow | ทั้งโปรเจกต์ |
| 2 | Check Point API + pagination + Inline Layer | `checkpoint.py`, `inline_layers.py` |
| 3 | Resolver + Analyzer | `resolver.py`, `analyzer.py` |
| 4 | Traffic Path + tri-state | `traffic.py` |
| 5 | NAT analyzer | `nat_analyzer.py` |
| 6 | Frontend + Topology | `static/`, `templates/`, `topology_map.py` |

**เครื่องมือที่ควรรู้ว่ามี** (read-only ทั้งหมด):

```powershell
python -m tools.acceptance --package External-FW   # 26 check + หลักฐาน JSON
python -m tools.diag_topology                      # cluster / HA ตาม API จริง
python -m tools.diag_resolver Standard             # object ที่ resolve ไม่ออก
python -m tools.ch3_demo                           # พิสูจน์ทุกข้ออ้างในบทที่ 3
pytest -q                                          # 381 เทสต์ ไม่ต้องมี Management Server
```
