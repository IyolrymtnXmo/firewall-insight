# Firewall Insight — ประเมินโปรเจกต์แบบไม่อวย และตำแหน่งในตลาด

> เขียน 8 ก.ย. 2569 ที่ v4.23.0 สำหรับใช้เป็นวัตถุดิบของรูปเล่มรายงานและเปเปอร์
> ทุกข้อความเกี่ยวกับผลิตภัณฑ์ในตลาดมีลิงก์อ้างอิงท้ายเอกสาร
> ส่วนที่เป็นความเห็น เขียนว่า "ความเห็น" ส่วนที่วัดได้ เขียนตัวเลขที่วัดได้

---

## 1. โปรเจกต์นี้คืออะไร ในหนึ่งย่อหน้า

Firewall Insight เป็นเว็บแอปที่ต่อเข้ากับ Check Point Security Management Server
ผ่าน Management API แบบ **อ่านอย่างเดียว** แล้วตอบคำถาม 4 กลุ่มที่ SmartConsole ไม่ได้ตอบตรง ๆ:

1. **โครงสร้างนโยบายจริงเป็นต้นไม้หน้าตายังไง** — Inline Layer คือ policy ลูก ไม่ใช่กฎแบน
2. **กฎไหนซ้อนทับ/ซ้ำ/กว้างเกิน/ไม่เคยโดนยิง** — static anomaly analysis
3. **ทราฟฟิกเส้นนี้จะโดนกฎไหน ผลเป็นอะไร** — จำลองจาก configuration แบบ tri-state
4. **NAT rule ไหนเกี่ยวข้อง และ estate หน้าตายังไง** — NAT analysis + logical topology map

ขนาดโค้ด ณ v4.23.0: backend ~3,700 บรรทัด + frontend ~3,900 บรรทัด, 17 API endpoint
(GET ทั้งหมด), 461 unit test, acceptance กับแล็บจริง 26/26 และ 17/17

---

## 2. ทำได้จริงอะไรบ้าง (วัดจากแล็บ ไม่ใช่จากโบรชัวร์)

| ความสามารถ | สถานะ | หลักฐาน |
|---|---|---|
| เดิน Inline Layer เป็นต้นไม้ recursive พร้อมเลข display (`8.1`, `8.2.1`) | ทำได้ | External-FW: 9 top-level + 1 layer/4 inline rule |
| แยก "จำนวนกฎ" ออกจาก "จำนวนกฎที่วิเคราะห์" | ทำได้ | `Access Rules 9` / `Total Inspected 13` |
| Shadow / duplicate / Any-Any-Any / zero-hit | ทำได้ (subset) | ดูข้อ 5.2 |
| Traffic path tri-state + inline-aware | ทำได้ | 8 เคสบวก/ลบ ผ่าน + 1 เคสตอบ `unverified` อย่างถูกต้อง |
| ปฏิเสธที่จะตอบเมื่อพิสูจน์ไม่ได้ | ทำได้ | `VLAN20 → AD tcp/9999` = `unverified` เพราะติด `ALL_DCE_RPC` |
| NAT analysis (duplicate / broad / no-translation / disabled / install-on) | ทำได้ | 11 rule (External) / 10 rule (Internal) |
| Topology map จาก interface address + cluster + Mgmt HA | ทำได้ (logical) | 6 object → 22 node, 5 subnet |
| Traffic path ทับบนแผนที่ แยก policy/topology confidence | ทำได้ (v4.23.0) | ดูข้อ 6.1 |
| **Routing จริง** | **ทำไม่ได้** | Management API ไม่ให้ routing table |
| **แก้ไขนโยบาย / remediate** | **ทำไม่ได้ โดยตั้งใจ** | ห้ามคำสั่ง `add-*` `set-*` `delete-*` `publish` |
| **หลายยี่ห้อ** | **ทำไม่ได้** | Check Point อย่างเดียว |

---

## 3. ในตลาดมีอะไรอยู่แล้วบ้าง

### 3.1 กลุ่มเชิงพาณิชย์ — NSPM (Network Security Policy Management)

**AlgoSec, Tufin, FireMon** ทำสิ่งที่โปรเจกต์นี้ทำ **ครบทุกข้อ และมากกว่านั้นมาก** มาสิบกว่าปีแล้ว
AlgoSec Firewall Analyzer ระบุความสามารถไว้ตรง ๆ ว่า visualize ทั้ง hybrid network,
ทำ **"what-if" traffic queries**, หา **"unused, duplicate or expired rules"**,
ให้ **"recommendations to remove, reorder or consolidate similar rules"**
และออก **"pre-populated, audit-ready compliance reports"** ครอบคลุมหลายยี่ห้อ
(Cisco ASA/Firepower, Palo Alto, Check Point, Fortinet, Juniper) รวมถึง router, load balancer, proxy

> **อย่าเขียนในรายงานว่า "ยังไม่มีเครื่องมือแบบนี้ในตลาด" — ไม่จริง และกรรมการที่รู้จัก AlgoSec
> จะจับได้ทันที** สิ่งที่เขียนได้คือ "มีในตลาดเชิงพาณิชย์ แต่เข้าถึงยากด้วยเหตุผล X"

**ราคา** — ผู้ผลิตไม่ประกาศราคาสาธารณะ ตัวเลขที่หาได้เป็นการรายงานจากบุคคลที่สาม
(และแหล่งหนึ่งเป็นคู่แข่งที่ขายของตัวเอง จึงต้องอ่านอย่างระวัง):
ช่วงที่ถูกอ้างถึงคือ AlgoSec ราว **$30,000–80,000/ปี** ต่อ environment ขนาดกลาง,
Tufin ราว $40k–80k+, FireMon ราว $35k–75k+ **ให้อ้างเป็น "ช่วงที่มีรายงาน" เท่านั้น
อย่าอ้างเป็นราคาทางการ**

### 3.2 กลุ่มโอเพนซอร์ส/งานวิจัย — Batfish

**Batfish** คือคู่เทียบทางวิชาการที่ตรงที่สุด และต้องอยู่ในเปเปอร์แน่นอน
เป็น network configuration analysis tool โอเพนซอร์ส สร้างโมเดลกลางที่ไม่ผูกยี่ห้อ
จาก **ไฟล์ config** แล้วตอบคำถาม reachability / ACL แบบมีหลักฐานเชิงรูปนัย
มีเปเปอร์ SIGCOMM 2023 สรุปบทเรียนจากวิวัฒนาการของตัวมันเอง

**ความต่างที่สำคัญที่สุด และเป็นจุดที่โปรเจกต์นี้ยืนได้:**
Batfish กิน **config file** — ต้องมีคนไป export config ออกมาก่อน
โปรเจกต์นี้กิน **Management API สด** — เห็น policy package, Inline Layer, object hierarchy
ตามที่ management server เห็นจริงในวินาทีนั้น ซึ่งเป็นคนละ input และคนละสถานการณ์ใช้งาน

### 3.3 เครื่องมือฟรีของ Check Point เอง — สำคัญมาก ต้องพูดถึง

| เครื่องมือ | ทำอะไร | ทำ**ไม่**ได้ |
|---|---|---|
| **ShowPolicyPackage** | export policy package + object เป็น HTML/JSON อ่านได้ | **ไม่วิเคราะห์อะไรเลย** ไม่หา shadow ไม่หา duplicate ไม่จำลองทราฟฟิก |
| **SmartMove** | แปลง config จาก Cisco ASA/FirePower, Juniper JunosOS/ScreenOS, Fortinet FortiOS, **PaloAlto PAN-OS และ Panorama** → policy ที่ Check Point R80.40+ ใช้ได้ | maintain แบบ best effort, ยังไม่ครอบทุกยี่ห้อ |
| **Compliance Blade** | Continuous Compliance Monitoring สแกน gateway/blade/policy/config เทียบกับฐานข้อมูลมาตรฐานและ best practice สแกนอัตโนมัติทุกวัน + หลัง publish | ผูกกับ ecosystem ของ Check Point, เกณฑ์เป็นของผู้ผลิต ไม่ใช่ของลูกค้า |

**ShowPolicyPackage คือคู่เทียบที่ยุติธรรมที่สุดสำหรับโปรเจกต์นี้** เพราะมันฟรี เป็นทางการ
และอยู่บน Management API เหมือนกัน ความต่างคือมัน **แสดง** ส่วนโปรเจกต์นี้ **วิเคราะห์**

### 3.4 ฐานทางวิชาการ

การจำแนก anomaly ของ firewall rule ที่เป็นมาตรฐานในวรรณกรรมคือของ
**Al-Shaer และ Hamed (2004)** — 5 ประเภท: **shadowing, correlation, generalization,
redundancy, irrelevance**

งานปี 2025 (Applied Sciences, MDPI) ที่ทบทวนสาขานี้ระบุ **ช่องว่างที่ยังเปิดอยู่** ไว้ 4 ข้อ:

1. เครื่องมือที่มีอยู่ **จำแนกผิด (misclassification)** — ตีกฎที่ถูกต้องว่าเป็น anomaly
   จนผู้ดูแลเลิกใช้ฟีเจอร์นั้นไปเลย
2. ไม่รองรับ **exception rule** — กฎที่จำเป็นแต่หน้าตาเหมือน anomaly
3. ไม่มี **การจัดลำดับความเสี่ยง** — บอกไม่ได้ว่าต้องแก้อันไหนก่อน
4. ไม่มีเครื่องมือ **decision support / visualization** ที่ช่วยให้เข้าใจความสัมพันธ์ระหว่างกฎก่อนแก้

**ข้อ 1 คือหัวใจของเปเปอร์ที่เขียนได้** — ดูข้อ 6

---

## 4. แล้วทำไมถึงต้องทำ (เหตุผลที่ยืนได้ ไม่ใช่เหตุผลที่ฟังดูดี)

**เหตุผลที่ยืนได้:**

1. **ช่องว่างราคา/การเข้าถึง** — ระหว่าง "ฟรีแต่ไม่วิเคราะห์" (ShowPolicyPackage)
   กับ "วิเคราะห์ครบแต่หลักล้านบาทต่อปี" (AlgoSec/Tufin/FireMon) **ไม่มีอะไรอยู่ตรงกลาง**
   สำหรับงาน pre-sales, งาน audit ครั้งคราว, แล็บ, หรือการเรียนการสอน การจ่ายระดับนั้นไม่เกิดขึ้น
2. **ความเสี่ยงศูนย์ในการเอาไปรันกับของลูกค้า** — read-only เชิงโครงสร้าง มีเทสต์บังคับว่า
   ไม่มี `add-*` `set-*` `delete-*` `publish` `install-policy` อยู่ใน `app/` และทุก route เป็น GET
   ตัวเลือกเชิงพาณิชย์ต้องติดตั้ง ต้องขอ account ต้องผ่าน change process
3. **จุดยืนเชิงญาณวิทยาที่ต่างจริง** — ดูข้อ 6 นี่คือส่วนที่เป็นงานวิจัยได้

**เหตุผลที่ *ฟังดูดี* แต่อย่าเขียน:**

- ❌ "ตลาดยังไม่มีเครื่องมือแบบนี้" — ไม่จริง
- ❌ "ทำแทน AlgoSec ได้" — ไม่จริง ต่างกันเป็นสิบเท่าในเชิงขอบเขต
- ❌ "เร็วกว่า/แม่นกว่าเครื่องมือเชิงพาณิชย์" — ไม่เคยวัดเทียบ อย่าอ้าง

---

## 5. ข้อเสียและข้อจำกัด (ส่วนที่ต้องอยู่ในรายงาน ถ้าอยากให้เชื่อถือ)

### 5.1 ยังไม่เคยพิสูจน์กับนโยบายขนาดจริง
แล็บมีกฎที่วิเคราะห์รวม **13 กฎ** (External-FW) และ **1 กฎ** (Internal-FW)
นโยบายลูกค้าจริงมีหลายร้อยถึงหลายพันกฎ **ยังไม่มีข้อมูลเลยว่า**
performance, การใช้หน่วยความจำ และความถูกต้องเป็นอย่างไรที่ขนาดนั้น
โดยเฉพาะ shadow analysis ซึ่งเป็นการเทียบกฎแบบคู่ (O(n²)) — นี่คือข้อจำกัดที่หนักที่สุด

### 5.2 ครอบคลุม taxonomy แค่บางส่วน
ทำ: shadowing (บางรูปแบบ), redundancy/duplicate, generalization (บางส่วนผ่าน Any-Any-Any)
**ไม่ทำ:** correlation anomaly และ irrelevance anomaly ตามนิยามของ Al-Shaer & Hamed
ต้องเขียนตรง ๆ ว่าครอบคลุม 3 จาก 5 ไม่ใช่ปล่อยให้เข้าใจว่าครบ

### 5.3 ไม่รู้เรื่อง routing
"เส้นทาง" ที่แสดงเป็นเส้นทาง **เชิงนโยบาย** ไม่ใช่เส้นทางจริง
ไม่รู้ routing table, PBR, VPN tunnel, asymmetric routing
Management API ไม่เปิดเผยข้อมูลนี้ (ดูข้อ 7.1)

### 5.4 บั๊กที่รู้ตัวและยังไม่แก้ ณ วันเขียน
**Traffic Path ไม่อ่านคอลัมน์ `vpn`** — `analyzer.py` ใช้, `policy_browser.py` แสดง,
แต่ `traffic.py` ไม่มีคำว่า `vpn` เลย แปลว่ากฎที่ผูกกับ VPN community เฉพาะ
จะถูกจับคู่เหมือนใช้กับทราฟฟิกทุกเส้น → ตอบ `accept · exact` ให้ทราฟฟิกที่ไม่ได้อยู่ใน VPN นั้น
ซึ่งขัดกับหลักการของตัวโปรเจกต์เอง **ต้องแก้ก่อนนำเสนอ**

### 5.5 Optimizer score เป็นตัวเลขที่คิดขึ้นเอง
เป็น heuristic ฝั่งแอป ไม่มีการ validate กับผู้เชี่ยวชาญ ไม่มีฐานทางวิชาการรองรับ
ห้ามเรียกว่า "Check Point official score" และในรายงานควรบอกว่ามันเป็น **ตัวชี้วัดเชิงสัมพัทธ์
สำหรับเทียบนโยบายเดียวกันข้ามเวลา** ไม่ใช่คะแนนสัมบูรณ์

### 5.6 อ่านอย่างเดียว = แก้ปัญหาให้ไม่ได้
NSPM เชิงพาณิชย์ทุกตัวมี change workflow (ขอเปิดพอร์ต → ตรวจผลกระทบ → push)
โปรเจกต์นี้จบที่ "บอกว่ามีปัญหา" ซึ่งเป็นการตัดสินใจที่ถูกสำหรับบริบทนี้
แต่ต้องยอมรับว่ามันครึ่งเดียวของวงจรงานจริง

### 5.7 ยังไม่ใช่ซอฟต์แวร์ที่พร้อมส่งมอบ
- ไม่มีระบบ authentication / ผู้ใช้หลายคน / audit trail — ใครเปิด URL ได้ก็เห็นทุกอย่าง
- รหัสผ่าน Management Server อยู่ใน `.env` ไฟล์เดียว ไม่มี secret management
- session เดียวใช้ร่วมกันทั้ง process, cache เป็น in-memory ไม่มี TTL ต่อผู้ใช้
- **ในรายงานควรระบุว่าเป็น engineering prototype ที่ทดสอบกับแล็บจริง ไม่ใช่ผลิตภัณฑ์**

### 5.8 ราคาของความซื่อสัตย์
tri-state ทำให้ตอบ `unverified` บ่อยกว่าเครื่องมือที่เดา
ผู้ใช้บางคนจะรู้สึกว่า "ถามอะไรก็ตอบไม่ได้" — นี่เป็น trade-off ที่ตั้งใจ
แต่ต้องยอมรับว่ามันคือต้นทุนด้าน UX ไม่ใช่ข้อดีล้วน ๆ

---

## 6. จุดที่อ้างความใหม่ได้จริง (สำหรับเปเปอร์)

**อย่าอ้างว่าฟีเจอร์ใหม่ — ให้อ้างว่า *วิธีจัดการความไม่รู้* ใหม่**

### 6.1 ข้อเสนอหลัก: แบบจำลอง tri-state ที่แพร่ความไม่แน่นอนตามโครงสร้างนโยบาย

เครื่องมือวิเคราะห์ firewall โดยทั่วไปตอบแบบทวิภาค: ตรง / ไม่ตรง
โปรเจกต์นี้ตอบสามค่า **match / no-match / unknown** และที่สำคัญกว่าคือ
**กฎการแพร่ความไม่แน่นอน 3 ข้อ**:

1. **กฎที่ประเมินไม่ได้ซึ่งอยู่ *ก่อน* กฎที่ตรงเป๊ะ ทำให้กฎหลังฟันธงไม่ได้**
   (`UNVERIFIED` ไม่ใช่ `Drop`) — เพราะ first-match-wins
2. **ความมั่นใจของผลลัพธ์ = จุดที่อ่อนที่สุดบนเส้นทาง** ข้าม Inline Layer
   (`exact` + `unknown` → `inferred`)
3. **ความมั่นใจสองแกนที่พังอิสระจากกัน** — v4.23.0 แยก `policy_confidence`
   (rulebase ตัดสินได้ไหม) ออกจาก `topology_confidence` (แพ็กเก็ตผ่านกล่องนี้จริงไหม)
   แล้ววาดตามตัวที่อ่อนกว่า

**ทำไมถึงเป็นงานวิจัย ไม่ใช่แค่ engineering:**
งานทบทวนปี 2025 ระบุว่าช่องว่างอันดับหนึ่งของสาขานี้คือ **การจำแนกผิดจนผู้ดูแลเลิกใช้ฟีเจอร์**
งานนี้เสนอว่าสาเหตุเชิงโครงสร้างคือ **การยุบ "ไม่รู้" ให้กลายเป็น "ไม่ตรง"**
และเสนอแบบจำลองที่ไม่ยุบ พร้อมกลไกวัดผลว่าเกิดขึ้นบ่อยแค่ไหนในนโยบายจริง

### 6.2 หลักฐานเชิงประจักษ์ที่มีอยู่แล้วและใช้อ้างได้

* **บั๊ก `_dimension_cover()` (v4.17)** — เซตว่างเป็นสับเซตของทุกเซตทางคณิตศาสตร์
  ทำให้กฎที่มิติหนึ่งไม่มีข้อมูลถูกรายงานว่า "ถูกกฎก่อนหน้าบังไว้"
  **นี่คือตัวอย่างรูปธรรมของ misclassification ที่เปเปอร์ปี 2025 พูดถึง** ในโค้ดจริง
* **บั๊กลำดับการจับคู่ (v4.23.0)** — วัดได้ว่า field เดียวกัน สลับลำดับ object แล้วได้คนละคำตอบ
  (`unknown` vs `match`) และ **461 เทสต์ไม่มีตัวไหนจับได้** จนกว่าจะจงใจไปทดลอง
* **`ALL_DCE_RPC`** — ตัวอย่างจริงจากแล็บที่พอร์ตเจรจาตอน runtime
  เครื่องมือที่ตอบ binary จะตอบ `Drop` อย่างมั่นใจ ซึ่งผิด

### 6.3 ข้อเสนอรอง: วิเคราะห์จาก API สด ไม่ใช่จากไฟล์ config

Batfish และเครื่องมือสาย formal verification ส่วนใหญ่กิน config file
งานนี้ทำงานบน Management API ตรง ทำให้เห็นสิ่งที่ไม่อยู่ในไฟล์ config:
policy package หลายชุด, Inline Layer hierarchy, object ที่ต้อง hydrate หลายรอบ
(`MAX_HYDRATION_ROUNDS = 6` เพราะ `details-level: standard` ให้แค่ uid/name/type)
**ปัญหา "มีข้อมูลใน dictionary ไม่ได้แปลว่าใช้ได้" เป็นปัญหาเฉพาะของการทำงานบน API
ที่งานสาย config-file ไม่เจอ** — เป็นข้อสังเกตที่ตีพิมพ์ได้

---

## 7. สิ่งที่ต้องไปตรวจต่อ ก่อนเขียนเปเปอร์

### 7.1 Gaia REST API เปิดอะไรบ้าง — ตรวจได้ในแล็บวันนี้
Check Point มี **Gaia RESTful API** แยกจาก Management API สำหรับอ่านข้อมูลและสั่งงาน Gaia OS
เอกสารระบุเองว่า *"Gaia API does not yet support the configuration of all Gaia OS settings"*
และมี reference ในเครื่องที่ `https://<IP>/gaia_docs/#introduction`

**ต้องเปิดดูในแล็บว่า มี endpoint อ่าน routing table / interface / bonding / cluster state หรือไม่**
ถ้ามี → ฟีเจอร์ที่ 1 และ 4 ทำได้ **โดยไม่ต้อง SSH** และไม่ทำลายหลักประกัน read-only ที่มีอยู่
ถ้าไม่มี → ต้องยอมรับตรง ๆ ว่าต้องใช้ช่องทางอื่น และประเมินความเสี่ยงใหม่

### 7.2 ต้องรันกับนโยบายขนาดใหญ่
ขอ config/นโยบายที่ใหญ่กว่านี้ (หรือ generate ขึ้นมา) แล้ววัดเวลาจริง
**ไม่มีตัวเลขนี้ เปเปอร์จะถูกถามแน่นอน**

### 7.3 ยังไม่ได้ตอบ: External-FW 11 NAT rule vs Internal-FW 10
ต้องเทียบ `/api/nat-analyze` ของสอง package แล้วอธิบายให้ได้

---

## 8. สรุปหนึ่งย่อหน้า สำหรับใส่บทคัดย่อ

> Firewall Insight เป็นเครื่องมือวิเคราะห์นโยบาย Check Point แบบอ่านอย่างเดียว
> ที่ทำงานบน Management API สด ความสามารถเชิงฟีเจอร์ (ตรวจกฎซ้อนทับ จำลองเส้นทาง
> รายงาน compliance) มีอยู่แล้วในผลิตภัณฑ์เชิงพาณิชย์อย่าง AlgoSec, Tufin และ FireMon
> และในเครื่องมือโอเพนซอร์สอย่าง Batfish งานนี้จึงไม่ได้เสนอฟีเจอร์ใหม่
> แต่เสนอ **แบบจำลองความไม่แน่นอนสามค่า (tri-state) ที่แพร่ไปตามลำดับกฎและตามลำดับชั้น
> Inline Layer** พร้อมกฎการรวมความมั่นใจแบบจุดที่อ่อนที่สุด และการแยกความมั่นใจ
> เชิงนโยบายออกจากความมั่นใจเชิงโครงสร้างเครือข่าย เพื่อตอบช่องว่างที่วรรณกรรมล่าสุด
> ระบุว่าเป็นสาเหตุให้ผู้ดูแลเลิกใช้ฟีเจอร์ตรวจ anomaly นั่นคือการจำแนกผิด
> อันเกิดจากการยุบสภาวะ "ประเมินไม่ได้" ให้กลายเป็น "ไม่ตรงเงื่อนไข"
> ระบบถูกทดสอบกับแล็บ Check Point R82 จริง (ClusterXL + Management HA)
> ด้วยชุดทดสอบ 461 รายการและชุด acceptance ที่รันกับ Management Server จริง

---

## 9. แหล่งอ้างอิง

- Batfish — https://batfish.org/ · https://github.com/batfish/batfish
- Batfish lessons, SIGCOMM 2023 — https://ratul.org/papers/sigcomm2023-batfish-lessons.pdf
- AlgoSec Firewall Analyzer — https://www.algosec.com/products/firewall-analyzer
- Check Point SmartMove — https://github.com/CheckPointSW/SmartMove/blob/master/README.md
- Check Point ShowPolicyPackage — https://github.com/CheckPointSW/ShowPolicyPackage
- Check Point Compliance (R81.20 Admin Guide) — https://sc1.checkpoint.com/documents/R81.20/WebAdminGuides/EN/CP_R81.20_SecurityManagement_AdminGuide/Content/Topics-SECMG/Compliance.htm
- Working with Gaia RESTful API (R82) — https://sc1.checkpoint.com/documents/R82/WebAdminGuides/EN/CP_R82_Gaia_AdminGuide/Content/Topics-GAG/API-for-Gaia.htm
- Anomaly classification / decision support (Applied Sciences, MDPI 2025) — https://www.mdpi.com/2076-3417/15/6/2979
  (อ้าง taxonomy ของ Al-Shaer & Hamed 2004 — **ต้องไปหาต้นฉบับมาอ้างเองด้วย ไม่ควรอ้างผ่าน**)
- ช่วงราคา NSPM (แหล่งบุคคลที่สาม อ่านอย่างระวัง แหล่งนี้เป็นผู้ขายคู่แข่ง) —
  https://safecadence.com/algosec-alternatives-2026/
