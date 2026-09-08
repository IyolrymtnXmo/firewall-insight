# กรณีศึกษา: เมื่อ "อนุญาตแล้ว" กับ "ผ่านได้" ไม่ใช่เรื่องเดียวกัน

> แล็บ Netpoleon, 8 ก.ย. 2569 · Firewall Insight v4.28.2
> เอกสารนี้บันทึกเหตุการณ์จริงที่เกิดขึ้นระหว่างทดสอบ ไม่ใช่ตัวอย่างสมมติ
> ใช้ประกอบหัวข้อ "ข้อจำกัดของการวิเคราะห์จาก configuration" ในรายงานและเปเปอร์

---

## 1. เรื่องเริ่มจากเครื่องมือบอกว่า "อ่านไม่ได้"

หน้า **Gateway Health** รายงาน finding ระดับ high:

```
HIGH · 172.23.31.176 · not-read · reachability
These gateways did not answer, so nothing below says anything about their
state. Absence of a finding is not health.
```

และหน้า **Network Mapping** เขียนไว้ในกรอบ limitations ว่าไม่ได้อ่าน routing จาก
`172.23.31.176` พร้อมเหตุผล แทนที่จะวาดแผนที่ให้ดูสมบูรณ์โดยเงียบ ๆ

**ถ้าเครื่องมือเลือกเงียบตรงนี้ เรื่องทั้งหมดข้างล่างนี้จะไม่ถูกค้นพบ**

---

## 2. ไล่หาสาเหตุ

| ขั้น | คำสั่ง | ผล | ตัดอะไรออก |
|---|---|---|---|
| 1 | `Test-NetConnection 172.23.31.176 -Port 443` | timeout, ping ก็ timeout | ไม่ใช่เรื่อง cert / รหัสผ่าน |
| 2 | `show route` บน .176 | `S 0.0.0.0/0 via 172.23.31.179, eth1, active` | มี default route อยู่แล้ว |
| 3 | `show allowed-client all` บน .176 | `Host Any` | Gaia Host Access เปิดหมด |
| 4 | `tcpdump -nni eth1 host 172.23.10.35` บน .176 | เห็น **ทั้ง** echo request และ echo reply | .176 รับและตอบปกติ |
| 5 | SmartConsole Logs กรอง `172.23.10.35` | ดูข้อ 3 | เจอตัวการ |

สองข้อแรกคือสมมติฐานที่ตั้งไว้ก่อน และ**ผิดทั้งคู่** — บันทึกไว้เพราะการไล่ที่ดี
คือการตัดสมมติฐานออกทีละข้อ ไม่ใช่การเดาถูกตั้งแต่แรก

---

## 3. หลักฐานชี้ขาด

`tcpdump` บน Internal-GW01 ยืนยันว่าเครื่องปลายทางตอบแล้ว:

```
14:47:40.675107 IP 172.23.10.35  > 172.23.31.176: ICMP echo request, seq 15957
14:47:40.675332 IP 172.23.31.176 > 172.23.10.35 : ICMP echo reply,   seq 15957
```

SmartConsole log บอกว่าใครฆ่ามัน:

```
Origin: External-GW01 | 172.23.31.176 → 172.23.10.35 | echo-reply   | Dropped
Origin: External-GW01 | 172.23.31.176 → 172.23.10.35 | TCP/5253     | Dropped
Origin: External-GW01 | 172.23.31.176 → 172.23.10.35 | TCP/25880    | Dropped
Origin: External-GW01 | 172.23.31.176 → 172.23.10.35 | dest-unreach | Dropped
```

**คอลัมน์ `Access Rule Name` ของทุกแถวที่ Dropped ว่างเปล่า** ไม่ใช่แม้แต่
`Cleanup rule` — แพ็กเก็ตไม่เคยไปถึงการ match rule มันถูกตัดที่ stateful
inspection ก่อนหน้านั้น

และในไฟล์เดียวกัน ขาไปถูกอนุญาตเรียบร้อย:

```
Origin: Internal-GW01 | 172.23.10.35 → 172.23.31.176 | https (TCP/443) | Accepted | Rule 1 Allow-Any
```

---

## 4. สาเหตุ: เส้นทางไม่สมมาตร

```
ขาไป : 172.23.10.35 → ICX6450 (ve31 172.23.31.254) → VLAN31 → 172.23.31.176
       ทั้งเส้น firewall ไม่เห็นแพ็กเก็ตเลย เพราะ core ส่งตรงใน VLAN เดียวกัน

ขากลับ: 172.23.31.176 → default route → 172.23.31.179 (External-Cluster VIP)
       cluster เห็นแพ็กเก็ตตอบของ connection ที่ตัวเองไม่เคยเห็น SYN
       → ไม่มีใน state table → drop
```

นี่ยังอธิบายด้วยว่าทำไม **.177 และ .178 ตอบได้ทั้งที่อยู่ subnet เดียวกัน** —
สองตัวนั้น *คือ* cluster เอง มันตอบจาก interface ตัวเองโดยตรง ไม่ต้อง forward
ผ่าน state table

---

## 5. ประเด็นสำหรับรายงานและเปเปอร์

### 5.1 Traffic Path ตอบถูก และผลลัพธ์จริงตรงข้าม

ถ้าถาม Traffic Path ว่า `172.23.10.35 → 172.23.31.176 tcp/443` จะได้:

> **Accept · exact**

ซึ่ง **ถูกต้องสมบูรณ์** — rule 2 `Admin-Access` มี `Internal-GW01` อยู่ใน
destination พร้อม https จริง ๆ และ Internal-FW ก็ Allow-Any จริง ๆ นโยบายอนุญาต
ทุกประการ

แต่ทราฟฟิกจริง **ไม่ผ่าน** เพราะสิ่งที่ฆ่ามันไม่ได้อยู่ในนโยบาย มันอยู่ใน
routing และ state table

นี่คือข้อจำกัดที่แอปประกาศไว้เองตั้งแต่ต้น ในหน้า Traffic Path และใน README:

> *"This is a configuration-based Access Control simulation. Identity Awareness,
> dynamic objects, time objects, implied rules, live gateway state, routing and
> kernel behavior can still make a live log differ."*

**เหตุการณ์นี้คือหลักฐานเชิงประจักษ์ของประโยคนั้น เก็บไว้ใช้ในหัวข้อข้อจำกัด**
ไม่ใช่ข้อบกพร่องที่ต้องซ่อน — เครื่องมือที่บอกข้อจำกัดตัวเองไว้ล่วงหน้าแล้ว
เจอเคสที่พิสูจน์ข้อจำกัดนั้นพอดี คือเครื่องมือที่ประกาศตัวเองอย่างซื่อสัตย์

### 5.2 finding "อ่านไม่ได้" คือสิ่งที่ทำให้ค้นพบ

ถ้าหน้า Gateway Health เลือกแสดงแค่ gateway ที่ตอบ แล้วเงียบเรื่องตัวที่ไม่ตอบ
รายงานจะ "เขียว" และไม่มีใครไปดู `.176` — ปัญหา asymmetric route จะยังอยู่
โดยไม่มีใครรู้

หลักการที่โค้ดยึดไว้คือ:

> *A gateway that did not answer produces no findings, which is not the same as
> producing none. Absence of a finding is not health.*

**ประโยคนี้คุ้มค่าที่จะอยู่ในเปเปอร์** เพราะมันคือรูปธรรมของข้อเสนอหลัก:
การแยก "ไม่รู้" ออกจาก "ไม่มีปัญหา"

### 5.3 ทำไม "เพิ่มกฎ Accept" ไม่ใช่คำตอบ

เพราะแพ็กเก็ตที่ถูก drop ไม่ได้ถูกประเมินโดย rulebase — log ยืนยันด้วยการที่
คอลัมน์ rule ว่าง การเพิ่มกฎจึงไม่มีผล และเป็นตัวอย่างที่ดีของสิ่งที่
policy analyzer **บอกไม่ได้** ไม่ว่าจะฉลาดแค่ไหน

---

## 6. การแก้ไข

**ทางที่เลือก** — ทำให้เส้นทางสมมาตร โดยไม่ให้ firewall ต้องเห็นทราฟฟิกนี้เลย:

```clish
set static-route 172.23.10.0/24 nexthop gateway address 172.23.31.254 on
save config
```

`172.23.31.254` คือ ve31 ของ ICX6450 ซึ่งเป็นเส้นที่ขาไปใช้อยู่แล้ว

**ทางที่ปฏิเสธ และเหตุผล:**

| ทางเลือก | ทำไมไม่เอา |
|---|---|
| `nexthop 172.23.31.179` | คือทางเดิมที่ default route ไปอยู่แล้ว ไม่เปลี่ยนอะไร |
| เพิ่มกฎ Accept ใน External-FW | แพ็กเก็ตไม่ถึง rulebase ตั้งแต่แรก |
| ปิด *Drop out of state packets* | ลดความปลอดภัยทั้ง gateway เพื่อแก้ปัญหา routing หนึ่งจุด |
| ปล่อยไว้ แล้วเอา .176 ออกจาก `GAIA_HOSTS` | ทำได้ และเครื่องมือจะเงียบลง — แต่ปัญหาจริงยังอยู่ |

**ผลกระทบที่ประเมินไว้:** route นี้แคบ แตะเฉพาะทราฟฟิกจาก `.176` ไปยัง
`172.23.10.0/24` ไม่แตะ default route, ไม่แตะ `192.168.10.0/24` และ
`192.168.20.0/24` (connected), และ encryption domain ของ VPN ใน rule 1 คือ
`10.130.56.0/24` ซึ่งเป็นคนละวง ถอนได้ด้วย `delete static-route 172.23.10.0/24`

---

## 7. ลำดับเวลา

| เวลา | เหตุการณ์ |
|---|---|
| 13:26 | Gateway Health รายงาน `.176` เป็น finding ระดับ high |
| 13:27 | Network Mapping เขียนใน limitations ว่าไม่ได้อ่าน routing จาก `.176` |
| ~14:00 | `Test-NetConnection` ยืนยัน timeout ทั้ง ping และ 443 |
| ~14:40 | `show route` / `show allowed-client all` ตัดสองสมมติฐานแรกออก |
| 14:47 | `tcpdump` พิสูจน์ว่า `.176` ตอบแล้ว |
| 14:48 | SmartConsole log ชี้ว่า External-GW01 drop ขากลับ โดยไม่มีชื่อ rule |
