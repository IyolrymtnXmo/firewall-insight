# Firewall Insight 4.42 patch — ใช้คู่กับ Report Paper v6

ปิดข้อ C001 (Implied Rules) และ C003 (ICMP code / source port / protocol signature / IPv6) จากผลตรวจรอบที่ 3
และเตรียมเครื่องมือสำหรับข้อ C002 (เทียบกับ `fw up_execute`) กับ C004 (commit / tag ที่อ้างอิงได้)

## 1. มีอะไรบ้าง

| ไฟล์ | เปลี่ยนอะไร |
|---|---|
| `app/implied.py` (ใหม่) | อ่าน Global Properties + รายการเกตเวย์ แล้วตัดสินว่ากฎโดยนัยอาจมีผลกับการเชื่อมต่อนั้นหรือไม่ (clear / possible / unread) |
| `app/traffic.py` | `trace_access_tree(..., implied=ctx)` ลดสถานะผลเมื่อกฎโดยนัยอาจมีผลหรืออ่านไม่ได้ |
| `app/api/traffic.py` | เส้นทางที่ UI และ Ask ใช้ ส่ง context ทุกครั้ง (แคชต่อเซสชัน) |
| `app/checkpoint.py` | เพิ่ม `show_global_properties()` — คำสั่งอ่าน `show-global-properties` |
| `app/resolver.py` | เก็บทั้ง IPv4 และ IPv6 ของวัตถุเดียวกัน · รู้จักเงื่อนไขเพิ่มของ service |
| `app/matching.py` | service ที่จำกัด source port / protocol signature / ICMP code / match expression → พอร์ตตรงได้แค่ "ไม่ทราบ" |
| `app/analyzer.py` | service ที่มีเงื่อนไขเพิ่มใช้เป็นกฎที่ครอบคลุมไม่ได้ (ยกเว้นเป็นวัตถุเดียวกัน) |
| `tools/acceptance.py` | อ่าน Global Properties แล้วส่ง context ให้ทุกกรณีทดสอบ บันทึกลง evidence |
| `tests/test_v442_implied.py`, `tests/test_v442_service_scope.py` | เทสต์ใหม่ 30 ข้อ |
| `tests/conftest.py` + เทสต์เดิม 6 ไฟล์ | เทสต์ 9 ข้อที่ล้มอยู่ในเครื่อง (ตั้งแต่ย้าย route ไปทำงานเบื้องหลังหลัง 4.39) อ่านผลจาก `/api/progress` แทน |
| `CHANGELOG.md` | เพิ่มรายการ 4.40, 4.41, 4.42 และคืนหัวข้อ 4.39 ที่ถูกเปลี่ยนเลขเป็น 4.41 |

## 2. นำเข้า (PowerShell)

```powershell
cd "A:\Co-Operation-NetpoleonTH\Project-Dev\Policy-Automation\Firewall-Insight-v4.7"
.\.venv\Scripts\Activate.ps1
mkdir experiments\v442_patch\backup_v441 -Force
robocopy app   experiments\v442_patch\backup_v441\app   analyzer.py checkpoint.py matching.py resolver.py traffic.py version.py
robocopy app\api experiments\v442_patch\backup_v441\app\api traffic.py
robocopy tests experiments\v442_patch\backup_v441\tests conftest.py test_v412_progress.py test_v423_route_overlay.py test_v425_snapshot_routes.py test_v426_compliance_routes.py test_v431_chrome.py test_v441_envelope.py
copy tools\acceptance.py experiments\v442_patch\backup_v441\
copy CHANGELOG.md        experiments\v442_patch\backup_v441\

robocopy experiments\v442_patch\app   app   /E
robocopy experiments\v442_patch\tests tests /E
robocopy experiments\v442_patch\tools tools /E
copy experiments\v442_patch\CHANGELOG.md CHANGELOG.md
pytest -q
```

ผลที่ควรได้: **1051 passed** (ตรวจใน cloud ด้วยโค้ดทั้งโฟลเดอร์ `app/`, `tests/`, `tools/` จากเครื่องคุณ และ dependency ตาม `requirements.txt`)
ก่อนแพตช์ โค้ดในเครื่อง (working tree) มี 1,021 ข้อ ล้ม 9 ข้อ

## 3. ต้องทำในแล็บ (ผมทำแทนไม่ได้)

1. **ยืนยันว่าอ่าน Global Properties ได้จริง**
   `python -m tools.acceptance --package External-FW` แล้วดูบรรทัด
   *Global Properties read for implied rules* และฟิลด์ `implied_rules` ใน `acceptance-report.json`
   ถ้าเซิร์ฟเวอร์ไม่รู้จักคำสั่งหรือบัญชีไม่มีสิทธิ์ โปรแกรมยังทำงานได้ แต่จะไม่ให้ผลยืนยันเลย — ให้จดไว้และแจ้งผม
   เพราะรูปแบบข้อมูลของ `show-global-properties` ผมเขียนตามเอกสาร Management API ยังไม่เคยเห็นของจริงจากแล็บ
2. **E5 เทียบกับเกตเวย์จริง** — `experiments\v442_patch\e5_up_execute\make_commands.py` สร้างคำสั่ง `fw up_execute`
   จากกรณีทดสอบเดิม ให้รันบนเกตเวย์ (expert mode) แล้วกรอกผลลง CSV จากนั้น `compare.py` จะสรุปตัวเลขที่ใส่ในตาราง E5 ของบทความ
3. **commit + tag** (ข้อ C004)
   ```powershell
   git add -A
   git commit -m "v4.42.0 - implied rules and object scope guards; 4.40/4.41 soundness fixes"
   git tag v4.42.0
   git push origin main --tags
   git rev-parse --short HEAD
   ```
   เลข commit ที่ได้ให้นำไปแทน `[COMMIT-4.42]` ในบทความ (ตอนนี้ commit ล่าสุดบน GitHub ยังเป็นของ 14 ก.ย. — รุ่น 4.40 และ 4.41 ยังไม่เคย commit)

## 4. ผลการทดลองที่ใช้ในบทความ (`experiments/`)

| การทดลอง | 4.41 | 4.42 |
|---|---|---|
| E2d กฎโดยนัย — สัดส่วนการเชื่อมต่อที่กฎโดยนัยอาจเกี่ยวข้อง 10 / 20 / 30% | W = 5.1 / 11.6 / 17.1% | W = 0 · A = 8.2 / 15.4 / 21.1% |
| E2e วัตถุที่มีเงื่อนไขเกินแบบจำลอง 10 / 20 / 30% ของกฎ | W = 5.9 / 11.2 / 16.1% | W = 0 · A = 7.9 / 15.3 / 22.2% |
| E1e คู่กฎที่ฝังไว้หลัง service ที่มีเงื่อนไขเพิ่ม (120 คู่จริง + 120 คู่ลวง) | precision 0.50 | precision 1.00 · recall 1.00 |

รันซ้ำ: `python e2d_implied.py <โฟลเดอร์ที่มี app/> <label>` และ `python e2e_scope.py <โฟลเดอร์ที่มี app/> <label>`
(ไฟล์ `gen.py`, `e1_anomaly.py`, `e2_tristate.py` อยู่ในโฟลเดอร์เดียวกันแล้ว) · E1, E2, E2b, E2c รันซ้ำบน 4.42 ได้ตัวเลขเดิมทุกค่า
