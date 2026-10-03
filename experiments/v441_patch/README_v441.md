# Firewall Insight 4.41 patch (รวม 4.40) — ใช้คู่กับ Report Paper v5

บทความ v5 อ้างพฤติกรรมของรุ่น 4.40 และ 4.41 **ต้องนำแพตช์นี้เข้า app/ ก่อนส่ง/ก่อนเดโม**
(ตอนนี้ `app/traffic.py` บนเครื่องยังเป็น 4.39)

## มีอะไรบ้าง
| ไฟล์ | เปลี่ยนอะไร |
|---|---|
| `app/traffic.py` | 4.40: Inline Layer ไม่เปลี่ยนเส้นทางที่ไม่แน่นอนให้กลายเป็นผลแน่นอน · 4.41: เรียก `envelope_state()` ทุกกฎ, หลาย Ordered Layer → ไม่ให้ผล final, แนบ `scope_notes` (implied rules) และ `gateway_final` |
| `app/envelope.py` (ใหม่) | ตรวจ Time / Content (+content-negate) / Install On ว่าเป็นค่าเริ่มต้นหรือไม่ |
| `app/analyzer.py` | กฎที่ถูกจำกัดด้วย Time/Content/Install On ไม่ถูกใช้เป็นกฎที่ "ครอบคลุม" ในการตรวจ shadowing |
| `tests/test_v440_inline_soundness.py` | 5 เทสต์ (Inline Layer) |
| `tests/test_v441_envelope.py` | 9 เทสต์ (envelope) |

## นำเข้า (PowerShell)
```powershell
cd "A:\Co-Operation-NetpoleonTH\Project-Dev\Policy-Automation\Firewall-Insight-v4.7"
mkdir experiments\v441_patch\backup_v439 -Force
copy app\traffic.py, app\analyzer.py experiments\v441_patch\backup_v439\
copy experiments\v441_patch\app\*.py app\
copy experiments\v441_patch\tests\*.py tests\
pytest -q
```
แล้วแก้ `app/version.py` เป็น `4.41.0` + เขียน CHANGELOG
ถ้าเทสต์โครงสร้าง/เอกสาร (เช่น test_v413_structure, test_v438_docs) ฟ้องเรื่องโมดูลใหม่ `envelope.py`
ให้เพิ่มชื่อโมดูลในรายการที่เทสต์นั้นอ้าง (README) — ตัวโค้ดไม่ได้เพิ่ม route หรือคำสั่ง API ใด ๆ

ตรวจในเครื่อง cloud แล้ว: เทสต์เดิมที่เกี่ยวกับ traffic, inline และ analyzer 54 ข้อ + เทสต์ใหม่ 14 ข้อ ผ่านทั้งหมด
(ยังไม่ได้รันทั้งชุด 1,007 ข้อ เพราะ conftest ต้องใช้โมดูลบนเครื่องคุณ)

## ผลการทดลองที่ใช้ในบทความ
- E2c (`e2_envelope_*.json`): กฎที่ถูกจำกัด 10/20/30% → v4.40 W = 3.7 / 8.1 / 12.3% · v4.41 W = 0 (A = 7.2 / 15.6 / 25.0%)
- E1c: shadowing precision v4.40 = 0.78 (FP 59) → v4.41 = 1.00, recall 1.00
- E3 (`e3_repeat_results.json`): warm-up 1 + วัดซ้ำ 5 (3 สำหรับ 2,363 กฎ) → 593 กฎ 4.6 s (4.4–4.8), 1,183 กฎ 18.1 s (17.9–18.8), 2,363 กฎ 71.5 s (70.6–72.9)

รันซ้ำ: `python e2_envelope.py <โฟลเดอร์ที่มี app/> <label>` (ต้องมี gen.py, e1_anomaly.py, e2_tristate.py จาก experiments\inline_soundness)
