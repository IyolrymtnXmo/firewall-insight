# E2b — Inline Layer soundness (ผลจากการแก้ตามผลตรวจ C001)

## สิ่งที่พบ
การทดลอง E2b (นโยบายที่มี Inline Layer + แบบจำลองเกตเวย์ R82 ที่รู้ค่าจริง) พบว่า
`trace_access_tree` รุ่น 4.39 ให้ **ผลยืนยัน (exact) ที่ผิด 5.4–8.4%** ใน 3 กรณี

1. กฎที่ไม่ทราบ (unknown) อยู่ก่อนกฎแม่ Inline Layer ที่ตรงแน่นอน → 4.39 ตอบ exact
2. กฎแม่ตรงแน่นอน แต่ในชั้นย่อยมีกฎ unknown ก่อนกฎที่ตรง → 4.39 ตอบ "No final matching rule" แบบ exact
3. กฎแม่เป็น unknown และไม่มีกฎย่อยตรง → 4.39 ข้ามไปยืนยันกฎถัดไป (มักเป็น Cleanup)
   ทั้งที่ถ้ากฎแม่ตรงจริง implicit cleanup ของชั้นย่อยจะเป็นผู้ตัดสิน

ชุดทดสอบเดิม 1,007 กรณีไม่จับกรณีเหล่านี้ เพราะ E2 เดิมใช้นโยบายชั้นเดียว

## ผล (30 ชุด × 400 การเชื่อมต่อ ต่อระดับ, seed 11)
| unknown | v4.39 W / A | v4.40 W / A | v4.40 + Kleene negation W / A |
|---|---|---|---|
| 10% | 5.4% / 26.3% | 0.0% / 49.0% | 0.0% / 33.7% |
| 20% | 6.6% / 56.5% | 0.0% / 79.9% | 0.0% / 66.4% |
| 30% | 8.4% / 68.8% | 0.0% / 90.9% | 0.0% / 79.7% |

E2 เดิม (ชั้นเดียว) ให้ผลเหมือนเดิมทุกตัวเลขกับ v4.40

## วิธีนำแก้เข้าโปรเจกต์ (ยังไม่ได้แก้ไฟล์ใน app/ ให้ — ทำเองแล้วรันเทสต์)
```powershell
cd "A:\Co-Operation-NetpoleonTH\Project-Dev\Policy-Automation\Firewall-Insight-v4.7"
copy app\traffic.py experiments\inline_soundness\traffic_v439_backup.py
copy experiments\inline_soundness\traffic.py app\traffic.py
copy experiments\inline_soundness\test_v440_inline_soundness.py tests\
pytest -q
```
แล้ว bump `app/version.py` เป็น 4.40.0 + เขียน CHANGELOG
(ดู diff ที่ `traffic_v440.diff` — แก้เฉพาะ branch Inline Layer ใน `recurse()`)

ตรวจในเครื่อง cloud แล้ว: เทสต์ที่เกี่ยวกับ traffic/inline 53 ข้อเดิม + 5 ข้อใหม่ผ่าน
(ยังไม่ได้รันทั้งชุด 1,007 ข้อ เพราะต้องใช้ conftest/โมดูลที่อยู่บนเครื่องคุณ)

## รันซ้ำ
ต้องมี `gen.py`, `e1_anomaly.py`, `e2_tristate.py`, `e2_neg.py` ในโฟลเดอร์เดียวกัน และ `app/` อยู่ใน path
```
python e2_inline.py app.traffic        # หลังนำแก้เข้า app/ แล้ว
python e2_inline_neg.py                # what-if: Kleene negation (แก้ import เป็น app.traffic)
```
