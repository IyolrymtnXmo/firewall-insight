# E4 — ทดสอบกับห้องปฏิบัติการจริงด้วยนโยบายทดสอบที่รู้คำตอบล่วงหน้า

1. ตั้งบัญชีที่เขียนได้ (เฉพาะสคริปต์สร้างนโยบาย — Firewall Insight ยังใช้บัญชีอ่านอย่างเดียวใน .env ตามเดิม)
   PowerShell ที่ root ของ repo:
   $env:SEED_USER="<admin ของแล็บ>"; $env:SEED_PASSWORD="<รหัส>"
2. สร้าง FIT-P1, FIT-P2, FIT-P3 (ไม่ install ลงเกตเวย์ ไม่กระทบทราฟฟิก):
   .venv\Scripts\python experiments\lab_profiles\seed_lab_profiles.py
3. ประเมินผลผ่าน Management API จริงด้วย client อ่านอย่างเดียวของเครื่องมือ:
   .venv\Scripts\python experiments\lab_profiles\eval_lab_profiles.py
   -> experiments\lab_profiles\results_lab.json
4. ลบทิ้งหลังใช้เสร็จ (ไม่บังคับ):
   .venv\Scripts\python experiments\lab_profiles\seed_lab_profiles.py --delete
