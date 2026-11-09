# CardFlow Members + Admin (Cloudflare Pages + D1)

## มีอะไรบ้าง
- หน้าแนะนำบริการ: `/`
- สมัครสมาชิก / เข้าสู่ระบบ / หน้าแอดมิน: `/app.html`
- แอดมินเพิ่มบัตร (ชื่อบัตร, issuer, เลขท้าย 4 หลัก, สกุลเงิน, หมายเหตุ) ให้สมาชิก
- แอดมินบันทึกรายการใช้จ่าย, เติมเงิน, คืนเงิน, ปรับยอด และเปลี่ยนสถานะบัตร/สมาชิก
- สมาชิกดูบัตรและรายการของตนเองเท่านั้น
- ใช้ D1 เก็บข้อมูล, PBKDF2 สำหรับรหัสผ่าน, HTTP-only cookie, ตรวจสอบสิทธิ์ที่ API

## วิธีติดตั้งบน Cloudflare Pages (สำคัญ)
1. แตก ZIP แล้วนำไฟล์ทั้งหมด **ภายในโฟลเดอร์** `cardflow-full/` ขึ้น GitHub Repository (ควรใช้ repo ส่วนตัว) ไม่ควรอัปโหลดไฟล์ ZIP ตรงแบบ static-only เพราะ Pages Functions และ D1 ต้องได้รับการ deploy ด้วย
2. Cloudflare Dashboard > Workers & Pages > Create > Pages > Connect to Git > เลือก repo, Framework preset `None`, Build command เว้นว่าง, Build output directory `.`
3. Cloudflare Dashboard > Storage & Databases > D1 > Create database ชื่อ `cardflow-db`
4. เปิด D1 database > Console > คัดลอก SQL ทั้งหมดจาก `migrations/0001_init.sql` ไปวางแล้ว Execute (ครั้งแรกเท่านั้น)
5. Pages project > Settings > Bindings > Add > D1 database: Variable name `DB`, เลือก `cardflow-db` แล้ว Deploy ใหม่
6. Pages project > Settings > Variables and Secrets > Add Secret: `ADMIN_SETUP_TOKEN` เป็นรหัสยาวแบบสุ่ม (อย่างน้อย 32 ตัวอักษร) แล้ว Deploy ใหม่ **ห้ามฝัง secret ใน HTML หรือ GitHub**
7. เปิด `https://YOUR-PROJECT.pages.dev/app.html#setup` ระบุชื่อ อีเมล รหัสผ่าน 12+ ตัว และรหัส `ADMIN_SETUP_TOKEN` เพื่อสร้างแอดมินคนแรก
8. **ลบ Secret `ADMIN_SETUP_TOKEN` หลังสร้างแอดมินเสร็จ** แล้ว Deploy ใหม่ (ระบบ endpoint นี้จะถูกปิด)
9. สมาชิกสมัครได้ที่ `/app.html#register`, แอดมินเปิด `/app.html` เพื่อจัดการข้อมูล

**หมายเหตุการ deploy:** การใช้ Git integration ที่รองรับ Pages Functions เป็นวิธีที่แนะนำ หลีกเลี่ยงการนำ ZIP ขึ้น Pages แบบ Drag & Drop โดยไม่ตรวจว่า Functions deploy มาด้วยหรือไม่ หาก API `/api/auth/me` ตอบ 404 ให้กลับไปตรวจการ deploy และ binding.

## ข้อจำกัดและความปลอดภัยก่อนใช้งานจริง
- ระบบนี้คือ **ทะเบียนบัตรและบัญชีรายการที่แอดมินกรอกเอง** ไม่ได้เชื่อม API ผู้ออกบัตร ไม่ได้ตรวจสอบการชำระเงิน ไม่ได้ออกบัตรจริง และไม่ใช่กระเป๋าเงิน
- **ห้ามเก็บเลขบัตรเต็ม, CVV/CVC, PIN, วันหมดอายุ, รหัส OTP หรือข้อมูลยืนยันตัวตนที่ละเอียดอ่อน** ในฟิลด์หมายเหตุ
- ยอดใช้จ่ายเป็นผลรวมของรายการที่บันทึก ไม่ใช่ยอดวงเงินคงเหลือที่ยืนยันจากธนาคาร; แต่ละสกุลเงินแยกกัน ไม่รวมเป็นยอดเดียว
- ไม่มีระบบลืมรหัสผ่านผ่านอีเมล / MFA / rate limiting / WAF; สำหรับใช้งานจริงกับลูกค้าควรเพิ่ม Turnstile, rate limits, email verification, MFA สำหรับ admin, ระบบสำรองฐานข้อมูลและนโยบายข้อมูลส่วนบุคคลก่อนเปิดใช้งาน
- เปิดการป้องกัน Cloudflare WAF / rate limiting ที่ `/api/auth/login`, `/api/auth/register`, `/api/auth/bootstrap` ก่อนใช้งานสาธารณะ
- Password hashing ใช้ Web Crypto PBKDF2-SHA256; ไม่ใช่ Argon2. ระบบ session หมดอายุหลัง 7 วัน และ cookie เป็น Secure, HttpOnly, SameSite=Lax
- รายการเดิมไม่มีปุ่มลบ เพื่อคงประวัติ; ควรวางระบบแก้ไขแบบ audit ก่อนให้บริการจริง
- ค่าธรรมเนียมที่หน้า Landing เป็นข้อมูลตัวอย่าง ไม่ใช่ราคาได้รับการยืนยัน

## โครงสร้าง
`index.html` หน้าแรก, `app.html` ระบบสมาชิกและแอดมิน, `functions/api/[[path]].js` API, `migrations/0001_init.sql` ตาราง D1, `wrangler.toml.example` ตัวอย่าง config
