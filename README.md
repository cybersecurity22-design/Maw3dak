# Maw3dak Secure

نسخة Backend حقيقية للموقع بدل تخزين البيانات الحساسة في localStorage.

## الأمان المضاف
- كلمات مرور الأدمن وأصحاب الصالونات مخزنة كـ bcrypt hashes.
- جلسات تسجيل دخول HttpOnly + SameSite cookies.
- قاعدة بيانات SQLite على الخادم.
- بيانات البنك لا تُرسل للواجهة العامة.
- Helmet security headers + rate limiting على تسجيل الدخول وAPI.
- روابط الدفع يجب أن تكون HTTPS ولا يتم تخزين رقم البطاقة أو CVV في الموقع.

## تشغيل محلي
1. ثبّت Node.js 20 أو أحدث.
2. عيّن المتغيرات:
   - `ADMIN_PASSWORD` كلمة مرور أولية من 12 حرفاً على الأقل.
   - `SESSION_SECRET` قيمة عشوائية طويلة.
3. شغّل `npm install` ثم `npm start`.

## Render
- ارفع جميع الملفات إلى مستودع GitHub.
- في Render اختر New > Web Service واربط المستودع.
- Build Command: `npm install`
- Start Command: `npm start`
- أضف Environment Variables: `ADMIN_PASSWORD` و `SESSION_SECRET`.
- إذا أردت بقاء قاعدة SQLite بعد إعادة النشر، استخدم Persistent Disk واربط مجلد `data` بخطة تدعم ذلك، أو انقل قاعدة البيانات إلى PostgreSQL مُدارة.
