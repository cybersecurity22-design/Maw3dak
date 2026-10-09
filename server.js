'use strict';
const path = require('path');
const fs = require('fs');
const express = require('express');
const helmet = require('helmet');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const { rateLimit } = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 10000;
const dataDir = path.join(__dirname, 'data');
fs.mkdirSync(dataDir, { recursive: true });
const db = new Database(path.join(dataDir, 'maw3dak.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS admins (id INTEGER PRIMARY KEY, password_hash TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY CHECK(id=1), brand_title TEXT NOT NULL, brand_subtitle TEXT NOT NULL, hero_title TEXT NOT NULL, hero_text TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS salons (id TEXT PRIMARY KEY, name TEXT NOT NULL, governorate TEXT NOT NULL, owner_phone TEXT NOT NULL, username TEXT NOT NULL UNIQUE COLLATE NOCASE, password_hash TEXT NOT NULL, subscription TEXT NOT NULL DEFAULT 'pending', active INTEGER NOT NULL DEFAULT 1, plan_id TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS plans (id TEXT PRIMARY KEY, name TEXT NOT NULL, price REAL NOT NULL, days INTEGER NOT NULL, payment_link TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS bank_settings (id INTEGER PRIMARY KEY CHECK(id=1), bank_name TEXT NOT NULL DEFAULT '', holder TEXT NOT NULL DEFAULT '', iban TEXT NOT NULL DEFAULT '', account_number TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS bookings (id TEXT PRIMARY KEY, salon_id TEXT NOT NULL, client_name TEXT NOT NULL, client_phone TEXT NOT NULL, book_time TEXT NOT NULL, created_at TEXT NOT NULL, FOREIGN KEY(salon_id) REFERENCES salons(id) ON DELETE CASCADE);
`);

const now = () => new Date().toISOString();
if (!db.prepare('SELECT 1 FROM settings WHERE id=1').get()) {
  db.prepare('INSERT INTO settings VALUES (1,?,?,?,?)').run('مواعيدي لصالونات الرجال','احجز موعدك في صالون رجال بسهولة','احجز موعدك في أفضل صالونات الرجال','ابحث عن صالون رجال باسم الصالون أو المحافظة واحجز موعدك بسهولة.');
}
if (!db.prepare('SELECT 1 FROM bank_settings WHERE id=1').get()) db.prepare('INSERT INTO bank_settings(id) VALUES(1)').run();
if (!db.prepare('SELECT 1 FROM plans LIMIT 1').get()) {
  const ins=db.prepare('INSERT INTO plans(id,name,price,days,payment_link) VALUES(?,?,?,?,?)');
  ins.run('monthly','شهري',15,30,''); ins.run('yearly','سنوي',70,365,'');
}
const adminPassword = process.env.ADMIN_PASSWORD;
if (!db.prepare('SELECT 1 FROM admins WHERE id=1').get()) {
  if (!adminPassword || adminPassword.length < 12) {
    console.error('ADMIN_PASSWORD environment variable is required and must be at least 12 characters.');
    process.exit(1);
  }
  db.prepare('INSERT INTO admins(id,password_hash,updated_at) VALUES(1,?,?)').run(bcrypt.hashSync(adminPassword,12), now());
}

app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc:["'self'"], scriptSrc:["'self'","https://cdn.tailwindcss.com"], styleSrc:["'self'","'unsafe-inline'","https://fonts.googleapis.com"], fontSrc:["'self'","https://fonts.gstatic.com"], imgSrc:["'self'","data:","https:"], connectSrc:["'self'"], frameAncestors:["'none'"] }}}));
app.use(express.json({limit:'50kb'}));
app.use(express.urlencoded({extended:false,limit:'50kb'}));
app.use(session({
  store: new SQLiteStore({ db: 'sessions.db', dir: dataDir }),
  name: 'maw3dak.sid',
  secret: process.env.SESSION_SECRET || 'dev-only-change-me',
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: { httpOnly:true, secure: process.env.NODE_ENV === 'production', sameSite:'lax', maxAge: 1000*60*60*8 }
}));

const loginLimiter = rateLimit({windowMs:15*60*1000, limit:20, standardHeaders:'draft-8', legacyHeaders:false});
const apiLimiter = rateLimit({windowMs:60*1000, limit:120, standardHeaders:'draft-8', legacyHeaders:false});
app.use('/api', apiLimiter);

const GOVS=['عمان','العاصمة','الزرقاء','إربد','البلقاء','المفرق','جرش','عجلون','مادبا','الكرك','الطفيلة','معان','العقبة'];
const clean = (v,max=120)=>String(v??'').trim().slice(0,max);
const validPhone = v=>/^[0-9+ -]{8,16}$/.test(v);
const validHttps = v=>{ if(!v) return true; try{return new URL(v).protocol==='https:'}catch{return false} };
function auth(role){ return (req,res,next)=> req.session?.role===role ? next() : res.status(401).json({error:'غير مصرح'}); }
function csrfGuard(req,res,next){
  if(['GET','HEAD','OPTIONS'].includes(req.method)) return next();
  const origin=req.get('origin');
  if(origin){ try{ if(new URL(origin).host!==req.get('host')) return res.status(403).json({error:'طلب مرفوض'}); }catch{return res.status(403).json({error:'طلب مرفوض'});} }
  next();
}
app.use('/api', csrfGuard);

app.get('/api/public', (req,res)=>{
  const s=db.prepare('SELECT brand_title brandTitle, brand_subtitle brandSubtitle, hero_title heroTitle, hero_text heroText FROM settings WHERE id=1').get();
  const plans=db.prepare('SELECT id,name,price,days,payment_link paymentLink FROM plans ORDER BY rowid').all();
  const salons=db.prepare("SELECT id,name,governorate FROM salons WHERE active=1 AND subscription='active' ORDER BY created_at DESC").all();
  res.json({settings:s,plans,salons,governorates:GOVS.filter(x=>x!=='العاصمة')});
});
app.post('/api/bookings',(req,res)=>{
  const salonId=clean(req.body.salonId,80), clientName=clean(req.body.clientName,80), clientPhone=clean(req.body.clientPhone,16), bookTime=clean(req.body.bookTime,40);
  const salon=db.prepare("SELECT id FROM salons WHERE id=? AND active=1 AND subscription='active'").get(salonId);
  if(!salon || !clientName || !validPhone(clientPhone) || !bookTime) return res.status(400).json({error:'بيانات الحجز غير صحيحة'});
  const dt=new Date(bookTime); if(Number.isNaN(dt.getTime()) || dt.getTime()<Date.now()-60000) return res.status(400).json({error:'اختر موعداً صحيحاً'});
  db.prepare('INSERT INTO bookings VALUES(?,?,?,?,?,?)').run('b_'+Date.now()+'_'+Math.random().toString(36).slice(2,8),salonId,clientName,clientPhone,dt.toISOString(),now());
  res.status(201).json({ok:true});
});
app.post('/api/salons/register', async (req,res)=>{
  const name=clean(req.body.name,100), governorate=clean(req.body.governorate,30), ownerPhone=clean(req.body.ownerPhone,16), username=clean(req.body.username,30), password=String(req.body.password||'');
  if(!name||!GOVS.includes(governorate)||!validPhone(ownerPhone)||!/^[A-Za-z0-9_.-]{4,30}$/.test(username)||password.length<10) return res.status(400).json({error:'تحقق من البيانات وكلمة المرور (10 أحرف على الأقل)'});
  if(db.prepare('SELECT 1 FROM salons WHERE username=? COLLATE NOCASE').get(username)) return res.status(409).json({error:'اسم المستخدم مستخدم مسبقاً'});
  const id='s_'+Date.now()+'_'+Math.random().toString(36).slice(2,8);
  db.prepare('INSERT INTO salons(id,name,governorate,owner_phone,username,password_hash,created_at) VALUES(?,?,?,?,?,?,?)').run(id,name,governorate,ownerPhone,username,await bcrypt.hash(password,12),now());
  req.session.role='salon'; req.session.salonId=id; res.status(201).json({ok:true});
});
app.post('/api/salons/login', loginLimiter, async (req,res)=>{
  const username=clean(req.body.username,30), password=String(req.body.password||'');
  const s=db.prepare('SELECT * FROM salons WHERE username=? COLLATE NOCASE').get(username);
  if(!s || !s.active || !(await bcrypt.compare(password,s.password_hash))) return res.status(401).json({error:'بيانات الدخول غير صحيحة'});
  req.session.regenerate(err=>{ if(err) return res.status(500).json({error:'تعذر تسجيل الدخول'}); req.session.role='salon'; req.session.salonId=s.id; res.json({ok:true}); });
});
app.get('/api/salons/me',auth('salon'),(req,res)=>{
  const s=db.prepare('SELECT id,name,governorate,owner_phone ownerPhone,username,subscription,plan_id planId FROM salons WHERE id=?').get(req.session.salonId);
  if(!s) return res.status(404).json({error:'الحساب غير موجود'});
  const bookings=db.prepare('SELECT id,client_name clientName,client_phone clientPhone,book_time bookTime FROM bookings WHERE salon_id=? ORDER BY book_time DESC').all(s.id);
  res.json({salon:s,bookings});
});
app.post('/api/salons/logout',auth('salon'),(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.post('/api/salons/select-plan',auth('salon'),(req,res)=>{
  const id=clean(req.body.planId,80); const p=db.prepare('SELECT * FROM plans WHERE id=?').get(id); if(!p)return res.status(404).json({error:'الخطة غير موجودة'});
  db.prepare("UPDATE salons SET subscription='payment_pending',plan_id=? WHERE id=?").run(id,req.session.salonId);
  res.json({paymentLink:p.payment_link||'',plan:{id:p.id,name:p.name,price:p.price,days:p.days}});
});

app.post('/api/admin/login', loginLimiter, async (req,res)=>{
  const password=String(req.body.password||''); const a=db.prepare('SELECT password_hash FROM admins WHERE id=1').get();
  if(!a || !(await bcrypt.compare(password,a.password_hash))) return res.status(401).json({error:'كلمة مرور الإدارة غير صحيحة'});
  req.session.regenerate(err=>{if(err)return res.status(500).json({error:'تعذر تسجيل الدخول'});req.session.role='admin';res.json({ok:true});});
});
app.post('/api/admin/logout',auth('admin'),(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get('/api/admin/data',auth('admin'),(req,res)=>{
  const settings=db.prepare('SELECT brand_title brandTitle,brand_subtitle brandSubtitle,hero_title heroTitle,hero_text heroText FROM settings WHERE id=1').get();
  const bank=db.prepare('SELECT bank_name bankName,holder,iban,account_number accountNumber FROM bank_settings WHERE id=1').get();
  const plans=db.prepare('SELECT id,name,price,days,payment_link paymentLink FROM plans ORDER BY rowid').all();
  const salons=db.prepare('SELECT id,name,governorate,owner_phone ownerPhone,username,subscription,active,plan_id planId,created_at createdAt FROM salons ORDER BY created_at DESC').all();
  res.json({settings,bank,plans,salons});
});
app.put('/api/admin/settings',auth('admin'),(req,res)=>{
  const a=['brandTitle','brandSubtitle','heroTitle','heroText'].map(k=>clean(req.body[k],220)); if(a.some(x=>!x))return res.status(400).json({error:'جميع الحقول مطلوبة'});
  db.prepare('UPDATE settings SET brand_title=?,brand_subtitle=?,hero_title=?,hero_text=? WHERE id=1').run(...a);res.json({ok:true});
});
app.put('/api/admin/bank',auth('admin'),(req,res)=>{
  const bankName=clean(req.body.bankName,100),holder=clean(req.body.holder,120),iban=clean(req.body.iban,40).replace(/\s+/g,'').toUpperCase(),accountNumber=clean(req.body.accountNumber,50);
  if(iban&&!/^[A-Z]{2}[0-9A-Z]{13,32}$/.test(iban))return res.status(400).json({error:'صيغة IBAN غير صحيحة'});
  db.prepare('UPDATE bank_settings SET bank_name=?,holder=?,iban=?,account_number=? WHERE id=1').run(bankName,holder,iban,accountNumber);res.json({ok:true});
});
app.post('/api/admin/plans',auth('admin'),(req,res)=>{
  const name=clean(req.body.name,100),price=Number(req.body.price),days=Number(req.body.days),paymentLink=clean(req.body.paymentLink,500); if(!name||!Number.isFinite(price)||price<0||!Number.isInteger(days)||days<1||!validHttps(paymentLink))return res.status(400).json({error:'بيانات الخطة غير صحيحة'});
  db.prepare('INSERT INTO plans VALUES(?,?,?,?,?)').run('plan_'+Date.now(),name,price,days,paymentLink);res.status(201).json({ok:true});
});
app.delete('/api/admin/plans/:id',auth('admin'),(req,res)=>{ if(db.prepare('SELECT COUNT(*) c FROM plans').get().c<=1)return res.status(400).json({error:'يجب إبقاء خطة واحدة على الأقل'});db.prepare('DELETE FROM plans WHERE id=?').run(req.params.id);res.json({ok:true}); });
app.put('/api/admin/salons/:id',auth('admin'),(req,res)=>{
  const name=clean(req.body.name,100),governorate=clean(req.body.governorate,30),ownerPhone=clean(req.body.ownerPhone,16); if(!name||!GOVS.includes(governorate)||!validPhone(ownerPhone))return res.status(400).json({error:'بيانات الصالون غير صحيحة'});
  db.prepare('UPDATE salons SET name=?,governorate=?,owner_phone=? WHERE id=?').run(name,governorate,ownerPhone,req.params.id);res.json({ok:true});
});
app.post('/api/admin/salons/:id/toggle',auth('admin'),(req,res)=>{const s=db.prepare('SELECT active FROM salons WHERE id=?').get(req.params.id);if(!s)return res.status(404).json({error:'غير موجود'});db.prepare('UPDATE salons SET active=? WHERE id=?').run(s.active?0:1,req.params.id);res.json({ok:true});});
app.post('/api/admin/salons/:id/subscription',auth('admin'),(req,res)=>{const s=db.prepare('SELECT subscription FROM salons WHERE id=?').get(req.params.id);if(!s)return res.status(404).json({error:'غير موجود'});db.prepare('UPDATE salons SET subscription=? WHERE id=?').run(s.subscription==='active'?'pending':'active',req.params.id);res.json({ok:true});});
app.delete('/api/admin/salons/:id',auth('admin'),(req,res)=>{db.prepare('DELETE FROM salons WHERE id=?').run(req.params.id);res.json({ok:true});});
app.put('/api/admin/password',auth('admin'),async(req,res)=>{const p=String(req.body.password||'');if(p.length<12)return res.status(400).json({error:'استخدم 12 حرفاً على الأقل'});db.prepare('UPDATE admins SET password_hash=?,updated_at=? WHERE id=1').run(await bcrypt.hash(p,12),now());res.json({ok:true});});

app.use(express.static(path.join(__dirname,'public'),{extensions:['html']}));
app.get('/health',(req,res)=>res.json({ok:true}));
app.use((err,req,res,next)=>{console.error(err);res.status(500).json({error:'خطأ داخلي في الخادم'});});
app.listen(PORT,'0.0.0.0',()=>console.log(`Maw3dak running on ${PORT}`));
