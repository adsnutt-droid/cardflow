const enc = new TextEncoder();
const json=(obj,status=200,headers={})=>new Response(JSON.stringify(obj),{status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store',...headers}});
const bad=(message,status=400)=>json({error:message},status);
const hex=a=>Array.from(new Uint8Array(a)).map(x=>x.toString(16).padStart(2,'0')).join('');
const rand=n=>{let a=new Uint8Array(n);crypto.getRandomValues(a);return hex(a)};
const digest=async s=>hex(await crypto.subtle.digest('SHA-256',enc.encode(s)));
// Cloudflare Workers caps PBKDF2 at 100,000 iterations per deriveBits call.
// This versioned, multi-stage KDF stays within that limit while retaining 210,000
// total rounds. Existing schema remains unchanged (users.iterations = 210000).
const passhash=async(password,salt,iterations=210000)=>{
  const rawSalt=Uint8Array.from(salt.match(/../g).map(x=>parseInt(x,16)));
  let material=enc.encode(password);
  let remaining=iterations;
  let stage=0;
  if(!Number.isInteger(iterations)||iterations<1||iterations>1000000)throw Error('Invalid password hashing work factor');
  while(remaining>0){
    const count=Math.min(100000,remaining);
    const stageSalt=new Uint8Array(rawSalt.length+4);
    stageSalt.set(rawSalt);
    new DataView(stageSalt.buffer).setUint32(rawSalt.length,stage,false);
    const key=await crypto.subtle.importKey('raw',material,'PBKDF2',false,['deriveBits']);
    material=new Uint8Array(await crypto.subtle.deriveBits({name:'PBKDF2',salt:stageSalt,iterations:count,hash:'SHA-256'},key,256));
    remaining-=count;
    stage++;
  }
  return hex(material);
};
const cookie=(token,maxage)=>`cf_session=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxage}`;
const safeUser=u=>({id:u.id,email:u.email,full_name:u.full_name,role:u.role,status:u.status,created_at:u.created_at});
const norm=s=>String(s??'').trim();
const limit=(s,max=200)=>norm(s).slice(0,max);
const validMoney=v=>Number.isFinite(Number(v))&&Number(v)>=0&&Number(v)<=100000000&&Math.round(Number(v)*100)===Number(v)*100;
async function auth(req,db){const value=req.headers.get('cookie')?.match(/(?:^|;\s*)cf_session=([a-f0-9]{64})/)?.[1];if(!value)return null;return db.prepare("SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>datetime('now') AND u.status='active'").bind(await digest(value)).first()}
async function createSession(db,u){const token=rand(32);await db.prepare("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,datetime('now','+7 days'))").bind(await digest(token),u.id).run();return json({user:safeUser(u)},200,{'set-cookie':cookie(token,604800)})}
function originAllowed(req){let origin=req.headers.get('origin');if(!origin)return false;try{return new URL(origin).origin===new URL(req.url).origin}catch{return false}}
async function body(req){const s=req.headers.get('content-length');if(s&&Number(s)>16000)throw Error('ข้อมูลเกินขนาด');const text=await req.text();if(text.length>16000)throw Error('ข้อมูลเกินขนาด');return JSON.parse(text)}
const record=(db,actor,action,id)=>db.prepare('INSERT INTO audit_logs(id,actor_id,action,entity_id) VALUES(?,?,?,?)').bind(crypto.randomUUID(),actor,action,id).run();
export async function onRequest({request,env,params}){
 const db=env.DB;if(!db)return bad('ยังไม่ได้ผูกฐานข้อมูล D1 (DB)',503);
 const method=request.method;const path='/'+(params.path||[]).join('/');
 try{
  if(method!=='GET'&&!originAllowed(request))return bad('คำขอจาก origin ที่ไม่อนุญาต',403);
  const data=method==='GET'?{}:await body(request);
  if(path==='/auth/register'&&method==='POST'){
    const email=norm(data.email).toLowerCase(),name=limit(data.full_name,100),password=String(data.password||'');
    if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||email.length>200||name.length<2||password.length<12||password.length>128)return bad('ตรวจสอบชื่อ อีเมล และรหัสผ่านอย่างน้อย 12 ตัวอักษร');
    if(await db.prepare('SELECT id FROM users WHERE email=?').bind(email).first())return bad('อีเมลนี้ถูกลงทะเบียนแล้ว',409);
    const salt=rand(16),id=crypto.randomUUID(),hash=await passhash(password,salt);
    try{await db.prepare('INSERT INTO users(id,email,full_name,password_salt,password_hash,role) VALUES(?,?,?,?,?,?)').bind(id,email,name,salt,hash,'member').run()}catch{return bad('ไม่สามารถสมัครได้ กรุณาตรวจสอบข้อมูล',409)}
    return createSession(db,{id,email,full_name:name,role:'member',status:'active'});
  }
  if(path==='/auth/login'&&method==='POST'){
    const email=norm(data.email).toLowerCase(),password=String(data.password||'');
    const u=await db.prepare('SELECT * FROM users WHERE email=?').bind(email).first();
    const salt=u?.password_salt||'0123456789abcdef0123456789abcdef';const iterations=u?.iterations||210000;
    const hash=await passhash(password.slice(0,128),salt,iterations);
    if(!u||u.status!=='active'||hash!==u.password_hash)return bad('อีเมลหรือรหัสผ่านไม่ถูกต้อง',401);
    return createSession(db,u);
  }
  if(path==='/auth/bootstrap'&&method==='POST'){
    if(!env.ADMIN_SETUP_TOKEN||String(data.setup_token||'')!==env.ADMIN_SETUP_TOKEN)return bad('รหัสติดตั้งแอดมินไม่ถูกต้อง',403);
    const count=await db.prepare("SELECT COUNT(*) AS n FROM users WHERE role='admin'").first();
    if(count.n)return bad('มีแอดมินแล้ว ไม่สามารถสร้างผ่านช่องทางนี้อีก',409);
    const email=norm(data.email).toLowerCase(),name=limit(data.full_name,100),password=String(data.password||'');
    if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||name.length<2||password.length<12||password.length>128)return bad('กรอกชื่อ อีเมล และรหัสผ่านอย่างน้อย 12 ตัวอักษร');
    const id=crypto.randomUUID(),salt=rand(16),hash=await passhash(password,salt);
    try{await db.prepare("INSERT INTO users(id,email,full_name,password_salt,password_hash,role) VALUES(?,?,?,?,?,'admin')").bind(id,email,name,salt,hash).run()}catch{return bad('สร้างแอดมินไม่สำเร็จ',409)}
    return createSession(db,{id,email,full_name:name,role:'admin',status:'active'});
  }
  const u=await auth(request,db);
  if(path==='/auth/me'&&method==='GET')return json({user:u?safeUser(u):null});
  if(path==='/auth/logout'&&method==='POST'){
    const token=request.headers.get('cookie')?.match(/cf_session=([a-f0-9]{64})/)?.[1];if(token)await db.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await digest(token)).run();
    return json({ok:true},200,{'set-cookie':cookie('',0)});
  }
  if(!u)return bad('กรุณาเข้าสู่ระบบ',401);
  const admin=u.role==='admin';
  if(path==='/users'&&method==='GET'){
    if(!admin)return bad('ไม่มีสิทธิ์',403);
    return json({users:(await db.prepare('SELECT id,email,full_name,role,status,created_at FROM users ORDER BY created_at DESC LIMIT 500').all()).results});
  }
  if(path==='/users/status'&&method==='POST'){
    if(!admin)return bad('ไม่มีสิทธิ์',403);
    const {id,status}=data;if(!['active','blocked'].includes(status)||id===u.id)return bad('ข้อมูลไม่ถูกต้อง');
    const result=await db.prepare("UPDATE users SET status=? WHERE id=? AND role='member'").bind(status,id).run();
    if(!result.meta.changes)return bad('ไม่พบสมาชิก',404);
    if(status==='blocked')await db.prepare('DELETE FROM sessions WHERE user_id=?').bind(id).run();
    await record(db,u.id,'user.status',id);return json({ok:true});
  }
  if(path==='/cards'&&method==='GET'){
    const sql=admin?'SELECT c.*,u.email,u.full_name FROM cards c JOIN users u ON u.id=c.user_id ORDER BY c.created_at DESC LIMIT 500':'SELECT c.* FROM cards c WHERE c.user_id=? ORDER BY c.created_at DESC LIMIT 100';
    const rows=await (admin?db.prepare(sql):db.prepare(sql).bind(u.id)).all();return json({cards:rows.results});
  }
  if(path==='/cards'&&method==='POST'){
    if(!admin)return bad('ไม่มีสิทธิ์',403);
    const user_id=norm(data.user_id),label=limit(data.label,100),issuer=limit(data.issuer,100),last4=norm(data.last4),currency=norm(data.currency||'THB').toUpperCase(),note=limit(data.note,500);
    if(!label||!/^\d{4}$/.test(last4)||!/^[A-Z]{3}$/.test(currency))return bad('ชื่อบัตร เลขท้าย 4 หลัก หรือสกุลเงินไม่ถูกต้อง');
    if(!await db.prepare("SELECT id FROM users WHERE id=? AND role='member' AND status='active'").bind(user_id).first())return bad('ไม่พบสมาชิกที่ใช้งานได้',404);
    const id=crypto.randomUUID();await db.prepare('INSERT INTO cards(id,user_id,label,issuer,last4,currency,note) VALUES(?,?,?,?,?,?,?)').bind(id,user_id,label,issuer,last4,currency,note).run();await record(db,u.id,'card.create',id);return json({ok:true,id},201);
  }
  if(path==='/cards/status'&&method==='POST'){
    if(!admin)return bad('ไม่มีสิทธิ์',403);
    if(!['active','frozen','closed'].includes(data.status))return bad('สถานะไม่ถูกต้อง');
    const result=await db.prepare('UPDATE cards SET status=? WHERE id=?').bind(data.status,data.id).run();if(!result.meta.changes)return bad('ไม่พบบัตร',404);
    await record(db,u.id,'card.status',data.id);return json({ok:true});
  }
  if(path==='/transactions'&&method==='GET'){
    const sql=admin?'SELECT t.*,c.label,c.last4,u.email FROM transactions t JOIN cards c ON c.id=t.card_id JOIN users u ON u.id=c.user_id ORDER BY t.occurred_at DESC,t.created_at DESC LIMIT 1000':'SELECT t.*,c.label,c.last4 FROM transactions t JOIN cards c ON c.id=t.card_id WHERE c.user_id=? ORDER BY t.occurred_at DESC,t.created_at DESC LIMIT 500';
    const rows=await(admin?db.prepare(sql):db.prepare(sql).bind(u.id)).all();return json({transactions:rows.results});
  }
  if(path==='/transactions'&&method==='POST'){
    if(!admin)return bad('ไม่มีสิทธิ์',403);
    const card_id=norm(data.card_id),type=norm(data.type),merchant=limit(data.merchant,120),description=limit(data.description,500),when=norm(data.occurred_at);
    const card=await db.prepare('SELECT * FROM cards WHERE id=?').bind(card_id).first();
    if(!card||!['expense','topup','refund','adjustment'].includes(type)||!validMoney(data.amount)||!merchant||!/^\d{4}-\d{2}-\d{2}$/.test(when)||!Number.isFinite(Date.parse(when)))return bad('ข้อมูลรายการไม่ถูกต้อง');
    if(type==='expense'&&card.status==='closed')return bad('ไม่สามารถบันทึกรายการจ่ายของบัตรที่ปิดแล้ว');
    const id=crypto.randomUUID(),minor=Math.round(Number(data.amount)*100);
    await db.prepare('INSERT INTO transactions(id,card_id,type,amount_minor,currency,merchant,description,occurred_at,created_by) VALUES(?,?,?,?,?,?,?,?,?)').bind(id,card_id,type,minor,card.currency,merchant,description,when,u.id).run();await record(db,u.id,'transaction.create',id);return json({ok:true,id},201);
  }
  if(path==='/summary'&&method==='GET'){
    const cards=await(admin?db.prepare('SELECT COUNT(*) AS n FROM cards').first():db.prepare('SELECT COUNT(*) AS n FROM cards WHERE user_id=?').bind(u.id).first());
    const sql=admin?'SELECT t.type,t.currency,SUM(t.amount_minor) AS total,COUNT(*) AS count FROM transactions t GROUP BY t.type,t.currency':'SELECT t.type,t.currency,SUM(t.amount_minor) AS total,COUNT(*) AS count FROM transactions t JOIN cards c ON c.id=t.card_id WHERE c.user_id=? GROUP BY t.type,t.currency';
    const totals=(await(admin?db.prepare(sql):db.prepare(sql).bind(u.id)).all()).results;
    return json({card_count:cards.n,totals});
  }
  return bad('ไม่พบ API',404);
 }catch(err){return bad(err instanceof SyntaxError?'รูปแบบ JSON ไม่ถูกต้อง':(err.message==='ข้อมูลเกินขนาด'?err.message:'เกิดข้อผิดพลาด กรุณาลองอีกครั้ง'),err.message==='ข้อมูลเกินขนาด'?413:500)}
}
