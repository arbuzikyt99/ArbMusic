import { createServer } from 'node:http';
import { createReadStream, existsSync } from 'node:fs';
import { extname, resolve, sep } from 'node:path';
import { createHmac, createHash, randomBytes, randomInt, pbkdf2 as pbkdf2Callback, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import pg from 'pg';

const { Pool } = pg;
const pbkdf2 = promisify(pbkdf2Callback);
const dist = resolve('dist');
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : undefined });
const mime = { '.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.svg':'image/svg+xml','.png':'image/png','.jpg':'image/jpeg','.webp':'image/webp','.webmanifest':'application/manifest+json' };
const json = (res, status, value, headers = {}) => { res.writeHead(status, { 'Content-Type':'application/json; charset=utf-8', 'Cache-Control':'no-store', ...headers }); res.end(JSON.stringify(value)); };
const hashToken = value => createHash('sha256').update(value).digest('hex');
const phoneOf = value => {
  if (typeof value !== 'string') return null;
  let digits = value.replace(/\D/g, '');
  if (digits.length === 11 && digits[0] === '8') digits = `7${digits.slice(1)}`;
  if (digits.length === 10) digits = `7${digits}`;
  return digits.length >= 10 && digits.length <= 15 ? `+${digits}` : null;
};
const body = req => new Promise((done, fail) => {
  let raw = '';
  req.on('data', part => { raw += part; if (raw.length > 8192) fail(Error('too_large')); });
  req.on('end', () => { try { done(JSON.parse(raw || '{}')); } catch { fail(Error('bad_json')); } });
  req.on('error', fail);
});
const tokenOf = req => (req.headers.cookie || '').split(';').map(v => v.trim()).find(v => v.startsWith('arb_session='))?.slice(12);
const cookie = (token, age) => `arb_session=${token}; HttpOnly; Path=/; SameSite=Lax; Secure; Max-Age=${age}`;
const otpDigest = (phone, code) => createHmac('sha256', process.env.OTP_SECRET || process.env.DATABASE_URL).update(`${phone}:${code}`).digest();

async function initDb() {
  await pool.query(`CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,phone TEXT NOT NULL UNIQUE,password_salt TEXT NOT NULL,password_hash TEXT NOT NULL,created_at BIGINT NOT NULL,phone_verified BOOLEAN NOT NULL DEFAULT FALSE);
    ALTER TABLE users ADD COLUMN IF NOT EXISTS phone_verified BOOLEAN NOT NULL DEFAULT FALSE;
    CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,expires_at BIGINT NOT NULL);
    CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
    CREATE TABLE IF NOT EXISTS auth_attempts(id BIGSERIAL PRIMARY KEY,ip TEXT NOT NULL,phone TEXT NOT NULL,attempted_at BIGINT NOT NULL);
    CREATE INDEX IF NOT EXISTS auth_attempts_lookup ON auth_attempts(ip,phone,attempted_at);
    CREATE TABLE IF NOT EXISTS registration_codes(phone TEXT PRIMARY KEY,password_salt TEXT NOT NULL,password_hash TEXT NOT NULL,code_hash BYTEA NOT NULL,expires_at BIGINT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,send_count INTEGER NOT NULL DEFAULT 1,created_at BIGINT NOT NULL,last_sent_at BIGINT NOT NULL,ip TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS registration_codes_expiry ON registration_codes(expires_at);`);
}

async function limited(ip, phone) {
  const since = Date.now() - 10 * 60_000;
  const result = await pool.query('SELECT COUNT(*)::int AS n FROM auth_attempts WHERE ip=$1 AND phone=$2 AND attempted_at>$3', [ip, phone, since]);
  await pool.query('INSERT INTO auth_attempts(ip,phone,attempted_at) VALUES($1,$2,$3)', [ip, phone, Date.now()]);
  return result.rows[0].n >= 10;
}

async function sendSms(phone, code) {
  const apiId = process.env.SMS_RU_API_ID;
  if (!apiId) return false;
  const digits = phone.slice(1);
  const form = new URLSearchParams({ api_id: apiId, to: digits, msg: `Код ArbMusic: ${code}. Никому не сообщайте код.`, json: '1' });
  const response = await fetch('https://sms.ru/sms/send', { method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:form, signal:AbortSignal.timeout(15000) });
  if (!response.ok) return false;
  const result = await response.json();
  const message = result?.sms?.[digits];
  return result?.status_code === 100 && message?.status_code === 100 && message?.status === 'OK';
}

async function sendCode(req, res, { resend = false } = {}) {
  let data;
  try { data = await body(req); } catch (error) { return json(res, error.message === 'too_large' ? 413 : 400, { message:'Некорректный запрос' }); }
  const phone = phoneOf(data.phone);
  const password = data.password;
  if (!phone || (!resend && (typeof password !== 'string' || password.length < 8 || password.length > 128))) return json(res, 400, { message:'Проверь номер телефона и пароль (не менее 8 символов)' });
  if (!process.env.SMS_RU_API_ID) return json(res, 503, { message:'Отправка SMS ещё не настроена. Добавь ключ SMS.RU в настройках сервера.' });
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
  if (await limited(ip, phone)) return json(res, 429, { message:'Слишком много попыток. Попробуй позже.' });
  const existing = await pool.query('SELECT id FROM users WHERE phone=$1', [phone]);
  if (existing.rowCount) return json(res, 409, { message:'Аккаунт с таким номером уже есть. Выбери «Войти».' });
  const previous = (await pool.query('SELECT * FROM registration_codes WHERE phone=$1', [phone])).rows[0];
  const now = Date.now();
  if (previous && now - Number(previous.last_sent_at) < 60_000) return json(res, 429, { message:'Подожди минуту перед повторной отправкой кода.' });
  if (previous && now - Number(previous.created_at) < 24 * 60 * 60_000 && previous.send_count >= 5) return json(res, 429, { message:'Для этого номера уже отправлено 5 кодов за сутки.' });
  if (resend && !previous) return json(res, 400, { message:'Сначала введи номер и пароль, чтобы запросить код.' });

  const code = randomInt5();
  const expires = now + 10 * 60_000;
  let salt = previous?.password_salt, passwordHash = previous?.password_hash;
  if (!resend) {
    salt = randomBytes(16).toString('base64url');
    passwordHash = (await pbkdf2(password, salt, 120000, 32, 'sha256')).toString('hex');
  }
  const sendCount = previous && now - Number(previous.created_at) < 24 * 60 * 60_000 ? previous.send_count + 1 : 1;
  await pool.query(`INSERT INTO registration_codes(phone,password_salt,password_hash,code_hash,expires_at,attempts,send_count,created_at,last_sent_at,ip)
    VALUES($1,$2,$3,$4,$5,0,$6,$7,$8,$9) ON CONFLICT(phone) DO UPDATE SET password_salt=EXCLUDED.password_salt,password_hash=EXCLUDED.password_hash,code_hash=EXCLUDED.code_hash,expires_at=EXCLUDED.expires_at,attempts=0,send_count=EXCLUDED.send_count,created_at=EXCLUDED.created_at,last_sent_at=EXCLUDED.last_sent_at,ip=EXCLUDED.ip`,
    [phone, salt, passwordHash, otpDigest(phone, code), expires, sendCount, previous && now - Number(previous.created_at) < 24 * 60 * 60_000 ? previous.created_at : now, now, ip]);
  try {
    if (!await sendSms(phone, code)) throw Error('sms_failed');
  } catch {
    await pool.query('DELETE FROM registration_codes WHERE phone=$1 AND code_hash=$2', [phone, otpDigest(phone, code)]);
    return json(res, 502, { message:'Не получилось отправить SMS. Проверь номер и попробуй позже.' });
  }
  return json(res, 200, { verificationRequired:true, message:'Код из 5 цифр отправлен по SMS. Он действует 10 минут.' });
}

function randomInt5() { return String(randomInt(100000)).padStart(5, '0'); }

async function verifyRegistration(req, res) {
  let data;
  try { data = await body(req); } catch (error) { return json(res, error.message === 'too_large' ? 413 : 400, { message:'Некорректный запрос' }); }
  const phone = phoneOf(data.phone), code = data.code;
  if (!phone || typeof code !== 'string' || !/^\d{5}$/.test(code)) return json(res, 400, { message:'Введи код из пяти цифр.' });
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
  if (await limited(ip, phone)) return json(res, 429, { message:'Слишком много попыток. Попробуй позже.' });
  const pending = (await pool.query('SELECT * FROM registration_codes WHERE phone=$1', [phone])).rows[0];
  if (!pending) return json(res, 400, { message:'Сначала запроси код подтверждения.' });
  if (Number(pending.expires_at) < Date.now()) return json(res, 400, { message:'Код истёк. Нажми «Отправить код ещё раз».' });
  if (pending.attempts >= 5) return json(res, 429, { message:'Лимит ввода кода исчерпан. Запроси новый код.' });
  const expected = Buffer.from(pending.code_hash), actual = otpDigest(phone, code);
  if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) {
    await pool.query('UPDATE registration_codes SET attempts=attempts+1 WHERE phone=$1', [phone]);
    return json(res, 400, { message:'Неверный код. Проверь SMS и попробуй ещё раз.' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const id = randomBytes(18).toString('base64url');
    const created = await client.query('INSERT INTO users(id,phone,password_salt,password_hash,created_at,phone_verified) VALUES($1,$2,$3,$4,$5,TRUE) ON CONFLICT(phone) DO NOTHING RETURNING id,phone', [id,phone,pending.password_salt,pending.password_hash,Date.now()]);
    if (!created.rowCount) { await client.query('ROLLBACK'); return json(res,409,{message:'Аккаунт с таким номером уже есть. Войди в него.'}); }
    const token = randomBytes(32).toString('base64url'), expires = Date.now() + 30 * 24 * 60 * 60_000;
    await client.query('DELETE FROM sessions WHERE expires_at <= $1', [Date.now()]);
    await client.query('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES($1,$2,$3)', [hashToken(token),id,expires]);
    await client.query('DELETE FROM registration_codes WHERE phone=$1', [phone]);
    await client.query('COMMIT');
    return json(res,200,{user:{phone}},{'Set-Cookie':cookie(token,2592000)});
  } catch (error) { await client.query('ROLLBACK'); throw error; }
  finally { client.release(); }
}

async function login(req, res) {
  let data;
  try { data = await body(req); } catch (error) { return json(res, error.message === 'too_large' ? 413 : 400, { message:'Некорректный запрос' }); }
  const phone = phoneOf(data.phone), password = data.password;
  if (!phone || typeof password !== 'string' || password.length > 128) return json(res,400,{message:'Проверь номер телефона и пароль'});
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
  if (await limited(ip,phone)) return json(res,429,{message:'Слишком много попыток. Попробуй позже.'});
  const user=(await pool.query('SELECT id,phone,password_salt,password_hash FROM users WHERE phone=$1',[phone])).rows[0];
  const salt=user?.password_salt||randomBytes(16).toString('base64url'),candidate=await pbkdf2(password,salt,120000,32,'sha256');
  if(!user||!timingSafeEqual(candidate,Buffer.from(user.password_hash,'hex')))return json(res,401,{message:'Неверный номер или пароль'});
  const token=randomBytes(32).toString('base64url'),expires=Date.now()+30*24*60*60_000;
  await pool.query('DELETE FROM sessions WHERE expires_at<=$1',[Date.now()]);
  await pool.query('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES($1,$2,$3)',[hashToken(token),user.id,expires]);
  return json(res,200,{user:{phone:user.phone}},{'Set-Cookie':cookie(token,2592000)});
}

async function route(req, res) {
  const url = new URL(req.url, 'http://localhost');
  if (url.pathname === '/health') return json(res,200,{ok:true});
  if (url.pathname === '/api/auth/register' && req.method === 'POST') return sendCode(req,res);
  if (url.pathname === '/api/auth/resend-code' && req.method === 'POST') return sendCode(req,res,{resend:true});
  if (url.pathname === '/api/auth/verify' && req.method === 'POST') return verifyRegistration(req,res);
  if (url.pathname === '/api/auth/login' && req.method === 'POST') return login(req,res);
  if (url.pathname === '/api/auth/logout' && req.method === 'POST') {
    const token=tokenOf(req); if(token) await pool.query('DELETE FROM sessions WHERE token_hash=$1',[hashToken(decodeURIComponent(token))]);
    return json(res,200,{ok:true},{'Set-Cookie':cookie('',0)});
  }
  if (url.pathname === '/api/auth/me' && req.method === 'GET') {
    const token=tokenOf(req); if(!token)return json(res,401,{message:'Не выполнен вход'});
    const result=await pool.query('SELECT u.phone FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>$2',[hashToken(decodeURIComponent(token)),Date.now()]);
    return result.rowCount?json(res,200,{user:{phone:result.rows[0].phone}}):json(res,401,{message:'Сессия завершена'});
  }
  if (url.pathname.startsWith('/api/')) return json(res,404,{message:'Не найдено'});
  const relative=decodeURIComponent(url.pathname).replace(/^\/+/, '')||'index.html';
  let file=resolve(dist,relative);
  if(!file.startsWith(dist+sep)&&file!==resolve(dist,'index.html'))return json(res,403,{message:'Запрещено'});
  if(!existsSync(file))file=resolve(dist,'index.html');
  res.writeHead(200,{'Content-Type':mime[extname(file)]||'application/octet-stream','Cache-Control':file.endsWith('index.html')?'no-cache':'public, max-age=3600'});
  createReadStream(file).pipe(res);
}

const databaseReady=Boolean(process.env.DATABASE_URL);
if(databaseReady) await initDb();
createServer((req,res)=>{
  if(req.url.startsWith('/api/auth/')&&!databaseReady)return json(res,503,{message:'База аккаунтов ещё не подключена'});
  return route(req,res).catch(error=>{console.error(error);if(!res.headersSent)json(res,500,{message:'Внутренняя ошибка сервера'});else res.destroy()});
}).listen(Number(process.env.PORT)||3000,'0.0.0.0');
