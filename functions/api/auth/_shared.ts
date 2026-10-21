export interface Env { DB: D1Database; APP_ORIGIN?: string }

export function json(data: unknown, status = 200, headers: HeadersInit = {}) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json; charset=utf-8', ...Object.fromEntries(new Headers(headers)) } });
}

export async function body(request: Request): Promise<{ phone?: string; password?: string }> {
  try { return await request.json() as { phone?: string; password?: string }; }
  catch { return {}; }
}

export function normalizePhone(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  let digits = value.replace(/\D/g, '');
  if (digits.length === 11 && digits.startsWith('8')) digits = `7${digits.slice(1)}`;
  if (digits.length === 10) digits = `7${digits}`;
  return digits.length >= 10 && digits.length <= 15 ? `+${digits}` : null;
}

function encode(bytes: Uint8Array): string {
  let raw = '';
  bytes.forEach(byte => raw += String.fromCharCode(byte));
  return btoa(raw).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export function randomToken(bytes = 32): string {
  const buffer = new Uint8Array(bytes);
  crypto.getRandomValues(buffer);
  return encode(buffer);
}

export async function sha256(value: string): Promise<string> {
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return [...new Uint8Array(hash)].map(byte => byte.toString(16).padStart(2, '0')).join('');
}

export async function passwordHash(password: string, saltText: string): Promise<string> {
  const salt = Uint8Array.from(atob(saltText.replace(/-/g, '+').replace(/_/g, '/')), char => char.charCodeAt(0));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const hash = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 120000, hash: 'SHA-256' }, key, 256);
  return [...new Uint8Array(hash)].map(byte => byte.toString(16).padStart(2, '0')).join('');
}

export async function limited(env: Env, request: Request, phone: string): Promise<boolean> {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const since = Date.now() - 10 * 60 * 1000;
  const row = await env.DB.prepare('SELECT COUNT(*) AS total FROM auth_attempts WHERE ip = ? AND phone = ? AND attempted_at > ?').bind(ip, phone, since).first<{ total: number }>();
  if ((row?.total || 0) >= 10) return true;
  await env.DB.prepare('INSERT INTO auth_attempts (ip, phone, attempted_at) VALUES (?, ?, ?)').bind(ip, phone, Date.now()).run();
  return false;
}

export async function issueSession(env: Env, request: Request, user: { id: string; phone: string }): Promise<Response> {
  const token = randomToken();
  const tokenHash = await sha256(token);
  const expires = Date.now() + 30 * 24 * 60 * 60 * 1000;
  await env.DB.prepare('DELETE FROM sessions WHERE expires_at <= ?').bind(Date.now()).run();
  await env.DB.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)').bind(tokenHash, user.id, expires).run();
  const secure = new URL(request.url).protocol === 'https:';
  const origin = request.headers.get('Origin');
  const sameSite = origin && origin !== new URL(request.url).origin ? 'None' : 'Lax';
  const cookie = `arb_session=${token}; HttpOnly; Path=/; Max-Age=2592000; SameSite=${sameSite}${secure ? '; Secure' : ''}`;
  return json({ user: { phone: user.phone } }, 200, { 'Set-Cookie': cookie, 'Cache-Control': 'no-store' });
}

export function cookieToken(request: Request): string | null {
  const cookie = request.headers.get('Cookie') || '';
  const item = cookie.split(';').map(part => part.trim()).find(part => part.startsWith('arb_session='));
  return item ? decodeURIComponent(item.slice('arb_session='.length)) : null;
}

export function clearCookie(request: Request): string {
  const origin = request.headers.get('Origin');
  const sameSite = origin && origin !== new URL(request.url).origin ? 'None' : 'Lax';
  return `arb_session=; HttpOnly; Path=/; Max-Age=0; SameSite=${sameSite}${new URL(request.url).protocol === 'https:' ? '; Secure' : ''}`;
}
