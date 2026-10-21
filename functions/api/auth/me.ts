import { cookieToken, json, sha256, type Env } from './_shared';

export const onRequestGet: PagesFunction<Env> = async ({ request, env }) => {
  const token = cookieToken(request);
  if (!token) return json({ message: 'Не выполнен вход' }, 401, { 'Cache-Control': 'no-store' });
  const user = await env.DB.prepare('SELECT users.phone FROM sessions JOIN users ON users.id = sessions.user_id WHERE sessions.token_hash = ? AND sessions.expires_at > ?').bind(await sha256(token), Date.now()).first<{ phone: string }>();
  if (!user) return json({ message: 'Сессия завершена' }, 401, { 'Cache-Control': 'no-store' });
  return json({ user }, 200, { 'Cache-Control': 'no-store' });
};
