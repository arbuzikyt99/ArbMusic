import { clearCookie, cookieToken, json, sha256, type Env } from './_shared';

export const onRequestPost: PagesFunction<Env> = async ({ request, env }) => {
  const token = cookieToken(request);
  if (token) await env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(await sha256(token)).run();
  return json({ ok: true }, 200, { 'Set-Cookie': clearCookie(request), 'Cache-Control': 'no-store' });
};
