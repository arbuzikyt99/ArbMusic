import { body, json, limited, normalizePhone, passwordHash, type Env, issueSession } from './_shared';

export const onRequestPost: PagesFunction<Env> = async ({ request, env }) => {
  const data = await body(request);
  const phone = normalizePhone(data.phone);
  const password = data.password;
  if (!phone || typeof password !== 'string') return json({ message: 'Проверь номер телефона и пароль' }, 400);
  if (await limited(env, request, phone)) return json({ message: 'Слишком много попыток. Подожди 10 минут и попробуй снова.' }, 429);
  const user = await env.DB.prepare('SELECT id, phone, password_salt, password_hash FROM users WHERE phone = ?').bind(phone).first<{ id: string; phone: string; password_salt: string; password_hash: string }>();
  if (!user || await passwordHash(password, user.password_salt) !== user.password_hash) return json({ message: 'Неверный номер или пароль' }, 401);
  return issueSession(env, request, user);
};
