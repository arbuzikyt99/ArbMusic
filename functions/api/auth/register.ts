import { body, issueSession, json, limited, normalizePhone, passwordHash, randomToken, type Env } from './_shared';

export const onRequestPost: PagesFunction<Env> = async ({ request, env }) => {
  const data = await body(request);
  const phone = normalizePhone(data.phone);
  const password = data.password;
  if (!phone) return json({ message: 'Введи корректный номер телефона' }, 400);
  if (typeof password !== 'string' || password.length < 8 || password.length > 128) return json({ message: 'Пароль должен содержать от 8 до 128 символов' }, 400);
  if (await limited(env, request, phone)) return json({ message: 'Слишком много попыток. Подожди 10 минут и попробуй снова.' }, 429);

  const existing = await env.DB.prepare('SELECT id FROM users WHERE phone = ?').bind(phone).first();
  if (existing) return json({ message: 'Аккаунт с таким номером уже есть. Выбери «Войти».' }, 409);

  const id = randomToken(18);
  const salt = randomToken(16);
  const hash = await passwordHash(password, salt);
  await env.DB.prepare('INSERT INTO users (id, phone, password_salt, password_hash, created_at) VALUES (?, ?, ?, ?, ?)').bind(id, phone, salt, hash, Date.now()).run();
  return issueSession(env, request, { id, phone });
};
