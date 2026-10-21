interface Env { DB: D1Database; APP_ORIGIN?: string }

export const onRequest: PagesFunction<Env> = async (context) => {
  const request = context.request;
  const origin = request.headers.get('Origin');
  const ownOrigin = new URL(request.url).origin;
  const allowed = new Set([ownOrigin, context.env.APP_ORIGIN].filter(Boolean));

  if (origin && !allowed.has(origin)) {
    return new Response(JSON.stringify({ message: 'Источник запроса не разрешён' }), {
      status: 403,
      headers: { 'Content-Type': 'application/json; charset=utf-8' },
    });
  }

  if (request.method === 'OPTIONS') {
    const headers = new Headers({ 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type', 'Access-Control-Max-Age': '86400' });
    if (origin) {
      headers.set('Access-Control-Allow-Origin', origin);
      headers.set('Access-Control-Allow-Credentials', 'true');
      headers.set('Vary', 'Origin');
    }
    return new Response(null, { status: 204, headers });
  }

  const response = await context.next();
  if (origin) {
    const headers = new Headers(response.headers);
    headers.set('Access-Control-Allow-Origin', origin);
    headers.set('Access-Control-Allow-Credentials', 'true');
    headers.append('Vary', 'Origin');
    return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
  }
  return response;
};
