import crypto from 'node:crypto';

const COOKIE_NAME = 'zan_session';
const MAX_AGE = 7 * 24 * 3600;
const SECRET = process.env.SESSION_SECRET || '';

if (!SECRET || SECRET.length < 16) {
  console.error('[auth] 请在 .env 中配置足够长的 SESSION_SECRET（至少 16 位）');
  process.exit(1);
}

function b64url(input) {
  return Buffer.from(input).toString('base64url');
}

export function signToken(payload) {
  const body = b64url(JSON.stringify({ ...payload, exp: Math.floor(Date.now() / 1000) + MAX_AGE }));
  const sig = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  return body + '.' + sig;
}

export function verifyToken(token) {
  if (!token || typeof token !== 'string') return null;
  const [body, sig] = token.split('.');
  if (!body || !sig) return null;
  const expected = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (!payload.exp || payload.exp * 1000 < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

export function parseCookies(req) {
  const raw = req.headers.cookie || '';
  const out = {};
  raw.split(';').forEach(part => {
    const i = part.indexOf('=');
    if (i < 0) return;
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    if (k) out[k] = decodeURIComponent(v);
  });
  return out;
}

export function setSessionCookie(res, user) {
  const token = signToken({ uid: user.id, u: user.username });
  const secure = process.env.COOKIE_SECURE === '1' ? '; Secure' : '';
  res.setHeader('Set-Cookie',
    `${COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${MAX_AGE}${secure}`);
}

export function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', `${COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`);
}

export function currentUser(req) {
  const token = parseCookies(req)[COOKIE_NAME];
  return verifyToken(token);
}

export function requireAuth(req, res, next) {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: '未登录' });
  req.user = user;
  next();
}

/* 简单的内存限流，防止暴力尝试与刷单 */
const buckets = new Map();

export function rateLimit(key, max, windowMs) {
  const now = Date.now();
  const item = buckets.get(key);
  if (!item || now > item.reset) {
    buckets.set(key, { count: 1, reset: now + windowMs });
    return true;
  }
  item.count += 1;
  if (item.count > max) return false;
  return true;
}

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of buckets) {
    if (now > v.reset) buckets.delete(k);
  }
}, 60 * 1000).unref?.();
