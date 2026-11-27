import crypto from 'node:crypto';

/* 轻量 TOTP 实现（RFC 6238），只依赖 node:crypto，无需额外依赖 */

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(buf) {
  let bits = 0, value = 0, out = '';
  for (const b of buf) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(str) {
  const clean = String(str || '').toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0, value = 0;
  const out = [];
  for (const ch of clean) {
    const idx = ALPHABET.indexOf(ch);
    if (idx < 0) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

export function generateSecret(bytes = 20) {
  return base32Encode(crypto.randomBytes(bytes));
}

export function totpCode(secret, timeMs = Date.now(), step = 30) {
  const counter = Math.floor(timeMs / 1000 / step);
  const buf = Buffer.alloc(8);
  buf.writeUInt32BE(Math.floor(counter / 4294967296), 0);
  buf.writeUInt32BE(counter >>> 0, 4);
  const hmac = crypto.createHmac('sha1', base32Decode(secret)).update(buf).digest();
  const off = hmac[hmac.length - 1] & 0x0f;
  const code = (hmac.readUInt32BE(off) & 0x7fffffff) % 1000000;
  return String(code).padStart(6, '0');
}

export function verifyTotp(secret, code, window = 1) {
  if (!secret) return false;
  const c = String(code || '').replace(/\s/g, '');
  if (!/^\d{6}$/.test(c)) return false;
  for (let i = -window; i <= window; i++) {
    if (totpCode(secret, Date.now() + i * 30000) === c) return true;
  }
  return false;
}

export function otpauthUri(secret, account, issuer = '赞赏管理台') {
  const label = encodeURIComponent(issuer + ':' + account);
  return 'otpauth://totp/' + label +
    '?secret=' + secret +
    '&issuer=' + encodeURIComponent(issuer) +
    '&digits=6&period=30';
}
