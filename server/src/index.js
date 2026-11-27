import 'dotenv/config';
import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import bcrypt from 'bcryptjs';
import { pool } from './db.js';
import { DEFAULT_CONFIG, DEFAULT_NOTIFY, NOTIFY_TYPES, ROLES } from './defaults.js';
import {
  setSessionCookie, clearSessionCookie, currentUser, rateLimit
} from './auth.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '../..');
const PORT = Number(process.env.PORT || 3000);

const DUMMY_HASH = bcrypt.hashSync('dummy-password-for-timing', 10);

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.json({ limit: '64kb' }));
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'same-origin');
  next();
});

/* ---------- 通用工具 ---------- */

async function loadUser(req) {
  const token = currentUser(req);
  if (!token) return null;
  const [rows] = await pool.query(
    'SELECT id, username, role FROM admins WHERE id = ? LIMIT 1', [token.uid]
  );
  return rows[0] || null;
}

async function requireUser(req, res, next) {
  try {
    const user = await loadUser(req);
    if (!user) return res.status(401).json({ error: '未登录' });
    req.user = user;
    next();
  } catch (e) {
    console.error('[auth:load]', e.message);
    res.status(500).json({ error: '服务异常' });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || roles.indexOf(req.user.role) < 0) {
      return res.status(403).json({ error: '权限不足' });
    }
    next();
  };
}

async function audit(actor, action, detail, ip) {
  try {
    await pool.query(
      'INSERT INTO audit_logs (actor, action, detail, ip) VALUES (?, ?, ?, ?)',
      [actor == null ? null : String(actor).slice(0, 50), action,
        detail == null ? null : String(detail).slice(0, 500),
        ip == null ? null : String(ip).slice(0, 45)]
    );
  } catch (e) {
    console.error('[audit]', e.message);
  }
}

function safeStr(v, max) {
  const s = String(v == null ? '' : v).trim();
  if (!s || s.length > max) return null;
  if (/[<>"']/.test(s)) return null;
  return s;
}

function safeAsset(v) {
  const s = safeStr(v, 300);
  if (!s) return null;
  if (/^(javascript|data|vbscript):/i.test(s)) return null;
  return s;
}

function readCookie(req, name) {
  const raw = req.headers.cookie || '';
  for (const part of raw.split(';')) {
    const idx = part.indexOf('=');
    if (idx < 0) continue;
    if (part.slice(0, idx).trim() === name) {
      try { return decodeURIComponent(part.slice(idx + 1).trim()); } catch { return null; }
    }
  }
  return null;
}

function validateTheme(t) {
  const d = DEFAULT_CONFIG.theme;
  const src = t && typeof t === 'object' ? t : {};

  const accent = String(src.accent == null ? d.accent : src.accent).trim().toUpperCase();
  if (!/^#[0-9A-F]{6}$/.test(accent)) return null;

  const title = src.title == null ? d.title : safeStr(src.title, 30);
  const pageTitle = src.pageTitle == null ? d.pageTitle : safeStr(src.pageTitle, 40);
  const footer = src.footer == null ? d.footer : safeStr(src.footer, 80);
  if (!title || !pageTitle || !footer) return null;

  return { accent, title, pageTitle, footer };
}

function validateConfig(body) {
  if (!body || typeof body !== 'object') return null;
  const theme = validateTheme(body.theme);
  if (!theme) return null;

  const amounts = Array.isArray(body.amounts)
    ? Array.from(new Set(body.amounts.map(Number).filter(n => Number.isFinite(n) && n > 0 && n <= 1000000)
        .map(n => Math.round(n * 100) / 100))).sort((a, b) => a - b)
    : null;
  if (!amounts || !amounts.length || amounts.length > 30) return null;

  if (!Array.isArray(body.projects) || !body.projects.length || body.projects.length > 12) return null;
  const projects = [];
  for (const p of body.projects) {
    const name = safeStr(p && p.name, 40);
    const id = safeStr(p && p.id, 40);
    const code = safeStr(p && p.code, 40);
    const prefix = safeStr(p && p.prefix, 4);
    const qr = safeAsset(p && p.qr);
    const avatar = safeAsset(p && p.avatar);
    const sub = safeStr(p && p.sub, 60);
    if (!name || !id || !code || !prefix || !qr || !avatar || !sub) return null;
    if (!/^[A-Za-z0-9_-]+$/.test(id) || !/^[A-Za-z0-9_-]+$/.test(code)) return null;
    if (!/^[A-Z]{1,4}$/.test(prefix.toUpperCase())) return null;
    projects.push({ id, name, code, prefix: prefix.toUpperCase(), qr, avatar, sub });
  }
  return { amounts, theme, projects };
}

async function readSetting(key, fallback) {
  try {
    const [rows] = await pool.query('SELECT v FROM settings WHERE k = ? LIMIT 1', [key]);
    if (rows.length) return JSON.parse(rows[0].v);
  } catch (e) {
    console.error('[setting:read]', key, e.message);
  }
  return fallback;
}

async function writeSetting(key, value) {
  await pool.query(
    'INSERT INTO settings (k, v) VALUES (?, ?) ON DUPLICATE KEY UPDATE v = VALUES(v)',
    [key, JSON.stringify(value)]
  );
}

async function readConfig() {
  const parsed = await readSetting('page_config', null);
  if (parsed && Array.isArray(parsed.amounts) && Array.isArray(parsed.projects)) {
    if (!parsed.theme) parsed.theme = DEFAULT_CONFIG.theme;
    return parsed;
  }
  return DEFAULT_CONFIG;
}

/* ---------- 消息通知 ---------- */

function isPrivateHost(hostname) {
  const h = String(hostname || '').toLowerCase();
  if (!h) return true;
  if (h === 'localhost' || h.endsWith('.localhost')) return true;
  if (/^(127\.|10\.|192\.168\.|169\.254\.|0\.0\.0\.0)/.test(h)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(h)) return true;
  if (h === '::1' || h === '[::1]') return true;
  return false;
}

function validateWebhook(type, url) {
  if (NOTIFY_TYPES.indexOf(type) < 0) return null;
  if (type === 'none') return { type, url: '' };

  const raw = String(url || '').trim();
  if (!raw || raw.length > 500) return null;
  let u;
  try { u = new URL(raw); } catch { return null; }
  if (u.protocol !== 'https:') return null;
  if (isPrivateHost(u.hostname)) return null;
  return { type, url: u.toString() };
}

async function sendWebhook(cfg, text) {
  if (!cfg || cfg.type === 'none' || !cfg.url) return { ok: false, error: '未配置通知' };

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 5000);
  try {
    let headers = { 'Content-Type': 'application/json' };
    let body;
    if (cfg.type === 'feishu') {
      body = JSON.stringify({ msg_type: 'text', content: { text } });
    } else if (cfg.type === 'dingtalk') {
      body = JSON.stringify({ msgtype: 'text', text: { content: text } });
    } else if (cfg.type === 'serverchan') {
      headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
      body = new URLSearchParams({ title: '新赞赏订单', desp: text }).toString();
    } else {
      body = JSON.stringify({ text });
    }
    const res = await fetch(cfg.url, { method: 'POST', headers, body, signal: ctrl.signal });
    return { ok: res.ok, status: res.status };
  } catch (e) {
    return { ok: false, error: e.message };
  } finally {
    clearTimeout(timer);
  }
}

/* ---------- 健康检查 ---------- */

app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true });
  } catch {
    res.status(500).json({ ok: false });
  }
});

/* ---------- 访问统计 ---------- */

app.post('/api/track', async (req, res) => {
  const ip = req.ip || 'unknown';
  if (!rateLimit('track:' + ip, 120, 60 * 1000)) return res.status(204).end();

  let vid = readCookie(req, 'zan_vid');
  if (!vid || !/^[0-9a-fA-F-]{16,40}$/.test(vid)) {
    vid = randomUUID();
    res.cookie('zan_vid', vid, {
      maxAge: 365 * 864e5, httpOnly: true, sameSite: 'lax', path: '/'
    });
  }

  try {
    await pool.query(
      'INSERT INTO daily_stats (day, pv) VALUES (CURDATE(), 1) ON DUPLICATE KEY UPDATE pv = pv + 1'
    );
    const [r] = await pool.query(
      'INSERT IGNORE INTO daily_visitors (day, visitor) VALUES (CURDATE(), ?)', [vid]
    );
    if (r.affectedRows) {
      await pool.query('UPDATE daily_stats SET uv = uv + 1 WHERE day = CURDATE()');
    }
    if (Math.random() < 0.01) {
      await pool.query('DELETE FROM daily_visitors WHERE day < DATE_SUB(CURDATE(), INTERVAL 120 DAY)');
    }
  } catch (e) {
    console.error('[track]', e.message);
  }
  res.status(204).end();
});

app.get('/api/stats/daily', requireUser, async (req, res) => {
  const days = Math.max(7, Math.min(90, Number(req.query.days) || 14));
  try {
    const [statRows] = await pool.query(
      `SELECT DATE_FORMAT(day, '%Y-%m-%d') AS d, pv, uv
       FROM daily_stats WHERE day >= DATE_SUB(CURDATE(), INTERVAL ? DAY)`,
      [days - 1]
    );
    const [orderRows] = await pool.query(
      `SELECT DATE_FORMAT(created_at, '%Y-%m-%d') AS d, COUNT(*) AS c, COALESCE(SUM(amount), 0) AS s
       FROM orders WHERE created_at >= DATE_SUB(CURDATE(), INTERVAL ? DAY) GROUP BY d`,
      [days - 1]
    );

    const statMap = new Map(statRows.map(r => [r.d, { pv: Number(r.pv), uv: Number(r.uv) }]));
    const orderMap = new Map(orderRows.map(r => [r.d, { c: Number(r.c), s: Number(r.s) }]));

    const list = [];
    const base = new Date();
    base.setHours(0, 0, 0, 0);
    for (let i = days - 1; i >= 0; i--) {
      const d = new Date(base.getTime() - i * 864e5);
      const key = d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' +
        String(d.getDate()).padStart(2, '0');
      const st = statMap.get(key) || { pv: 0, uv: 0 };
      const od = orderMap.get(key) || { c: 0, s: 0 };
      list.push({
        day: key,
        pv: st.pv,
        uv: st.uv,
        orders: od.c,
        amount: Math.round(od.s * 100) / 100,
        conv: st.uv > 0 ? Math.round((od.c / st.uv) * 1000) / 10 : 0
      });
    }

    const total = list.reduce((acc, x) => ({
      pv: acc.pv + x.pv, uv: acc.uv + x.uv, orders: acc.orders + x.orders,
      amount: Math.round((acc.amount + x.amount) * 100) / 100
    }), { pv: 0, uv: 0, orders: 0, amount: 0 });
    total.conv = total.uv > 0 ? Math.round((total.orders / total.uv) * 1000) / 10 : 0;

    res.json({ days: list, total, span: days });
  } catch (e) {
    console.error('[stats:daily]', e.message);
    res.status(500).json({ error: '读取失败' });
  }
});

/* ---------- 登录 ---------- */

app.post('/api/login', async (req, res) => {
  const ip = req.ip || 'unknown';
  if (!rateLimit('login:' + ip, 10, 15 * 60 * 1000)) {
    return res.status(429).json({ error: '尝试次数过多，请 15 分钟后再试' });
  }

  const username = String(req.body?.username || '').trim();
  const password = String(req.body?.password || '');
  if (!username || !password || username.length > 50 || password.length > 200) {
    return res.status(400).json({ error: '请输入用户名和密码' });
  }

  try {
    const [rows] = await pool.query(
      'SELECT id, username, password_hash, role FROM admins WHERE username = ? LIMIT 1',
      [username]
    );
    const row = rows[0];
    const ok = await bcrypt.compare(password, row ? row.password_hash : DUMMY_HASH);
    if (!row || !ok) {
      await audit(username, 'login_fail', '密码错误或账号不存在', ip);
      return res.status(401).json({ error: '用户名或密码错误' });
    }

    setSessionCookie(res, row);
    await audit(row.username, 'login', '登录成功（' + row.role + '）', ip);
    res.json({ ok: true, username: row.username, role: row.role });
  } catch (e) {
    console.error('[login]', e.message);
    res.status(500).json({ error: '服务异常，请稍后再试' });
  }
});

app.post('/api/logout', (req, res) => {
  clearSessionCookie(res);
  res.json({ ok: true });
});

app.get('/api/me', requireUser, (req, res) => {
  res.json({ username: req.user.username, role: req.user.role });
});

app.post('/api/me/password', requireUser, async (req, res) => {
  const oldPassword = String(req.body?.oldPassword || '');
  const newPassword = String(req.body?.newPassword || '');
  if (newPassword.length < 8 || newPassword.length > 200) {
    return res.status(400).json({ error: '新密码至少 8 位' });
  }
  try {
    const [rows] = await pool.query(
      'SELECT password_hash FROM admins WHERE id = ? LIMIT 1', [req.user.id]
    );
    const ok = rows.length && await bcrypt.compare(oldPassword, rows[0].password_hash);
    if (!ok) return res.status(400).json({ error: '原密码不正确' });

    const hash = await bcrypt.hash(newPassword, 12);
    await pool.query('UPDATE admins SET password_hash = ? WHERE id = ?', [hash, req.user.id]);
    await audit(req.user.username, 'password_change', '修改自己的密码', req.ip);
    res.json({ ok: true });
  } catch (e) {
    console.error('[password]', e.message);
    res.status(500).json({ error: '修改失败' });
  }
});

/* ---------- 页面配置 ---------- */

app.get('/api/config', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.json(await readConfig());
});

app.put('/api/config', requireUser, requireRole('admin', 'editor'), async (req, res) => {
  const config = validateConfig(req.body);
  if (!config) return res.status(400).json({ error: '配置格式不正确，请检查金额、主题和项目字段' });
  try {
    await writeSetting('page_config', config);
    await audit(req.user.username, 'config_update',
      config.projects.length + ' 个项目 / ' + config.amounts.length + ' 个金额档位 / 主题色 ' + config.theme.accent,
      req.ip);
    res.json({ ok: true, config });
  } catch (e) {
    console.error('[config:save]', e.message);
    res.status(500).json({ error: '保存失败' });
  }
});

/* ---------- 通知设置 ---------- */

app.get('/api/notify', requireUser, requireRole('admin'), async (req, res) => {
  res.json(await readSetting('notify_config', DEFAULT_NOTIFY));
});

app.put('/api/notify', requireUser, requireRole('admin'), async (req, res) => {
  const cfg = validateWebhook(String(req.body?.type || ''), req.body?.url);
  if (!cfg) {
    return res.status(400).json({ error: '通知地址必须是 https 公网地址，且类型正确' });
  }
  try {
    await writeSetting('notify_config', cfg);
    await audit(req.user.username, 'notify_update',
      cfg.type === 'none' ? '关闭通知' : '通知方式改为 ' + cfg.type, req.ip);
    res.json({ ok: true, config: cfg });
  } catch (e) {
    console.error('[notify:save]', e.message);
    res.status(500).json({ error: '保存失败' });
  }
});

app.post('/api/notify/test', requireUser, requireRole('admin'), async (req, res) => {
  const cfg = await readSetting('notify_config', DEFAULT_NOTIFY);
  const result = await sendWebhook(cfg,
    '这是一条测试消息\n来自赞赏管理台 · ' + new Date().toLocaleString('zh-CN'));
  if (!result.ok) {
    return res.status(400).json({ error: result.error || ('推送失败，接口返回 ' + result.status) });
  }
  res.json({ ok: true });
});

/* ---------- 订单 ---------- */

app.post('/api/orders', async (req, res) => {
  const ip = req.ip || 'unknown';
  if (!rateLimit('order:' + ip, 60, 60 * 1000)) {
    return res.status(429).json({ error: '提交过于频繁' });
  }

  const orderNo = String(req.body?.order || '').trim();
  const project = String(req.body?.project || '').trim();
  const amount = Number(req.body?.amount);
  let source = String(req.body?.source || '').trim().slice(0, 60);
  if (/[<>"']/.test(source)) source = '';

  if (!/^[A-Za-z0-9-]{6,40}$/.test(orderNo)) {
    return res.status(400).json({ error: '订单号格式不正确' });
  }
  if (!project || project.length > 80) {
    return res.status(400).json({ error: '项目名称不正确' });
  }
  if (!Number.isFinite(amount) || amount <= 0 || amount > 100000) {
    return res.status(400).json({ error: '金额不正确' });
  }

  try {
    const [result] = await pool.query(
      'INSERT INTO orders (order_no, project, amount, source, ip) VALUES (?, ?, ?, ?, ?)',
      [orderNo, project, amount.toFixed(2), source || null, ip.slice(0, 45)]
    );

    notifyNewOrder({ orderNo, project, amount, source });

    res.status(201).json({ ok: true, id: result.insertId });
  } catch (e) {
    console.error('[order:create]', e.message);
    res.status(500).json({ error: '写入失败' });
  }
});

async function notifyNewOrder({ orderNo, project, amount, source }) {
  try {
    const cfg = await readSetting('notify_config', DEFAULT_NOTIFY);
    if (!cfg || cfg.type === 'none' || !cfg.url) return;
    const text = '【新赞赏】' + project + ' ¥' + amount + '\n' +
      '订单号：' + orderNo + '\n' +
      (source ? '来源：' + source + '\n' : '') +
      '时间：' + new Date().toLocaleString('zh-CN');
    const result = await sendWebhook(cfg, text);
    if (!result.ok) console.error('[notify] 推送失败：', result.error || result.status);
  } catch (e) {
    console.error('[notify]', e.message);
  }
}

app.get('/api/orders', requireUser, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT id, order_no, project, amount, status, note, source,
              UNIX_TIMESTAMP(created_at) * 1000 AS created_ms,
              UNIX_TIMESTAMP(paid_at) * 1000 AS paid_ms
       FROM orders ORDER BY id DESC LIMIT 1000`
    );
    res.json({
      orders: rows.map(r => ({
        id: r.id,
        order: r.order_no,
        project: r.project,
        amount: Number(r.amount),
        status: r.status,
        note: r.note || '',
        source: r.source || '',
        createdMs: Number(r.created_ms),
        paidMs: r.paid_ms == null ? null : Number(r.paid_ms)
      }))
    });
  } catch (e) {
    console.error('[orders:list]', e.message);
    res.status(500).json({ error: '读取失败' });
  }
});

app.patch('/api/orders/:id', requireUser, requireRole('admin', 'editor'), async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: '无效的记录' });

  const body = req.body || {};
  const hasStatus = Object.prototype.hasOwnProperty.call(body, 'status');
  const hasNote = Object.prototype.hasOwnProperty.call(body, 'note');
  if (!hasStatus && !hasNote) return res.status(400).json({ error: '没有需要修改的内容' });

  let status = null;
  let note = null;
  if (hasStatus) {
    status = String(body.status);
    if (status !== 'paid' && status !== 'pending') return res.status(400).json({ error: '状态不正确' });
  }
  if (hasNote) {
    note = String(body.note == null ? '' : body.note).trim();
    if (note.length > 200) return res.status(400).json({ error: '备注最多 200 字' });
    if (/[<>]/.test(note)) return res.status(400).json({ error: '备注不能包含尖括号' });
    note = note || null;
  }

  const sets = [];
  const params = [];
  if (hasStatus) {
    sets.push('status = ?');
    params.push(status);
    sets.push('paid_at = ' + (status === 'paid' ? 'NOW()' : 'NULL'));
  }
  if (hasNote) {
    sets.push('note = ?');
    params.push(note);
  }
  params.push(id);

  try {
    const [result] = await pool.query(
      'UPDATE orders SET ' + sets.join(', ') + ' WHERE id = ?', params
    );
    if (!result.affectedRows) return res.status(404).json({ error: '记录不存在' });

    if (hasStatus) {
      await audit(req.user.username, 'order_status',
        '订单 #' + id + ' 标记为 ' + (status === 'paid' ? '已到账' : '待核对'), req.ip);
    }
    if (hasNote) {
      await audit(req.user.username, 'order_note',
        '订单 #' + id + ' 备注：' + (note || '（清空）'), req.ip);
    }
    res.json({ ok: true, status: hasStatus ? status : undefined, note: hasNote ? (note || '') : undefined });
  } catch (e) {
    console.error('[orders:patch]', e.message);
    res.status(500).json({ error: '更新失败' });
  }
});

app.delete('/api/orders/:id', requireUser, requireRole('admin', 'editor'), async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: '无效的记录' });
  try {
    await pool.query('DELETE FROM orders WHERE id = ?', [id]);
    await audit(req.user.username, 'order_delete', '删除订单 #' + id, req.ip);
    res.json({ ok: true });
  } catch (e) {
    console.error('[orders:delete]', e.message);
    res.status(500).json({ error: '删除失败' });
  }
});

app.delete('/api/orders', requireUser, requireRole('admin', 'editor'), async (req, res) => {
  try {
    const [result] = await pool.query('DELETE FROM orders');
    await audit(req.user.username, 'order_clear', '清空订单 ' + result.affectedRows + ' 条', req.ip);
    res.json({ ok: true, removed: result.affectedRows });
  } catch (e) {
    console.error('[orders:clear]', e.message);
    res.status(500).json({ error: '清空失败' });
  }
});

/* ---------- 管理员账号 ---------- */

app.get('/api/admins', requireUser, requireRole('admin'), async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT id, username, role, UNIX_TIMESTAMP(created_at) * 1000 AS created_ms
       FROM admins ORDER BY id ASC`
    );
    res.json({
      admins: rows.map(r => ({
        id: r.id, username: r.username, role: r.role, createdMs: Number(r.created_ms)
      }))
    });
  } catch (e) {
    console.error('[admins:list]', e.message);
    res.status(500).json({ error: '读取失败' });
  }
});

app.post('/api/admins', requireUser, requireRole('admin'), async (req, res) => {
  const username = String(req.body?.username || '').trim();
  const password = String(req.body?.password || '');
  const role = String(req.body?.role || 'editor');

  if (!/^[A-Za-z0-9_.-]{3,50}$/.test(username)) {
    return res.status(400).json({ error: '用户名只能用字母、数字、下划线、点和短横线，3-50 位' });
  }
  if (password.length < 8 || password.length > 200) {
    return res.status(400).json({ error: '密码至少 8 位' });
  }
  if (ROLES.indexOf(role) < 0) return res.status(400).json({ error: '角色不正确' });

  try {
    const hash = await bcrypt.hash(password, 12);
    const [result] = await pool.query(
      'INSERT INTO admins (username, password_hash, role) VALUES (?, ?, ?)',
      [username, hash, role]
    );
    await audit(req.user.username, 'admin_create', '创建账号 ' + username + '（' + role + '）', req.ip);
    res.status(201).json({ ok: true, id: result.insertId });
  } catch (e) {
    if (e.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: '用户名已存在' });
    console.error('[admins:create]', e.message);
    res.status(500).json({ error: '创建失败' });
  }
});

app.patch('/api/admins/:id', requireUser, requireRole('admin'), async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: '无效的账号' });

  const hasRole = Object.prototype.hasOwnProperty.call(req.body || {}, 'role');
  const hasPassword = Object.prototype.hasOwnProperty.call(req.body || {}, 'password');
  const role = hasRole ? String(req.body.role) : null;
  const password = hasPassword ? String(req.body.password) : null;

  if (hasRole && ROLES.indexOf(role) < 0) return res.status(400).json({ error: '角色不正确' });
  if (hasPassword && (password.length < 8 || password.length > 200)) {
    return res.status(400).json({ error: '密码至少 8 位' });
  }
  if (!hasRole && !hasPassword) return res.status(400).json({ error: '没有需要修改的内容' });

  try {
    const [rows] = await pool.query('SELECT id, username, role FROM admins WHERE id = ? LIMIT 1', [id]);
    const target = rows[0];
    if (!target) return res.status(404).json({ error: '账号不存在' });

    if (hasRole && id === req.user.id && role !== target.role) {
      return res.status(400).json({ error: '不能修改自己的角色' });
    }
    if (hasRole && target.role === 'admin' && role !== 'admin') {
      const [[{ n }]] = await pool.query("SELECT COUNT(*) AS n FROM admins WHERE role = 'admin'");
      if (n <= 1) return res.status(400).json({ error: '至少要保留一个管理员' });
    }

    if (hasRole) await pool.query('UPDATE admins SET role = ? WHERE id = ?', [role, id]);
    if (hasPassword) {
      const hash = await bcrypt.hash(password, 12);
      await pool.query('UPDATE admins SET password_hash = ? WHERE id = ?', [hash, id]);
    }
    await audit(req.user.username, 'admin_update',
      '修改账号 ' + target.username + (hasRole ? ' 角色为 ' + role : '') + (hasPassword ? ' 并重置密码' : ''),
      req.ip);
    res.json({ ok: true });
  } catch (e) {
    console.error('[admins:update]', e.message);
    res.status(500).json({ error: '修改失败' });
  }
});

app.delete('/api/admins/:id', requireUser, requireRole('admin'), async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: '无效的账号' });
  if (id === req.user.id) return res.status(400).json({ error: '不能删除当前登录的账号' });

  try {
    const [rows] = await pool.query('SELECT id, username, role FROM admins WHERE id = ? LIMIT 1', [id]);
    const target = rows[0];
    if (!target) return res.status(404).json({ error: '账号不存在' });

    if (target.role === 'admin') {
      const [[{ n }]] = await pool.query("SELECT COUNT(*) AS n FROM admins WHERE role = 'admin'");
      if (n <= 1) return res.status(400).json({ error: '至少要保留一个管理员' });
    }

    await pool.query('DELETE FROM admins WHERE id = ?', [id]);
    await audit(req.user.username, 'admin_delete', '删除账号 ' + target.username, req.ip);
    res.json({ ok: true });
  } catch (e) {
    console.error('[admins:delete]', e.message);
    res.status(500).json({ error: '删除失败' });
  }
});

/* ---------- 操作日志 ---------- */

app.get('/api/logs', requireUser, requireRole('admin'), async (req, res) => {
  const page = Math.max(1, Math.min(10000, Number(req.query.page) || 1));
  const size = 50;
  try {
    const [[{ total }]] = await pool.query('SELECT COUNT(*) AS total FROM audit_logs');
    const [rows] = await pool.query(
      `SELECT id, actor, action, detail, ip,
              UNIX_TIMESTAMP(created_at) * 1000 AS created_ms
       FROM audit_logs ORDER BY id DESC LIMIT ? OFFSET ?`,
      [size, (page - 1) * size]
    );
    res.json({
      total: Number(total),
      page,
      size,
      logs: rows.map(r => ({
        id: r.id,
        actor: r.actor,
        action: r.action,
        detail: r.detail,
        ip: r.ip,
        createdMs: Number(r.created_ms)
      }))
    });
  } catch (e) {
    console.error('[logs:list]', e.message);
    res.status(500).json({ error: '读取失败' });
  }
});

/* ---------- 静态资源 ---------- */

app.get('/admin', (req, res) => res.redirect('/admin.html'));

app.use((req, res, next) => {
  if (req.path.startsWith('/server/') || req.path.startsWith('/node_modules/') ||
      req.path.split('/').some(seg => seg.startsWith('.'))) {
    return res.status(404).end();
  }
  next();
});

app.use(express.static(ROOT, { index: 'index.html' }));

app.use((err, req, res, next) => {
  console.error('[error]', err.message);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: '服务异常' });
});

app.listen(PORT, () => {
  console.log(`[zan] listening on http://localhost:${PORT}`);
});
