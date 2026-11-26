import 'dotenv/config';
import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import bcrypt from 'bcryptjs';
import { pool } from './db.js';
import { DEFAULT_CONFIG, ROLES } from './defaults.js';
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

function validateConfig(body) {
  if (!body || typeof body !== 'object') return null;
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
  return { amounts, projects };
}

async function readConfig() {
  try {
    const [rows] = await pool.query("SELECT v FROM settings WHERE k = 'page_config' LIMIT 1");
    if (rows.length) {
      const parsed = JSON.parse(rows[0].v);
      if (parsed && Array.isArray(parsed.amounts) && Array.isArray(parsed.projects)) return parsed;
    }
  } catch (e) {
    console.error('[config:read]', e.message);
  }
  return DEFAULT_CONFIG;
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
  if (!config) return res.status(400).json({ error: '配置格式不正确，请检查金额和项目字段' });
  try {
    await pool.query(
      "INSERT INTO settings (k, v) VALUES ('page_config', ?) ON DUPLICATE KEY UPDATE v = VALUES(v)",
      [JSON.stringify(config)]
    );
    await audit(req.user.username, 'config_update',
      config.projects.length + ' 个项目 / ' + config.amounts.length + ' 个金额档位', req.ip);
    res.json({ ok: true, config });
  } catch (e) {
    console.error('[config:save]', e.message);
    res.status(500).json({ error: '保存失败' });
  }
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
      'INSERT INTO orders (order_no, project, amount, ip) VALUES (?, ?, ?, ?)',
      [orderNo, project, amount.toFixed(2), ip.slice(0, 45)]
    );
    res.status(201).json({ ok: true, id: result.insertId });
  } catch (e) {
    console.error('[order:create]', e.message);
    res.status(500).json({ error: '写入失败' });
  }
});

app.get('/api/orders', requireUser, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT id, order_no, project, amount, status,
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
  const status = String(req.body?.status || '');
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: '无效的记录' });
  if (status !== 'paid' && status !== 'pending') return res.status(400).json({ error: '状态不正确' });

  try {
    const [result] = await pool.query(
      status === 'paid'
        ? "UPDATE orders SET status = 'paid', paid_at = NOW() WHERE id = ?"
        : "UPDATE orders SET status = 'pending', paid_at = NULL WHERE id = ?",
      [id]
    );
    if (!result.affectedRows) return res.status(404).json({ error: '记录不存在' });
    await audit(req.user.username, 'order_status',
      '订单 #' + id + ' 标记为 ' + (status === 'paid' ? '已到账' : '待核对'), req.ip);
    res.json({ ok: true, status });
  } catch (e) {
    console.error('[orders:status]', e.message);
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
