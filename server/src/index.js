import 'dotenv/config';
import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import bcrypt from 'bcryptjs';
import { pool } from './db.js';
import {
  setSessionCookie, clearSessionCookie, currentUser,
  requireAuth, rateLimit
} from './auth.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '../..');
const PORT = Number(process.env.PORT || 3000);

/* 用于消除“用户名不存在”与“密码错误”的响应时间差异 */
const DUMMY_HASH = bcrypt.hashSync('dummy-password-for-timing', 10);

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.json({ limit: '16kb' }));
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'same-origin');
  next();
});

app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true });
  } catch {
    res.status(500).json({ ok: false });
  }
});

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
      'SELECT id, username, password_hash FROM admins WHERE username = ? LIMIT 1',
      [username]
    );
    const row = rows[0];
    const ok = await bcrypt.compare(password, row ? row.password_hash : DUMMY_HASH);
    if (!row || !ok) return res.status(401).json({ error: '用户名或密码错误' });

    setSessionCookie(res, row);
    res.json({ ok: true, username: row.username });
  } catch (e) {
    console.error('[login]', e.message);
    res.status(500).json({ error: '服务异常，请稍后再试' });
  }
});

app.post('/api/logout', (req, res) => {
  clearSessionCookie(res);
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: '未登录' });
  res.json({ username: user.u });
});

/* 赞赏页生成订单号时调用，公开接口，仅记录“发起过赞赏” */
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

app.get('/api/orders', requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT id, order_no, project, amount,
              UNIX_TIMESTAMP(created_at) * 1000 AS created_ms
       FROM orders ORDER BY id DESC LIMIT 1000`
    );
    res.json({
      orders: rows.map(r => ({
        id: r.id,
        order: r.order_no,
        project: r.project,
        amount: Number(r.amount),
        createdMs: Number(r.created_ms)
      }))
    });
  } catch (e) {
    console.error('[orders:list]', e.message);
    res.status(500).json({ error: '读取失败' });
  }
});

app.delete('/api/orders/:id', requireAuth, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: '无效的记录' });
  try {
    await pool.query('DELETE FROM orders WHERE id = ?', [id]);
    res.json({ ok: true });
  } catch (e) {
    console.error('[orders:delete]', e.message);
    res.status(500).json({ error: '删除失败' });
  }
});

app.delete('/api/orders', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM orders');
    res.json({ ok: true });
  } catch (e) {
    console.error('[orders:clear]', e.message);
    res.status(500).json({ error: '清空失败' });
  }
});

app.get('/admin', (req, res) => res.redirect('/admin.html'));

/* 禁止把后端代码和依赖当作静态文件暴露 */
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
