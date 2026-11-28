import 'dotenv/config';
import express from 'express';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID, createHmac, timingSafeEqual } from 'node:crypto';
import bcrypt from 'bcryptjs';
import { pool } from './db.js';
import {
  DEFAULT_CONFIG, DEFAULT_NOTIFY, DEFAULT_SUMMARY, DEFAULT_EMAIL, DEFAULT_QUICK_PAID,
  NOTIFY_TYPES, ROLES, SKIN_KEYS, DEFAULT_BACKUP
} from './defaults.js';
import {
  setSessionCookie, clearSessionCookie, currentUser, rateLimit
} from './auth.js';
import {
  createBackup, listBackups, backupPath, readBackupFile, deleteBackup, pruneOld,
  readBackupConfig, scheduleBackups, setNotifyHook
} from './backup.js';
import { generateSecret, verifyTotp, otpauthUri } from './totp.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '../..');
const UPLOAD_DIR = path.resolve(__dirname, '..', 'uploads');
const PORT = Number(process.env.PORT || 3000);

const DUMMY_HASH = bcrypt.hashSync('dummy-password-for-timing', 10);

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.json({ limit: '4mb' }));
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

  let skin = String(src.skin == null ? d.skin : src.skin).trim().toLowerCase();
  if (SKIN_KEYS.indexOf(skin) < 0) skin = 'coral';

  const title = src.title == null ? d.title : safeStr(src.title, 30);
  const pageTitle = src.pageTitle == null ? d.pageTitle : safeStr(src.pageTitle, 40);
  const footer = src.footer == null ? d.footer : safeStr(src.footer, 80);
  if (!title || !pageTitle || !footer) return null;

  return { skin, accent, title, pageTitle, footer };
}

function normalizeCustomAmount(input) {
  const d = DEFAULT_CONFIG.customAmount;
  const src = input && typeof input === 'object' ? input : {};
  const enabled = input === undefined ? d.enabled : !!src.enabled;
  let min = Number(src.min);
  let max = Number(src.max);
  if (!Number.isFinite(min) || min <= 0) min = d.min;
  if (!Number.isFinite(max) || max <= 0) max = d.max;
  min = Math.round(Math.min(min, 100000) * 100) / 100;
  max = Math.round(Math.min(max, 100000) * 100) / 100;
  if (min > max) { const t = min; min = max; max = t; }
  return { enabled, min, max };
}

function normalizeGoal(input) {
  const d = DEFAULT_CONFIG.goal;
  const src = input && typeof input === 'object' ? input : {};
  const enabled = input === undefined ? d.enabled : !!src.enabled;
  const title = safeStr(src.title, 30) || d.title;
  let target = Number(src.target);
  if (!Number.isFinite(target) || target <= 0 || target > 10000000) target = d.target;
  target = Math.round(target * 100) / 100;
  return { enabled, title, target };
}

function normalizeWall(input) {
  const d = DEFAULT_CONFIG.wall;
  const src = input && typeof input === 'object' ? input : {};
  const enabled = input === undefined ? d.enabled : !!src.enabled;
  const title = safeStr(src.title, 30) || d.title;
  return { enabled, title };
}

function normalizeShare(input) {
  const d = DEFAULT_CONFIG.share;
  const src = input && typeof input === 'object' ? input : {};
  const enabled = input === undefined ? d.enabled : !!src.enabled;
  const text = safeStr(src.text, 120) || d.text;
  return { enabled, text };
}

function validateConfig(body) {
  if (!body || typeof body !== 'object') return null;
  const theme = validateTheme(body.theme);
  if (!theme) return null;

  let expireHours = body.expireHours === undefined ? DEFAULT_CONFIG.expireHours : Number(body.expireHours);
  if (!Number.isFinite(expireHours) || expireHours < 0 || expireHours > 720) return null;
  expireHours = Math.round(expireHours);

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
    const prefix = safeStr(p && p.prefix, 10);
    const qr = safeAsset(p && p.qr);
    const avatar = safeAsset(p && p.avatar);
    const sub = safeStr(p && p.sub, 60);
    if (!name || !id || !code || !prefix || !qr || !avatar || !sub) return null;
    if (!/^[A-Za-z0-9_-]+$/.test(id) || !/^[A-Za-z0-9_-]+$/.test(code)) return null;
    if (!/^[A-Z]{1,10}$/.test(prefix.toUpperCase())) return null;
    projects.push({ id, name, code, prefix: prefix.toUpperCase(), qr, avatar, sub });
  }
  return {
    amounts, theme, projects, expireHours,
    customAmount: normalizeCustomAmount(body.customAmount),
    goal: normalizeGoal(body.goal),
    wall: normalizeWall(body.wall),
    share: normalizeShare(body.share)
  };
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
    if (typeof parsed.expireHours !== 'number') parsed.expireHours = DEFAULT_CONFIG.expireHours;
    parsed.customAmount = normalizeCustomAmount(parsed.customAmount);
    parsed.goal = normalizeGoal(parsed.goal);
    parsed.wall = normalizeWall(parsed.wall);
    parsed.share = normalizeShare(parsed.share);
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
  if (type === 'none' || type === 'email') return { type, url: '' };

  const raw = String(url || '').trim();
  if (!raw || raw.length > 500) return null;
  let u;
  try { u = new URL(raw); } catch { return null; }
  if (u.protocol !== 'https:') return null;
  if (isPrivateHost(u.hostname)) return null;
  return { type, url: u.toString() };
}

function normalizeEmail(input) {
  const d = DEFAULT_EMAIL;
  const src = input && typeof input === 'object' ? input : {};
  const enabled = !!src.enabled;
  const host = safeStr(src.host, 120) || d.host;
  let port = Number(src.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) port = d.port;
  const secure = src.secure === undefined ? d.secure : !!src.secure;
  const user = safeStr(src.user, 200) || '';
  const pass = src.pass == null ? '' : String(src.pass).slice(0, 200);
  const to = safeStr(src.to, 300) || '';
  return { enabled, host, port, secure, user, pass, to };
}

function normalizeQuickPaid(input) {
  const d = DEFAULT_QUICK_PAID;
  const src = input && typeof input === 'object' ? input : {};
  let enabled = src.enabled === undefined ? d.enabled : !!src.enabled;
  let baseUrl = '';
  const raw = String(src.baseUrl == null ? '' : src.baseUrl).trim().replace(/\/+$/, '');
  if (raw) {
    try {
      const u = new URL(raw);
      if (u.protocol === 'https:' || u.protocol === 'http:') {
        baseUrl = u.origin + (u.pathname && u.pathname !== '/' ? u.pathname.replace(/\/+$/, '') : '');
      }
    } catch (e) { baseUrl = ''; }
  }
  if (!baseUrl) enabled = false;
  return { enabled, baseUrl };
}

/* 校验并规整周期总结配置，缺项补默认值 */
function normalizeSummary(input) {
  const def = JSON.parse(JSON.stringify(DEFAULT_SUMMARY));
  if (!input || typeof input !== 'object') return def;
  for (const p of ['daily', 'weekly', 'monthly']) {
    const src = input[p] || {};
    const d = def[p];
    d.enabled = !!src.enabled;
    const h = Number(src.hour);
    if (Number.isInteger(h) && h >= 0 && h <= 23) d.hour = h;
    if (p !== 'daily') {
      const dd = Number(src.day);
      if (p === 'weekly') {
        if (Number.isInteger(dd) && dd >= 0 && dd <= 6) d.day = dd;
      } else {
        if (Number.isInteger(dd) && dd >= 1 && dd <= 28) d.day = dd;
      }
    }
  }
  return def;
}

async function sendEmail(ec, subject, text) {
  if (!ec || !ec.host || !ec.to) return { ok: false, error: '邮件配置不完整' };
  try {
    const nodemailer = (await import('nodemailer')).default;
    const transporter = nodemailer.createTransport({
      host: ec.host,
      port: ec.port,
      secure: !!ec.secure,
      auth: ec.user ? { user: ec.user, pass: ec.pass } : undefined,
      connectionTimeout: 8000,
      greetingTimeout: 8000
    });
    await transporter.sendMail({
      from: ec.user || ec.to,
      to: ec.to,
      subject: subject || '赞赏系统通知',
      text
    });
    return { ok: true, status: 200 };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

async function sendWebhook(cfg, text, subject) {
  if (!cfg || cfg.type === 'none') return { ok: false, error: '未配置通知' };
  if (cfg.type === 'email') return sendEmail(cfg.email, subject, text);
  if (!cfg.url) return { ok: false, error: '未配置通知' };

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 5000);
  try {
    let headers = { 'Content-Type': 'application/json' };
    let body;
    if (cfg.type === 'feishu') {
      body = JSON.stringify({ msg_type: 'text', content: { text } });
    } else if (cfg.type === 'dingtalk' || cfg.type === 'wecom') {
      body = JSON.stringify({ msgtype: 'text', text: { content: text } });
    } else if (cfg.type === 'serverchan') {
      headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
      body = new URLSearchParams({ title: subject || '新赞赏订单', desp: text }).toString();
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

/* 聚合发送：Webhook 渠道与邮件可以同时启用 */
function hasNotifyChannel(cfg) {
  if (!cfg) return false;
  const webhook = ['feishu', 'dingtalk', 'wecom', 'serverchan', 'generic'];
  if (webhook.indexOf(cfg.type) > -1 && cfg.url) return true;
  if (cfg.type === 'email') return !!(cfg.email && cfg.email.host && cfg.email.to);
  return !!(cfg.email && cfg.email.enabled && cfg.email.host && cfg.email.to);
}

async function sendNotify(cfg, text, subject) {
  if (!cfg) return { ok: false, error: '未配置通知' };
  const tasks = [];
  const webhook = ['feishu', 'dingtalk', 'wecom', 'serverchan', 'generic'];
  if (webhook.indexOf(cfg.type) > -1 && cfg.url) {
    tasks.push({ name: 'webhook', p: sendWebhook(cfg, text, subject) });
  }
  if (cfg.email && cfg.email.enabled) {
    tasks.push({ name: 'email', p: sendEmail(cfg.email, subject || '赞赏系统通知', text) });
  }
  if (!tasks.length) return { ok: false, error: '未配置通知' };
  const results = await Promise.all(tasks.map(t => t.p));
  const failed = [];
  results.forEach((r, i) => {
    if (!r || !r.ok) failed.push(tasks[i].name + '：' + ((r && (r.error || ('HTTP ' + r.status))) || '发送失败'));
  });
  if (failed.length) return { ok: false, error: failed.join('；'), sent: results.length - failed.length };
  return { ok: true, sent: results.length };
}

/* 系统级告警（备份失败、异地同步失败、登录锁定等） */
async function pushNotify(text) {
  try {
    const cfg = await loadNotifyConfig();
    if (!hasNotifyChannel(cfg)) return;
    const result = await sendNotify(cfg, '【赞赏系统】' + text, '赞赏系统告警');
    if (!result.ok) console.error('[notify] 推送失败：', result.error || result.status);
  } catch (e) {
    console.error('[notify]', e.message);
  }
}

setNotifyHook(text => { pushNotify(text); });

/* ---------- 周期总结（日/周/月推送） ---------- */

function pad2(n) { return n < 10 ? '0' + n : '' + n; }

/* 本地时间 → "YYYY-MM-DD HH:MM:SS"，直接与 DATETIME 列比较，避免时区错位 */
function fmtDT(d) {
  return d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate()) +
    ' ' + pad2(d.getHours()) + ':' + pad2(d.getMinutes()) + ':' + pad2(d.getSeconds());
}
function fmtDate(d) { return d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate()); }
function fmtMD(d) { return pad2(d.getMonth() + 1) + '-' + pad2(d.getDate()); }

/* 计算各周期的时间窗起点（本地 00:00:00）与展示标签；统计口径必须绑定此窗口 */
function summaryWindow(period, now) {
  now = now || new Date();
  const start = new Date(now);
  let label;
  if (period === 'daily') {
    start.setHours(0, 0, 0, 0);
    label = fmtDate(start) + ' 00:00 至今';
  } else if (period === 'weekly') {
    const diff = (start.getDay() + 6) % 7; // 周一为一周起点
    start.setDate(start.getDate() - diff);
    start.setHours(0, 0, 0, 0);
    const end = new Date(start);
    end.setDate(end.getDate() + 6);
    label = fmtMD(start) + ' 至 ' + fmtMD(end) + '（截至今日）';
  } else {
    start.setDate(1);
    start.setHours(0, 0, 0, 0);
    label = start.getFullYear() + '年' + pad2(start.getMonth() + 1) + '月（截至今日）';
  }
  return { start: fmtDT(start), label };
}

/* 周期去重桶 key：同一桶内只发一次 */
function summaryBucket(period, now) {
  now = now || new Date();
  if (period === 'daily') return fmtDate(now);
  if (period === 'weekly') {
    const d = new Date(now);
    d.setDate(d.getDate() - ((d.getDay() + 6) % 7));
    return fmtDate(d);
  }
  return now.getFullYear() + '-' + pad2(now.getMonth() + 1);
}

async function summaryStats(period, now) {
  const { start } = summaryWindow(period, now);
  const [rows] = await pool.query(
    `SELECT COUNT(*) AS total_count,
            COALESCE(SUM(amount),0) AS total_sum,
            SUM(CASE WHEN status='paid' THEN 1 ELSE 0 END) AS paid_count,
            COALESCE(SUM(CASE WHEN status='paid' THEN amount ELSE 0 END),0) AS paid_sum,
            SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END) AS pending_count,
            COALESCE(SUM(CASE WHEN status='pending' THEN amount ELSE 0 END),0) AS pending_sum,
            SUM(CASE WHEN status='refunded' THEN 1 ELSE 0 END) AS refunded_count,
            COALESCE(SUM(CASE WHEN status='refunded' THEN amount ELSE 0 END),0) AS refunded_sum
     FROM orders WHERE created_at >= ?`,
    [start]
  );
  const r = rows[0] || {};
  const [proj] = await pool.query(
    `SELECT project, COUNT(*) AS count, COALESCE(SUM(amount),0) AS sum
     FROM orders WHERE created_at >= ?
     GROUP BY project ORDER BY sum DESC LIMIT 20`,
    [start]
  );
  return {
    totalCount: Number(r.total_count) || 0,
    totalSum: Number(r.total_sum) || 0,
    paidCount: Number(r.paid_count) || 0,
    paidSum: Number(r.paid_sum) || 0,
    pendingCount: Number(r.pending_count) || 0,
    pendingSum: Number(r.pending_sum) || 0,
    refundedCount: Number(r.refunded_count) || 0,
    refundedSum: Number(r.refunded_sum) || 0,
    byProject: proj.map(p => ({ project: p.project, count: Number(p.count), sum: Number(p.sum) }))
  };
}

const SUMMARY_TITLE = { daily: '赞赏日报', weekly: '赞赏周报', monthly: '赞赏月报' };

function buildSummaryText(period, stats, windowLabel, now) {
  const lines = ['【' + (SUMMARY_TITLE[period] || '赞赏总结') + '】'];
  lines.push('统计范围：' + windowLabel);
  lines.push('总笔数：' + stats.totalCount + ' 笔，总金额：¥' + stats.totalSum.toFixed(2));
  lines.push('已到账：' + stats.paidCount + ' 笔 ¥' + stats.paidSum.toFixed(2) +
    '，待核对：' + stats.pendingCount + ' 笔 ¥' + stats.pendingSum.toFixed(2));
  if (stats.refundedCount) {
    lines.push('已退款：' + stats.refundedCount + ' 笔 ¥' + stats.refundedSum.toFixed(2));
  }
  if (stats.byProject.length) {
    lines.push('项目分布：');
    for (const p of stats.byProject) lines.push('- ' + p.project + '：' + p.count + ' 笔 ¥' + p.sum.toFixed(2));
  } else {
    lines.push('项目分布：暂无订单');
  }
  lines.push('生成时间：' + (now || new Date()).toLocaleString('zh-CN'));
  return lines.join('\n');
}

/* 读取并规整当前通知配置（summary 缺项补默认） */
async function loadNotifyConfig() {
  const cfg = await readSetting('notify_config', DEFAULT_NOTIFY);
  const base = cfg && typeof cfg === 'object' ? { ...cfg } : { ...DEFAULT_NOTIFY };
  if (NOTIFY_TYPES.indexOf(base.type) < 0) base.type = 'none';
  if (typeof base.url !== 'string') base.url = '';
  base.summary = normalizeSummary(base.summary);
  base.email = normalizeEmail(base.email);
  if (base.type === 'email') base.email.enabled = true;
  base.quickPaid = normalizeQuickPaid(base.quickPaid);
  return base;
}

async function sendSummary(period, now) {
  const cfg = await loadNotifyConfig();
  if (!hasNotifyChannel(cfg)) return { ok: false, error: '未配置通知' };
  const win = summaryWindow(period, now);
  const stats = await summaryStats(period, now);
  const text = buildSummaryText(period, stats, win.label, now);
  const result = await sendNotify(cfg, text, '赞赏' + ({ daily: '日报', weekly: '周报', monthly: '月报' }[period] || '总结'));
  if (!result.ok) console.error('[summary] 推送失败：', period, result.error || result.status);
  return result;
}

/* 各周期上次成功发送的桶 key，持久化以防重启重复发送 */
async function getSummaryLast() { return (await readSetting('summary_last', {})) || {}; }
async function setSummaryLastSent(period, bucket) {
  const cur = await getSummaryLast();
  cur[period] = bucket;
  await writeSetting('summary_last', cur);
}

let summaryTimer = null;
function scheduleSummary() {
  if (summaryTimer) { clearInterval(summaryTimer); summaryTimer = null; }
  summaryTimer = setInterval(summaryTick, 60 * 1000);
  summaryTimer.unref?.();
  summaryTick().catch(e => console.error('[summary:tick]', e.message));
}

async function summaryTick() {
  try {
    const cfg = await loadNotifyConfig();
    const s = cfg.summary || normalizeSummary(null);
    const now = new Date();
    const last = await getSummaryLast();
    for (const period of ['daily', 'weekly', 'monthly']) {
      const conf = s[period];
      if (!conf || !conf.enabled) continue;
      if (now.getHours() !== conf.hour) continue;
      if (period === 'weekly' && now.getDay() !== conf.day) continue;
      if (period === 'monthly' && now.getDate() !== conf.day) continue;
      const bucket = summaryBucket(period, now);
      if (last[period] === bucket) continue;
      const result = await sendSummary(period, now);
      if (result.ok) {
        await setSummaryLastSent(period, bucket);
        console.log('[summary] 已推送 ' + period + ' 总结');
      }
    }
  } catch (e) {
    console.error('[summary:tick]', e.message);
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

app.get('/api/stats/summary', requireUser, async (req, res) => {
  try {
    await expireStale(false);
    const [[row]] = await pool.query(
      `SELECT COUNT(*) AS total_count,
              COALESCE(SUM(amount), 0) AS total_sum,
              COALESCE(SUM(CASE WHEN status = 'paid' THEN amount END), 0) AS paid_sum,
              COALESCE(SUM(status = 'paid'), 0) AS paid_count,
              COALESCE(SUM(status = 'pending'), 0) AS pending_count,
              COALESCE(SUM(status = 'expired'), 0) AS expired_count,
              COALESCE(SUM(status = 'refunded'), 0) AS refunded_count,
              COALESCE(SUM(CASE WHEN status = 'refunded' THEN amount ELSE 0 END), 0) AS refunded_sum,
              COALESCE(SUM(DATE(created_at) = CURDATE()), 0) AS today_count,
              COALESCE(SUM(CASE WHEN DATE(created_at) = CURDATE() THEN amount ELSE 0 END), 0) AS today_sum,
              COALESCE(SUM(created_at >= DATE_FORMAT(CURDATE(), '%Y-%m-01')), 0) AS month_count,
              COALESCE(SUM(CASE WHEN created_at >= DATE_FORMAT(CURDATE(), '%Y-%m-01') THEN amount ELSE 0 END), 0) AS month_sum
       FROM orders`
    );
    const r2 = v => Math.round(Number(v) * 100) / 100;
    const totalCount = Number(row.total_count);
    const totalSum = Number(row.total_sum);
    res.json({
      totalCount,
      totalSum: r2(totalSum),
      paidSum: r2(row.paid_sum),
      paidCount: Number(row.paid_count),
      pendingCount: Number(row.pending_count),
      expiredCount: Number(row.expired_count),
      refundedCount: Number(row.refunded_count),
      refundedSum: r2(row.refunded_sum),
      todayCount: Number(row.today_count),
      todaySum: r2(row.today_sum),
      monthCount: Number(row.month_count),
      monthSum: r2(row.month_sum),
      avg: totalCount ? r2(totalSum / totalCount) : 0,
      paidAvg: Number(row.paid_count) ? r2(Number(row.paid_sum) / Number(row.paid_count)) : 0
    });
  } catch (e) {
    console.error('[stats:summary]', e.message);
    res.status(500).json({ error: '读取失败' });
  }
});

/* 渠道来源分析（近 N 天，按来源聚合） */
app.get('/api/stats/sources', requireUser, async (req, res) => {
  let days = Number(req.query.days);
  if ([7, 30, 90].indexOf(days) < 0) days = 30;
  try {
    const [rows] = await pool.query(
      `SELECT COALESCE(NULLIF(source, ''), '(直接访问)') AS src,
              COUNT(*) AS cnt,
              COALESCE(SUM(amount), 0) AS sum,
              COALESCE(SUM(status = 'paid'), 0) AS paid_cnt,
              COALESCE(SUM(CASE WHEN status = 'paid' THEN amount ELSE 0 END), 0) AS paid_sum
       FROM orders
       WHERE created_at >= DATE_SUB(NOW(), INTERVAL ` + days + ` DAY)
       GROUP BY src ORDER BY cnt DESC LIMIT 20`
    );
    const r2 = v => Math.round(Number(v) * 100) / 100;
    res.json({
      days,
      items: rows.map(r => ({
        source: r.src,
        count: Number(r.cnt),
        sum: r2(r.sum),
        paidCount: Number(r.paid_cnt),
        paidSum: r2(r.paid_sum)
      }))
    });
  } catch (e) {
    console.error('[stats:sources]', e.message);
    res.status(500).json({ error: '读取失败' });
  }
});

/* 导出对账 CSV，可按月（YYYY-MM），不传则导出全部 */
app.get('/api/orders/export', requireUser, async (req, res) => {
  const month = String(req.query.month || '').trim();
  let where = '';
  const params = [];
  if (month) {
    if (!/^\d{4}-(0[1-9]|1[0-2])$/.test(month)) {
      return res.status(400).json({ error: '月份格式应为 YYYY-MM' });
    }
    const y = Number(month.slice(0, 4));
    const m = Number(month.slice(5, 7));
    const start = new Date(y, m - 1, 1, 0, 0, 0);
    const end = new Date(y, m, 1, 0, 0, 0);
    where = 'WHERE created_at >= ? AND created_at < ?';
    params.push(fmtDT(start), fmtDT(end));
  }
  try {
    const [rows] = await pool.query(
      `SELECT order_no, project, amount, status, source, note, admin_note, created_at, paid_at
       FROM orders ` + where + ` ORDER BY created_at DESC`, params
    );
    const statusMap = { pending: '待核对', paid: '已到账', expired: '已过期', refunded: '已退款' };
    const cell = v => {
      const s = v == null ? '' : String(v);
      return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
    };
    const head = ['订单号', '项目', '金额', '状态', '来源', '留言', '内部备注', '创建时间', '到账时间'];
    const lines = [head.join(',')];
    for (const r of rows) {
      lines.push([
        r.order_no, r.project, r.amount, statusMap[r.status] || r.status,
        r.source || '', r.note || '', r.admin_note || '',
        r.created_at ? fmtDT(new Date(r.created_at)) : '',
        r.paid_at ? fmtDT(new Date(r.paid_at)) : ''
      ].map(cell).join(','));
    }
    const fname = 'zan-orders-' + (month || 'all') + '.csv';
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="' + fname + '"');
    res.send('\ufeff' + lines.join('\r\n'));
  } catch (e) {
    console.error('[orders:export]', e.message);
    res.status(500).json({ error: '导出失败' });
  }
});

/* ---------- 登录 ---------- */

const LOGIN_MAX_FAIL = 5;
const LOGIN_LOCK_MS = 15 * 60 * 1000;
const loginFails = new Map(); // key: ip|username -> { count, lockUntil }

function loginFailKey(ip, username) {
  return String(ip) + '|' + String(username || '').toLowerCase();
}

function registerLoginFail(key, username, ip) {
  const now = Date.now();
  const item = loginFails.get(key) || { count: 0, lockUntil: 0 };
  if (item.lockUntil && item.lockUntil <= now) { item.count = 0; item.lockUntil = 0; }
  item.count += 1;
  if (item.count >= LOGIN_MAX_FAIL) {
    item.lockUntil = now + LOGIN_LOCK_MS;
    item.count = 0;
    pushNotify('账号 ' + username + ' 连续登录失败 ' + LOGIN_MAX_FAIL + ' 次，已锁定 15 分钟（IP ' + ip + '）');
  }
  loginFails.set(key, item);
  return item;
}

app.post('/api/login', async (req, res) => {
  const ip = req.ip || 'unknown';
  if (!rateLimit('login:' + ip, 30, 15 * 60 * 1000)) {
    return res.status(429).json({ error: '尝试次数过多，请 15 分钟后再试' });
  }

  const username = String(req.body?.username || '').trim();
  const password = String(req.body?.password || '');
  const code = String(req.body?.code || '').trim();
  if (!username || !password || username.length > 50 || password.length > 200) {
    return res.status(400).json({ error: '请输入用户名和密码' });
  }

  const key = loginFailKey(ip, username);
  const fail = loginFails.get(key);
  if (fail && fail.lockUntil > Date.now()) {
    const mins = Math.ceil((fail.lockUntil - Date.now()) / 60000);
    return res.status(429).json({ error: '该账号已锁定，请 ' + mins + ' 分钟后再试' });
  }

  try {
    const [rows] = await pool.query(
      'SELECT id, username, password_hash, role, totp_secret, totp_enabled FROM admins WHERE username = ? LIMIT 1',
      [username]
    );
    const row = rows[0];
    const ok = await bcrypt.compare(password, row ? row.password_hash : DUMMY_HASH);
    if (!row || !ok) {
      registerLoginFail(key, username, ip);
      await audit(username, 'login_fail', '密码错误或账号不存在', ip);
      return res.status(401).json({ error: '用户名或密码错误' });
    }

    if (row.totp_enabled) {
      if (!code) {
        return res.status(401).json({ error: '请输入动态验证码', need2fa: true });
      }
      if (!verifyTotp(row.totp_secret, code)) {
        registerLoginFail(key, username, ip);
        await audit(username, 'login_fail', '动态验证码错误', ip);
        return res.status(401).json({ error: '动态验证码不正确', need2fa: true });
      }
    }

    loginFails.delete(key);
    setSessionCookie(res, row);
    await audit(row.username, 'login', '登录成功（' + row.role + '）', ip);
    res.json({ ok: true, username: row.username, role: row.role, totpEnabled: !!row.totp_enabled });
  } catch (e) {
    console.error('[login]', e.message);
    res.status(500).json({ error: '服务异常，请稍后再试' });
  }
});

app.post('/api/logout', (req, res) => {
  clearSessionCookie(res);
  res.json({ ok: true });
});

app.get('/api/me', requireUser, async (req, res) => {
  let totpEnabled = false;
  try {
    const [rows] = await pool.query('SELECT totp_enabled FROM admins WHERE id = ? LIMIT 1', [req.user.id]);
    totpEnabled = !!(rows[0] && rows[0].totp_enabled);
  } catch (e) {}
  res.json({ username: req.user.username, role: req.user.role, totpEnabled });
});

/* ---------- 两步验证（TOTP） ---------- */

app.post('/api/me/2fa/setup', requireUser, async (req, res) => {
  try {
    const secret = generateSecret();
    await pool.query(
      'UPDATE admins SET totp_secret = ?, totp_enabled = 0 WHERE id = ?', [secret, req.user.id]
    );
    res.json({ ok: true, secret, uri: otpauthUri(secret, req.user.username) });
  } catch (e) {
    console.error('[2fa:setup]', e.message);
    res.status(500).json({ error: '生成失败' });
  }
});

app.post('/api/me/2fa/enable', requireUser, async (req, res) => {
  const code = String(req.body?.code || '').trim();
  try {
    const [rows] = await pool.query('SELECT totp_secret FROM admins WHERE id = ? LIMIT 1', [req.user.id]);
    const secret = rows[0] && rows[0].totp_secret;
    if (!secret) return res.status(400).json({ error: '请先获取密钥' });
    if (!verifyTotp(secret, code)) return res.status(400).json({ error: '验证码不正确，请确认手机时间准确' });
    await pool.query('UPDATE admins SET totp_enabled = 1 WHERE id = ?', [req.user.id]);
    await audit(req.user.username, 'totp_enable', '开启两步验证', req.ip);
    res.json({ ok: true });
  } catch (e) {
    console.error('[2fa:enable]', e.message);
    res.status(500).json({ error: '开启失败' });
  }
});

app.post('/api/me/2fa/disable', requireUser, async (req, res) => {
  const password = String(req.body?.password || '');
  try {
    const [rows] = await pool.query('SELECT password_hash FROM admins WHERE id = ? LIMIT 1', [req.user.id]);
    const ok = rows.length && await bcrypt.compare(password, rows[0].password_hash);
    if (!ok) return res.status(400).json({ error: '密码不正确' });
    await pool.query('UPDATE admins SET totp_secret = NULL, totp_enabled = 0 WHERE id = ?', [req.user.id]);
    await audit(req.user.username, 'totp_disable', '关闭两步验证', req.ip);
    res.json({ ok: true });
  } catch (e) {
    console.error('[2fa:disable]', e.message);
    res.status(500).json({ error: '关闭失败' });
  }
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

/* 公开：留言墙（仅已到账且带留言的订单） */
app.get('/api/wall', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const cfg = await readConfig();
    if (!cfg.wall || !cfg.wall.enabled) return res.json({ enabled: false, items: [] });
    const [rows] = await pool.query(
      `SELECT project, note, created_at FROM orders
       WHERE status = 'paid' AND note IS NOT NULL AND note <> ''
       ORDER BY created_at DESC LIMIT 30`
    );
    res.json({
      enabled: true,
      title: cfg.wall.title,
      items: rows.map(r => ({ project: r.project, note: r.note, time: r.created_at }))
    });
  } catch (e) {
    console.error('[wall]', e.message);
    res.status(500).json({ enabled: false, items: [] });
  }
});

/* 公开：本月赞赏目标进度（按已到账金额） */
app.get('/api/goal', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const cfg = await readConfig();
    if (!cfg.goal || !cfg.goal.enabled || !(cfg.goal.target > 0)) {
      return res.json({ enabled: false });
    }
    const [[row]] = await pool.query(
      `SELECT COALESCE(SUM(amount), 0) AS cur FROM orders
       WHERE status = 'paid' AND created_at >= DATE_FORMAT(CURDATE(), '%Y-%m-01')`
    );
    res.json({
      enabled: true,
      title: cfg.goal.title,
      target: cfg.goal.target,
      current: Math.round(Number(row.cur) * 100) / 100
    });
  } catch (e) {
    console.error('[goal]', e.message);
    res.json({ enabled: false });
  }
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
  res.json(await loadNotifyConfig());
});

app.put('/api/notify', requireUser, requireRole('admin'), async (req, res) => {
  const cfg = validateWebhook(String(req.body?.type || ''), req.body?.url);
  if (!cfg) {
    return res.status(400).json({ error: '通知地址必须是 https 公网地址，且类型正确' });
  }
  try {
    const existing = await readSetting('notify_config', DEFAULT_NOTIFY);
    cfg.email = normalizeEmail(req.body?.email === undefined ? (existing && existing.email) : req.body.email);
    if (cfg.type === 'email') cfg.email.enabled = true;
    cfg.quickPaid = normalizeQuickPaid(req.body?.quickPaid === undefined
      ? (existing && existing.quickPaid) : req.body.quickPaid);
    cfg.summary = req.body?.summary === undefined
      ? normalizeSummary(existing && existing.summary)
      : normalizeSummary(req.body.summary);
    if (cfg.email.enabled && (!cfg.email.host || !cfg.email.to)) {
      return res.status(400).json({ error: '启用邮件通知需填写 SMTP 服务器和收件人' });
    }
    await writeSetting('notify_config', cfg);
    const channels = [];
    if (cfg.type !== 'none' && cfg.type !== 'email') channels.push(cfg.type);
    if (cfg.email.enabled) channels.push('email');
    await audit(req.user.username, 'notify_update',
      channels.length ? ('通知渠道：' + channels.join(' + ')) : '关闭通知', req.ip);
    scheduleSummary();
    res.json({ ok: true, config: cfg });
  } catch (e) {
    console.error('[notify:save]', e.message);
    res.status(500).json({ error: '保存失败' });
  }
});

app.post('/api/notify/test', requireUser, requireRole('admin'), async (req, res) => {
  const cfg = await loadNotifyConfig();
  const result = await sendNotify(cfg,
    '这是一条测试消息\n来自赞赏管理台 · ' + new Date().toLocaleString('zh-CN'),
    '赞赏系统测试');
  if (!result.ok) {
    return res.status(400).json({ error: result.error || ('推送失败，接口返回 ' + result.status) });
  }
  res.json({ ok: true, sent: result.sent });
});

/* 立即推送一份指定周期的总结（用于面板验证） */
app.post('/api/notify/summary/test', requireUser, requireRole('admin'), async (req, res) => {
  const period = String(req.body?.period || 'daily');
  if (['daily', 'weekly', 'monthly'].indexOf(period) < 0) {
    return res.status(400).json({ error: '周期参数不正确' });
  }
  const cfg = await loadNotifyConfig();
  if (!hasNotifyChannel(cfg)) {
    return res.status(400).json({ error: '请先配置通知方式' });
  }
  const result = await sendSummary(period);
  if (!result.ok) {
    return res.status(400).json({ error: result.error || ('推送失败，接口返回 ' + result.status) });
  }
  res.json({ ok: true });
});

/* ---------- 订单 ---------- */

/* 超时未到账自动归档；由列表请求与定时任务共同触发，60 秒内不重复扫描 */
let lastExpireSweep = 0;
async function expireStale(force) {
  const now = Date.now();
  if (!force && now - lastExpireSweep < 60000) return;
  lastExpireSweep = now;
  try {
    const cfg = await readConfig();
    const hours = Number(cfg.expireHours);
    if (!Number.isFinite(hours) || hours <= 0) return;
    const [r] = await pool.query(
      "UPDATE orders SET status = 'expired' WHERE status = 'pending' AND created_at < DATE_SUB(NOW(), INTERVAL ? HOUR)",
      [hours]
    );
    if (r.affectedRows) console.log('[orders] 已归档超时未到账 ' + r.affectedRows + ' 笔');
  } catch (e) {
    console.error('[orders:expire]', e.message);
  }
}

app.get('/api/orders/status/:orderNo', async (req, res) => {
  const ip = req.ip || 'unknown';
  if (!rateLimit('ostatus:' + ip, 120, 60 * 1000)) return res.status(429).json({ error: '查询过于频繁' });
  const orderNo = String(req.params.orderNo || '');
  if (!/^[A-Za-z0-9-]{6,40}$/.test(orderNo)) return res.status(400).json({ error: '订单号不正确' });
  try {
    const [rows] = await pool.query('SELECT status FROM orders WHERE order_no = ? LIMIT 1', [orderNo]);
    if (!rows.length) return res.json({ status: 'unknown' });
    res.setHeader('Cache-Control', 'no-store');
    res.json({ status: rows[0].status });
  } catch (e) {
    console.error('[orders:status]', e.message);
    res.status(500).json({ error: '查询失败' });
  }
});

/* 推送内一键标记到账（签名链接，无需登录）
   采用「GET 确认页 + POST 提交」两段式，避免聊天工具/邮件客户端预抓取链接时误改状态 */
function verifyQuickPaid(req) {
  const id = Number(req.params.id);
  const exp = Number(req.query.exp);
  const t = String(req.query.t || '');
  if (!Number.isInteger(id) || id <= 0) return { ok: false, error: '链接无效' };
  if (!Number.isFinite(exp) || exp < Date.now()) return { ok: false, error: '链接已过期，请到后台手动标记' };
  const expect = signQuickPaid(id, exp);
  let same = false;
  try {
    same = t.length === expect.length && timingSafeEqual(Buffer.from(t), Buffer.from(expect));
  } catch (e) { same = false; }
  if (!same) return { ok: false, error: '链接无效' };
  return { ok: true, id };
}

function renderQuickPaid(res, status, title, inner) {
  res.status(status).send(
    '<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<title>赞赏系统</title><div style="font-family:system-ui,-apple-system,sans-serif;padding:56px 24px;' +
    'text-align:center;color:#333;line-height:1.7"><div style="font-size:44px;margin-bottom:12px">' +
    (status === 200 ? '✅' : '⚠️') + '</div><h2 style="font-size:18px;margin:0 0 8px">' + title + '</h2>' +
    inner + '<p style="color:#999;font-size:13px;margin:14px 0 0">可以关闭此页面</p></div>'
  );
}

app.get('/api/orders/quick-paid/:id', async (req, res) => {
  const v = verifyQuickPaid(req);
  if (!v.ok) return renderQuickPaid(res, 400, v.error, '');
  try {
    const [rows] = await pool.query('SELECT status FROM orders WHERE id = ? LIMIT 1', [v.id]);
    if (!rows.length) return renderQuickPaid(res, 400, '订单不存在', '');
    if (rows[0].status === 'paid') return renderQuickPaid(res, 200, '该订单已是到账状态', '');
    if (rows[0].status !== 'pending') return renderQuickPaid(res, 400, '该订单当前状态无法标记到账', '');
    const action = '/api/orders/quick-paid/' + v.id +
      '?exp=' + encodeURIComponent(String(req.query.exp)) +
      '&t=' + encodeURIComponent(String(req.query.t));
    renderQuickPaid(res, 200, '确认将这笔订单标记为已到账？',
      '<form method="post" action="' + action + '" style="margin-top:20px">' +
      '<button type="submit" style="height:44px;padding:0 26px;border:none;border-radius:10px;' +
      'background:#2e8b57;color:#fff;font-size:15px;cursor:pointer">确认标记到账</button></form>');
  } catch (e) {
    console.error('[orders:quick-paid:get]', e.message);
    renderQuickPaid(res, 400, '操作失败，请稍后再试', '');
  }
});

app.post('/api/orders/quick-paid/:id', async (req, res) => {
  const v = verifyQuickPaid(req);
  if (!v.ok) return renderQuickPaid(res, 400, v.error, '');
  try {
    const [result] = await pool.query(
      "UPDATE orders SET status = 'paid', paid_at = NOW() WHERE id = ? AND status = 'pending'", [v.id]
    );
    if (!result.affectedRows) {
      const [rows] = await pool.query('SELECT status FROM orders WHERE id = ? LIMIT 1', [v.id]);
      if (!rows.length) return renderQuickPaid(res, 400, '订单不存在', '');
      if (rows[0].status === 'paid') return renderQuickPaid(res, 200, '该订单已是到账状态', '');
      return renderQuickPaid(res, 400, '该订单当前状态无法标记到账', '');
    }
    await audit('quick-link', 'order_status', '订单 #' + v.id + ' 通过推送链接标记到账', req.ip);
    renderQuickPaid(res, 200, '已标记到账', '');
  } catch (e) {
    console.error('[orders:quick-paid:post]', e.message);
    renderQuickPaid(res, 400, '操作失败，请稍后再试', '');
  }
});

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
  let note = String(req.body?.note || '').trim().slice(0, 100);
  if (/[<>]/.test(note)) note = '';

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
      'INSERT INTO orders (order_no, project, amount, note, source, ip) VALUES (?, ?, ?, ?, ?, ?)',
      [orderNo, project, amount.toFixed(2), note || null, source || null, ip.slice(0, 45)]
    );

    notifyNewOrder({ id: result.insertId, orderNo, project, amount, source, note });

    res.status(201).json({ ok: true, id: result.insertId });
  } catch (e) {
    console.error('[order:create]', e.message);
    res.status(500).json({ error: '写入失败' });
  }
});

const QUICK_PAID_TTL_MS = 7 * 24 * 3600 * 1000;

function signQuickPaid(id, exp) {
  return createHmac('sha256', process.env.SESSION_SECRET || 'zan-quick-paid')
    .update('qp:' + id + ':' + exp).digest('hex').slice(0, 32);
}

function quickPaidLink(id, baseUrl) {
  if (!id || !baseUrl) return '';
  const exp = Date.now() + QUICK_PAID_TTL_MS;
  return baseUrl + '/api/orders/quick-paid/' + id + '?exp=' + exp + '&t=' + signQuickPaid(id, exp);
}

async function notifyNewOrder({ id, orderNo, project, amount, source, note }) {
  try {
    const cfg = await loadNotifyConfig();
    if (!hasNotifyChannel(cfg)) return;
    let text = '【新赞赏】' + project + ' ¥' + amount + '\n' +
      '订单号：' + orderNo + '\n' +
      (note ? '留言：' + note + '\n' : '') +
      (source ? '来源：' + source + '\n' : '') +
      '时间：' + new Date().toLocaleString('zh-CN');
    if (cfg.quickPaid && cfg.quickPaid.enabled) {
      const link = quickPaidLink(id, cfg.quickPaid.baseUrl);
      if (link) text += '\n一键标记到账（7 天内有效）：\n' + link;
    }
    const result = await sendNotify(cfg, text, '新赞赏 ¥' + amount + ' · ' + project);
    if (!result.ok) console.error('[notify] 推送失败：', result.error || result.status);
  } catch (e) {
    console.error('[notify]', e.message);
  }
}

app.get('/api/orders', requireUser, async (req, res) => {
  try {
    await expireStale(false);
    const [rows] = await pool.query(
      `SELECT id, order_no, project, amount, status, note, admin_note, proof, source,
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
        adminNote: r.admin_note || '',
        proof: r.proof || '',
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
  const hasAdminNote = Object.prototype.hasOwnProperty.call(body, 'adminNote');
  if (!hasStatus && !hasNote && !hasAdminNote) return res.status(400).json({ error: '没有需要修改的内容' });

  let status = null;
  let note = null;
  let adminNote = null;
  if (hasStatus) {
    status = String(body.status);
    if (status !== 'paid' && status !== 'pending' && status !== 'refunded') {
      return res.status(400).json({ error: '状态不正确' });
    }
  }
  if (hasNote) {
    note = String(body.note == null ? '' : body.note).trim();
    if (note.length > 200) return res.status(400).json({ error: '备注最多 200 字' });
    if (/[<>]/.test(note)) return res.status(400).json({ error: '备注不能包含尖括号' });
    note = note || null;
  }
  if (hasAdminNote) {
    adminNote = String(body.adminNote == null ? '' : body.adminNote).trim();
    if (adminNote.length > 500) return res.status(400).json({ error: '内部备注最多 500 字' });
    if (/[<>]/.test(adminNote)) return res.status(400).json({ error: '内部备注不能包含尖括号' });
    adminNote = adminNote || null;
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
  if (hasAdminNote) {
    sets.push('admin_note = ?');
    params.push(adminNote);
  }
  params.push(id);

  try {
    const [result] = await pool.query(
      'UPDATE orders SET ' + sets.join(', ') + ' WHERE id = ?', params
    );
    if (!result.affectedRows) return res.status(404).json({ error: '记录不存在' });

    if (hasStatus) {
      await audit(req.user.username, 'order_status',
        '订单 #' + id + ' 标记为 ' +
        ({ paid: '已到账', pending: '待核对', refunded: '已退款' }[status] || status), req.ip);
    }
    if (hasNote) {
      await audit(req.user.username, 'order_note',
        '订单 #' + id + ' 备注：' + (note || '（清空）'), req.ip);
    }
    if (hasAdminNote) {
      await audit(req.user.username, 'order_admin_note',
        '订单 #' + id + ' 内部备注：' + (adminNote || '（清空）'), req.ip);
    }
    res.json({
      ok: true,
      status: hasStatus ? status : undefined,
      note: hasNote ? (note || '') : undefined,
      adminNote: hasAdminNote ? (adminNote || '') : undefined
    });
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

/* ---------- 到账凭证 ---------- */

const PROOF_RE = /^[a-f0-9-]{36}\.(jpg|png|webp)$/;

function ensureUploadDir() {
  if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

app.post('/api/orders/:id/proof', requireUser, requireRole('admin', 'editor'), async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: '无效的记录' });

  const data = String(req.body?.data || '');
  const m = /^data:image\/(png|jpe?g|webp);base64,([A-Za-z0-9+/=]+)$/.exec(data);
  if (!m) return res.status(400).json({ error: '请上传 png / jpg / webp 图片' });
  const ext = m[1] === 'jpeg' ? 'jpg' : m[1];
  const buf = Buffer.from(m[2], 'base64');
  if (!buf.length || buf.length > 2.8 * 1024 * 1024) {
    return res.status(400).json({ error: '图片需小于 2.8MB' });
  }

  try {
    const [rows] = await pool.query('SELECT proof FROM orders WHERE id = ? LIMIT 1', [id]);
    if (!rows.length) return res.status(404).json({ error: '记录不存在' });

    ensureUploadDir();
    const file = randomUUID() + '.' + ext;
    fs.writeFileSync(path.join(UPLOAD_DIR, file), buf);
    await pool.query('UPDATE orders SET proof = ? WHERE id = ?', [file, id]);

    const old = rows[0].proof;
    if (old && PROOF_RE.test(old)) {
      try { fs.unlinkSync(path.join(UPLOAD_DIR, old)); } catch (e) {}
    }
    await audit(req.user.username, 'order_proof', '订单 #' + id + ' 上传到账凭证', req.ip);
    res.json({ ok: true, proof: file });
  } catch (e) {
    console.error('[orders:proof]', e.message);
    res.status(500).json({ error: '上传失败' });
  }
});

app.get('/api/orders/:id/proof', requireUser, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: '无效的记录' });
  try {
    const [rows] = await pool.query('SELECT proof FROM orders WHERE id = ? LIMIT 1', [id]);
    const file = rows[0] && rows[0].proof;
    if (!file || !PROOF_RE.test(file)) return res.status(404).json({ error: '没有凭证' });
    const full = path.join(UPLOAD_DIR, file);
    if (!fs.existsSync(full)) return res.status(404).json({ error: '文件不存在' });
    res.sendFile(full);
  } catch (e) {
    console.error('[orders:proof:get]', e.message);
    res.status(500).json({ error: '读取失败' });
  }
});

app.delete('/api/orders/:id/proof', requireUser, requireRole('admin', 'editor'), async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: '无效的记录' });
  try {
    const [rows] = await pool.query('SELECT proof FROM orders WHERE id = ? LIMIT 1', [id]);
    if (!rows.length) return res.status(404).json({ error: '记录不存在' });
    const old = rows[0].proof;
    if (old && PROOF_RE.test(old)) {
      try { fs.unlinkSync(path.join(UPLOAD_DIR, old)); } catch (e) {}
    }
    await pool.query('UPDATE orders SET proof = NULL WHERE id = ?', [id]);
    await audit(req.user.username, 'order_proof', '订单 #' + id + ' 删除到账凭证', req.ip);
    res.json({ ok: true });
  } catch (e) {
    console.error('[orders:proof:del]', e.message);
    res.status(500).json({ error: '删除失败' });
  }
});

/* ---------- 导入对账单自动核对 ---------- */

function parseCsvLine(line) {
  const cells = [];
  let cur = '', inQ = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inQ) {
      if (ch === '"') { if (line[i + 1] === '"') { cur += '"'; i++; } else inQ = false; }
      else cur += ch;
    } else {
      if (ch === '"') inQ = true;
      else if (ch === ',') { cells.push(cur); cur = ''; }
      else cur += ch;
    }
  }
  cells.push(cur);
  return cells;
}

function findCol(headers, re) {
  for (let i = 0; i < headers.length; i++) {
    if (re.test(String(headers[i] || ''))) return i;
  }
  return -1;
}

function parseAmount(s) {
  const n = parseFloat(String(s == null ? '' : s).replace(/[¥￥,\s]/g, ''));
  return Number.isFinite(n) ? n : NaN;
}

function parseTime(s) {
  if (!s) return null;
  const d = new Date(String(s).trim().replace(/\//g, '-'));
  return isNaN(d.getTime()) ? null : d;
}

// 把 "YYYY-MM-DD HH:MM:SS" 当作 UTC 解析成毫秒，用于跨时区一致的墙上时间求差
function naiveMs(s) {
  if (!s) return NaN;
  const m = /^(\d{4})-(\d{1,2})-(\d{1,2})[ T](\d{1,2}):(\d{1,2})(?::(\d{1,2}))?/.exec(String(s).trim());
  if (!m) return NaN;
  return Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +(m[6] || 0));
}

function parseStatement(text) {
  const raw = String(text || '').replace(/^\uFEFF/, '');
  const lines = raw.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  if (!lines.length) return [];
  let hi = 0;
  for (let i = 0; i < Math.min(lines.length, 5); i++) {
    if (/金额|交易时间|订单号|收款/.test(lines[i])) { hi = i; break; }
  }
  const headers = parseCsvLine(lines[hi]);
  const idx = {
    time: findCol(headers, /交易时间|下单时间|创建时间|付款时间/),
    amount: findCol(headers, /金额|实付|收款金额|订单金额/),
    note: findCol(headers, /备注|商家备注/),
    project: findCol(headers, /商品|收款项目|项目名称|商品名称/),
    wechat: findCol(headers, /微信订单号|支付订单号|交易单号/),
    merchant: findCol(headers, /商户订单号|商户单号/)
  };
  const rows = [];
  for (let i = hi + 1; i < lines.length; i++) {
    const c = parseCsvLine(lines[i]);
    if (!c.length || c.every(x => !x)) continue;
    rows.push({
      time: idx.time >= 0 ? c[idx.time] : '',
      amount: idx.amount >= 0 ? c[idx.amount] : '',
      note: idx.note >= 0 ? c[idx.note] : '',
      project: idx.project >= 0 ? c[idx.project] : '',
      wechat: idx.wechat >= 0 ? c[idx.wechat] : '',
      merchant: idx.merchant >= 0 ? c[idx.merchant] : ''
    });
  }
  return rows;
}

async function loadOrdersForMatch() {
  const [orders] = await pool.query(
    `SELECT id, order_no, project, amount, status, note, paid_at AS paid_raw, created_at AS created_raw
     FROM orders ORDER BY id ASC`
  );
  return orders;
}

function matchStatement(rows, orders) {
  const used = new Set();
  const matched = [];
  const unmatchedCsv = [];

  for (const r of rows) {
    const amt = parseAmount(r.amount);
    const note = String(r.note || '');
    const merchant = String(r.merchant || '');
    let found = null;

    if (!found) {
      for (const o of orders) {
        if (used.has(o.id)) continue;
        if (note.indexOf(o.order_no) >= 0) { found = o; break; }
      }
    }
    if (!found && merchant) {
      for (const o of orders) {
        if (used.has(o.id)) continue;
        if (merchant.trim() === o.order_no) { found = o; break; }
      }
    }
    if (!found && Number.isFinite(amt)) {
      let best = null, bestDt = Infinity;
      const candidates = [];
      const rMs = naiveMs(r.time);
      for (const o of orders) {
        if (used.has(o.id)) continue;
        if (Math.abs(Number(o.amount) - amt) > 0.01) continue;
        if (r.project && o.project) {
          if (r.project.indexOf(o.project) < 0 && o.project.indexOf(r.project) < 0) continue;
        }
        candidates.push(o);
        const oMs = naiveMs(o.created_raw);
        if (!isNaN(oMs) && !isNaN(rMs)) {
          const dt = Math.abs(oMs - rMs) / 1000;
          if (dt <= 300 && dt < bestDt) { bestDt = dt; best = o; }
        }
      }
      // 时区无关兜底：同金额同项目仅有一笔时直接匹配
      if (!best && candidates.length === 1) best = candidates[0];
      found = best;
    }

    if (found) { used.add(found.id); matched.push({ row: r, order: found }); }
    else { unmatchedCsv.push({ time: r.time, amount: r.amount, note: note.slice(0, 60) }); }
  }

  return { matched, unmatchedCsv, used };
}

function readImportCsv(req, res) {
  const csv = String(req.body?.csv || '');
  if (csv.length > 4 * 1024 * 1024) {
    res.status(400).json({ error: '内容过大' });
    return null;
  }
  const rows = parseStatement(csv);
  if (!rows.length) {
    res.status(400).json({ error: '没有识别到有效行，请确认粘贴的是对账单 CSV' });
    return null;
  }
  if (rows.length > 20000) {
    res.status(400).json({ error: '单次最多 20000 行' });
    return null;
  }
  return rows;
}

/* 预览：只做匹配，不写库 */
app.post('/api/orders/import/preview', requireUser, requireRole('admin', 'editor'), async (req, res) => {
  const rows = readImportCsv(req, res);
  if (!rows) return;
  try {
    const orders = await loadOrdersForMatch();
    const { matched, unmatchedCsv, used } = matchStatement(rows, orders);

    const items = matched.map(m => ({
      id: m.order.id,
      order: m.order.order_no,
      project: m.order.project,
      amount: Number(m.order.amount),
      csvTime: m.row.time || '',
      csvAmount: m.row.amount || '',
      csvNote: m.row.note || '',
      action: m.order.status === 'paid' ? 'skip' : 'paid'
    }));

    const unmatchedOrders = orders
      .filter(o => !used.has(o.id) && o.status !== 'paid' && o.status !== 'expired')
      .map(o => ({ order: o.order_no, project: o.project, amount: Number(o.amount) }));

    res.json({
      ok: true,
      csvRows: rows.length,
      matched: matched.length,
      toUpdate: items.filter(i => i.action === 'paid').length,
      skipped: items.filter(i => i.action === 'skip').length,
      items: items.slice(0, 200),
      unmatchedCsv: unmatchedCsv.slice(0, 50),
      unmatchedCsvCount: unmatchedCsv.length,
      unmatchedOrders: unmatchedOrders.slice(0, 50),
      unmatchedOrdersCount: unmatchedOrders.length
    });
  } catch (e) {
    console.error('[orders:import:preview]', e.message);
    res.status(500).json({ error: '处理失败' });
  }
});

app.post('/api/orders/import', requireUser, requireRole('admin', 'editor'), async (req, res) => {
  const rows = readImportCsv(req, res);
  if (!rows) return;

  try {
    const orders = await loadOrdersForMatch();
    const { matched, unmatchedCsv, used } = matchStatement(rows, orders);

    let updated = 0, skippedAlreadyPaid = 0;
    const changes = [];
    for (const m of matched) {
      if (m.order.status === 'paid') { skippedAlreadyPaid++; continue; }
      const paidAt = parseTime(m.row.time) ? String(m.row.time).trim() : null;
      const append = '（自动核对' + (m.row.wechat ? ' · 微信订单 ' + m.row.wechat : '') + '）';
      const newNote = ((m.order.note ? m.order.note + ' ' : '') + append).slice(0, 200);
      await pool.query(
        'UPDATE orders SET status = ?, paid_at = ' + (paidAt ? '?' : 'NOW()') + ', note = ? WHERE id = ?',
        paidAt ? ['paid', paidAt, newNote, m.order.id] : ['paid', newNote, m.order.id]
      );
      changes.push({
        id: m.order.id,
        prevStatus: m.order.status,
        prevPaidAt: m.order.paid_raw == null ? null : String(m.order.paid_raw),
        prevNote: m.order.note || null
      });
      updated++;
    }

    const unmatchedOrders = orders.filter(o => !used.has(o.id) && o.status !== 'paid' && o.status !== 'expired')
      .map(o => ({ order: o.order_no, project: o.project, amount: Number(o.amount) }));

    let batchId = null;
    if (changes.length) {
      const [ins] = await pool.query(
        'INSERT INTO import_batches (actor, csv_rows, matched, updated, changes) VALUES (?, ?, ?, ?, ?)',
        [req.user.username, rows.length, matched.length, updated, JSON.stringify(changes)]
      );
      batchId = ins.insertId;
    }

    if (updated > 0 || matched.length > 0) {
      await audit(req.user.username, 'order_import',
        '导入对账单：' + rows.length + ' 行，匹配 ' + matched.length + ' 笔，标记到账 ' + updated + ' 笔', req.ip);
    }

    res.json({
      ok: true,
      batchId,
      csvRows: rows.length,
      matched: matched.length,
      updated,
      skippedAlreadyPaid,
      unmatchedCsv: unmatchedCsv.slice(0, 20),
      unmatchedCsvCount: unmatchedCsv.length,
      unmatchedOrders: unmatchedOrders.slice(0, 20),
      unmatchedOrdersCount: unmatchedOrders.length
    });
  } catch (e) {
    console.error('[orders:import]', e.message);
    res.status(500).json({ error: '处理失败' });
  }
});

app.get('/api/orders/imports', requireUser, requireRole('admin', 'editor'), async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT id, actor, csv_rows, matched, updated, undone,
              UNIX_TIMESTAMP(created_at) * 1000 AS created_ms
       FROM import_batches ORDER BY id DESC LIMIT 20`
    );
    res.json({
      batches: rows.map(r => ({
        id: r.id,
        actor: r.actor,
        csvRows: r.csv_rows,
        matched: r.matched,
        updated: r.updated,
        undone: !!r.undone,
        createdMs: Number(r.created_ms)
      }))
    });
  } catch (e) {
    console.error('[orders:imports]', e.message);
    res.status(500).json({ error: '读取失败' });
  }
});

app.post('/api/orders/import/:id/undo', requireUser, requireRole('admin', 'editor'), async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: '无效的批次' });
  try {
    const [rows] = await pool.query(
      'SELECT id, changes, undone FROM import_batches WHERE id = ? LIMIT 1', [id]
    );
    const batch = rows[0];
    if (!batch) return res.status(404).json({ error: '批次不存在' });
    if (batch.undone) return res.status(400).json({ error: '该批次已撤销过' });

    let changes = [];
    try { changes = JSON.parse(batch.changes || '[]'); } catch (e) { changes = []; }

    let reverted = 0, skipped = 0;
    for (const c of changes) {
      const [r] = await pool.query(
        "UPDATE orders SET status = ?, paid_at = ?, note = ? WHERE id = ? AND status = 'paid'",
        [c.prevStatus || 'pending', c.prevPaidAt || null, c.prevNote || null, c.id]
      );
      if (r.affectedRows) reverted++; else skipped++;
    }
    await pool.query('UPDATE import_batches SET undone = 1 WHERE id = ?', [id]);
    await audit(req.user.username, 'order_import_undo',
      '撤销导入批次 #' + id + '：恢复 ' + reverted + ' 笔' + (skipped ? '，跳过 ' + skipped + ' 笔' : ''), req.ip);
    res.json({ ok: true, reverted, skipped });
  } catch (e) {
    console.error('[orders:import:undo]', e.message);
    res.status(500).json({ error: '撤销失败' });
  }
});

/* ---------- 批量操作 ---------- */

app.post('/api/orders/batch', requireUser, requireRole('admin', 'editor'), async (req, res) => {
  const ids = Array.isArray(req.body?.ids) ? req.body.ids.map(Number) : [];
  const action = String(req.body?.action || '');
  const clean = ids.filter(n => Number.isInteger(n) && n > 0);
  if (!clean.length || clean.length > 1000) return res.status(400).json({ error: '请选择 1-1000 条记录' });
  if (action !== 'paid' && action !== 'pending' && action !== 'refunded' && action !== 'delete') {
    return res.status(400).json({ error: '操作不正确' });
  }
  const ph = clean.map(() => '?').join(',');
  try {
    let result;
    if (action === 'delete') {
      [result] = await pool.query('DELETE FROM orders WHERE id IN (' + ph + ')', clean);
    } else {
      [result] = await pool.query(
        'UPDATE orders SET status = ?, paid_at = ' + (action === 'paid' ? 'NOW()' : 'NULL') +
        ' WHERE id IN (' + ph + ')', [action, ...clean]
      );
    }
    await audit(req.user.username, 'order_batch',
      '批量' + ({ paid: '标记到账', pending: '取消到账', refunded: '标记退款', delete: '删除' }[action]) +
      ' ' + result.affectedRows + ' 条', req.ip);
    res.json({ ok: true, affected: result.affectedRows });
  } catch (e) {
    console.error('[orders:batch]', e.message);
    res.status(500).json({ error: '操作失败' });
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

/* ---------- 备份 ---------- */

app.get('/api/backups', requireUser, requireRole('admin', 'editor'), async (req, res) => {
  try {
    res.json({ backups: listBackups(), config: await readBackupConfig() });
  } catch (e) {
    console.error('[backup:list]', e.message);
    res.status(500).json({ error: '读取失败' });
  }
});

app.get('/api/backups/config', requireUser, requireRole('admin', 'editor'), async (req, res) => {
  try {
    res.json({ config: await readBackupConfig() });
  } catch (e) {
    res.status(500).json({ error: '读取失败' });
  }
});

app.put('/api/backups/config', requireUser, requireRole('admin'), async (req, res) => {
  const body = req.body || {};
  const config = {
    enabled: !!body.enabled,
    hour: Math.max(0, Math.min(23, Math.floor(Number(body.hour) || 0))),
    keepDays: Math.max(1, Math.min(3650, Math.floor(Number(body.keepDays) || 30))),
    remote: { type: 'none', url: '', username: '', password: '' }
  };

  if (body.remote && body.remote.type === 'webdav') {
    const url = String(body.remote.url || '').trim().replace(/\/+$/, '');
    const username = String(body.remote.username || '').trim();
    const password = String(body.remote.password || '');
    if (!/^https?:\/\/[^\s]{4,300}$/i.test(url)) {
      return res.status(400).json({ error: '异地备份地址需以 http:// 或 https:// 开头' });
    }
    if (!username || !password) {
      return res.status(400).json({ error: '请填写异地备份的账号和密码' });
    }
    config.remote = { type: 'webdav', url, username, password };
  }

  try {
    await writeSetting('backup_config', config);
    let remoteError = null;
    if (config.enabled) {
      const info = await createBackup().catch(() => null);
      if (info && info.remote && info.remote.ok === false) remoteError = info.remote.error;
      pruneOld(config.keepDays);
    }
    scheduleBackups();
    await audit(req.user.username, 'backup_config',
      '备份设置：' + (config.enabled ? '开启' : '关闭') + '，每天 ' + config.hour + ' 点，保留 ' + config.keepDays + ' 天' +
      (config.remote.type === 'webdav' ? '，异地同步开启' : ''), req.ip);
    res.json({ ok: true, config, remoteError });
  } catch (e) {
    console.error('[backup:config]', e.message);
    res.status(500).json({ error: '保存失败' });
  }
});

app.post('/api/backups', requireUser, requireRole('admin', 'editor'), async (req, res) => {
  try {
    const info = await createBackup();
    await audit(req.user.username, 'backup', '手动创建备份 ' + info.file, req.ip);
    res.json({ ok: true, file: info.file, size: info.size, remote: info.remote });
  } catch (e) {
    console.error('[backup:create]', e.message);
    res.status(500).json({ error: '创建失败' });
  }
});

app.get('/api/backups/:file', requireUser, requireRole('admin', 'editor'), (req, res) => {
  const full = backupPath(req.params.file);
  if (!full) return res.status(404).json({ error: '文件不存在' });
  res.download(full, req.params.file);
});

app.delete('/api/backups/:file', requireUser, requireRole('admin'), async (req, res) => {
  if (!deleteBackup(req.params.file)) return res.status(404).json({ error: '文件不存在' });
  await audit(req.user.username, 'backup', '删除备份 ' + req.params.file, req.ip);
  res.json({ ok: true });
});

/* 从备份恢复：只恢复订单与页面/通知/备份配置，不动管理员账号 */
function sqlTime(v) {
  if (v == null || v === '') return null;
  if (typeof v === 'string' && /^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}/.test(v)) {
    return v.slice(0, 19).replace('T', ' ');
  }
  const d = new Date(v);
  if (isNaN(d.getTime())) return null;
  const p = n => (n < 10 ? '0' + n : '' + n);
  return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' +
    p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
}

app.post('/api/backups/:file/restore', requireUser, requireRole('admin'), async (req, res) => {
  if (String(req.body?.confirm || '') !== 'RESTORE') {
    return res.status(400).json({ error: '请输入 RESTORE 确认恢复' });
  }
  const data = readBackupFile(req.params.file);
  if (!data || !data.tables) return res.status(400).json({ error: '备份文件无效' });
  const orders = Array.isArray(data.tables.orders) ? data.tables.orders : null;
  if (!orders) return res.status(400).json({ error: '备份中没有订单数据' });

  let pre = null;
  try { pre = await createBackup(); } catch (e) {}

  let conn;
  try {
    conn = await pool.getConnection();
    await conn.beginTransaction();
    await conn.query('DELETE FROM orders');
    for (const o of orders) {
      const status = (o.status === 'paid' || o.status === 'expired') ? o.status : 'pending';
      await conn.query(
        `INSERT INTO orders (id, order_no, project, amount, status, paid_at, note, admin_note, proof, source, ip, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [o.id, o.order_no, o.project, Number(o.amount) || 0, status, sqlTime(o.paid_at),
          o.note || null, o.admin_note || null, o.proof || null, o.source || null, o.ip || null,
          sqlTime(o.created_at) || new Date()]
      );
    }
    const settingsRows = Array.isArray(data.tables.settings) ? data.tables.settings : [];
    for (const s of settingsRows) {
      if (['page_config', 'notify_config', 'backup_config'].indexOf(s.k) < 0) continue;
      await conn.query(
        'INSERT INTO settings (k, v) VALUES (?, ?) ON DUPLICATE KEY UPDATE v = VALUES(v)',
        [s.k, s.v]
      );
    }
    await conn.commit();
    await audit(req.user.username, 'backup_restore',
      '从备份 ' + req.params.file + ' 恢复 ' + orders.length + ' 条订单' +
      (pre ? '（恢复前已自动备份 ' + pre.file + '）' : ''), req.ip);
    res.json({ ok: true, restored: orders.length, preBackup: pre ? pre.file : null });
  } catch (e) {
    if (conn) { try { await conn.rollback(); } catch (err) {} }
    console.error('[backup:restore]', e.message);
    res.status(500).json({ error: '恢复失败：' + e.message });
  } finally {
    if (conn) conn.release();
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
  scheduleBackups();
  scheduleSummary();
  expireStale(true);
  setInterval(() => expireStale(true), 30 * 60 * 1000).unref?.();
});
