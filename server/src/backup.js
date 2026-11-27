import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { pool } from './db.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BACKUP_DIR = path.resolve(__dirname, '..', 'backups');
const FILE_RE = /^backup-\d{8}-\d{6}\.json$/;

function ensureDir() {
  if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR, { recursive: true });
}

function pad(n) { return n < 10 ? '0' + n : '' + n; }

function stamp(d) {
  return d.getFullYear() + pad(d.getMonth() + 1) + pad(d.getDate()) + '-' +
    pad(d.getHours()) + pad(d.getMinutes()) + pad(d.getSeconds());
}

export async function createBackup() {
  ensureDir();
  const file = 'backup-' + stamp(new Date()) + '.json';
  const data = { version: 1, createdAt: new Date().toISOString(), tables: {} };

  const tables = ['orders', 'settings', 'audit_logs', 'daily_stats', 'admins'];
  for (const t of tables) {
    try {
      const [rows] = await pool.query('SELECT * FROM ' + t);
      data.tables[t] = rows;
    } catch (e) {
      data.tables[t] = { error: e.message };
    }
  }

  fs.writeFileSync(path.join(BACKUP_DIR, file), JSON.stringify(data, null, 2));
  return { file, size: fs.statSync(path.join(BACKUP_DIR, file)).size };
}

export function listBackups() {
  ensureDir();
  const files = fs.readdirSync(BACKUP_DIR).filter(f => FILE_RE.test(f));
  return files.map(f => {
    const st = fs.statSync(path.join(BACKUP_DIR, f));
    return { file: f, size: st.size, mtime: st.mtimeMs };
  }).sort((a, b) => b.mtime - a.mtime);
}

export function backupPath(file) {
  if (!FILE_RE.test(file)) return null;
  const full = path.join(BACKUP_DIR, file);
  if (!fs.existsSync(full)) return null;
  return full;
}

export function deleteBackup(file) {
  if (!FILE_RE.test(file)) return false;
  const full = path.join(BACKUP_DIR, file);
  if (!fs.existsSync(full)) return false;
  fs.unlinkSync(full);
  return true;
}

export function pruneOld(keepDays) {
  const days = Math.max(1, Math.min(3650, Number(keepDays) || 30));
  const cutoff = Date.now() - days * 864e5;
  let removed = 0;
  for (const b of listBackups()) {
    if (b.mtime < cutoff) {
      try { deleteBackup(b.file); removed++; } catch (e) {}
    }
  }
  return removed;
}

/* ---------- 定时调度 ---------- */

let timer = null;

function msUntilNext(hour) {
  const now = new Date();
  const next = new Date(now);
  next.setHours(hour, 0, 0, 0);
  if (next <= now) next.setDate(next.getDate() + 1);
  return next.getTime() - now.getTime();
}

export async function readBackupConfig() {
  try {
    const [rows] = await pool.query("SELECT v FROM settings WHERE k = 'backup_config' LIMIT 1");
    if (rows.length) {
      const parsed = JSON.parse(rows[0].v);
      return {
        enabled: !!parsed.enabled,
        hour: Math.max(0, Math.min(23, Number(parsed.hour) || 0)),
        keepDays: Math.max(1, Math.min(3650, Number(parsed.keepDays) || 30))
      };
    }
  } catch (e) {}
  return { enabled: false, hour: 3, keepDays: 30 };
}

async function runScheduled() {
  const cfg = await readBackupConfig();
  if (!cfg.enabled) return;
  try {
    await createBackup();
    pruneOld(cfg.keepDays);
    console.log('[backup] 定时备份完成');
  } catch (e) {
    console.error('[backup] 定时备份失败：', e.message);
  }
}

export function scheduleBackups() {
  if (timer) { clearTimeout(timer); timer = null; }
  (async () => {
    const cfg = await readBackupConfig();
    const delay = Math.max(60 * 1000, msUntilNext(cfg.hour));
    timer = setTimeout(async () => {
      await runScheduled();
      scheduleBackups();
    }, delay);
    console.log('[backup] 下次自动备份将在 ' + Math.round(delay / 60000) + ' 分钟后');
  })();
}
