import 'dotenv/config';
import mysql from 'mysql2/promise';
import { pool } from '../src/db.js';
import { DEFAULT_CONFIG, DEFAULT_NOTIFY, DEFAULT_BACKUP, DEFAULT_SUMMARY, SKIN_KEYS } from '../src/defaults.js';

/* 幂等升级：已存在的旧库直接执行，不会重复加列或丢数据 */
async function columnExists(table, column) {
  const [rows] = await pool.query(
    `SELECT 1 FROM information_schema.COLUMNS
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ?
     LIMIT 1`,
    [table, column]
  );
  return rows.length > 0;
}

async function indexExists(table, index) {
  const [rows] = await pool.query(
    `SELECT 1 FROM information_schema.STATISTICS
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND INDEX_NAME = ? LIMIT 1`,
    [table, index]
  );
  return rows.length > 0;
}

async function addColumn(table, column, ddl) {
  if (await columnExists(table, column)) {
    console.log(`  = ${table}.${column} 已存在`);
    return;
  }
  await pool.query(ddl);
  console.log(`  + ${table}.${column} 已添加`);
}

async function main() {
  console.log('[migrate] 开始升级数据库…');

  /* 全新环境：库还不存在时先建库，否则连接池第一句就会失败 */
  const dbName = process.env.DB_NAME || 'zan';
  const boot = await mysql.createConnection({
    host: process.env.DB_HOST || '127.0.0.1',
    port: Number(process.env.DB_PORT || 3306),
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || ''
  });
  try {
    await boot.query(
      `CREATE DATABASE IF NOT EXISTS \`${dbName}\` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`
    );
    console.log('  = 数据库 ' + dbName + ' 就绪');
  } catch (e) {
    console.log('  ! 建库跳过（' + e.message + '），继续尝试连接现有库');
  } finally {
    await boot.end();
  }

  await pool.query(
    `CREATE TABLE IF NOT EXISTS admins (
      id INT UNSIGNED NOT NULL AUTO_INCREMENT,
      username VARCHAR(50) NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      role ENUM('admin','editor','viewer') NOT NULL DEFAULT 'admin',
      totp_secret VARCHAR(64) DEFAULT NULL,
      totp_enabled TINYINT(1) NOT NULL DEFAULT 0,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      UNIQUE KEY uk_username (username)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`
  );
  console.log('  = admins 表就绪');

  await pool.query(
    `CREATE TABLE IF NOT EXISTS orders (
      id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      order_no VARCHAR(40) NOT NULL,
      project VARCHAR(80) NOT NULL,
      amount DECIMAL(10,2) NOT NULL,
      status ENUM('pending','paid','expired') NOT NULL DEFAULT 'pending',
      paid_at DATETIME DEFAULT NULL,
      note VARCHAR(200) DEFAULT NULL,
      admin_note VARCHAR(500) DEFAULT NULL,
      proof VARCHAR(120) DEFAULT NULL,
      source VARCHAR(60) DEFAULT NULL,
      ip VARCHAR(45) DEFAULT NULL,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      KEY idx_created (created_at),
      KEY idx_project (project),
      KEY idx_order_no (order_no),
      KEY idx_status (status)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`
  );
  console.log('  = orders 表就绪');

  /* 老库补列（新库已由上面的建表覆盖，这里是幂等空操作） */
  await addColumn('admins', 'role',
    "ALTER TABLE admins ADD COLUMN role ENUM('admin','editor','viewer') NOT NULL DEFAULT 'admin' AFTER password_hash");
  await addColumn('admins', 'totp_secret',
    'ALTER TABLE admins ADD COLUMN totp_secret VARCHAR(64) NULL AFTER role');
  await addColumn('admins', 'totp_enabled',
    'ALTER TABLE admins ADD COLUMN totp_enabled TINYINT(1) NOT NULL DEFAULT 0 AFTER totp_secret');
  await addColumn('orders', 'status',
    "ALTER TABLE orders ADD COLUMN status ENUM('pending','paid','expired') NOT NULL DEFAULT 'pending' AFTER amount");
  await addColumn('orders', 'paid_at',
    'ALTER TABLE orders ADD COLUMN paid_at DATETIME NULL AFTER status');
  await addColumn('orders', 'note',
    'ALTER TABLE orders ADD COLUMN note VARCHAR(200) NULL AFTER paid_at');
  await addColumn('orders', 'admin_note',
    'ALTER TABLE orders ADD COLUMN admin_note VARCHAR(500) NULL AFTER note');
  await addColumn('orders', 'proof',
    'ALTER TABLE orders ADD COLUMN proof VARCHAR(120) NULL AFTER admin_note');
  await addColumn('orders', 'source',
    'ALTER TABLE orders ADD COLUMN source VARCHAR(60) NULL AFTER proof');

  /* 老库的 status 枚举里没有 expired，需要扩展 */
  const [statusCol] = await pool.query(
    `SELECT COLUMN_TYPE AS t FROM information_schema.COLUMNS
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'orders' AND COLUMN_NAME = 'status' LIMIT 1`
  );
  if (statusCol.length && String(statusCol[0].t).indexOf('expired') < 0) {
    await pool.query(
      "ALTER TABLE orders MODIFY COLUMN status ENUM('pending','paid','expired') NOT NULL DEFAULT 'pending'"
    );
    console.log('  + orders.status 已支持 expired');
  }

  if (!(await indexExists('orders', 'idx_status'))) {
    await pool.query('ALTER TABLE orders ADD INDEX idx_status (status)');
    console.log('  + orders.idx_status 已添加');
  }

  await pool.query(
    `CREATE TABLE IF NOT EXISTS import_batches (
      id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      actor VARCHAR(50) DEFAULT NULL,
      csv_rows INT UNSIGNED NOT NULL DEFAULT 0,
      matched INT UNSIGNED NOT NULL DEFAULT 0,
      updated INT UNSIGNED NOT NULL DEFAULT 0,
      changes MEDIUMTEXT DEFAULT NULL,
      undone TINYINT(1) NOT NULL DEFAULT 0,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      KEY idx_created (created_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`
  );
  console.log('  = import_batches 表就绪');

  await pool.query(
    `CREATE TABLE IF NOT EXISTS settings (
      k VARCHAR(64) NOT NULL,
      v MEDIUMTEXT NOT NULL,
      updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      PRIMARY KEY (k)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`
  );
  console.log('  = settings 表就绪');

  await pool.query(
    `CREATE TABLE IF NOT EXISTS daily_stats (
      day DATE NOT NULL,
      pv INT UNSIGNED NOT NULL DEFAULT 0,
      uv INT UNSIGNED NOT NULL DEFAULT 0,
      PRIMARY KEY (day)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`
  );
  await pool.query(
    `CREATE TABLE IF NOT EXISTS daily_visitors (
      day DATE NOT NULL,
      visitor CHAR(36) NOT NULL,
      PRIMARY KEY (day, visitor)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`
  );
  console.log('  = 访问统计表就绪');

  await pool.query(
    `CREATE TABLE IF NOT EXISTS audit_logs (
      id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      actor VARCHAR(50) DEFAULT NULL,
      action VARCHAR(40) NOT NULL,
      detail VARCHAR(500) DEFAULT NULL,
      ip VARCHAR(45) DEFAULT NULL,
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      KEY idx_created (created_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`
  );
  console.log('  = audit_logs 表就绪');

  const [cfg] = await pool.query("SELECT k, v FROM settings WHERE k = 'page_config' LIMIT 1");
  if (!cfg.length) {
    await pool.query(
      "INSERT INTO settings (k, v) VALUES ('page_config', ?)",
      [JSON.stringify(DEFAULT_CONFIG)]
    );
    console.log('  + 已写入默认页面配置');
  } else {
    let conf = null;
    try { conf = JSON.parse(cfg[0].v); } catch (e) { conf = null; }
    if (!conf) {
      console.log('  = 页面配置已存在（解析失败，跳过）');
    } else {
      let changed = false;
      if (!conf.theme) { conf.theme = DEFAULT_CONFIG.theme; changed = true; }
      else if (typeof conf.theme.skin !== 'string' || SKIN_KEYS.indexOf(conf.theme.skin) < 0) {
        conf.theme.skin = DEFAULT_CONFIG.theme.skin; changed = true;
      }
      if (typeof conf.expireHours !== 'number') {
        conf.expireHours = DEFAULT_CONFIG.expireHours; changed = true;
      }
      if (changed) {
        await pool.query("UPDATE settings SET v = ? WHERE k = 'page_config'", [JSON.stringify(conf)]);
        console.log('  + 已补充/修正页面配置');
      } else {
        console.log('  = 页面配置已存在');
      }
    }
  }

  const [notify] = await pool.query("SELECT k, v FROM settings WHERE k = 'notify_config' LIMIT 1");
  if (!notify.length) {
    await pool.query(
      "INSERT INTO settings (k, v) VALUES ('notify_config', ?)",
      [JSON.stringify({ ...DEFAULT_NOTIFY, summary: DEFAULT_SUMMARY })]
    );
    console.log('  + 已写入默认通知配置');
  } else {
    let nconf = null;
    try { nconf = JSON.parse(notify[0].v); } catch (e) { nconf = null; }
    if (nconf && typeof nconf === 'object' && !nconf.summary) {
      nconf.summary = JSON.parse(JSON.stringify(DEFAULT_SUMMARY));
      await pool.query("UPDATE settings SET v = ? WHERE k = 'notify_config'", [JSON.stringify(nconf)]);
      console.log('  + 已补充周期总结默认配置');
    }
  }

  const [bk] = await pool.query("SELECT k, v FROM settings WHERE k = 'backup_config' LIMIT 1");
  if (!bk.length) {
    await pool.query(
      "INSERT INTO settings (k, v) VALUES ('backup_config', ?)",
      [JSON.stringify(DEFAULT_BACKUP)]
    );
    console.log('  + 已写入默认备份配置');
  } else {
    let bconf = null;
    try { bconf = JSON.parse(bk[0].v); } catch (e) { bconf = null; }
    if (bconf && typeof bconf === 'object' && !bconf.remote) {
      bconf.remote = DEFAULT_BACKUP.remote;
      await pool.query("UPDATE settings SET v = ? WHERE k = 'backup_config'", [JSON.stringify(bconf)]);
      console.log('  + 已补充备份异地配置');
    }
  }

  console.log('[migrate] 完成');
  await pool.end();
}

main().catch(async err => {
  console.error('[migrate] 失败：', err.message);
  try { await pool.end(); } catch (e) {}
  process.exit(1);
});
