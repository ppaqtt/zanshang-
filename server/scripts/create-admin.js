import bcrypt from 'bcryptjs';
import { pool } from '../src/db.js';

const [username, password, role = 'admin'] = process.argv.slice(2);

if (!username || !password) {
  console.error('用法: npm run create-admin -- <用户名> <密码> [admin|editor|viewer]');
  process.exit(1);
}
if (!/^[A-Za-z0-9_.-]{3,50}$/.test(username)) {
  console.error('用户名只能包含字母、数字、下划线、点和短横线，长度 3-50');
  process.exit(1);
}
if (password.length < 8) {
  console.error('密码至少 8 位');
  process.exit(1);
}
if (['admin', 'editor', 'viewer'].indexOf(role) < 0) {
  console.error('角色只能是 admin、editor 或 viewer');
  process.exit(1);
}

const hash = await bcrypt.hash(password, 12);
await pool.query(
  `INSERT INTO admins (username, password_hash, role) VALUES (?, ?, ?)
   ON DUPLICATE KEY UPDATE password_hash = VALUES(password_hash), role = VALUES(role)`,
  [username, hash, role]
);
console.log(`账号 ${username} 已创建/更新，角色 ${role}`);
await pool.end();
