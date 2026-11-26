import bcrypt from 'bcryptjs';
import { pool } from '../src/db.js';

const [username, password] = process.argv.slice(2);

if (!username || !password) {
  console.error('用法: npm run create-admin -- <用户名> <密码>');
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

const hash = await bcrypt.hash(password, 12);
await pool.query(
  'INSERT INTO admins (username, password_hash) VALUES (?, ?) ON DUPLICATE KEY UPDATE password_hash = VALUES(password_hash)',
  [username, hash]
);
console.log(`管理员 ${username} 已创建/更新`);
await pool.end();
