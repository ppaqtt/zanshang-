export const SKINS = {
  coral: { name: '珊瑚暖橘', accent: '#E4573D', bg: '#e9e9ec', ink: '#2b2b2b', phone: '#ffffff' },
  forest: { name: '森林墨绿', accent: '#2E7D5B', bg: '#e8efe9', ink: '#1f3a2c', phone: '#ffffff' },
  sunset: { name: '落日橙粉', accent: '#FF7A45', bg: '#fdf0e6', ink: '#3a2a1f', phone: '#ffffff' },
  mint: { name: '薄荷青', accent: '#16A085', bg: '#e6f4f1', ink: '#14302a', phone: '#ffffff' },
  night: { name: '暗夜紫', accent: '#6C5CE7', bg: '#15151f', ink: '#e8e8f0', phone: '#23232f' }
};
export const SKIN_KEYS = Object.keys(SKINS);

export const DEFAULT_CONFIG = {
  amounts: [1, 5, 10, 20, 50, 100, 500, 666, 888, 1000],
  expireHours: 24,
  customAmount: { enabled: true, min: 1, max: 1000 },
  goal: { enabled: false, title: '本月小目标', target: 500 },
  wall: { enabled: false, title: '大家的留言' },
  rank: { enabled: false, title: '本月支持榜' },
  share: { enabled: true, text: '我刚刚赞赏了《{project}》，感谢创作！' },
  theme: {
    skin: 'coral',
    accent: '#E4573D',
    title: '感谢相伴',
    pageTitle: '感谢相伴',
    footer: '赞赏是为表示鼓励而对文章内容的无偿赠予'
  },
  projects: [
    {
      id: 'qingjian',
      name: '清笺',
      code: 'qingjian',
      prefix: 'QJ',
      qr: 'assets/qingjian-qr.jpg',
      avatar: 'assets/qingjian-logo.jpg',
      sub: '感谢你的支持与陪伴'
    },
    {
      id: 'xiaomengjizhang',
      name: '小萌记账',
      code: 'xiaomengjizhang',
      prefix: 'XM',
      qr: 'assets/xiaomengjizhang-qr.jpg',
      avatar: 'assets/xiaomengjizhang-logo.jpg',
      sub: '感谢你的支持与陪伴'
    },
    {
      id: 'ppdxpz',
      name: '平平的小破站',
      code: 'ppdxpz',
      prefix: 'PPDXPZ',
      qr: 'assets/ppdxpz-qr.jpg',
      avatar: 'assets/ppdxpz-logo.webp',
      sub: '感谢你的支持与陪伴'
    }
  ]
};

export const DEFAULT_NOTIFY = { type: 'none', url: '' };

/* 新订单推送文案模板；可用占位符见 renderNewOrderText */
export const DEFAULT_NOTIFY_TEMPLATE =
  '【新赞赏】{project} ¥{amount}\n订单号：{orderNo}\n{note}{source}时间：{time}';

/* 夜间免打扰；start > end 表示跨午夜（如 23:00 - 08:00） */
export const DEFAULT_QUIET = { enabled: false, start: '23:00', end: '08:00' };

/* 邮件通知（SMTP）默认配置 */
export const DEFAULT_EMAIL = {
  enabled: false,
  host: '',
  port: 465,
  secure: true,
  user: '',
  pass: '',
  to: ''
};

/* 推送内一键标记到账链接 */
export const DEFAULT_QUICK_PAID = { enabled: false, baseUrl: '' };

/* 周期总结默认配置；weekday: 0=周日,1=周一,...,6=周六；monthly day: 1-28 */
export const DEFAULT_SUMMARY = {
  daily: { enabled: true, hour: 20 },
  weekly: { enabled: true, day: 1, hour: 21 },
  monthly: { enabled: true, day: 1, hour: 9 }
};

export const NOTIFY_TYPES = ['none', 'feishu', 'dingtalk', 'wecom', 'serverchan', 'generic', 'email'];

export const ROLES = ['admin', 'editor', 'viewer'];

export const DEFAULT_BACKUP = {
  enabled: false,
  hour: 3,
  keepDays: 30,
  remote: { type: 'none', url: '', username: '', password: '' }
};
