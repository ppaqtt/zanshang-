export const DEFAULT_CONFIG = {
  amounts: [1, 5, 10, 20, 50, 100, 500, 666, 888, 1000],
  theme: {
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
      prefix: 'PP',
      qr: 'assets/ppdxpz-qr.jpg',
      avatar: 'assets/ppdxpz-logo.webp',
      sub: '感谢你的支持与陪伴'
    }
  ]
};

export const DEFAULT_NOTIFY = { type: 'none', url: '' };

export const NOTIFY_TYPES = ['none', 'feishu', 'dingtalk', 'serverchan', 'generic'];

export const ROLES = ['admin', 'editor', 'viewer'];
