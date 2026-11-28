const form = document.querySelector('#support');
const amountButtons = [...document.querySelectorAll('.amount-button')];
const customAmount = document.querySelector('#custom-amount');
const customValue = document.querySelector('#custom-value');
const messageInput = document.querySelector('#message');
const status = document.querySelector('#form-status');
const messageRail = document.querySelector('.message-rail');
const submitButton = document.querySelector('.submit-button');

let selectedAmount = '12';
let statusTimer;

amountButtons.forEach((button) => {
  button.addEventListener('click', () => {
    selectedAmount = button.dataset.amount;

    amountButtons.forEach((option) => {
      const isSelected = option === button;
      option.classList.toggle('selected', isSelected);
      option.setAttribute('aria-pressed', String(isSelected));
    });

    const isCustom = selectedAmount === 'custom';
    customAmount.hidden = !isCustom;
    status.textContent = '';

    if (isCustom) {
      customValue.focus();
    }
  });
});

form.addEventListener('submit', (event) => {
  event.preventDefault();
  window.clearTimeout(statusTimer);

  if (selectedAmount === 'custom') {
    const value = Number(customValue.value);
    if (!Number.isFinite(value) || value < 1 || value > 99999) {
      status.textContent = '请输入 1 至 99999 之间的金额。';
      customValue.focus();
      return;
    }
  }

  const message = messageInput.value.trim();
  if (message) {
    addMessage(message);
    messageInput.value = '';
  }

  status.textContent = '心意已收到，谢谢你的喜欢。此操作仅为页面演示。';
  submitButton.textContent = '谢谢你，小岛收到啦';

  statusTimer = window.setTimeout(() => {
    submitButton.textContent = '送出这份心意';
  }, 2800);
});

function addMessage(message) {
  const article = document.createElement('article');
  article.className = 'message-item is-new';

  const avatar = document.createElement('div');
  avatar.className = 'avatar';
  avatar.setAttribute('aria-hidden', 'true');
  avatar.textContent = '你';

  const content = document.createElement('div');
  const heading = document.createElement('h3');
  heading.textContent = '一位新朋友';
  const paragraph = document.createElement('p');
  paragraph.textContent = message;

  content.append(heading, paragraph);
  article.append(avatar, content);
  messageRail.prepend(article);
}
