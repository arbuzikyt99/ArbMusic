const $ = selector => document.querySelector(selector);
const apiBase = window.ARBMUSIC_API_BASE || ((location.protocol === 'http:' || location.protocol === 'https:') ? location.origin : '');
const form = $('#account-form');
const phoneInput = $('#phone-input');
const passwordInput = $('#password-input');
const codeInput = $('#verification-code');
let registrationStep = false;
let pendingPhone = localStorage.getItem('arb-registration-phone') || '';

function setMode(mode) {
  registrationStep = mode === 'register' && !!pendingPhone;
  if (registrationStep) phoneInput.value = pendingPhone;
  $('#credential-fields').hidden = registrationStep;
  $('#verification-fields').hidden = !registrationStep;
  phoneInput.disabled = registrationStep;
  passwordInput.disabled = registrationStep;
  phoneInput.required = !registrationStep;
  passwordInput.required = !registrationStep;
  codeInput.disabled = !registrationStep;
  codeInput.required = registrationStep;
  if (!registrationStep) codeInput.value = '';
  $('#auth-submit').textContent = mode === 'login' ? 'Войти' : registrationStep ? 'Подтвердить код' : 'Получить код из SMS';
  $('#auth-description').textContent = mode === 'login' ? 'Войди по номеру телефона и паролю.' : registrationStep ? 'Введи пять цифр из SMS. Код действует 10 минут.' : 'При первой регистрации отправим SMS с кодом из 5 цифр.';
  $('#auth-title').textContent = mode === 'login' ? 'Вход в ArbMusic' : registrationStep ? 'Подтверди номер телефона' : 'Создать аккаунт';
  $('#auth-status').textContent = '';
}

document.querySelectorAll('[data-auth-mode]').forEach(button => button.addEventListener('click', () => setMode(button.dataset.authMode)));
$('#auth-open').addEventListener('click', () => { if ($('#auth-logout').hidden) setMode(document.querySelector('[data-auth-mode].active')?.dataset.authMode || 'login'); });
codeInput.addEventListener('input', () => { codeInput.value = codeInput.value.replace(/\D/g, '').slice(0, 5); });

async function post(path, data) {
  const response = await fetch(`${apiBase}/api/auth/${path}`, { method:'POST', headers:{'Content-Type':'application/json'}, credentials:'include', body:JSON.stringify(data) });
  const result = await response.json();
  if (!response.ok) throw new Error(result.message || 'Не удалось выполнить запрос');
  return result;
}

form.addEventListener('submit', async event => {
  event.preventDefault();
  event.stopImmediatePropagation();
  const mode = document.querySelector('[data-auth-mode].active')?.dataset.authMode || 'login';
  const phone = (registrationStep ? pendingPhone : phoneInput.value).trim();
  const submit = $('#auth-submit');
  submit.disabled = true;
  try {
    if (mode === 'login') {
      $('#auth-status').textContent = 'Входим…';
      const result = await post('login', { phone, password:passwordInput.value });
      completeLogin(result.user);
      return;
    }
    if (!registrationStep) {
      $('#auth-status').textContent = 'Отправляем SMS…';
      const result = await post('register', { phone, password:passwordInput.value });
      pendingPhone = phone;
      localStorage.setItem('arb-registration-phone', phone);
      registrationStep = true;
      phoneInput.disabled = true;
      passwordInput.disabled = true;
      phoneInput.required = false;
      passwordInput.required = false;
      $('#credential-fields').hidden = true;
      $('#verification-fields').hidden = false;
      codeInput.disabled = false;
      codeInput.required = true;
      $('#auth-title').textContent = 'Подтверди номер телефона';
      $('#auth-description').textContent = 'Введи пять цифр из SMS. Код действует 10 минут.';
      submit.textContent = 'Подтвердить код';
      $('#auth-status').textContent = result.message;
      codeInput.focus();
      return;
    }
    $('#auth-status').textContent = 'Проверяем код…';
    const result = await post('verify', { phone:pendingPhone, code:codeInput.value });
    localStorage.removeItem('arb-registration-phone');
    pendingPhone = '';
    completeLogin(result.user);
  } catch (error) {
    $('#auth-status').textContent = error.message;
  } finally {
    submit.disabled = false;
  }
}, true);

$('#resend-code').addEventListener('click', async event => {
  const button = event.currentTarget;
  button.disabled = true;
  $('#auth-status').textContent = 'Отправляем новый код…';
  try {
    const result = await post('resend-code', { phone:pendingPhone });
    $('#auth-status').textContent = result.message;
  } catch (error) {
    $('#auth-status').textContent = error.message;
  } finally {
    button.disabled = false;
  }
});

function completeLogin(user) {
  window.ARBMUSIC_SET_AUTH_USER?.(user);
  $('#auth-modal').hidden = true;
  $('#auth-status').textContent = '';
  window.dispatchEvent(new CustomEvent('arbmusic:login', { detail:user }));
}

if (pendingPhone) {
  phoneInput.value = pendingPhone;
  document.querySelector('[data-auth-mode="register"]').addEventListener('click', () => setMode('register'));
}
