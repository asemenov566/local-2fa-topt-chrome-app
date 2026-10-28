import {normalizeAccount,validateBindings,totp,parseOtp,otpUri,parseMigration,MigrationBatch,fingerprint,identity,parseBackup,exportText} from './core.js';
import {createKey,seal,unseal,loadVault,saveVault,validateEnvelope,chooseVaultFile,fileStatus,authorizeFile,vaultToken,publishVaultMeta,setVaultPath} from './vault.js';
import {scanFile,cameraError} from './qr.js';
import {createQRReader} from './qr-reader.js';
import {migrationUris} from './migration-export.js';
import {timerSector} from './timer.js';
import {getPasswordGate,attemptPassword} from './auth-attempts.js';
import {rememberKey,prepareRememberKey,recallKey,enrollPasskey,unlockPasskey,lockEpoch} from './security.js';
const $ = id => document.getElementById(id);
const full = new URLSearchParams(location.search).has('full');
if (full) document.body.classList.add('full');
if (full) { document.querySelector('h1').textContent = 'CHROME-APP-TOTP'; $('menu-title').textContent = 'CHROME-APP-TOTP'; }
const authOnly = new URLSearchParams(location.search).has('auth');
if (authOnly) document.body.classList.add('auth-only');
let accounts = [], key = null, salt = null, vault = null, revision = 0, generation = 0, editing = null;
let idleTimer, tickTimer, toastTimer, lastActivity = Date.now(), autoExpires = 0, writing = false;
let rows = new Map(), pending = [], batch = new MigrationBatch(), importWarnings = [], encryptedImport = null, batchComplete = false;
let cameraReader = null, fileScanAbort = new AbortController();
let cameraStarted = 0, cameraLastDetected = 0, cameraLastEnhanced = 0, cameraMode = 'idle';
let stream = null, scanTimer, cameraGeneration = 0, cameraSeen = new Set(), scanBusy = false;
const codeCache = new Map();
let sharedAccountId = null;
let protectedMode = true, passkeyConfig = null;
let reorderMode = false, draftOrder = [], dragId = null;
let importGeneration = 0, deleteTarget = null;
let fileImportBusy = false;
let exportQRParts = [], exportQRIndex = 0;
let lockSetup = 0;
let unlockBusy = false, pinDraft = '', pinBlockedUntil = 0, pinGateTimer, pinGateVersion = 0;
let lockConfiguring = false, localLockRequest = false;
let lockAlertAction = 'retry';
let importWindowBusy = false;
const keepImportOnClose = new Set();
const title = a => a.issuer ? (a.name ? `${a.issuer}: ${a.name}` : a.issuer) : a.name;
function element(tag,className,text) { const el = document.createElement(tag); if (className) el.className = className; if (text !== undefined) el.textContent = text; return el; }
function toast(text) { $('toast').textContent = text; $('toast').hidden = false; clearTimeout(toastTimer); toastTimer = setTimeout(() => {$('toast').hidden = true;},3000); }
function show(id) { $(id).showModal(); }
function hide(id) { if ($(id).open) $(id).close(); }
function requireOpen() { if (!key) { toast('Сначала разблокируйте хранилище.'); return false; } return true; }
async function openWindow(mode = '') { await chrome.windows.create({url:chrome.runtime.getURL('app.html?full=1' + (mode ? '&' + mode + '=1' : '')),type:'popup',width:410,height:780}); }
async function takeImportDraft(id) {
  return navigator.locks.request('chrome-app-totp-security',async () => {
    const {importWindowDrafts={}} = await chrome.storage.session.get('importWindowDrafts');
    const draft = importWindowDrafts[id]; if (!draft) return null;
    delete importWindowDrafts[id];
    if (Object.keys(importWindowDrafts).length) await chrome.storage.session.set({importWindowDrafts});
    else await chrome.storage.session.remove('importWindowDrafts');
    return draft;
  });
}
async function openImportWindow(camera = false) {
  if (importWindowBusy || !requireOpen()) return;
  importWindowBusy = true;
  stopCamera();
  const id = crypto.randomUUID(), token = generation;
  try {
  await navigator.locks.request('chrome-app-totp-security',async () => {
    const {manualLock,importWindowDrafts={}} = await chrome.storage.session.get(['manualLock','importWindowDrafts']);
    if (!key || generation !== token || manualLock) throw new Error('Хранилище заблокировано.');
    for (const [draftId,draft] of Object.entries(importWindowDrafts)) if (draft.expires <= Date.now()) delete importWindowDrafts[draftId];
    if (Object.keys(importWindowDrafts).length >= 4) throw new Error('Завершите перенос импорта в уже открытые окна.');
    importWindowDrafts[id] = {id,token:vaultToken(vault),expires:Date.now()+60000,pending,parts:[...batch.parts.values()],importWarnings,encryptedImport,batchComplete};
    await chrome.storage.session.set({importWindowDrafts});
  });
  if (!key || generation !== token) { await takeImportDraft(id); return; }
  await chrome.windows.create({url:chrome.runtime.getURL(`app.html?full=1&${camera ? 'camera' : 'import'}=1&draft=${id}`),type:'popup',width:410,height:780});
  keepImportOnClose.add('camera-dialog'); hide('camera-dialog');
  } catch (e) { await takeImportDraft(id); throw e; }
  finally { importWindowBusy = false; }
}
function resetImport() {
  fileScanAbort.abort(); fileScanAbort = new AbortController();
  importGeneration++;
  fileImportBusy = false;
  $('import-files').disabled = false;
  $('decrypt-backup').disabled = false;
  $('file-drop-zone').classList.remove('drag-over');
  pending = []; batch.clear(); batchComplete = false; importWarnings = []; encryptedImport = null;
  $('import-text').value = ''; $('import-files').value = ''; $('backup-password').value = ''; $('backup-password-label').hidden = true; $('import-error').textContent = ''; cameraSeen.clear(); renderPreview();
  $('file-import-error').textContent = $('text-import-error').textContent = '';
}
function closeSensitiveDialogs() {
  clearExportQR();
  for (const dialog of document.querySelectorAll('dialog[open]')) dialog.close();
  for (const input of document.querySelectorAll('input[type="password"],#secret,#import-text')) input.value = '';
  $('secret').type = 'password'; $('show-secret').checked = false; resetImport(); $('export-list').replaceChildren(); editing = null; deleteTarget = null; $('share-qr').width = $('share-qr').height = 0;
}
function lockLocal() {
  lockConfiguring = true; $('password').disabled = true; $('unlock-passkey').disabled = true;
  clearTimeout(toastTimer); $('toast').hidden = true; $('toast').textContent = '';
  pinDraft = ''; clearTimeout(pinGateTimer); pinGateVersion++; $('password').value = ''; $('password-confirm').value = '';
  if (vault) { document.body.classList.add('pin-auth'); renderPinDots(); }
  reorderMode = false; draftOrder = []; orderBar.hidden = true; $('search').disabled = false; $('menu-button').disabled = false;
  generation++; key = null; salt = null; accounts = []; rows.clear(); codeCache.clear(); clearTimeout(idleTimer); clearTimeout(tickTimer); stopCamera(); closeSensitiveDialogs();
  $('accounts').replaceChildren(); $('search').value = ''; $('codes-screen').hidden = true; $('lock-screen').hidden = false; $('lock-button').hidden = true; $('add-button').hidden = true; $('auto-toggle').disabled = false; updateAutoLabel();
  $('search-panel').hidden = true; $('search-toggle').hidden = true; $('search-toggle').disabled = false; $('search-toggle').setAttribute('aria-expanded','false');
}
async function lock() {
  localLockRequest = true; lockLocal();
  try { await chrome.runtime.sendMessage({type:'lock'}); autoExpires = 0; updateAutoLabel(); await configureLock(); }
  finally { localLockRequest = false; renderPinGate(); focusPin(); }
}
function touch() {
  lastActivity = Date.now();
}
function updateAutoLabel() {
  const enabled = $('auto-toggle').checked;
  $('auto-status').textContent = !enabled ? 'Выключено · обычный аутентификатор' : Date.now() < autoExpires ? 'Активна в этой сессии Chrome' : key ? 'Привяжите сервис через шестерёнку' : 'Разблокируйте для автоустановки';
}
async function activateAuto() {
  if (!$('auto-toggle').checked) { await chrome.runtime.sendMessage({type:'deactivate'}); autoExpires = 0; updateAutoLabel(); return; }
  if (!key) { await chrome.runtime.sendMessage({type:'configure'}); autoExpires = 0; updateAutoLabel(); return; }
  const r = await chrome.runtime.sendMessage({type:'activate',accounts:accounts.filter(a => a.binding),revision,token:vaultToken(vault)});
  if (!r?.ok) throw new Error(r?.error || 'Не удалось включить автоустановку.');
  autoExpires = r.expires; updateAutoLabel();
}
async function persist(next, nextKey = key, nextSalt = salt, nextPasswordLength = vault?.passwordLength) {
  if (!key || writing) throw new Error('Дождитесь завершения сохранения.');
  if (next.length > 2000) throw new Error('Максимум 2000 аккаунтов.');
  validateBindings(next); writing = true;
  const token = generation;
  try {
    const epoch = await lockEpoch();
    const envelope = await seal(next,nextKey,nextSalt,revision + 1,nextPasswordLength);
    const preparedKey = await prepareRememberKey(nextKey,nextSalt,epoch);
    if (token !== generation) throw new Error('Хранилище заблокировано.');
    await saveVault(envelope,vaultToken(vault));
    if (token !== generation) return;
    vault = envelope; revision = envelope.revision; accounts = next; key = nextKey; salt = nextSalt; await rememberKey(key,salt,protectedMode,epoch,preparedKey);
    if (token !== generation) return;
    generation++; codeCache.clear(); renderAccounts(); if ($('settings-dialog').open) renderOrder();
  } finally { writing = false; }
  try { await activateAuto(); } catch (e) { toast(e.message); }
}
async function configureLock() {
  const setup = ++lockSetup;
  lockConfiguring = true; $('password').disabled = true; $('unlock-passkey').disabled = true;
  $('unlock-button').disabled = true;
  $('lock-retry').disabled = true;
  try {
  passkeyConfig = (await chrome.storage.local.get('passkeyConfig')).passkeyConfig ?? null;
  if (setup !== lockSetup) return;
  $('passkey-toggle').checked = !!passkeyConfig;
  $('passkey-setting').hidden = !protectedMode;
  $('unlock-passkey').hidden = !passkeyConfig || !protectedMode;
  const status = await fileStatus();
  if (setup !== lockSetup) return;
  $('file-status').textContent = 'Файл базы: ' + status.location;
  document.querySelector('.file-controls').hidden = true;
  $('file-new').hidden = true; $('file-open').hidden = true;
  $('file-retry').hidden = status.permitted;
  $('file-authorize').hidden = status.native || !status.selected || status.permitted;
  $('unlock-form').hidden = !status.selected || !status.permitted;
  if (!status.selected || !status.permitted) { showLockAlert(status.error || 'Требуется доступ к файлу базы. Нажмите «Разрешить доступ» и подтвердите разрешение в окне Chrome.',!status.native && status.selected ? 'authorize' : 'retry'); return; }
  try { const loaded = await loadVault(); if (setup !== lockSetup) return; vault = loaded; } catch (e) { if (setup !== lockSetup) return; showLockAlert(e.message); return; }
  revision = vault?.revision ?? 0;
  if (!vault) {
    try {
      const prepared = await chrome.runtime.sendMessage({type:'prepare-new-vault'});
      if (setup !== lockSetup) return;
      if (!prepared?.ok) { const error = new Error(prepared?.error || 'Расширение обновлено. Нажмите «Перезапустить», затем снова откройте его значок.'); error.action = prepared?.error ? 'retry' : 'reload'; throw error; }
      if (prepared.exists) return configureLock();
      protectedMode = true; passkeyConfig = null;
      $('protection-toggle').checked = false; $('passkey-toggle').checked = false; $('passkey-toggle').disabled = false;
      $('passkey-setting').hidden = false; $('unlock-passkey').hidden = true;
      $('auto-toggle').checked = false; autoExpires = 0; updateAutoLabel();
    } catch (e) {
      if (setup !== lockSetup) return;
      showLockAlert(e.message,e.action); return;
    }
  }
  $('lock-title').textContent = vault ? 'Введите мастер-пароль' : 'Создайте мастер-пароль';
  $('lock-description').textContent = vault ? 'Чтобы открыть зашифрованную базу кодов.' : 'После подтверждения пароля приложение автоматически создаст зашифрованную базу.';
  $('password').autocomplete = vault ? 'current-password' : 'new-password'; $('password').minLength = 1;
  $('unlock-button').textContent = vault ? 'Разблокировать' : 'Создать хранилище'; $('password-note').hidden = !!vault;
  pinDraft = ''; pinBlockedUntil = 0; $('password').value = ''; $('password-confirm').value = '';
  $('pin-length-label').hidden = !!vault;
  document.body.classList.remove('lock-error'); $('lock-alert').hidden = true;
  document.body.classList.add('pin-auth'); renderPinDots(); await refreshPinGate();
  if (setup === lockSetup) focusPin();
  } catch (e) { if (setup === lockSetup) showLockAlert(e.message); }
  finally { if (setup === lockSetup) { lockConfiguring = false; $('lock-retry').disabled = false; $('unlock-button').disabled = false; renderPinGate(); focusPin(); } }
}
function showLockAlert(message,action='retry') {
  closeSensitiveDialogs();
  clearTimeout(toastTimer); $('toast').hidden = true;
  lockAlertAction = action;
  document.body.classList.add('pin-auth','lock-error');
  $('unlock-form').hidden = true; $('unlock-passkey').hidden = true; $('password').disabled = true;
  document.querySelector('.file-controls').hidden = true;
  $('lock-alert-message').textContent = message; $('lock-alert').hidden = false;
  $('lock-retry').textContent = action==='reload' ? 'Перезапустить' : action==='authorize' ? 'Разрешить доступ' : 'Повторить';
}
$('lock-retry').addEventListener('click',async()=>{
  if ($('lock-retry').disabled) return;
  $('lock-retry').disabled = true;
  if (lockAlertAction==='reload') { chrome.runtime.reload(); return; }
  try { if (lockAlertAction==='authorize') await authorizeFile(); await configureLock(); }
  catch (e) { showLockAlert(e.message,lockAlertAction); }
  finally { $('lock-retry').disabled = false; }
});
function pinLength() { return vault ? vault.passwordLength : Number($('pin-length').value); }
function focusPin() {
  if (key || document.hidden || !document.body.classList.contains('pin-auth') || $('password').disabled || $('shell').inert) return;
  $('password').focus({preventScroll:true});
  const end = $('password').value.length; $('password').setSelectionRange(end,end);
}
function renderPinDots() {
  const count = Array.from($('password').value).length, length = pinLength();
  $('pin-dots').replaceChildren(...Array.from({length},(_,i) => element('span','pin-dot'+(i<count?' filled':''))));
}
function renderPinGate() {
  clearTimeout(pinGateTimer);
  if (key || !document.body.classList.contains('pin-auth') || document.body.classList.contains('lock-error')) return;
  const seconds = Math.max(0,Math.ceil((pinBlockedUntil-Date.now())/1000));
  $('password').disabled = localLockRequest || lockConfiguring || unlockBusy || seconds>0;
  $('unlock-passkey').disabled = localLockRequest || lockConfiguring || unlockBusy;
  $('pin-length').disabled = unlockBusy;
  $('pin-prompt').textContent = seconds ? 'Повторите через '+Math.floor(seconds/60)+':'+String(seconds%60).padStart(2,'0') : unlockBusy ? 'Проверяем…' : vault ? 'Введите пароль' : pinDraft ? 'Повторите пароль' : 'Задайте пароль';
  if (seconds && !document.hidden) pinGateTimer = setTimeout(() => { renderPinGate(); if (Date.now()>=pinBlockedUntil) focusPin(); },Math.min(1000,pinBlockedUntil-Date.now()));
}
async function refreshPinGate() {
  const version = ++pinGateVersion, source = vault;
  const state = source ? await getPasswordGate(source) : {blockedUntil:0};
  if (version !== pinGateVersion || source !== vault || key) return;
  pinBlockedUntil = state.blockedUntil; renderPinGate();
}
function rejectPin(error) {
  $('password').value = ''; $('password-confirm').value = ''; renderPinDots();
  if (error.code === 'PASSWORD_BLOCKED') { pinBlockedUntil = error.blockedUntil; $('unlock-error').textContent = ''; }
  else $('unlock-error').textContent = error.message;
  $('pin-dots').classList.remove('shake'); void $('pin-dots').offsetWidth; $('pin-dots').classList.add('shake');
}
$('pin-dots').addEventListener('animationend',() => $('pin-dots').classList.remove('shake'));
$('pin-length').addEventListener('change',() => { pinDraft = ''; $('password').value = ''; $('password-confirm').value = ''; $('unlock-error').textContent = ''; renderPinDots(); renderPinGate(); focusPin(); });
function pinInput(event) {
  if (localLockRequest || lockConfiguring || unlockBusy || pinBlockedUntil>Date.now()) { $('password').value = ''; renderPinDots(); return; }
  const length = pinLength(), chars = Array.from($('password').value);
  if (length && chars.length>length) $('password').value = chars.slice(0,length).join('');
  renderPinDots();
  if (!event.isComposing && length && Array.from($('password').value).length===length) $('unlock-form').requestSubmit();
}
$('password').addEventListener('input',pinInput);
$('password').addEventListener('compositionend',pinInput);
document.addEventListener('click',e => { if (!e.target.closest('select,a,button')) focusPin(); });
window.addEventListener('focus',focusPin);
async function selectFile(create) {
  if (!full) { await openWindow(); return; }
  try { await chooseVaultFile(create); await lock(); $('unlock-error').textContent = ''; } catch (e) { if (e.name !== 'AbortError') $('lock-description').textContent = e.message; }
}
$('file-new').addEventListener('click',() => { void selectFile(true); });
$('file-open').addEventListener('click',() => { void selectFile(false); });
$('file-retry').addEventListener('click',() => { void configureLock(); });
$('file-authorize').addEventListener('click',async () => { try { await authorizeFile(); await configureLock(); } catch (e) { $('lock-description').textContent = e.message; } });
async function acceptUnlocked(unlocked,envelope,authEpoch) {
  const token = generation;
  if (vaultToken(await loadVault()) !== vaultToken(envelope)) throw new Error('Файл изменился во время входа. Повторите разблокировку.');
  await publishVaultMeta(envelope); await rememberKey(unlocked.key,unlocked.salt,protectedMode,authEpoch);
  if (token !== generation) throw new Error('Вход отменён из-за блокировки в другом окне.');
  key = unlocked.key; salt = unlocked.salt; accounts = unlocked.accounts; vault = envelope; revision = vault.revision; generation++;
  pinDraft = ''; pinBlockedUntil = 0; pinGateVersion++; clearTimeout(pinGateTimer); document.body.classList.remove('pin-auth','lock-error'); $('lock-alert').hidden = true;
  $('password').value = ''; $('password-confirm').value = ''; $('unlock-error').textContent = ''; $('lock-screen').hidden = true; $('codes-screen').hidden = false; $('lock-button').hidden = false; $('auto-toggle').disabled = false;
  $('search-toggle').hidden = false;
  renderAccounts(); try { await activateAuto(); } catch (error) { toast(error.message); }
  if (authOnly) {
    await chrome.storage.session.remove('authRequest');
    const win = await chrome.windows.getCurrent(); await chrome.windows.remove(win.id); return;
  }
  const params = new URLSearchParams(location.search);
  if (params.has('camera') || params.has('import')) {
    resetImport();
    const draft = await takeImportDraft(params.get('draft'));
    if (draft?.id === params.get('draft')) {
      if (key && draft.token === vaultToken(vault) && draft.expires > Date.now()) {
        pending = draft.pending; let batchStatus; for (const part of draft.parts) batchStatus = batch.add(part);
        importWarnings = draft.importWarnings; encryptedImport = draft.encryptedImport; batchComplete = draft.batchComplete;
        if (batchStatus) { $('batch-status').hidden = false; $('batch-status').textContent = batchStatus.complete ? `Все части получены (${batch.size}/${batch.size}).` : `Получено ${batch.parts.size}/${batch.size}. Не хватает QR: ${batchStatus.missing.map(i => i + 1).join(', ')}.`; }
        $('backup-password-label').hidden = !encryptedImport; renderPreview();
      }
    }
    history.replaceState(null,'','app.html?full=1');
    if (key) openImport(params.has('camera') ? 'camera' : 'file',true);
  }
}
$('unlock-form').addEventListener('submit',async e => {
  e.preventDefault();
  if (localLockRequest || lockConfiguring || unlockBusy || key || $('unlock-form').hidden || pinBlockedUntil>Date.now() || !document.body.classList.contains('pin-auth')) return;
  const password = $('password').value, length = pinLength();
  if (!password || (length && Array.from(password).length!==length)) return;
  if (!vault && !pinDraft) { pinDraft = password; $('password').value = ''; $('password-confirm').value = ''; $('unlock-error').textContent = ''; renderPinDots(); renderPinGate(); focusPin(); return; }
  if (!vault && password !== pinDraft) { pinDraft = ''; rejectPin(new Error('Пароли не совпадают.')); renderPinGate(); focusPin(); return; }
  unlockBusy = true; renderPinGate(); $('unlock-error').textContent = ''; $('unlock-button').disabled = true;
  const token = generation;
  const expectedVault = vaultToken(vault);
  try {
    const authEpoch = await lockEpoch();
    const current = await loadVault(); let unlocked;
    if (vaultToken(current) !== expectedVault) throw new Error('Файл изменился. Откройте приложение снова.');
    if (!current) {
      unlocked = {...await createKey(password),accounts:[]};
      const envelope = await seal([],unlocked.key,unlocked.salt,1,unlocked.passwordLength); await saveVault(envelope,null); vault = envelope;
    } else { unlocked = await attemptPassword(current,password); vault = current; await publishVaultMeta(current); }
    if (token !== generation) return;
    await acceptUnlocked(unlocked,vault,authEpoch);
  } catch (error) { if (token === generation && !key) rejectPin(error); }
  finally { unlockBusy = false; $('unlock-button').disabled = false; renderPinGate(); focusPin(); }
});
function renderAccounts() {
  const root = $('accounts'); root.replaceChildren(); rows.clear();
  const search = $('search').value.trim().toLowerCase();
  for (const a of reorderMode ? draftOrder : accounts) {
    if (!title(a).toLowerCase().includes(search)) continue;
    const row = element('article','account'); row.setAttribute('role','listitem');
    const head = element('div','account-head'), name = element('div','account-label',title(a)); name.title = title(a);
    const gear = element('button','gear',reorderMode ? '×' : '⚙'); gear.setAttribute('aria-label',`${reorderMode ? 'Удалить' : 'Настроить'} ${title(a)}`); gear.title = reorderMode ? 'Удалить после сохранения' : 'Настроить аккаунт'; gear.addEventListener('click',() => { if (reorderMode) { requestDelete(a.id); } else editAccount(a); }); head.append(name,gear);
    if (reorderMode) {
      const grip = element('button','grip','⠿'); grip.draggable = true; grip.setAttribute('aria-label',`Переместить ${title(a)}`); grip.title = 'Перетащить или нажать ↑ / ↓'; head.prepend(grip);
      grip.addEventListener('dragstart',e => { dragId = a.id; e.dataTransfer.effectAllowed = 'move'; e.dataTransfer.setData('text/plain',a.id); row.classList.add('dragging'); });
      grip.addEventListener('dragend',() => { dragId = null; row.classList.remove('dragging'); });
      grip.addEventListener('keydown',e => { if (!['ArrowUp','ArrowDown'].includes(e.key)) return; e.preventDefault(); const index = draftOrder.findIndex(x => x.id === a.id), target = draftOrder[index + (e.key === 'ArrowUp' ? -1 : 1)]; if (target) moveDraft(a.id,target.id); });
      row.addEventListener('dragover',e => { if (dragId && dragId !== a.id) { e.preventDefault(); e.dataTransfer.dropEffect = 'move'; } });
      row.addEventListener('drop',e => { e.preventDefault(); if (dragId) moveDraft(dragId,a.id); dragId = null; });
    }
    const line = element('div','code-line'), code = element('button','code' + (a.digits === 8 ? ' eight' : ''),'—'); code.setAttribute('aria-label',`Скопировать код ${title(a)}`); code.title = 'Нажмите, чтобы скопировать';
    code.disabled = reorderMode;
    code.addEventListener('click',async () => { const token = generation; try { const value = await totp(a); if (!key || token !== generation) return; await navigator.clipboard.writeText(value); toast('Код скопирован'); } catch { toast('Не удалось скопировать код.'); } });
    const timer = element('div','timer'); timer.setAttribute('role','img');
    const svg = document.createElementNS('http://www.w3.org/2000/svg','svg'); svg.setAttribute('viewBox','0 0 32 32');
    const progress = document.createElementNS(svg.namespaceURI,'path'); svg.append(progress);
    timer.append(svg); line.append(code,timer); row.append(head,line);
    if (a.binding) row.append(element('div','account-bound',a.binding.service === 'gosuslugi' ? 'Госуслуги · автоустановка' : new URL(a.binding.origin).hostname + ' · Битрикс'));
    root.append(row); rows.set(a.id,{code,timer,progress});
  }
  $('empty').hidden = accounts.length !== 0 || reorderMode; $('no-results').hidden = !accounts.length || rows.size !== 0 || reorderMode; $('add-button').hidden = !key || reorderMode;
  void tick();
}
async function tick() {
  clearTimeout(tickTimer);
  if (!key || document.hidden) return;
  const token = generation, now = Date.now();
  await Promise.all(accounts.filter(a => rows.has(a.id)).map(async a => {
    const step = Math.floor(now/1000/a.period), remaining = a.period - now/1000 % a.period;
    const cached = codeCache.get(a.id); let value;
    try { value = cached?.step === step ? cached.value : await totp(a,now); } catch { value = 'Ошибка'; }
    if (token !== generation || !key || !rows.has(a.id)) return;
    codeCache.set(a.id,{step,value});
    const {code,timer,progress} = rows.get(a.id);
    code.textContent = /^\d+$/.test(value) ? value.slice(0,value.length/2) + ' ' + value.slice(value.length/2) : value;
    const urgent = remaining <= Math.min(5,a.period/4); code.classList.toggle('urgent',urgent); timer.classList.toggle('urgent',urgent);
    progress.setAttribute('d',timerSector(remaining / a.period)); timer.setAttribute('aria-label',`Осталось ${Math.ceil(remaining)} с`); timer.title = `${Math.ceil(remaining)} с`;
  }));
  if (token === generation && key && !document.hidden) { updateAutoLabel(); tickTimer = setTimeout(tick,1000 - Date.now() % 1000); }
}
function editAccount(a = null) {
  $('share-button').hidden = !a;
  if (!requireOpen()) return; editing = a?.id ?? null; $('edit-form').reset(); $('edit-error').textContent = ''; $('show-secret').checked = !a; $('secret').type = a ? 'password' : 'text';
  $('edit-title').textContent = a ? 'Настройки аккаунта' : 'Новый аккаунт'; $('issuer').value = a?.issuer ?? ''; $('account-name').value = a?.name ?? ''; $('secret').value = a?.secret ?? ''; $('algorithm').value = a?.algorithm ?? 'SHA1'; $('digits').value = a?.digits ?? 6; $('period').value = a?.period ?? 30; $('service').value = a?.binding?.service ?? 'none'; $('site-url').value = a?.binding?.service === 'bitrix' ? a.binding.origin : ''; $('delete-button').hidden = !a; updateSite(); show('edit-dialog');
}
function updateSite() { const bitrix = $('service').value === 'bitrix'; $('site-label').hidden = !bitrix; $('site-url').required = bitrix; }
$('service').addEventListener('change',updateSite);
const shareButton = element('button','wide','QR для переноса на телефон'); shareButton.id = 'share-button'; shareButton.type = 'button'; $('edit-form').insertBefore(shareButton,$('edit-error'));
shareButton.addEventListener('click',() => {
  if (!requireOpen()) return;
  const a = accounts.find(a => a.id === editing); if (!a) return;
  sharedAccountId = a.id; $('share-error').textContent = ''; $('share-name').textContent = title(a); $('share-params').textContent = `TOTP · ${a.algorithm} · ${a.digits} цифр · период ${a.period} с`;
  const canvas = $('share-qr'); canvas.width = canvas.height = 0;
  if (a.name.includes(':') || a.issuer.includes(':')) $('share-params').textContent += '. В QR двоеточия названия заменены на « · » для совместимости; локальное имя не меняется.';
  try {
    const qr = GATOTP_QR.create(otpUri(a),{errorCorrectionLevel:'M'}), size = qr.modules.size, cell = 5, margin = 4;
    canvas.width = canvas.height = (size + margin * 2) * cell; const ctx = canvas.getContext('2d'); ctx.fillStyle = '#fff'; ctx.fillRect(0,0,canvas.width,canvas.height); ctx.fillStyle = '#000';
    for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) if (qr.modules.data[y * size + x]) ctx.fillRect((x + margin) * cell,(y + margin) * cell,cell,cell);
  } catch { $('share-error').textContent = 'Данные слишком длинные для QR. Используйте ручной перенос ключа.'; }
  show('share-dialog');
});
$('copy-secret').addEventListener('click',async () => { if (!requireOpen()) return; const a = accounts.find(a => a.id === sharedAccountId); if (!a) return; try { await navigator.clipboard.writeText(a.secret); toast('Секретный ключ скопирован'); } catch { $('share-error').textContent = 'Не удалось скопировать ключ.'; } });
$('share-dialog').addEventListener('close',() => { sharedAccountId = null; $('share-qr').width = $('share-qr').height = 0; $('share-name').textContent = ''; $('share-params').textContent = ''; });
$('show-secret').addEventListener('change',() => {$('secret').type = $('show-secret').checked ? 'text' : 'password';});
$('edit-form').addEventListener('submit',async e => {
  e.preventDefault(); $('edit-error').textContent = '';
  const token = generation, editId = editing;
  try {
    const a = normalizeAccount({id:editing,name:$('account-name').value,issuer:$('issuer').value,secret:$('secret').value,algorithm:$('algorithm').value,digits:$('digits').value,period:$('period').value,binding:{service:$('service').value,origin:$('site-url').value}});
    const next = editing ? accounts.map(old => old.id === editing ? a : old) : [...accounts,a]; validateBindings(next);
    if (!editing && accounts.some(old => fingerprint(old) === fingerprint(a))) throw new Error('Такой ключ с этими параметрами уже есть. Используйте редактирование или импорт с проверкой дубликатов.');
    // Permission request remains in the click/submit gesture, before crypto awaits.
    if (a.binding && !(await chrome.permissions.request({origins:[a.binding.origin + '/*']}))) throw new Error('Доступ к сайту не предоставлен. Выберите «Не привязан» или разрешите доступ.');
    if (!key || generation !== token || editing !== editId || !$('edit-dialog').open) return;
    if (!editing) { resetImport(); pending = [{account:a,choice:'add',manual:true}]; hide('edit-dialog'); renderPreview(); show('import-dialog'); return; }
    $('save-account').disabled = true; await persist(next); hide('edit-dialog'); toast('Аккаунт сохранён');
  } catch (error) { $('edit-error').textContent = error.message; } finally { $('save-account').disabled = false; }
});
function requestDelete(id) { const a = (reorderMode ? draftOrder : accounts).find(a => a.id === id); if (!a) return; deleteTarget = id; $('confirm-title').textContent = `Удалить «${title(a)}»?`; show('confirm-dialog'); }
$('delete-button').addEventListener('click',() => requestDelete(editing));
$('cancel-delete').addEventListener('click',() => { deleteTarget = null; hide('confirm-dialog'); });
$('confirm-delete').addEventListener('click',async () => { const id = deleteTarget; if (!id) return; if (reorderMode) { draftOrder = draftOrder.filter(a => a.id !== id); deleteTarget = null; hide('confirm-dialog'); renderAccounts(); toast('Удаление применится после «Сохранить»'); return; } try { await persist(accounts.filter(a => a.id !== id)); deleteTarget = null; hide('confirm-dialog'); hide('edit-dialog'); toast('Аккаунт удалён'); } catch (e) { hide('confirm-dialog'); $('edit-error').textContent = e.message; } });
const importSourceIds = {file:'file-import-dialog',text:'text-import-dialog',camera:'camera-dialog'};
function sourceError() { return $('file-import-dialog').open ? $('file-import-error') : $('text-import-dialog').open ? $('text-import-error') : $('camera-dialog').open ? $('camera-error') : $('import-error'); }
function openImport(source='file',preserve=false) {
  if (!requireOpen()) return; hide('add-dialog'); hide('menu-dialog');
  if (!preserve) resetImport();
  const dialog = $(importSourceIds[source]); dialog.querySelector('.backup-slot').append($('backup-password-label'));
  show(dialog.id); renderPreview();
  if (source === 'camera') { $('camera-window').hidden = true; void startCamera($('camera-select').value); }
}
function confirmImport() {
  if (encryptedImport || !pending.length || (batch.size && !batchComplete)) return;
  for (const id of Object.values(importSourceIds)) if ($(id).open) { keepImportOnClose.add(id); if(id==='camera-dialog')stopCamera(); hide(id); }
  renderPreview(); show('import-dialog');
}
function ingest(text) {
  const value = text.trim(); if (value.length > 2000000) throw new Error('Слишком большой файл или текст.');
  if (value.startsWith('otpauth-migration:')) {
    const part = parseMigration(value);
    if (part.size === 0) {
      pending.push(...part.accounts.map(account => ({account:{...account,id:crypto.randomUUID(),binding:null},choice:null})));
      importWarnings.push(...part.warnings);
      const notice = 'Число частей экспорта не указано. Если Google показывает несколько QR, добавьте каждый перед сохранением.';
      if (!importWarnings.includes(notice)) importWarnings.push(notice);
    } else {
    const status = batch.add(part);
    if (status.complete && !batchComplete) { pending.push(...batch.collect().map(a => ({account:{...a,id:crypto.randomUUID(),binding:null},choice:null}))); importWarnings.push(...batch.warnings()); batchComplete = true; }
    $('batch-status').hidden = false;
    $('batch-status').textContent = status.complete ? `Все части получены (${batch.size}/${batch.size}).${status.duplicate ? ' Повтор QR пропущен.' : ''}` : `Получено ${batch.parts.size}/${batch.size}. Не хватает QR: ${status.missing.map(i => i + 1).join(', ')}. Не закрывайте окно импорта.`;
    }
  } else if (value.startsWith('otpauth:')) { pending.push({account:parseOtp(value),choice:null}); }
  else if (value.startsWith('{')) {
    let data; try { data = JSON.parse(value); } catch { throw new Error('Повреждённый JSON.'); }
    if (data.format === 'chrome-app-totp-vault') { encryptedImport = validateEnvelope(data); $('backup-password-label').hidden = false; }
    else pending.push(...parseBackup(value).map(a => ({account:{...a,id:crypto.randomUUID(),binding:null},choice:null})));
  } else {
    const links = value.split(/\r?\n/).map(s => s.trim()).filter(s => s.startsWith('otpauth:') || s.startsWith('otpauth-migration:'));
    if (!links.length) throw new Error('Не найдены ссылки otpauth или данные резервной копии CHROME-APP-TOTP.');
    for (const link of links) ingest(link);
  }
  if (pending.length > 2000) { pending = pending.slice(0,2000); throw new Error('В одном импорте допускается до 2000 аккаунтов.'); }
}
function importClassification(a,working) {
  const exact = working.find(old => fingerprint(old) === fingerprint(a));
  const conflict = working.find(old => identity(old) === identity(a)) ?? working.find(old => old.secret === a.secret);
  return {exact,conflict};
}
function renderPreview() {
  const root = $('import-preview'); root.replaceChildren(); let working = [...accounts], count = 0;
  for (const item of pending) {
    const a = item.account, {exact,conflict} = importClassification(a,working);
    if (!item.choice) item.choice = exact || conflict ? 'skip' : 'add';
    if (exact) item.choice = 'skip';
    if (!conflict && item.choice === 'replace') item.choice = 'add';
    const row = element('div','preview-row'); row.append(element('strong','',title(a)),element('small','',`${a.algorithm} · ${a.digits} цифр · ${a.period} с`));
    const select = element('select'); select.setAttribute('aria-label',`Действие для ${title(a)}`);
    const options = exact ? [['skip','Дубликат ключа — пропустить']] : conflict ? [['skip','Конфликт названия — пропустить'],['add','Сохранить как отдельный аккаунт'],['replace','Заменить существующий ключ']] : [['add','Добавить'],['skip','Пропустить']];
    for (const [value,text] of options) { const option = element('option','',text); option.value = value; select.append(option); }
    select.value = item.choice; select.disabled = !!exact; select.addEventListener('change',() => { item.choice = select.value; renderPreview(); }); row.append(select); root.append(row);
    if (item.choice === 'replace' && conflict) { working = working.map(old => old.id === conflict.id ? {...a,id:conflict.id,binding:old.binding} : old); count++; }
    else if (item.choice === 'add' && !exact) { working.push(a); count++; }
  }
  $('import-warnings').replaceChildren(...importWarnings.map(s => element('p','',s))); $('import-warnings').hidden = !importWarnings.length;
  if (!batch.size) $('batch-status').hidden = true;
  $('commit-import').disabled = !count || (batch.size > 0 && !batchComplete); $('commit-import').textContent = `Добавить${count ? ' (' + count + ')' : ''}`;
  const incomplete = !!encryptedImport || !pending.length || (batch.size > 0 && !batchComplete);
  $('file-save').disabled = incomplete || fileImportBusy; $('camera-save').disabled = incomplete;
  const status = batch.size ? $('batch-status').textContent : encryptedImport ? 'Введите пароль резервной копии.' : pending.length ? `Распознано аккаунтов: ${pending.length}` : '';
  $('file-import-status').textContent = $('text-import-status').textContent = status;
}
function parseText() { sourceError().textContent = ''; try { if ($('import-text').value.trim()) { ingest($('import-text').value); $('import-text').value = ''; } else if (!pending.length && !encryptedImport) throw new Error('Введите ссылку или данные для добавления.'); renderPreview(); confirmImport(); } catch (e) { sourceError().textContent = e.message; renderPreview(); } }
$('parse-text').addEventListener('click',parseText);
$('clear-import').addEventListener('click',resetImport);
async function processFiles(files) {
  if (fileImportBusy || !key || !$('file-import-dialog').open || !files.length) return;
  fileImportBusy = true; $('import-files').disabled = true;
  const token = generation, importToken = importGeneration; sourceError().textContent = ''; const errors = []; $('commit-import').disabled = $('file-save').disabled = true;
  $('file-import-status').textContent = 'Читаем файлы…';
  for (const file of files) {
    try {
      if (!key || token !== generation || importToken !== importGeneration) return;
      if (file.size > 15 * 1024 * 1024) throw new Error('Файл больше 15 МБ.');
      const values = /\.(json|txt|vault)$/i.test(file.name) ? [await file.text()] : await scanFile(file,fileScanAbort.signal);
      if (!key || token !== generation || importToken !== importGeneration) return;
      for (const value of values) ingest(value);
    } catch (e) { errors.push(e.message); }
  }
  if (importToken !== importGeneration || token !== generation) return;
  fileImportBusy = false; $('import-files').disabled = false;
  $('import-files').value = ''; sourceError().textContent = errors.join('\n'); renderPreview();
}
$('import-files').addEventListener('change',e => { void processFiles([...e.target.files]); });
function transferredFiles(data) {
  const files = [...(data?.files ?? [])];
  return files.length ? files : [...(data?.items ?? [])].filter(i => i.kind === 'file').map(i => i.getAsFile()).filter(Boolean);
}
const fileDialog = $('file-import-dialog'), fileDropZone = $('file-drop-zone');
fileDialog.addEventListener('dragover',e => {
  if (!e.dataTransfer?.types.includes('Files')) return;
  e.preventDefault(); e.dataTransfer.dropEffect = fileImportBusy ? 'none' : 'copy';
  if (!fileImportBusy) fileDropZone.classList.add('drag-over');
});
fileDialog.addEventListener('dragleave',e => { if (!fileDialog.contains(e.relatedTarget)) fileDropZone.classList.remove('drag-over'); });
fileDialog.addEventListener('drop',e => {
  e.preventDefault(); fileDropZone.classList.remove('drag-over');
  const files = transferredFiles(e.dataTransfer);
  if (files.length) void processFiles(files);
});
document.addEventListener('paste',e => {
  if (!$('file-import-dialog').open) return;
  const files = transferredFiles(e.clipboardData);
  if (files.length) { e.preventDefault(); void processFiles(files); }
  else if (!e.target.closest('input,textarea')) {
    $('file-import-error').textContent = 'В буфере нет доступного файла или изображения. Перетащите файл в это окно или выберите его.';
  }
});
$('decrypt-backup').addEventListener('click',async () => {
  if (fileImportBusy || !encryptedImport || !key) return;
  fileImportBusy = true; $('import-files').disabled = true; $('file-save').disabled = true;
  const token = generation, importToken = importGeneration; $('decrypt-backup').disabled = true;
  try {
    if (!encryptedImport) return;
    const result = await unseal(encryptedImport,$('backup-password').value);
    if (!key || token !== generation || importToken !== importGeneration) return;
    pending.push(...result.accounts.map(a => ({account:{...a,id:crypto.randomUUID(),binding:null},choice:null}))); encryptedImport = null; $('backup-password').value = ''; $('backup-password-label').hidden = true; sourceError().textContent = ''; renderPreview();
  } catch (e) { if (key && token === generation && importToken === importGeneration) sourceError().textContent = e.message; }
  finally {
    if (token === generation && importToken === importGeneration) {
      fileImportBusy = false; $('import-files').disabled = false; $('decrypt-backup').disabled = false; renderPreview();
    }
  }
});
$('commit-import').addEventListener('click',async () => {
  if (batch.size && !batchComplete) return;
  $('commit-import').disabled = true;
  try {
    let next = [...accounts];
    for (const item of pending) {
      const {exact,conflict} = importClassification(item.account,next);
      if (exact || item.choice === 'skip') continue;
      if (item.choice === 'replace' && conflict) next = next.map(old => old.id === conflict.id ? {...item.account,id:conflict.id,binding:old.binding} : old);
      else if (item.choice === 'add') next.push({...item.account,id:crypto.randomUUID(),binding:item.manual ? item.account.binding : null});
    }
    await persist(next); resetImport(); hide('import-dialog'); toast('Импорт завершён');
  } catch (e) { $('import-error').textContent = e.message; renderPreview(); }
});
function stopCamera() { cameraGeneration++; cameraReader?.close(); cameraReader = null; clearTimeout(scanTimer); stream?.getTracks().forEach(t => t.stop()); stream = null; $('video').srcObject = null; scanBusy = false; scanCanvas.width = scanCanvas.height = 0; }
function cameraStage(mode) {
  cameraMode = mode;
  $('camera-live').hidden = mode !== 'live';
  $('camera-processing').hidden = mode !== 'processing';
  $('camera-next').hidden = !['complete','error'].includes(mode);
  $('camera-next').textContent = mode === 'error' ? 'Повторить сканирование' : batch.size && !batchComplete ? 'Сканировать следующий QR' : 'Сканировать ещё';
}
async function acceptCameraQR(values) {
  stopCamera(); const token = cameraGeneration, importToken = importGeneration;
  cameraStage('processing'); $('camera-error').textContent = ''; $('camera-status').textContent = 'QR считан. Камера выключена.';
  $('camera-save').disabled = true;
  // Give the captured state a paint before parsing and preparing the account list.
  await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
  if (token !== cameraGeneration || importToken !== importGeneration || !key || document.hidden || !$('camera-dialog').open) return;
  let accepted = false, duplicate = false;
  for (const value of values) {
    if (cameraSeen.has(value)) { duplicate = true; continue; }
    try { ingest(value); cameraSeen.add(value); accepted = true; touch(); }
    catch (e) { $('camera-error').textContent = e.message === 'Не найдены ссылки otpauth или данные резервной копии CHROME-APP-TOTP.' ? 'Этот QR не содержит ключ TOTP или экспорт Google Authenticator.' : e.message; }
  }
  renderPreview();
  cameraStage(accepted || duplicate ? 'complete' : 'error');
  $('camera-status').textContent = accepted ? (batch.size ? $('batch-status').textContent : 'QR распознан. Нажмите «Сохранить» для подтверждения добавления.') : duplicate ? 'Этот QR уже считан. Покажите следующую часть экспорта.' : 'QR прочитан, но добавить его не удалось.';
}
async function startCamera(deviceId = '') {
  stopCamera(); cameraStage('live'); const token = cameraGeneration; cameraStarted = Date.now(); cameraLastDetected = 0; cameraLastEnhanced = 0; $('camera-window').hidden = true; $('camera-error').textContent = ''; $('camera-status').textContent = 'Ожидание доступа к камере…';
  try {
    if (!full) {
      let permission; try { permission = await navigator.permissions.query({name:'camera'}); } catch {}
      if (!key || document.hidden || token !== cameraGeneration || !$('camera-dialog').open) return;
      if (permission && permission.state !== 'granted') { try { await openImportWindow(true); } catch(e) { $('camera-error').textContent=e.message; $('camera-window').hidden=false; } return; }
    }
    const acquired = await navigator.mediaDevices.getUserMedia({video:{...(deviceId ? {deviceId:{exact:deviceId}} : {facingMode:'environment'}),width:{ideal:1920},height:{ideal:1080},frameRate:{ideal:10},resizeMode:{ideal:'none'}},audio:false});
    if (!key || document.hidden || token !== cameraGeneration || !$('camera-dialog').open) { acquired.getTracks().forEach(t => t.stop()); return; }
    stream = acquired; $('video').srcObject = stream; await $('video').play();
    const devices = (await navigator.mediaDevices.enumerateDevices()).filter(d => d.kind === 'videoinput');
    $('camera-select').replaceChildren(...devices.map((d,i) => { const option = element('option','',d.label || `Камера ${i + 1}`); option.value = d.deviceId; return option; }));
    $('camera-select').value = stream.getVideoTracks()[0].getSettings().deviceId || devices[0]?.deviceId || ''; $('camera-status').textContent = 'Наведите камеру на QR-код. Все части экспорта добавляются по очереди.';
    scanFrame(token);
  } catch (e) { if (token === cameraGeneration) { stopCamera(); cameraStage('error'); $('camera-error').textContent = cameraError(e); $('camera-status').textContent = 'Камера выключена'; $('camera-window').hidden = full; if (!full && ['NotAllowedError','SecurityError'].includes(e.name)) { try { await openImportWindow(true); } catch(error) { $('camera-error').textContent=error.message; } } } }
}
const scanCanvas = document.createElement('canvas'), scanContext = scanCanvas.getContext('2d',{willReadFrequently:true});
async function scanFrame(token) {
  if (token !== cameraGeneration || !stream || document.hidden || scanBusy) return;
  const video = $('video');
  if (video.readyState >= 2 && !scanBusy) {
    scanBusy = true;
    try {
      const scale = Math.min(1,1920 / Math.max(video.videoWidth,video.videoHeight)); scanCanvas.width = Math.round(video.videoWidth * scale); scanCanvas.height = Math.round(video.videoHeight * scale);
      scanContext.drawImage(video,0,0,scanCanvas.width,scanCanvas.height); const pixels = scanContext.getImageData(0,0,scanCanvas.width,scanCanvas.height);
      cameraReader ??= createQRReader();
      const enhance = Date.now() - cameraLastEnhanced >= 2000;
      if (enhance) cameraLastEnhanced = Date.now();
      const {values,detected} = await cameraReader.decode(pixels,true,enhance);
      if (token !== cameraGeneration || !key || document.hidden || !$('camera-dialog').open) return;
      if (detected) cameraLastDetected = Date.now();
      if (!values.length && !$('camera-error').textContent) {
        if (detected) $('camera-status').textContent = 'QR обнаружен, но данные пока не удалось прочитать. Держите код целиком в кадре.';
        else if (Date.now() - cameraStarted >= 8000 && Date.now() - cameraLastDetected >= 3000) $('camera-status').textContent = `Код пока не распознан. Камера: ${video.videoWidth} × ${video.videoHeight}. Попробуйте изменить расстояние до QR или импортировать его изображение.`;
      }
      if (values.length) { await acceptCameraQR(values); return; }
    } catch (e) { if (token === cameraGeneration && e.name !== 'AbortError') { stopCamera(); cameraStage('error'); $('camera-error').textContent = e.message; $('camera-status').textContent = 'Сканирование остановлено.'; } }
    finally { if (token === cameraGeneration) scanBusy = false; }
  }
  if (token === cameraGeneration && stream && !document.hidden) scanTimer = setTimeout(() => { void scanFrame(token); },500);
}
function openCamera() { openImport('camera'); }
$('camera-window').addEventListener('click',() => { void openImportWindow(true).catch(e => { $('camera-error').textContent = e.message; }); });
$('camera-select').addEventListener('change',() => { void startCamera($('camera-select').value); });
$('camera-next').addEventListener('click',() => { void startCamera($('camera-select').value); });
$('camera-dialog').addEventListener('close',() => { stopCamera(); cameraStage('idle'); });
$('camera-save').addEventListener('click',confirmImport); $('file-save').addEventListener('click',confirmImport);
for (const id of Object.values(importSourceIds)) $(id).addEventListener('close',() => { if (!keepImportOnClose.delete(id)) resetImport(); });
function openExport() {
  if (!requireOpen()) return; hide('menu-dialog'); $('export-list').replaceChildren(); $('export-error').textContent = ''; $('select-all').checked = true; $('export-format').value = 'encrypted'; $('plain-consent').checked = false; updateExportFormat();
  for (const a of accounts) { const label = element('label','check'), check = document.createElement('input'); check.type = 'checkbox'; check.checked = true; check.value = a.id; label.append(check,element('span','',title(a))); $('export-list').append(label); }
  show('export-dialog');
}
function updateExportFormat() {
  const plain = $('export-format').value !== 'encrypted'; $('plain-consent-label').hidden = !plain; $('plain-consent').checked = false;
  const qr = $('export-format').value.startsWith('qr-');
  $('download-export').textContent = qr ? 'Показать QR' : 'Сохранить файл';
  $('export-info').textContent = plain ? 'Открытый файл не зашифрован. Не отправляйте его в чат, почту или онлайн-декодеры.' : 'Копия защищена текущим мастер-паролем. Сохраните пароль отдельно.';
  if (qr) $('export-info').textContent = 'QR содержит секретные ключи. Показывайте его только своему устройству.';
}
function clearExportQR() {
  exportQRParts = []; exportQRIndex = 0;
  $('export-qr').width = $('export-qr').height = 0; $('export-qr-status').textContent = '';
}
function renderExportQR() {
  if (!key || !exportQRParts.length) return;
  const part = exportQRParts[exportQRIndex], qr = GATOTP_QR.create(part.uri,{errorCorrectionLevel:'M'});
  const canvas = $('export-qr'), size = qr.modules.size, cell = 5, margin = 4;
  canvas.width = canvas.height = (size+margin*2)*cell;
  const ctx = canvas.getContext('2d'); ctx.fillStyle = '#fff'; ctx.fillRect(0,0,canvas.width,canvas.height); ctx.fillStyle = '#000';
  for (let y=0;y<size;y++) for(let x=0;x<size;x++) if(qr.modules.data[y*size+x])ctx.fillRect((x+margin)*cell,(y+margin)*cell,cell,cell);
  $('export-qr-status').textContent = 'QR '+(exportQRIndex+1)+' из '+exportQRParts.length+' · '+(part.name || 'аккаунтов: '+part.count);
  $('export-qr-prev').disabled = exportQRIndex === 0; $('export-qr-next').disabled = exportQRIndex === exportQRParts.length-1;
}
$('export-qr-prev').addEventListener('click',() => { if(exportQRIndex>0) {exportQRIndex--;renderExportQR();} });
$('export-qr-next').addEventListener('click',() => { if(exportQRIndex+1<exportQRParts.length) {exportQRIndex++;renderExportQR();} });
$('export-qr-dialog').addEventListener('close',clearExportQR);
$('export-format').addEventListener('change',updateExportFormat);
$('select-all').addEventListener('change',() => { for (const input of $('export-list').querySelectorAll('input')) input.checked = $('select-all').checked; });
$('download-export').addEventListener('click',async () => {
  const token = generation; $('download-export').disabled = true; $('export-error').textContent = '';
  try {
    const ids = new Set([...$('export-list').querySelectorAll('input:checked')].map(i => i.value)), selected = accounts.filter(a => ids.has(a.id));
    if (!selected.length) throw new Error('Выберите хотя бы один аккаунт.');
    const format = $('export-format').value;
    if (format !== 'encrypted' && !$('plain-consent').checked) throw new Error('Подтвердите экспорт открытых секретов.');
    if (format.startsWith('qr-')) {
      clearExportQR();
      const parts = format === 'qr-google' ? migrationUris(selected) : selected.map(a => ({uri:otpUri(a),count:1,name:title(a)}));
      if (parts.some(p => p.uri.length > 2000)) throw new Error('Один из аккаунтов слишком большой для QR. Используйте экспорт в файл.');
      exportQRParts = parts;
      try { renderExportQR(); } catch { clearExportQR(); throw new Error('Данные слишком длинные для QR. Используйте экспорт в файл.'); }
      hide('export-dialog'); show('export-qr-dialog'); return;
    }
    const content = format === 'txt' ? exportText(selected) : JSON.stringify(format === 'encrypted' ? await seal(selected,key,salt,1,vault?.passwordLength) : {format:'chrome-app-totp-plain',version:1,accounts:selected},null,2);
    if (!key || token !== generation) return;
    const url = URL.createObjectURL(new Blob([content],{type:format === 'txt' ? 'text/plain;charset=utf-8' : 'application/json'}));
    const link = document.createElement('a'); link.href = url; link.download = `CHROME-APP-TOTP-${format === 'encrypted' ? 'encrypted' : 'OPEN-SECRETS'}-${new Date().toISOString().slice(0,10)}.${format === 'txt' ? 'txt' : 'json'}`; document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url),30000); toast('Файл передан в загрузки Chrome');
  } catch (e) { $('export-error').textContent = e.message; } finally { $('download-export').disabled = false; }
});
function openSettings() { if (!key) return; if (reorderMode) { toast('Сохраните или отмените порядок'); return; } hide('menu-dialog'); $('settings-error').textContent = ''; renderOrder(); void renderFileInfo(); show('settings-dialog'); }
const storageSection = element('section','storage-settings'); storageSection.append(element('h2','','Файл базы'));
const storageRow = element('div','storage-path-row'), storagePath = element('button','storage-path','%USERPROFILE%\\.CHROME-APP-TOTP.vault'), storageDefault = element('button','','По умолчанию');
storagePath.id = 'storage-path'; storagePath.setAttribute('aria-label','Выбрать файл базы'); storageDefault.id = 'storage-default'; storageRow.append(storagePath,storageDefault); storageSection.append(storageRow); $('settings-dialog').insertBefore(storageSection,$('settings-error'));
async function renderFileInfo() { const s = await fileStatus(); storagePath.textContent = s.location; storagePath.title = s.location; const {vaultPickerError} = await chrome.storage.session.get('vaultPickerError'); if(vaultPickerError)$('settings-error').textContent=vaultPickerError; }
async function changeFile(useDefault) {
  storagePath.disabled = storageDefault.disabled = true; $('settings-error').textContent = '';
  try { const result = await chrome.runtime.sendMessage({type:useDefault?'default-vault':'choose-vault'}); if (!result?.ok) throw new Error(result?.error || 'Не удалось выбрать файл.'); if (!result.cancelled) { lockLocal(); await configureLock(); toast('Файл базы изменён. Войдите мастер-паролем.'); } }
  catch(e){$('settings-error').textContent=e.message;} finally {storagePath.disabled = storageDefault.disabled = false; await renderFileInfo();}
}
storagePath.addEventListener('click',() => { void changeFile(false); });
storageDefault.addEventListener('click',() => { void changeFile(true); });
const orderButton = element('button','wide','Изменить порядок'); orderButton.id = 'change-order'; orderButton.hidden = true; $('settings-dialog').querySelector('.dialog-head').after(orderButton);
const orderBar = element('div','order-bar'); orderBar.id = 'order-bar'; orderBar.hidden = true;
const saveOrder = element('button','primary','Сохранить'), cancelOrder = element('button','','Отмена'); saveOrder.id = 'save-order'; cancelOrder.id = 'cancel-order'; orderBar.append(element('span','','Порядок аккаунтов'),cancelOrder,saveOrder); $('codes-screen').prepend(orderBar);
function renderOrder() { orderButton.hidden = !key || accounts.length === 0; orderButton.disabled = orderButton.hidden; }
function moveDraft(id,targetId) { const from = draftOrder.findIndex(a => a.id === id), to = draftOrder.findIndex(a => a.id === targetId); if (from < 0 || to < 0 || from === to) return; const [a] = draftOrder.splice(from,1); draftOrder.splice(to,0,a); renderAccounts(); }
function endOrder() { reorderMode = false; draftOrder = []; orderBar.hidden = true; $('search').disabled = false; $('search-toggle').disabled = false; $('menu-button').disabled = false; renderAccounts(); }
orderButton.addEventListener('click',() => { if (!requireOpen()) return; hide('settings-dialog'); reorderMode = true; draftOrder = [...accounts]; closeSearch(); $('search').disabled = true; $('search-toggle').disabled = true; $('menu-button').disabled = true; orderBar.hidden = false; renderAccounts(); });
cancelOrder.addEventListener('click',endOrder);
saveOrder.addEventListener('click',async () => { saveOrder.disabled = true; try { await persist([...draftOrder]); endOrder(); toast('Порядок сохранён'); } catch (e) { toast(e.message); } finally { saveOrder.disabled = false; } });
$('protection-toggle').addEventListener('change',async () => {
  const target = !$('protection-toggle').checked;
  $('protection-toggle').disabled = true;
  try {
    if (!target && !requireOpen()) { $('protection-toggle').checked = !protectedMode; return; }
    if (target) {
      // Remove persistent raw material BEFORE publishing the protected setting.
      await navigator.locks.request('chrome-app-totp-security',async () => { await chrome.storage.local.remove('deviceKey'); await chrome.storage.session.remove('uiUnlock'); await chrome.storage.local.set({protectedMode:true}); });
      protectedMode = true; $('passkey-setting').hidden = false; $('passkey-toggle').disabled = false; await lock(); toast('Ключ устройства удалён. Защита включена.');
    } else {
      const epoch = await lockEpoch();
      protectedMode = false; $('passkey-setting').hidden = true; await chrome.storage.local.set({protectedMode:false});
      try { await rememberKey(key,salt,false,epoch); }
      catch (error) { await navigator.locks.request('chrome-app-totp-security',async()=>{await chrome.storage.local.remove('deviceKey'); await chrome.storage.local.set({protectedMode:true});}); protectedMode = true; $('passkey-setting').hidden = false; throw error; }
      await chrome.storage.local.remove('passkeyConfig'); passkeyConfig = null; $('passkey-toggle').checked = false; $('passkey-toggle').disabled = true; toast('Автоматическое открытие включено');
    }
  } catch (e) { $('protection-toggle').checked = !protectedMode; $('settings-error').textContent = e.message; }
  finally { $('protection-toggle').disabled = false; }
});
$('passkey-toggle').addEventListener('change',async () => {
  if (!$('passkey-toggle').checked) { await chrome.storage.local.remove('passkeyConfig'); passkeyConfig = null; $('unlock-passkey').hidden = true; return; }
  if (!protectedMode || !requireOpen()) { $('passkey-toggle').checked = false; return; }
  const token = generation; $('passkey-toggle').disabled = true; $('settings-error').textContent = 'Подтвердите создание ключа в системном диалоге.';
  try {
    const config = await enrollPasskey(key,salt);
    if (!key || generation !== token) return;
    await chrome.storage.local.set({passkeyConfig:config}); passkeyConfig = config; $('settings-error').textContent = ''; toast('Ключ доступа подключён');
  } catch (e) { $('passkey-toggle').checked = false; $('settings-error').textContent = e.message; }
  finally { $('passkey-toggle').disabled = !protectedMode; }
});
async function usePasskey() {
  if (unlockBusy || lockConfiguring || localLockRequest || $('unlock-form').hidden) return;
  unlockBusy = true; renderPinGate();
  $('unlock-passkey').disabled = true; $('unlock-error').textContent = '';
  const token = generation;
  try { const authEpoch = await lockEpoch(); const current = await loadVault(); const unlocked = await unlockPasskey(current,passkeyConfig); if (token !== generation) return; await acceptUnlocked(unlocked,current,authEpoch); }
  catch (e) { if (!key && token === generation) $('unlock-error').textContent = e.message; } finally { unlockBusy = false; $('unlock-passkey').disabled = false; renderPinGate(); focusPin(); }
}
$('unlock-passkey').addEventListener('click',() => { void usePasskey(); });
$('theme').addEventListener('change',async () => { document.documentElement.dataset.theme = $('theme').value; await chrome.storage.local.set({theme:$('theme').value}); });
$('layout').addEventListener('change',async () => { document.documentElement.dataset.layout = $('layout').value; await chrome.storage.local.set({layout:$('layout').value}); });
$('auto-toggle').addEventListener('change',async () => {
  try { await chrome.storage.local.set({autoEnabled:$('auto-toggle').checked}); await activateAuto(); if ($('auto-toggle').checked && !autoExpires) toast('Привяжите сервис через шестерёнку аккаунта.'); }
  catch (e) { toast(e.message); }
});
$('revoke-sites').addEventListener('click',async () => { await chrome.storage.local.set({autoEnabled:false}); $('auto-toggle').checked = false; await activateAuto(); const permissions = await chrome.permissions.getAll(); if (permissions.origins?.length) await chrome.permissions.remove({origins:permissions.origins}); toast('Доступ к сайтам отключён'); });
let passwordChangeBusy = false, passwordDialogGeneration = 0;
function updateOldPasswordField() { $('old-password-label').hidden = protectedMode; $('old-password').required = !protectedMode; }
function updateNewPasswordLength() {
  const length = Number($('new-password-length').value);
  for (const id of ['new-password','new-password-confirm']) { $(id).value = ''; $(id).minLength = length; $(id).maxLength = length*2; }
}
$('new-password-length').addEventListener('change',updateNewPasswordLength);
$('change-password-open').addEventListener('click',() => { if (requireOpen()) { $('change-password-form').reset(); updateNewPasswordLength(); updateOldPasswordField(); $('password-error').textContent = ''; show('password-dialog'); } });
$('password-dialog').addEventListener('close',() => { passwordDialogGeneration++; $('change-password-form').reset(); });
$('change-password-form').addEventListener('submit',async e => {
  e.preventDefault(); if (passwordChangeBusy || !requireOpen()) return;
  const token = generation, dialogToken = passwordDialogGeneration;
  const submit = $('change-password-form').querySelector('button.primary');
  const newPassword = $('new-password').value, oldPassword = $('old-password').value;
  passwordChangeBusy = true; submit.disabled = true; $('password-error').textContent = '';
  try {
    if (Array.from(newPassword).length !== Number($('new-password-length').value)) throw new Error('Введите ровно '+$('new-password-length').value+' символа.');
    if (newPassword !== $('new-password-confirm').value) throw new Error('Пароли не совпадают.');
    const mustVerify = (await chrome.storage.local.get('protectedMode')).protectedMode === false;
    if (mustVerify) {
      if (!oldPassword) throw new Error('Введите текущий мастер-пароль.');
      const current = await loadVault();
      if (!current || vaultToken(current) !== vaultToken(vault)) throw new Error('База изменилась. Откройте её заново.');
      // Verify the supplied password against the encrypted file, not a saved key.
      await attemptPassword(current,oldPassword);
    }
    const next = await createKey(newPassword);
    if (token !== generation || !key || dialogToken !== passwordDialogGeneration) return;
    if (!mustVerify && (await chrome.storage.local.get('protectedMode')).protectedMode === false) throw new Error('Режим изменился. Введите текущий мастер-пароль и повторите смену.');
    if (token !== generation || !key || dialogToken !== passwordDialogGeneration) return;
    await persist(accounts,next.key,next.salt,next.passwordLength);
    await chrome.storage.local.remove('passkeyConfig'); passkeyConfig = null; $('passkey-toggle').checked = false;
    $('change-password-form').reset(); hide('password-dialog'); toast('JSON перешифрован. Ключ доступа нужно привязать заново.');
  } catch (error) { if (dialogToken === passwordDialogGeneration) $('password-error').textContent = error.message; }
  finally { passwordChangeBusy = false; submit.disabled = false; }
});
for (const button of document.querySelectorAll('.close')) button.addEventListener('click',() => { const dialog=button.closest('dialog'); if(dialog.id==='camera-dialog')stopCamera(); if(dialog.id==='export-qr-dialog')clearExportQR(); dialog.close(); });
$('edit-dialog').addEventListener('close',() => { $('secret').value = ''; $('secret').type = 'password'; $('show-secret').checked = false; });
$('import-dialog').addEventListener('close',resetImport);
$('menu-button').addEventListener('click',() => show('menu-dialog'));
$('window-button').addEventListener('click',() => { void openWindow(); });
$('settings-button').addEventListener('click',openSettings);
for (const id of ['empty-add','add-button','menu-add']) $(id).addEventListener('click',() => { if (requireOpen()) { hide('menu-dialog'); show('add-dialog'); } });
$('add-manual').addEventListener('click',() => { hide('add-dialog'); editAccount(); });
$('add-qr').addEventListener('click',() => openImport('file')); $('add-link').addEventListener('click',() => openImport('text'));
$('add-screen').addEventListener('click',async () => {
  if (!requireOpen()) return;
  openImport('file');
  const token = generation, importToken = importGeneration;
  fileImportBusy = true; $('import-files').disabled = true; $('file-save').disabled = true;
  $('file-import-status').textContent = 'Создаём снимок вкладки…';
  try {
    const win = await chrome.windows.getLastFocused({windowTypes:['normal']});
    const [before] = await chrome.tabs.query({active:true,windowId:win.id});
    if (!before || before.url?.startsWith(chrome.runtime.getURL(''))) throw new Error('Выберите вкладку с QR и откройте расширение её кнопкой на панели Chrome.');
    if (!key || token !== generation || importToken !== importGeneration) return;
    const image = await chrome.tabs.captureVisibleTab(win.id,{format:'png'});
    const [after] = await chrome.tabs.query({active:true,windowId:win.id});
    if (!key || token !== generation || importToken !== importGeneration) return;
    if (before.id !== after?.id) throw new Error('Вкладка изменилась. Повторите снимок нужной страницы.');
    const raw = image.split(',')[1], bytes = Uint8Array.from(atob(raw),c => c.charCodeAt(0));
    const file = new File([bytes],'Снимок вкладки.png',{type:'image/png'});
    fileImportBusy = false;
    await processFiles([file]);
  } catch (error) {
    if (key && token === generation && importToken === importGeneration) {
      $('file-import-status').textContent = '';
      $('file-import-error').textContent = error.message.startsWith('Выберите') || error.message.startsWith('Вкладка изменилась') ? error.message : 'Chrome не разрешил снимок. Откройте расширение кнопкой на панели нужной вкладки и повторите, либо вставьте скриншот через Ctrl+V.';
    }
  } finally {
    if (token === generation && importToken === importGeneration) {
      fileImportBusy = false; $('import-files').disabled = false;
    }
  }
});
$('menu-export').addEventListener('click',openExport);
$('add-camera').addEventListener('click',openCamera);
$('search').addEventListener('input',renderAccounts); $('lock-button').addEventListener('click',() => { void lock(); });
function closeSearch() { $('search-panel').hidden = true; $('search').value = ''; $('search-toggle').setAttribute('aria-expanded','false'); renderAccounts(); }
$('search-toggle').addEventListener('click',() => { if (!key || reorderMode) return; if (!$('search-panel').hidden) closeSearch(); else { $('search-panel').hidden = false; $('search-toggle').setAttribute('aria-expanded','true'); $('search').focus(); } });
$('search').addEventListener('keydown',e => { if (e.key === 'Escape') { e.preventDefault(); closeSearch(); $('search-toggle').focus(); } });
for (const name of ['pointerdown','keydown','input']) document.addEventListener(name,touch,{passive:true});
document.addEventListener('visibilitychange',() => {
  clearTimeout(tickTimer);
  clearTimeout(pinGateTimer);
  if (!document.hidden && !key) { void refreshPinGate(); focusPin(); }
  if (document.hidden) { const scanning = ['live','processing'].includes(cameraMode); stopCamera(); if ($('camera-dialog').open && scanning) { cameraStage('paused'); $('camera-status').textContent = 'Камера приостановлена, пока окно скрыто.'; } }
  else { void tick(); if ($('camera-dialog').open && key && cameraMode === 'paused') void startCamera($('camera-select').value); }
});
window.addEventListener('pagehide',() => { generation++; key = null; accounts = []; clearExportQR(); codeCache.clear(); clearTimeout(tickTimer); clearTimeout(idleTimer); stopCamera(); });
chrome.storage.onChanged.addListener((changes,area) => {
  if (area === 'local' && changes.passwordAttemptGate && !key) void refreshPinGate();
  if (area === 'local' && changes.vaultMeta && key && !writing && changes.vaultMeta.newValue?.token !== vaultToken(vault)) { lockLocal(); void configureLock(); toast('Файл изменился в другом окне. Откройте его снова.'); }
  if (area === 'local' && changes.vaultFileChanged) { if (key) { lockLocal(); void chrome.runtime.sendMessage({type:'lock'}); } void configureLock(); }
  if (area === 'local' && changes.autoEnabled) { $('auto-toggle').checked = changes.autoEnabled.newValue === true; updateAutoLabel(); }
  if (area === 'local' && changes.layout) { const layout = changes.layout.newValue === 'tiles' ? 'tiles' : 'rows'; $('layout').value = layout; document.documentElement.dataset.layout = layout; }
  if (area === 'local' && changes.protectedMode) { protectedMode = changes.protectedMode.newValue !== false; $('protection-toggle').checked = !protectedMode; $('passkey-toggle').disabled = !protectedMode; $('passkey-setting').hidden = !protectedMode; updateOldPasswordField(); }
  if (area === 'session' && changes.autofillSession) { autoExpires = changes.autofillSession.newValue?.expires ?? 0; updateAutoLabel(); }
  if (area === 'session' && changes.lockEpoch && !localLockRequest) { lockLocal(); void configureLock(); }
});
async function init() {
  const prefs = await chrome.storage.local.get(['theme','layout','autoEnabled','protectedMode']); $('theme').value = ['light','dark'].includes(prefs.theme) ? prefs.theme : 'auto'; document.documentElement.dataset.theme = $('theme').value; $('layout').value = prefs.layout === 'tiles' ? 'tiles' : 'rows'; document.documentElement.dataset.layout = $('layout').value; $('auto-toggle').checked = prefs.autoEnabled === true; $('auto-toggle').disabled = false;
  protectedMode = prefs.protectedMode !== false; $('protection-toggle').checked = !protectedMode; $('passkey-toggle').disabled = !protectedMode;
  const status = await chrome.runtime.sendMessage({type:'status'}); autoExpires = status?.expires ?? 0; updateAutoLabel(); await configureLock();
  if (vault && !$('unlock-form').hidden) { const authEpoch = await lockEpoch(); const remembered = await recallKey(vault,protectedMode); if (remembered) await acceptUnlocked(remembered,vault,authEpoch); }
  if (authOnly && !key && passkeyConfig && protectedMode && vault && !$('unlock-form').hidden) await usePasskey();
  const params = new URLSearchParams(location.search);
  if (params.has('settings')) { history.replaceState(null,'','app.html?full=1'); openSettings(); }
  if (params.has('passkey') && !key && passkeyConfig && protectedMode && vault && !$('unlock-form').hidden) { history.replaceState(null,'','app.html?full=1'); await usePasskey(); }
}
$('startup-retry').addEventListener('click',() => location.reload());
void init().then(() => {
  // Reveal the resolved screen in one synchronous step, after file/session checks.
  $('startup-status').hidden = true;
  $('shell').inert = false; $('shell').setAttribute('aria-busy','false');
  document.body.removeAttribute('data-starting');
  focusPin();
}).catch(() => {
  // Never show the default "create password" form when initialization failed.
  $('startup-message').textContent = 'Не удалось открыть хранилище.';
  $('startup-retry').hidden = false;
});

