import {normalizeAccount} from './core.js';
import {nativeFile} from './native.js';
const iterations = 600000;
const utf8 = new TextEncoder();
const to64 = bytes => btoa(Array.from(bytes,b => String.fromCharCode(b)).join(''));
const from64 = s => Uint8Array.from(atob(s),c => c.charCodeAt(0));
export function validateEnvelope(v) {
  if (!v || v.format !== 'chrome-app-totp-vault' || v.version !== 1 || v.kdf !== 'PBKDF2-SHA256' || v.iterations !== iterations || !Number.isSafeInteger(v.revision) || v.revision < 1) throw new Error('Неизвестный формат зашифрованной копии.');
  if (![4,6,12].includes(v.passwordLength)) throw new Error('Некорректная длина код-пароля в файле.');
  try {
    if (typeof v.salt !== 'string' || typeof v.iv !== 'string' || typeof v.ciphertext !== 'string' || v.ciphertext.length > 8000000 || from64(v.salt).length !== 16 || from64(v.iv).length !== 12 || from64(v.ciphertext).length < 16) throw new Error();
  } catch { throw new Error('Повреждена зашифрованная копия.'); }
  return v;
}
async function derive(password,salt) {
  const material = await crypto.subtle.importKey('raw',utf8.encode(password),'PBKDF2',false,['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',salt,iterations},material,{name:'AES-GCM',length:256},true,['encrypt','decrypt']);
}
export async function createKey(password) {
  if (typeof password !== 'string' || ![4,6,12].includes(Array.from(password).length)) throw new Error('Код-пароль должен содержать 4, 6 или 12 символов.');
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const passwordLength = Array.from(password).length;
  return {key:await derive(password.toUpperCase(),salt),salt:to64(salt),passwordLength};
}
function additionalData(salt,revision,passwordLength) {
  // The chosen code length is authenticated along with the vault revision.
  return utf8.encode('chrome-app-totp-vault:1:'+salt+':'+revision+':passwordLength:'+passwordLength);
}
export async function seal(accounts, key, salt, revision, passwordLength) {
  if (![4,6,12].includes(passwordLength)) throw new Error('Некорректная длина код-пароля.');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aad = additionalData(salt,revision,passwordLength);
  const plaintext = utf8.encode(JSON.stringify(accounts));
  const encrypted = await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:aad},key,plaintext);
  plaintext.fill(0);
  return {format:'chrome-app-totp-vault',version:1,kdf:'PBKDF2-SHA256',iterations,salt,iv:to64(iv),revision,ciphertext:to64(new Uint8Array(encrypted)),passwordLength};
}
export async function unseal(v,password) {
  validateEnvelope(v);
  if (typeof password !== 'string' || Array.from(password).length !== v.passwordLength) {
    const error = new Error('Неверный пароль или повреждённая резервная копия.'); error.code = 'INVALID_PASSWORD'; throw error;
  }
  const normalized = password.toUpperCase(), salt = from64(v.salt);
  try { return await unsealWithKey(v,await derive(normalized,salt)); }
  catch (error) {
    // Older files used the exact entered case. Keep them readable until their
    // password is changed; new files always derive from the uppercase value.
    if (error.code !== 'INVALID_PASSWORD' || normalized === password) throw error;
    return unsealWithKey(v,await derive(password,salt));
  }
}
export async function exportKey(key) { return to64(new Uint8Array(await crypto.subtle.exportKey('raw',key))); }
export async function importKey(raw) { const bytes = from64(raw); if (bytes.length !== 32) throw new Error('Некорректный ключ устройства.'); return crypto.subtle.importKey('raw',bytes,{name:'AES-GCM'},true,['encrypt','decrypt']); }
export async function unsealWithKey(v,key) {
  validateEnvelope(v);
  let plain;
  try { plain = new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:from64(v.iv),additionalData:additionalData(v.salt,v.revision,v.passwordLength)},key,from64(v.ciphertext))); }
  catch { const error = new Error('Неверный пароль или повреждённая резервная копия.'); error.code = 'INVALID_PASSWORD'; throw error; }
  try {
    const raw = JSON.parse(new TextDecoder().decode(plain));
    if (!Array.isArray(raw) || raw.length > 2000) throw new Error();
    const accounts = raw.map(normalizeAccount);
    if (new Set(accounts.map(a => a.id)).size !== accounts.length) throw new Error();
    return {key,salt:v.salt,accounts,passwordLength:v.passwordLength};
  } catch { throw new Error('Повреждены записи хранилища.'); }
  finally { plain.fill(0); }
}
// IndexedDB holds ONLY a file handle. Account data lives in the user's encrypted
// JSON file, never in Chrome storage. The browser must grant access to that file.
let database;
async function db() {
  if (!database) database = new Promise((resolve,reject) => {
    const request = indexedDB.open('chrome-app-totp-file-link',1);
    request.onupgradeneeded = () => request.result.createObjectStore('links');
    request.onsuccess = () => resolve(request.result); request.onerror = () => reject(new Error('Не удалось сохранить ссылку на файл.'));
  });
  return database;
}
async function handle() {
  const database = await db();
  return new Promise((resolve,reject) => { const request = database.transaction('links','readonly').objectStore('links').get('vault'); request.onsuccess = () => resolve(request.result ?? null); request.onerror = () => reject(new Error('Не удалось прочитать ссылку на файл.')); });
}
export async function attachHandle(fileHandle) {
  if (!fileHandle || fileHandle.kind !== 'file') throw new Error('Выберите JSON-файл хранилища.');
  return navigator.locks.request('chrome-app-totp-vault-write',async () => {
  return navigator.locks.request('chrome-app-totp-security',async () => {
  const database = await db();
  await new Promise((resolve,reject) => { const tx = database.transaction('links','readwrite'); tx.objectStore('links').put(fileHandle,'vault'); tx.oncomplete = resolve; tx.onerror = () => reject(new Error('Не удалось запомнить файл.')); });
  await chrome.storage.local.remove('vaultMeta');
  await chrome.storage.local.remove(['deviceKey','passkeyConfig']);
  await chrome.storage.session.remove('uiUnlock');
  await chrome.storage.local.set({vaultFileChanged:crypto.randomUUID()});
  await chrome.storage.local.set({vaultLocation:fileHandle.name});
  await chrome.storage.local.remove('nativeVaultPath');
  });
  });
}
export async function chooseVaultFile(create = false) {
  const options = {types:[{description:'Зашифрованное хранилище CHROME-APP-TOTP',accept:{'application/json':['.json']}}],excludeAcceptAllOption:false};
  const selected = create ? await window.showSaveFilePicker({...options,suggestedName:'CHROME-APP-TOTP.vault.json'}) : (await window.showOpenFilePicker({...options,multiple:false}))[0];
  // Validate before replacing a working file link. Existing files are never reset.
  const file = await selected.getFile();
  if (file.size) { if (file.size > 8000000) throw new Error('Файл хранилища слишком большой.'); let data; try { data = JSON.parse(await file.text()); } catch { throw new Error('Выбранный файл не является хранилищем CHROME-APP-TOTP.'); } validateEnvelope(data); }
  if (!file.size && !create) throw new Error('Выбран пустой файл. Создайте новое хранилище или выберите существующее.');
  if (await selected.requestPermission({mode:'readwrite'}) !== 'granted') throw new Error('Для сохранения аккаунтов нужен доступ на чтение и запись выбранного файла.');
  await attachHandle(selected);
}
export async function fileStatus() {
  const {h,path} = await backend();
  if (!h) {
    try { const status = await nativeFile({op:'status',path}); return {selected:true,permitted:true,native:true,name:status.path.split('\\').pop(),location:status.path,defaultPath:status.defaultPath,exists:status.exists}; }
    catch (e) { return {selected:true,permitted:false,native:true,location:path || '%USERPROFILE%\\.CHROME-APP-TOTP.vault',error:e.message}; }
  }
  const {vaultLocation} = await chrome.storage.local.get('vaultLocation');
  return {selected:!!h,name:h?.name ?? '',location:vaultLocation ?? h?.name ?? '',permitted:h ? await h.queryPermission({mode:'readwrite'}) === 'granted' : false};
}
export async function chooseVaultDirectory() {
  const dir = await window.showDirectoryPicker({id:'chrome-app-totp-vault-folder',mode:'readwrite',startIn:'documents'});
  const file = await dir.getFileHandle('CHROME-APP-TOTP.vault.json',{create:true});
  const contents = await file.getFile();
  if (contents.size) { if (contents.size > 8000000) throw new Error('Файл слишком большой.'); let v; try { v = JSON.parse(await contents.text()); } catch { throw new Error('В папке уже есть файл с таким именем, но это не хранилище CHROME-APP-TOTP. Он не изменён.'); } validateEnvelope(v); }
  await attachHandle(file);
  await chrome.storage.local.set({vaultLocation:'…/' + dir.name + '/' + file.name});
}
export async function authorizeFile() { const h = await handle(); if (!h || await h.requestPermission({mode:'readwrite'}) !== 'granted') throw new Error('Доступ к файлу не предоставлен.'); }
export const vaultToken = v => v ? `${v.salt}:${v.iv}:${v.revision}` : null;
export async function loadVault() {
  const {h,path} = await backend();
  return h ? readVaultHandle(h) : readNative(path);
}
async function backend() {
  const {nativeVaultPath} = await chrome.storage.local.get('nativeVaultPath');
  return nativeVaultPath !== undefined ? {path:nativeVaultPath} : {h:await handle(),path:''};
}
async function readNative(path) {
  const result = await nativeFile({op:'read',path});
  return result.data === null ? null : validateEnvelope(JSON.parse(result.data));
}
// Change location explicitly. A missing destination receives a ciphertext copy;
// an existing valid vault is opened, never overwritten. Keep the old file as backup.
export async function setVaultPath(path) {
  if (typeof path !== 'string' || path.length > 1024) throw new Error('Некорректный путь к базе.');
  return navigator.locks.request('chrome-app-totp-vault-write',async () => {
    const target = await nativeFile({op:'status',path:path.trim()});
    const existing = await readNative(target.path);
    if (!existing) {
      const current = await loadVault();
      if (current) await nativeFile({op:'write',path:target.path,data:JSON.stringify(current),expectedToken:null});
    }
    await navigator.locks.request('chrome-app-totp-security',async () => {
      const {lockEpoch=0} = await chrome.storage.session.get('lockEpoch');
      await chrome.storage.local.remove(['vaultMeta','deviceKey','passkeyConfig']);
      await chrome.storage.session.remove(['uiUnlock','autofillSession','loginIntents','authRequest','importWindowDrafts']);
      await chrome.storage.session.set({manualLock:true,lockEpoch:Math.max(Date.now(),lockEpoch+1)});
      await chrome.storage.local.set({nativeVaultPath:target.path,vaultLocation:target.path,vaultFileChanged:crypto.randomUUID(),autofillBindings:[]});
    });
    return target.path;
  });
}
async function readVaultHandle(h) {
  if (await h.queryPermission({mode:'readwrite'}) !== 'granted') throw new Error('Нужно разрешить доступ к файлу.');
  let file; try { file = await h.getFile(); } catch { throw new Error('Файл перемещён или недоступен. Выберите его заново.'); }
  if (!file.size) return null;
  if (file.size > 8000000) throw new Error('Файл хранилища слишком большой.');
  let v; try { v = JSON.parse(await file.text()); } catch { throw new Error('Повреждён JSON хранилища. Выберите исправную резервную копию.'); }
  return validateEnvelope(v);
}
export async function publishVaultMeta(v) { await chrome.storage.local.set({vaultMeta:{revision:v.revision,token:vaultToken(v)}}); }
// File writes use Chrome's safe writable stream (replacement on close). A Web
// Lock and authenticated-envelope token prevent stale writes between our windows.
export async function saveVault(v, expectedToken) {
  validateEnvelope(v);
  const serialized = JSON.stringify(v,null,2);
  if (utf8.encode(serialized).byteLength > 8000000) throw new Error('Зашифрованная база превышает 8 МБ. Уменьшите число записей или длину ключей. Исходный файл не изменён.');
  return navigator.locks.request('chrome-app-totp-vault-write',async () => {
    const {h,path} = await backend();
    if (!h) { await nativeFile({op:'write',path,data:serialized,expectedToken}); await publishVaultMeta(v); return; }
    const previous = await readVaultHandle(h);
    if (vaultToken(previous) !== expectedToken) throw new Error('Файл изменился в другом окне или программе. Заблокируйте хранилище и откройте его снова.');
    let writable;
    try { writable = await h.createWritable(); await writable.write(serialized); await writable.close(); }
    catch { try { await writable?.abort(); } catch {} throw new Error('Не удалось сохранить JSON. Проверьте доступ к файлу, свободное место и подключение диска.'); }
    await publishVaultMeta(v);
  });
}
