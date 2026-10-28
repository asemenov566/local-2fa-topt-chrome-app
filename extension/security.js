import {exportKey,importKey,unsealWithKey} from './vault.js';
import {nativeFile} from './native.js';
const to64 = bytes => btoa(Array.from(new Uint8Array(bytes),b => String.fromCharCode(b)).join(''));
const from64 = s => Uint8Array.from(atob(s),c => c.charCodeAt(0));
export async function lockEpoch() { return (await chrome.storage.session.get('lockEpoch')).lockEpoch ?? 0; }
const securityLock = fn => navigator.locks.request('chrome-app-totp-security',fn);
const preparedKeys = new WeakMap();
const cancelled = () => new Error('Разблокировка отменена: хранилище или режим защиты изменились в другом окне.');
const validDevice = d => !!d && typeof d === 'object' && d.version === 1 && d.protection === 'windows-dpapi' && typeof d.wrapped === 'string' && d.wrapped.length <= 5464 && !('raw' in d);
const sameDevice = (a,b) => validDevice(a) && validDevice(b) && a.salt === b.salt && a.wrapped === b.wrapped;
async function checkPrepared(record) {
  const session = await chrome.storage.session.get(['manualLock','lockEpoch']);
  const prefs = await chrome.storage.local.get('protectedMode');
  if ((session.lockEpoch ?? 0) !== record.epoch || (record.implicit && session.manualLock) || (prefs.protectedMode !== false) !== record.protectedMode) throw cancelled();
}
// Prepare before changing a password on disk. Native calls never hold the lock
// needed by another window to hide codes and erase its unlocked session.
export async function prepareRememberKey(key,salt,authEpoch) {
  const record = await securityLock(async () => {
    const session = await chrome.storage.session.get(['manualLock','lockEpoch']);
    const epoch = session.lockEpoch ?? 0;
    if (authEpoch !== undefined ? authEpoch !== epoch : session.manualLock) throw cancelled();
    const prefs = await chrome.storage.local.get('protectedMode');
    return {key,salt,epoch,implicit:authEpoch === undefined,protectedMode:prefs.protectedMode !== false};
  });
  record.saved = {raw:await exportKey(key),salt};
  if (!record.protectedMode) {
    const result = await nativeFile({op:'protect-key',key:record.saved.raw});
    if (typeof result.wrapped !== 'string' || result.wrapped.length > 5464) throw new Error('Не удалось защитить ключ на этом компьютере.');
    record.device = {version:1,protection:'windows-dpapi',salt,wrapped:result.wrapped};
  }
  await securityLock(() => checkPrepared(record));
  const token = Object.freeze({}); preparedKeys.set(token,record); return token;
}
export async function rememberKey(key,salt,protectedMode,authEpoch,preparedToken) {
  const token = preparedToken ?? await prepareRememberKey(key,salt,authEpoch);
  const record = preparedKeys.get(token); preparedKeys.delete(token);
  if (!record || record.key !== key || record.salt !== salt || (authEpoch !== undefined && record.epoch !== authEpoch)) throw cancelled();
  await securityLock(async () => {
    await checkPrepared(record);
    await chrome.storage.session.set({uiUnlock:record.saved,manualLock:false});
    if (record.protectedMode) await chrome.storage.local.remove('deviceKey');
    else await chrome.storage.local.set({deviceKey:record.device});
  });
}
export async function recallKey(v,protectedMode) {
  const snapshot = await securityLock(async () => {
    const session = await chrome.storage.session.get(['uiUnlock','manualLock','lockEpoch']);
    const local = await chrome.storage.local.get(['deviceKey','protectedMode']);
    if (local.deviceKey && !validDevice(local.deviceKey)) await chrome.storage.local.remove('deviceKey');
    if (session.manualLock) return null;
    return {session:session.uiUnlock,device:local.deviceKey,epoch:session.lockEpoch ?? 0,protectedMode:local.protectedMode !== false};
  });
  if (!snapshot) return null;
  const fromSession = snapshot.session?.salt === v.salt;
  if (!fromSession && (protectedMode || snapshot.protectedMode || !validDevice(snapshot.device) || snapshot.device.salt !== v.salt)) return null;
  let unlocked;
  try {
    const raw = fromSession ? snapshot.session.raw : (await nativeFile({op:'unprotect-key',wrapped:snapshot.device.wrapped})).key;
    unlocked = await unsealWithKey(v,await importKey(raw));
  } catch {
    await securityLock(async () => {
      if ((await lockEpoch()) !== snapshot.epoch) return;
      if (fromSession) {
        const current = (await chrome.storage.session.get('uiUnlock')).uiUnlock;
        if (current?.salt === snapshot.session.salt && current.raw === snapshot.session.raw) await chrome.storage.session.remove('uiUnlock');
      } else {
        const current = (await chrome.storage.local.get('deviceKey')).deviceKey;
        if (sameDevice(current,snapshot.device)) await chrome.storage.local.remove('deviceKey');
      }
    });
    return null;
  }
  return securityLock(async () => {
    const session = await chrome.storage.session.get(['uiUnlock','manualLock','lockEpoch']);
    const local = await chrome.storage.local.get(['deviceKey','protectedMode']);
    if (session.manualLock || (session.lockEpoch ?? 0) !== snapshot.epoch || (local.protectedMode !== false) !== snapshot.protectedMode) return null;
    if (fromSession ? session.uiUnlock?.salt !== snapshot.session.salt || session.uiUnlock?.raw !== snapshot.session.raw : !sameDevice(local.deviceKey,snapshot.device)) return null;
    return unlocked;
  });
}
function capability() {
  if (!globalThis.PublicKeyCredential || !navigator.credentials) throw new Error('Этот браузер не поддерживает ключи доступа. Используйте мастер-пароль.');
}
function translate(e) {
  if (e.name === 'NotAllowedError' || e.name === 'AbortError') return new Error('Подтверждение ключом отменено или не завершено. Можно войти мастер-паролем.');
  if (e.name === 'SecurityError' || e.name === 'NotSupportedError') return new Error('Этот браузер или провайдер не поддерживает безопасную разблокировку ключом для расширения. Используйте мастер-пароль.');
  return e;
}
async function wrappingKey(result) {
  const bytes = result?.getClientExtensionResults()?.prf?.results?.first;
  if (!bytes) throw new Error('Этот ключ доступа не поддерживает PRF для шифрования. Выберите совместимый провайдер (например, Google Password Manager) или используйте мастер-пароль. Парольная защита сохранена.');
  return crypto.subtle.importKey('raw',bytes,{name:'AES-GCM'},false,['encrypt','decrypt']);
}
async function assertion(config) {
  return navigator.credentials.get({publicKey:{challenge:crypto.getRandomValues(new Uint8Array(32)),rpId:location.hostname,allowCredentials:[{type:'public-key',id:from64(config.credential)}],userVerification:'required',timeout:60000,extensions:{prf:{eval:{first:from64(config.prfSalt)}}}}});
}
export async function enrollPasskey(key,salt) {
  capability();
  try {
    const prfSalt = crypto.getRandomValues(new Uint8Array(32));
    const credential = await navigator.credentials.create({publicKey:{challenge:crypto.getRandomValues(new Uint8Array(32)),rp:{name:'CHROME-APP-TOTP',id:location.hostname},user:{id:crypto.getRandomValues(new Uint8Array(32)),name:'CHROME-APP-TOTP vault',displayName:'Локальное хранилище CHROME-APP-TOTP'},pubKeyCredParams:[{type:'public-key',alg:-7},{type:'public-key',alg:-257}],authenticatorSelection:{residentKey:'preferred',userVerification:'required'},timeout:60000,attestation:'none',extensions:{prf:{eval:{first:prfSalt}}}}});
    if (!credential?.getClientExtensionResults()?.prf?.enabled) throw new Error('Выбранный ключ не поддерживает PRF. Парольная защита сохранена; выберите другой провайдер ключей доступа.');
    const config = {version:1,credential:to64(credential.rawId),prfSalt:to64(prfSalt),salt};
    const result = credential.getClientExtensionResults()?.prf?.results?.first ? credential : await assertion(config);
    const wrap = await wrappingKey(result), iv = crypto.getRandomValues(new Uint8Array(12));
    const raw = from64(await exportKey(key));
    try { config.wrapped = to64(await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:new TextEncoder().encode(salt)},wrap,raw)); }
    finally { raw.fill(0); }
    config.iv = to64(iv); return config;
  } catch (e) { throw translate(e); }
}
export async function unlockPasskey(v,config) {
  capability();
  if (!config || config.version !== 1 || config.salt !== v.salt) throw new Error('Ключ доступа не привязан к этому файлу или пароль был изменён. Войдите мастер-паролем и привяжите ключ заново.');
  try {
    const wrap = await wrappingKey(await assertion(config));
    const raw = new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:from64(config.iv),additionalData:new TextEncoder().encode(config.salt)},wrap,from64(config.wrapped)));
    try { return await unsealWithKey(v,await importKey(to64(raw))); } finally { raw.fill(0); }
  } catch (e) { throw translate(e); }
}
