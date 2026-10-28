import {unseal,validateEnvelope} from './vault.js';

const storageName = 'passwordAttemptGate';
const lockName = 'chrome-app-totp-password-attempts';
const lockDuration = 60000;
function cleanState(raw,now) {
  if (!raw || !Number.isInteger(raw.failures) || raw.failures < 0 || raw.failures > 3 || !Number.isSafeInteger(raw.blockedUntil) || raw.blockedUntil < 0) return {failures:0,blockedUntil:0};
  if (raw.blockedUntil && raw.blockedUntil <= now) return {failures:0,blockedUntil:0};
  return {failures:raw.failures,blockedUntil:raw.blockedUntil};
}
function blockedError(blockedUntil) {
  const error = new Error('Слишком много попыток. Повторите ввод через минуту.');
  error.code = 'PASSWORD_BLOCKED'; error.blockedUntil = blockedUntil; error.failures = 3;
  return error;
}
async function states() {
  const saved = (await chrome.storage.local.get(storageName))[storageName];
  if (!saved || typeof saved !== 'object' || Array.isArray(saved)) return {};
  return Object.fromEntries(Object.entries(saved).filter(([,entry]) => entry && typeof entry === 'object' && !Array.isArray(entry)));
}
export async function getPasswordGate(v) {
  validateEnvelope(v);
  const saved = await states();
  return cleanState(saved[v.salt],Date.now());
}
export async function attemptPassword(v,password) {
  validateEnvelope(v);
  // One extension-origin lock also protects updates for different vault salts.
  // No timer/worker is kept alive while the user waits or the popup is closed.
  return navigator.locks.request(lockName,async () => {
    const saved = await states(), now = Date.now();
    const gate = cleanState(saved[v.salt],now);
    if (gate.blockedUntil > now) throw blockedError(gate.blockedUntil);
    try {
      const unlocked = await unseal(v,password);
      if (Object.hasOwn(saved,v.salt)) {
        delete saved[v.salt];
        if (Object.keys(saved).length) await chrome.storage.local.set({[storageName]:saved});
        else await chrome.storage.local.remove(storageName);
      }
      return unlocked;
    } catch (error) {
      if (error.code !== 'INVALID_PASSWORD') throw error;
      const failures = gate.failures + 1, blockedUntil = failures >= 3 ? Date.now()+lockDuration : 0;
      // Discard expired cooldowns and old inactive entries. Keep active cooldowns
      // even at the bound; neither switching files nor reopening bypasses them.
      for (const [salt,entry] of Object.entries(saved)) {
        if (salt !== v.salt && (entry.blockedUntil > 0 && entry.blockedUntil <= now || entry.touched < now-7*86400000)) delete saved[salt];
      }
      const entries = Object.entries(saved).filter(([salt,entry]) => salt !== v.salt && !(entry.blockedUntil > now)).sort((a,b) => (a[1].touched||0)-(b[1].touched||0));
      while (Object.keys(saved).length >= 128 && entries.length) delete saved[entries.shift()[0]];
      saved[v.salt] = {failures,blockedUntil,touched:Date.now()};
      await chrome.storage.local.set({[storageName]:saved});
      if (blockedUntil) throw blockedError(blockedUntil);
      error.failures = failures; error.blockedUntil = 0;
      throw error;
    }
  });
}
