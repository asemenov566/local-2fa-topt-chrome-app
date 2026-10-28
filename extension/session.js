// One-shot session deadlines. No periodic wakeups or activity-based renewal.
export const SESSION_ALARM = 'totp-session-expiry';
export function sessionLifetime(prefs = {}) {
  if ([0,30,60,300].includes(prefs.sessionLifetime)) return prefs.sessionLifetime;
  return prefs.protectedMode === false ? 0 : 60;
}
export function sessionAlive(unlock, now = Date.now()) {
  return !!unlock && Number.isFinite(unlock.authenticatedAt) &&
    (unlock.expiresAt === 0 || (Number.isFinite(unlock.expiresAt) && unlock.expiresAt > now));
}
const securityLock = fn => navigator.locks.request('chrome-app-totp-security',fn);
let lockExpired, scheduling = Promise.resolve();
// A lost port (worker suspension) cannot leave a deferred setting pending forever.
export async function reconcileSessionPolicy(closedDocument) {
  const {pendingSessionPolicy:pending} = await chrome.storage.session.get('pendingSessionPolicy');
  if (!pending) return;
  if (pending.documentId !== closedDocument && chrome.runtime.getContexts) {
    const contexts = await chrome.runtime.getContexts({documentIds:[pending.documentId]});
    if (contexts.length) return;
  } else if (pending.documentId !== closedDocument) return;
  await securityLock(async () => {
    const current = await chrome.storage.session.get(['pendingSessionPolicy','uiUnlock']);
    if (current.pendingSessionPolicy?.id !== pending.id) return;
    const seconds = sessionLifetime(await chrome.storage.local.get(['sessionLifetime','protectedMode']));
    if (current.uiUnlock && current.uiUnlock.authenticatedAt === pending.authenticatedAt) await chrome.storage.session.set({uiUnlock:{...current.uiUnlock,expiresAt:seconds === 0 ? 0 : current.uiUnlock.authenticatedAt + seconds*1000}});
    await chrome.storage.session.remove('pendingSessionPolicy');
  });
}
export async function enforceSessionDeadline() {
  await reconcileSessionPolicy();
  const {uiUnlock} = await chrome.storage.session.get('uiUnlock');
  if (!uiUnlock || sessionAlive(uiUnlock)) return true;
  if (lockExpired) await lockExpired(uiUnlock);
  return false;
}
async function updateDeadline() {
  const {uiUnlock} = await chrome.storage.session.get('uiUnlock');
  if (uiUnlock?.expiresAt > Date.now()) await chrome.alarms.create(SESSION_ALARM,{when:uiUnlock.expiresAt});
  else {
    await chrome.alarms.clear(SESSION_ALARM);
    if (uiUnlock && !sessionAlive(uiUnlock)) await enforceSessionDeadline();
  }
}
function scheduleDeadline() {
  scheduling = scheduling.catch(() => {}).then(updateDeadline);
  return scheduling;
}
export async function closeSessionView(documentId) {
  if (typeof documentId !== 'string' || !documentId) return;
  await reconcileSessionPolicy(documentId);
  await enforceSessionDeadline();
  await scheduleDeadline();
}
export function installSessionManager(lock) {
  lockExpired = lock;
  chrome.alarms.onAlarm.addListener(alarm => { if (alarm.name === SESSION_ALARM) void enforceSessionDeadline(); });
  chrome.storage.onChanged.addListener((changes,area) => {
    if (area === 'session' && changes.uiUnlock) void scheduleDeadline();
  });
  chrome.runtime.onConnect.addListener(port => {
    if (port.name !== 'totp-session-view' || port.sender?.id !== chrome.runtime.id ||
        port.sender?.url?.split('?')[0].split('#')[0] !== chrome.runtime.getURL('app.html')) return;
    port.postMessage({documentId:port.sender.documentId});
    port.onMessage.addListener(message => {
      if (message?.closing === true) void closeSessionView(port.sender.documentId);
    });
    port.onDisconnect.addListener(() => {
      // Confirm the document actually closed, rather than an idle port disconnect.
      void reconcileSessionPolicy().then(enforceSessionDeadline).then(scheduleDeadline);
    });
  });
  void enforceSessionDeadline().then(scheduleDeadline);
}
