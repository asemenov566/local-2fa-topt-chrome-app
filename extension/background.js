import {normalizeAccount,validateBindings,totp} from './core.js';
import {loadVault,publishVaultMeta,vaultToken,fileStatus,setVaultPath} from './vault.js';
import {nativeFile} from './native.js';
import {recallKey,rememberKey,lockEpoch} from './security.js';
import {strategyScripts,strategyRoute} from './strategy/registry.js';
import {sessionAlive,installSessionManager,enforceSessionDeadline,closeSessionView} from './session.js';
const SESSION='autofillSession';
const ready=Promise.all([chrome.storage.local.setAccessLevel({accessLevel:'TRUSTED_CONTEXTS'}),chrome.storage.session.setAccessLevel({accessLevel:'TRUSTED_CONTEXTS'})]);
let queue=Promise.resolve();
let lockGeneration=0;
let pickingVault=false;
async function selectVault(useDefault) {
  if(pickingVault)return {ok:false,error:'Выбор файла уже открыт.'};
  pickingVault=true;
  try {
    await chrome.storage.session.remove('vaultPickerError');
    let selectedPath='';
    if(!useDefault){const current=await fileStatus();const result=await nativeFile({op:'pick',path:current.native?current.location:''});if(result.cancelled)return {ok:true,cancelled:true};selectedPath=result.path;}
    return {ok:true,path:await serial(() => setVaultPath(selectedPath))};
  } catch(e) {await chrome.storage.session.set({vaultPickerError:e.message});return {ok:false,error:e.message};}
  finally {pickingVault=false;}
}
function serial(fn){const p=queue.then(fn);queue=p.catch(()=>{});return p;}
async function notifyBindings(type,bindings){
  for(const b of bindings) for(const tab of await chrome.tabs.query({url:b.origin+'/*'})) if(tab.id) try{await chrome.tabs.sendMessage(tab.id,{type,service:b.service});}catch{}
}
async function disable(){
  await chrome.storage.session.remove([SESSION,'loginIntents','authRequest']);await chrome.scripting.unregisterContentScripts();
  const {autofillBindings=[]}=await chrome.storage.local.get('autofillBindings');await notifyBindings('ga-disable',autofillBindings);
}
async function prepareNewVault(){
  return navigator.locks.request('chrome-app-totp-vault-write',async()=>{
    if(await loadVault())return {ok:true,exists:true};
    await disable();
    await navigator.locks.request('chrome-app-totp-security',async()=>{
      const local=await chrome.storage.local.get(['vaultMeta','deviceKey','passkeyConfig','passwordAttemptGate']);
      const session=await chrome.storage.session.get(['uiUnlock','loginIntents','authRequest','importWindowDrafts','lockEpoch']);
      const stale=Object.keys(local).length>0||['uiUnlock','loginIntents','authRequest','importWindowDrafts'].some(k=>session[k]!==undefined);
      await chrome.storage.local.remove(['vaultMeta','deviceKey','passkeyConfig','passwordAttemptGate']);
      await chrome.storage.session.remove(['uiUnlock',SESSION,'loginIntents','authRequest','importWindowDrafts']);
      await chrome.storage.local.set({protectedMode:true,sessionLifetime:60,autoEnabled:false,autofillBindings:[]});
      await chrome.storage.session.remove('pendingSessionPolicy');
      if(stale)await chrome.storage.session.set({manualLock:true,lockEpoch:Math.max(Date.now(),(session.lockEpoch??0)+1)});
    });
    return {ok:true,exists:false};
  });
}
async function registrations(){
  const generation=lockGeneration;
  const {autoEnabled,autofillBindings=[]}=await chrome.storage.local.get(['autoEnabled','autofillBindings']);
  if(!autoEnabled){await disable();return;}
  const allowed=[];for(const b of autofillBindings)if(strategyScripts(b.service).length&&await chrome.permissions.contains({origins:[b.origin+'/*']}))allowed.push(b);
  const desired=allowed.map((b,i)=>({id:'ga-'+i,matches:[b.origin+'/*'],js:strategyScripts(b.service),allFrames:false,runAt:'document_idle',persistAcrossSessions:true}));
  const current=await chrome.scripting.getRegisteredContentScripts();
  if(generation!==lockGeneration)return;
  const signature=scripts=>JSON.stringify(scripts.map(s=>({id:s.id,matches:s.matches,js:s.js})).sort((a,b)=>a.id.localeCompare(b.id)));
  if(signature(current)!==signature(desired)){await chrome.scripting.unregisterContentScripts();if(desired.length)await chrome.scripting.registerContentScripts(desired);}
  for(const b of allowed)for(const tab of await chrome.tabs.query({url:b.origin+'/*'})){if(generation!==lockGeneration)return;if(tab.id)try{await chrome.scripting.executeScript({target:{tabId:tab.id},files:strategyScripts(b.service)});}catch{}}
}
async function activate(accounts,revision,token){
  await enforceSessionDeadline();
  const generation=lockGeneration;
  await ready;const {vaultMeta,autoEnabled}=await chrome.storage.local.get(['vaultMeta','autoEnabled']);
  const unlocked=await chrome.storage.session.get(['uiUnlock','manualLock','lockEpoch']);if(!unlocked.uiUnlock||unlocked.manualLock)return {ok:false,error:'Хранилище заблокировано.'};
  if(!vaultMeta||vaultMeta.revision!==revision||vaultMeta.token!==token)return {ok:false,error:'Файл изменился. Откройте его снова.'};
  const selected=accounts.map(normalizeAccount).filter(a=>a.binding);validateBindings(selected);
  const old=(await chrome.storage.local.get('autofillBindings')).autofillBindings??[];
  const bindings=selected.map(a=>({id:a.id,...a.binding}));await notifyBindings('ga-disable',old.filter(b=>!bindings.some(n=>n.origin===b.origin&&n.service===b.service&&n.id===b.id)));
  await chrome.storage.local.set({autofillBindings:bindings});
  if(!autoEnabled){await disable();return {ok:true,expires:0,enabled:0};}
  const allowed=[];for(const a of selected)if(await chrome.permissions.contains({origins:[a.binding.origin+'/*']}))allowed.push(a);
  const committed=await navigator.locks.request('chrome-app-totp-security',async()=>{
    const current=await chrome.storage.session.get(['uiUnlock','manualLock','lockEpoch']);
    const latest=await chrome.storage.local.get(['vaultMeta','autoEnabled']);
    if(generation!==lockGeneration||current.manualLock||!current.uiUnlock||(current.lockEpoch??0)!==(unlocked.lockEpoch??0)||latest.vaultMeta?.token!==token||!latest.autoEnabled)return false;
    if(!sessionAlive(current.uiUnlock))return false;
    await chrome.storage.session.set({[SESSION]:{accounts:allowed,revision,token,expires:current.uiUnlock.expiresAt||Number.MAX_SAFE_INTEGER}});return true;
  });
  if(!committed)return {ok:false,error:'Хранилище заблокировано.'};
  await registrations();
  const {loginIntents={}}=await chrome.storage.session.get('loginIntents');
  for(const [tabId,intent] of Object.entries(loginIntents))if(intent.until>Date.now())try{await chrome.tabs.sendMessage(Number(tabId),{type:'ga-resume',service:intent.service});}catch{}
  return {ok:true,expires:allowed.length?(unlocked.uiUnlock.expiresAt||Number.MAX_SAFE_INTEGER):0,enabled:allowed.length};
}
async function promptUnlock(tabId,intent,generation,epoch){
  const request={id:crypto.randomUUID(),tabId,origin:intent.origin,until:Date.now()+120000};
  const allowed=await navigator.locks.request('chrome-app-totp-security',async()=>{
    const state=await chrome.storage.session.get(['authRequest','lockEpoch','loginIntents']);
    if(generation!==lockGeneration||(state.lockEpoch??0)!==epoch||state.authRequest?.until>Date.now()||state.loginIntents?.[String(tabId)]?.until!==intent.until)return false;
    await chrome.storage.session.set({authRequest:request});return true;
  });
  if(!allowed)return;
  let win;
  try{
    win=await chrome.windows.create({url:chrome.runtime.getURL('app.html?full=1&auth=1'),type:'popup',width:410,height:280,focused:true});
    const kept=await navigator.locks.request('chrome-app-totp-security',async()=>{
      const state=await chrome.storage.session.get(['authRequest','lockEpoch']);
      if(generation!==lockGeneration||(state.lockEpoch??0)!==epoch||state.authRequest?.id!==request.id)return false;
      await chrome.storage.session.set({authWindowId:win.id});return true;
    });
    if(!kept&&win.id)await chrome.windows.remove(win.id);
  }catch{await navigator.locks.request('chrome-app-totp-security',async()=>{if((await chrome.storage.session.get('authRequest')).authRequest?.id===request.id)await chrome.storage.session.remove('authRequest');});}
}
async function pageAction(m,sender){
  await enforceSessionDeadline();
  const generation=lockGeneration;
  await ready;if(!sender.tab||sender.frameId!==0||!sender.url)return {ok:false};
  const epoch=await lockEpoch();
  const url=new URL(sender.url);if(url.protocol!=='https:')return {ok:false};
  const {autoEnabled,autofillBindings=[],vaultMeta}=await chrome.storage.local.get(['autoEnabled','autofillBindings','vaultMeta']);if(!autoEnabled)return {ok:false};
  const binding=autofillBindings.find(b=>b.origin===url.origin);if(!binding||!(await chrome.permissions.contains({origins:[url.origin+'/*']})))return {ok:false};
  if(!strategyRoute(binding.service,url,m.type==='otp-ready'))return {ok:false};
  const {loginIntents={}}=await chrome.storage.session.get('loginIntents');const tabKey=String(sender.tab.id);
  if(m.type==='login-click')return navigator.locks.request('chrome-app-totp-security',async()=>{
    if(generation!==lockGeneration||await lockEpoch()!==epoch)return {ok:false};
    loginIntents[tabKey]={origin:url.origin,service:binding.service,until:Date.now()+120000};for(const [k,i]of Object.entries(loginIntents))if(i.until<Date.now())delete loginIntents[k];await chrome.storage.session.set({loginIntents});return {ok:true,service:binding.service};
  });
  const intent=loginIntents[tabKey];if(!intent||intent.origin!==url.origin||intent.until<Date.now())return {ok:false};
  if(generation!==lockGeneration||await lockEpoch()!==epoch)return {ok:false};
  if(m.type==='pending-login')return {ok:true,service:binding.service};if(m.type!=='otp-ready'||m.service!==binding.service)return {ok:false};
  // Read the selected file only at an actual OTP request. No filesystem polling.
  let file;
  try { file=await loadVault(); } catch {}
  const valid=await navigator.locks.request('chrome-app-totp-security',async()=>{
    if(generation!==lockGeneration||await lockEpoch()!==epoch)return false;
    if(!file||vaultToken(file)!==vaultMeta?.token){await chrome.storage.session.remove([SESSION,'uiUnlock']);if(file)await publishVaultMeta(file);}
    return true;
  });
  if(!valid)return {ok:false};
  if(generation!==lockGeneration)return {ok:false};
  const state=await chrome.storage.session.get([SESSION,'manualLock','lockEpoch']);
  const s=state.manualLock?null:state[SESSION];
  if(!s||s.token!==vaultMeta?.token){await promptUnlock(sender.tab.id,intent,generation,epoch);return {ok:false,authenticationRequested:true};}
  const a=s.accounts.find(a=>a.id===binding.id&&a.binding.origin===url.origin);if(!a)return {ok:false};
  const at=Date.now(),code=await totp(a,at),validUntil=(Math.floor(at/1000/a.period)+1)*a.period*1000;if(Date.now()>=validUntil)return {ok:false};
  return navigator.locks.request('chrome-app-totp-security',async()=>{
    const current=await chrome.storage.session.get(['manualLock','lockEpoch',SESSION,'loginIntents','uiUnlock']);
    const latest=await chrome.storage.local.get(['autoEnabled','autofillBindings']);
    if(!latest.autoEnabled||!latest.autofillBindings?.some(b=>b.id===binding.id&&b.origin===binding.origin&&b.service===binding.service)||!(await chrome.permissions.contains({origins:[url.origin+'/*']})))return {ok:false};
    if(generation!==lockGeneration||current.manualLock||!sessionAlive(current.uiUnlock)||(current.lockEpoch??0)!==(state.lockEpoch??0)||current[SESSION]?.token!==s.token||Date.now()>=validUntil)return {ok:false};
    const intents=current.loginIntents??{};if(!intents[tabKey]||intents[tabKey].until<=Date.now())return {ok:false};
    delete intents[tabKey];await chrome.storage.session.set({loginIntents:intents});return {ok:true,code,service:binding.service,validUntil};
  });
}
async function lockVault(expectedSession,afterSave=false){
  await ready;
  const locked=await navigator.locks.request('chrome-app-totp-security',async()=>{
    if(expectedSession){
      const {uiUnlock,lockEpoch=0}=await chrome.storage.session.get(['uiUnlock','lockEpoch']);
      if(!uiUnlock||uiUnlock.authenticatedAt!==expectedSession.authenticatedAt)return false;
      if(afterSave){
        if(!Number.isFinite(expectedSession.authenticatedAt)||!Number.isFinite(expectedSession.lockEpoch)||typeof expectedSession.salt!=='string'||lockEpoch!==expectedSession.lockEpoch||uiUnlock.salt!==expectedSession.salt)return false;
      }else if(uiUnlock.expiresAt!==expectedSession.expiresAt||sessionAlive(uiUnlock))return false;
      lockGeneration++;
    }
    const {lockEpoch=0}=await chrome.storage.session.get('lockEpoch');
    await chrome.storage.session.remove([SESSION,'uiUnlock','loginIntents','authRequest','importWindowDrafts','pendingSessionPolicy']);
    await chrome.storage.session.set({lockEpoch:Math.max(Date.now(),lockEpoch+1),manualLock:true});
    return true;
  });
  if(!locked)return {ok:false};
  const {autofillBindings=[]}=await chrome.storage.local.get('autofillBindings');await notifyBindings('ga-reset',autofillBindings);return {ok:true};
}
installSessionManager(lockVault);
chrome.runtime.onMessage.addListener((m,sender,reply)=>{
  if(sender.id!==chrome.runtime.id||!m||typeof m!=='object')return;
  const trusted=sender.url&&sender.url.split('?')[0].split('#')[0]===chrome.runtime.getURL('app.html');
  if(trusted&&m.type==='session-expire'){void lockVault({authenticatedAt:m.authenticatedAt,expiresAt:m.expiresAt}).then(reply,()=>reply({ok:false}));return true;}
  if(trusted&&m.type==='lock-after-save'){if(!m.expected||typeof m.expected!=='object'){reply({ok:false});return;}void lockVault(m.expected,true).then(reply,()=>reply({ok:false}));return true;}
  if(trusted&&m.type==='session-view-closing'){void closeSessionView(sender.documentId).then(()=>reply({ok:true}),()=>reply({ok:false}));return true;}
  if(trusted&&m.type==='lock'){lockGeneration++;void lockVault().then(reply,()=>reply({ok:false,error:'Не удалось завершить блокировку.'}));return true;}
  // The worker owns the native dialog, so closing the action popup cannot cancel
  // the choice. Do not put user interaction in the autofill/lock serial queue.
  if(trusted&&(m.type==='choose-vault'||m.type==='default-vault')){void selectVault(m.type==='default-vault').then(reply);return true;}
  const requestGeneration=lockGeneration;
  const action=async()=>{
    if(requestGeneration!==lockGeneration&&['login-click','pending-login','otp-ready','activate'].includes(m.type))return {ok:false};
    if(['login-click','pending-login','otp-ready'].includes(m.type))return pageAction(m,sender);if(!trusted)return {ok:false};
    if(m.type==='activate'&&Array.isArray(m.accounts)&&m.accounts.length<=2000)return activate(m.accounts,m.revision,m.token);
    if(m.type==='deactivate'){await disable();return {ok:true};}
    if(m.type==='configure'){await registrations();return {ok:true};}
    if(m.type==='status'){const s=(await chrome.storage.session.get(SESSION))[SESSION];return {ok:true,expires:s?.expires??0};}
    if(m.type==='prepare-new-vault')return prepareNewVault();
    if(m.type==='auth-cancel'){await chrome.storage.session.remove(['loginIntents','authRequest']);return {ok:true};}
    return {ok:false};
  };serial(action).then(reply,()=>reply({ok:false,error:'Не удалось настроить автоустановку. Проверьте файл и доступ к сайту.'}));return true;
});
async function boot(){
  await ready;await chrome.storage.session.remove(SESSION);await registrations();const prefs=await chrome.storage.local.get(['protectedMode','autoEnabled']);if(prefs.protectedMode!==false||!prefs.autoEnabled)return;
  try{const epoch=await lockEpoch();const v=await loadVault();if(!v)return;const unlocked=await recallKey(v,false);if(!unlocked)return;await rememberKey(unlocked.key,v.salt,false,epoch);await publishVaultMeta(v);await activate(unlocked.accounts,v.revision,vaultToken(v));}catch{}
}
chrome.runtime.onStartup.addListener(()=>{void serial(boot);});chrome.runtime.onInstalled.addListener(()=>{void serial(boot);});
function interruptAutofill(){
  lockGeneration++;
  // Detach pages now, even if a native read occupies the worker's serial queue.
  void chrome.storage.local.get('autofillBindings').then(({autofillBindings=[]})=>notifyBindings('ga-disable',autofillBindings));
}
chrome.permissions.onRemoved.addListener(()=>{interruptAutofill();void serial(async()=>{await disable();await registrations();});});
chrome.storage.onChanged.addListener((c,a)=>{
  if(a==='session'&&c.uiUnlock?.newValue)void navigator.locks.request('chrome-app-totp-security',async()=>{
    const state=await chrome.storage.session.get(['uiUnlock','manualLock',SESSION]);
    const {vaultMeta}=await chrome.storage.local.get('vaultMeta');
    const active=state[SESSION],expires=state.uiUnlock?.expiresAt||Number.MAX_SAFE_INTEGER;
    if(active&&!state.manualLock&&sessionAlive(state.uiUnlock)&&active.token===vaultMeta?.token&&active.expires!==expires)await chrome.storage.session.set({[SESSION]:{...active,expires}});
  });
  if(a!=='local')return;
  if(c.autoEnabled){if(c.autoEnabled.newValue===true)void serial(registrations);else{interruptAutofill();void serial(disable);}}
  if(c.autofillBindings)void serial(async()=>{
    const next=c.autofillBindings.newValue??[];
    await notifyBindings('ga-disable',(c.autofillBindings.oldValue??[]).filter(b=>!next.some(n=>n.origin===b.origin&&n.service===b.service&&n.id===b.id)));
    await registrations();
  });
});
chrome.windows.onRemoved.addListener(id=>{void serial(async()=>{const s=await chrome.storage.session.get(['authWindowId','authRequest']);if(s.authWindowId===id){await chrome.storage.session.remove(['authWindowId','authRequest']);if(s.authRequest)await chrome.storage.session.remove('loginIntents');}});});
