const assert=require('node:assert/strict'),path=require('node:path'),QR=require('qrcode'),{chromium}=require('./test-browser.cjs');
(async()=>{
 const ext=path.resolve('extension'),context=await chromium.launchPersistentContext(path.resolve('work/transfer-'+Date.now()),{executablePath:process.env.TOTP_CHROMIUM_PATH||chromium.executablePath(),headless:true,args:['--load-extension='+ext,'--disable-extensions-except='+ext],viewport:{width:390,height:560}});
 try {
  const worker=context.serviceWorkers()[0]||await context.waitForEvent('serviceworker'),id=worker.url().split('/')[2],page=await context.newPage();
  await page.goto('chrome-extension://'+id+'/package.json');
  await page.evaluate(async()=>{const v=await import('./vault.js'),h=await(await navigator.storage.getDirectory()).getFileHandle('TEST.vault',{create:true});await v.attachHandle(h);const k=await v.createKey('246813');await v.saveVault(await v.seal([],k.key,k.salt,1,k.passwordLength),null);});
  await page.goto('chrome-extension://'+id+'/app.html');await page.locator('#password').fill('246813');await page.locator('#codes-screen').waitFor({state:'visible'});
  await page.locator('#settings-button').click();assert.equal(await page.locator('#change-order').isVisible(),false);await page.locator('#settings-dialog .close').click();
  const open=async()=>{await page.locator('#empty-add').click();await page.locator('#add-qr').click();};
  const uri='otpauth://totp/Synthetic?secret=JBSWY3DPEHPK3PXP';
  const send=async(kind,name,data,type)=>page.evaluate(({kind,name,data,type})=>{
   const t=new DataTransfer();t.items.add(new File([Uint8Array.from(atob(data),c=>c.charCodeAt(0))],name,{type}));
   const dialog=document.querySelector('#file-import-dialog');
   if(kind==='drop'){dialog.dispatchEvent(new DragEvent('dragover',{bubbles:true,cancelable:true,dataTransfer:t}));if(!document.querySelector('#file-drop-zone').classList.contains('drag-over'))throw Error('No drop feedback');}
   const e=kind==='drop'?new DragEvent('drop',{bubbles:true,cancelable:true,dataTransfer:t}):new ClipboardEvent('paste',{bubbles:true,cancelable:true,clipboardData:t});
   dialog.dispatchEvent(e);return e.defaultPrevented;
  },{kind,name,data:Buffer.from(data).toString('base64'),type});
  await open();assert.equal(await send('drop','codes.txt',uri,'text/plain'),true);
  await page.waitForFunction(()=>!document.querySelector('#file-save').disabled);assert.equal(await page.locator('.preview-row').count(),1);
  assert.equal(await page.locator('#file-drop-zone').evaluate(e=>e.classList.contains('drag-over')),false);
  await page.locator('#file-import-dialog .close').first().click();
  const vint=n=>{const a=[];do{const b=n&127;n>>>=7;a.push(b|(n?128:0));}while(n);return a;};
  const field=(n,v)=>typeof v==='number'?[...vint(n*8),...vint(v)]:[...vint(n*8+2),...vint(v.length),...v];
  const migrationEntry=[...field(1,Array.from({length:20},(_,i)=>i+1)),...field(2,[...Buffer.from('Synthetic metadata-free')]),...field(4,0),...field(5,0),...field(6,2)];
  const migration='otpauth-migration://offline?data='+encodeURIComponent(Buffer.from(field(1,migrationEntry)).toString('base64'));
  await open();await send('drop','metadata-free.txt',migration,'text/plain');await page.waitForFunction(()=>!document.querySelector('#file-save').disabled);
  assert.doesNotMatch(await page.locator('#file-import-status').innerText(),/Все части получены/);await page.locator('#file-save').click();await page.locator('#import-dialog').waitFor({state:'visible'});
  assert.match(await page.locator('#import-warnings').innerText(),/Число частей/);assert.doesNotMatch(await page.locator('#batch-status').textContent(),/Все части получены/);assert.equal(await page.locator('.preview-row').count(),1);await page.locator('#import-dialog .close').first().click();
  await open();const png=await QR.toBuffer(uri,{width:440,margin:4});assert.equal(await send('paste','clipboard.png',png,'image/png'),true);
  await page.waitForFunction(()=>!document.querySelector('#file-save').disabled);assert.equal(await page.locator('.preview-row').count(),1);
  await page.locator('#file-save').click();await page.locator('#import-dialog').waitFor({state:'visible'});await page.locator('#commit-import').click();await page.locator('#import-dialog').waitFor({state:'hidden'});
  await page.locator('#settings-button').click();assert.equal(await page.locator('#change-order').isVisible(),true);assert.equal(await page.locator('#change-order').evaluate(e=>e.previousElementSibling.classList.contains('dialog-head')),true);
  await page.locator('#change-order').click();assert.equal(await page.locator('#settings-dialog').isVisible(),false);await page.locator('#cancel-order').click();
  console.log('PASS File drop, clipboard image, confirmation, empty/nonempty reorder visibility and first settings position');
  console.log('PASS Metadata-free Google export accepts enum defaults and warns about unknown part count');
  const backups=await page.evaluate(async()=>{const v=await import('./vault.js'),c=await import('./core.js'),k=await v.createKey('975310');return Promise.all(['Backup A','Backup B'].map(name=>v.seal([c.normalizeAccount({name,secret:'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'})],k.key,k.salt,1,k.passwordLength).then(JSON.stringify)));});
  const openExisting=async()=>{await page.locator('#menu-button').click();await page.locator('#menu-add').click();await page.locator('#add-qr').click();};
  await page.evaluate(()=>{
   const originalDerive=crypto.subtle.deriveKey.bind(crypto.subtle),originalDecrypt=crypto.subtle.decrypt.bind(crypto.subtle);
   globalThis.reviewGates=[];globalThis.reviewDecryptCount=0;
   crypto.subtle.deriveKey=async(...args)=>{const key=await originalDerive(...args);await new Promise(release=>reviewGates.push({release}));return key;};
   crypto.subtle.decrypt=(...args)=>originalDecrypt(...args).finally(()=>reviewDecryptCount++);
   globalThis.restoreReviewCrypto=()=>{crypto.subtle.deriveKey=originalDerive;crypto.subtle.decrypt=originalDecrypt;};
  });
  const loadBackup=async data=>{await send('paste','backup.vault',data,'application/json');await page.locator('#backup-password-label').waitFor({state:'visible'});await page.waitForFunction(()=>!document.querySelector('#import-files').disabled);};
  await openExisting();await loadBackup(backups[0]);await page.locator('#backup-password').fill('975310');await page.locator('#decrypt-backup').click();await page.waitForFunction(()=>reviewGates.length===1);
  assert.equal(await page.locator('#import-files').isDisabled(),true);await send('paste','other.vault',backups[1],'application/json');await page.evaluate(()=>reviewGates[0].release());await page.waitForFunction(()=>!document.querySelector('#file-save').disabled);
  assert.match(await page.locator('#import-preview').textContent(),/Backup A/);assert.doesNotMatch(await page.locator('#import-preview').textContent(),/Backup B/);assert.equal(await page.locator('#backup-password-label').isVisible(),false);await page.locator('#file-import-dialog .close').first().click();
  await openExisting();await loadBackup(backups[0]);await page.locator('#backup-password').fill('000000');await page.locator('#decrypt-backup').click();await page.waitForFunction(()=>reviewGates.length===2);await page.locator('#file-import-dialog .close').first().click();
  await openExisting();await loadBackup(backups[1]);await page.locator('#backup-password').fill('975310');await page.locator('#decrypt-backup').click();await page.waitForFunction(()=>reviewGates.length===3);
  await page.evaluate(()=>reviewGates[1].release());await page.waitForFunction(()=>reviewDecryptCount>=2);await page.evaluate(()=>new Promise(r=>setTimeout(r,0)));
  assert.equal(await page.locator('#file-import-error').innerText(),'');assert.equal(await page.locator('#decrypt-backup').isDisabled(),true);assert.equal(await page.locator('#import-files').isDisabled(),true);
  await page.evaluate(()=>reviewGates[2].release());await page.waitForFunction(()=>!document.querySelector('#file-save').disabled);assert.match(await page.locator('#import-preview').textContent(),/Backup B/);assert.equal(await page.locator('#file-import-error').innerText(),'');await page.evaluate(()=>restoreReviewCrypto());
  console.log('PASS Decrypt blocks incoming files; cancelled decrypt cannot change errors or busy state of reopened import');
 }finally{await context.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
