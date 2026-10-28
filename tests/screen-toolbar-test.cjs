const assert=require('node:assert/strict'),path=require('node:path'),QR=require('qrcode'),{chromium}=require('./test-browser.cjs');
(async()=>{
 const ext=path.resolve('extension'),context=await chromium.launchPersistentContext(path.resolve('work/screen-toolbar-'+Date.now()),{executablePath:process.env.TOTP_CHROMIUM_PATH||chromium.executablePath(),headless:true,args:['--load-extension='+ext,'--disable-extensions-except='+ext],viewport:{width:390,height:560}});
 try {
  const worker=context.serviceWorkers()[0]||await context.waitForEvent('serviceworker'),id=worker.url().split('/')[2],page=await context.newPage();
  await page.goto('chrome-extension://'+id+'/package.json');
  await page.evaluate(async()=>{const v=await import('./vault.js'),c=await import('./core.js'),h=await(await navigator.storage.getDirectory()).getFileHandle('TEST.vault',{create:true});await v.attachHandle(h);const k=await v.createKey('246813');const a=Array.from({length:14},(_,i)=>c.normalizeAccount({name:'Test '+i,issuer:'Example',secret:'JBSWY3DPEHPK3PXP'}));await v.saveVault(await v.seal(a,k.key,k.salt,1,k.passwordLength),null);});
  await page.goto('chrome-extension://'+id+'/app.html');await page.locator('#password').fill('246813');await page.locator('#codes-screen').waitFor({state:'visible'});
  assert.equal(await page.locator('#lock-button').evaluate(e=>e.nextElementSibling.id),'search-toggle');
  assert.equal(await page.locator('header #add-button').count(),0);assert.equal(await page.locator('footer #add-button').count(),1);
  assert.equal(await page.locator('body').innerText().then(s=>s.includes('узкое окно')),false);
  const footer=await page.locator('footer').boundingBox();await page.evaluate(()=>scrollTo(0,document.body.scrollHeight));assert.deepEqual(await page.locator('footer').boundingBox(),footer);
  assert.equal(await page.locator('footer').evaluate(e=>getComputedStyle(e).backgroundColor),'rgb(255, 255, 255)');
  for(const width of [330,390]) {await page.setViewportSize({width,height:560});assert.equal(await page.locator('.footer-meta').evaluate(e=>e.scrollWidth>e.clientWidth),false);}
  await page.setViewportSize({width:390,height:560});await page.evaluate(()=>scrollTo(0,0));
  // Fixed sample times exercise the real render path, not a second timer formula.
  for(const [remaining,urgent] of [[22.5,false],[7.5,false],[4,true]]) {
   await page.evaluate(r=>{Date.now=()=>1800000000000+(30-r)*1000;document.querySelector('#search').dispatchEvent(new Event('input'));},remaining);
   await page.waitForFunction(n=>document.querySelector('.timer').title===Math.ceil(n)+' с',remaining);
   assert.equal(await page.locator('.timer').first().evaluate(e=>e.classList.contains('urgent')),urgent);
   const pathData=await page.locator('.timer path').first().getAttribute('d');assert.ok(pathData.startsWith('M16 16 L'));
   if(remaining===7.5)assert.equal(pathData,'M16 16 L0.0000 16.0000 A16 16 0 0 1 16 0 Z');
  }
  await page.screenshot({path:'outputs/toolbar-footer-1.3.4.png'});
  const png=await QR.toBuffer('otpauth://totp/Capture?secret=JBSWY3DPEHPK3PXP',{width:500,margin:4});
  await page.evaluate(data=>{globalThis.calls=0;chrome.windows.getLastFocused=async()=>({id:7});chrome.tabs.query=async()=>[{id:9,url:'https://example.test/qr'}];chrome.tabs.captureVisibleTab=async(windowId,opts)=>{if(windowId!==7||opts.format!=='png')throw Error('Wrong target');calls++;return data;};},'data:image/png;base64,'+png.toString('base64'));
  await page.locator('#add-button').click();await page.locator('#add-screen').click();await page.waitForFunction(()=>!document.querySelector('#file-save').disabled);
  assert.equal(await page.locator('dialog[open]').count(),1);assert.equal(await page.locator('#file-import-dialog').isVisible(),true);assert.equal(await page.locator('.preview-row').count(),1);assert.equal(await page.evaluate(()=>calls),1);
  await page.locator('#file-import-dialog .close').first().click();
  await page.evaluate(()=>{chrome.tabs.captureVisibleTab=()=>new Promise(resolve=>{globalThis.finishCapture=resolve;});});
  await page.locator('#add-button').click();await page.locator('#add-screen').click();await page.waitForFunction(()=>!!globalThis.finishCapture);await page.locator('#file-import-dialog .close').first().click();
  await page.locator('#add-button').click();await page.locator('#add-qr').click();await page.evaluate(data=>finishCapture(data),'data:image/png;base64,'+png.toString('base64'));await page.waitForTimeout(100);
  assert.equal(await page.locator('.preview-row').count(),0);assert.equal(await page.locator('#import-files').isDisabled(),false);
  await page.locator('#file-import-dialog .close').first().click();
  await page.evaluate(()=>{chrome.tabs.captureVisibleTab=async()=>{throw Error('activeTab permission missing');};});await page.locator('#add-button').click();await page.locator('#add-screen').click();await page.waitForFunction(()=>document.querySelector('#file-import-error').textContent.includes('Chrome не разрешил'));assert.equal(await page.locator('#import-files').isDisabled(),false);
  console.log('PASS Fixed opaque footer at 330/390px; lock/search placement; countdown sector direction and urgent color; one-shot capture import, cancellation and denied permission feedback');
 }finally{await context.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
