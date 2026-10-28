const fs=require('node:fs/promises'),path=require('node:path'),assert=require('node:assert/strict');
const {chromium}=require('./test-browser.cjs');
(async()=>{
 const root=path.resolve('.'),ext=path.join(root,'extension'),checks=[];
 const context=await chromium.launchPersistentContext(path.join(root,'work/compact-ui-'+Date.now()),{executablePath:process.env.TOTP_CHROMIUM_PATH||chromium.executablePath(),headless:true,args:[`--disable-extensions-except=${ext}`,`--load-extension=${ext}`],viewport:{width:390,height:560}});
 try{
  const worker=context.serviceWorkers()[0]||await context.waitForEvent('serviceworker'),id=worker.url().split('/')[2];const page=await context.newPage();await page.goto(`chrome-extension://${id}/package.json`);
  await page.evaluate(async()=>{const v=await import('./vault.js'),c=await import('./core.js'),handle=await(await navigator.storage.getDirectory()).getFileHandle('SYNTHETIC.vault',{create:true});await v.attachHandle(handle);const k=await v.createKey('246813');const records=Array.from({length:8},(_,i)=>c.normalizeAccount({id:crypto.randomUUID(),name:'Аккаунт '+(i+1),issuer:'Пример',secret:'JBSWY3DPEHPK3PXP',digits:i===1?8:6,algorithm:'SHA1',period:30}));await v.saveVault(await v.seal(records,k.key,k.salt,1,k.passwordLength),null);});
  await page.goto(`chrome-extension://${id}/app.html`);await page.locator('#password').fill('246813');await page.locator('#codes-screen').waitFor({state:'visible'});
  assert.equal(await page.locator('html').getAttribute('data-layout'),'rows');assert.equal(await page.locator('#search').isVisible(),false);
  await page.locator('#search-toggle').click();assert.equal(await page.locator('#search').evaluate(e=>document.activeElement===e),true);await page.locator('#search').fill('Аккаунт 3');assert.equal(await page.locator('.account').count(),1);await page.locator('#search-toggle').click();assert.equal(await page.locator('.account').count(),8);assert.equal(await page.locator('#search').isVisible(),false);
  const rowHeight=await page.locator('.account').first().evaluate(el=>el.getBoundingClientRect().height);assert.ok(rowHeight<85);checks.push('Rows default, compact height, collapsed search toggle clears filter');
  await page.locator('#settings-button').click();await page.locator('#layout').selectOption('tiles');await page.locator('#settings-dialog .close').click();await page.waitForFunction(()=>[...document.querySelectorAll('.code')].every(e=>/\d/.test(e.textContent)));
  const boxes=await page.locator('.account').evaluateAll(es=>es.map(e=>{const r=e.getBoundingClientRect();return {x:r.x,y:r.y,right:r.right,bottom:r.bottom,width:r.width};}));assert.equal(boxes[0].y,boxes[1].y);assert.equal(boxes[2].x,boxes[0].x);assert.ok(boxes[2].y>boxes[0].y);assert.ok(boxes.every(b=>b.right<=390));assert.ok(boxes[7].bottom<560);
  const overflow=await page.locator('.code-line').evaluateAll(es=>es.some(e=>e.scrollWidth>e.clientWidth));assert.equal(overflow,false);checks.push('Two tile columns fit eight codes including 8-digit code without horizontal overflow');
  await page.screenshot({path:path.join(root,'outputs/compact-tiles.png')});await page.reload();await page.locator('#codes-screen').waitFor({state:'visible'});assert.equal(await page.locator('html').getAttribute('data-layout'),'tiles');checks.push('View preference survives reload');
  await page.locator('#settings-button').click();await page.locator('#change-order').click();assert.equal(await page.locator('#search-toggle').isDisabled(),true);await page.locator('#cancel-order').click();assert.equal(await page.locator('#search-toggle').isDisabled(),false);
  await page.locator('#settings-button').click();await page.locator('#layout').selectOption('rows');await page.locator('#settings-dialog .close').click();await page.screenshot({path:path.join(root,'outputs/compact-rows.png')});
  console.log('PASS',checks.join('; '));await fs.writeFile(path.join(root,'work/compact-results.json'),JSON.stringify({checks},null,2));
 }finally{await context.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
