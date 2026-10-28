const fs=require('node:fs/promises'),path=require('node:path'),sharp=require('sharp'),QR=require('qrcode'),assert=require('node:assert/strict');
const {chromium}=require('./test-browser.cjs');
const root=path.resolve('.');
(async()=>{
 const vint=n=>{const a=[];do{const b=n&127;n>>>=7;a.push(b|(n?128:0));}while(n);return a;};const field=(n,v)=>typeof v==='number'?[...vint(n*8),...vint(v)]:[...vint(n*8+2),...vint(v.length),...v],str=s=>[...Buffer.from(s)];
 const entries=Array.from({length:10},(_,i)=>field(1,[...field(1,Array.from({length:20},(_,j)=>(i*17+j*13)%256)),...field(2,str('Synthetic-camera-user-'+i+'@example.test')),...field(3,str('Camera review '+i)),...field(4,1),...field(5,1),...field(6,2)]));const uri='otpauth-migration://offline?data='+encodeURIComponent(Buffer.from([...entries.flat(),...field(2,1),...field(3,1),...field(4,0),...field(5,123)]).toString('base64'));const source=await QR.toBuffer(uri,{scale:8,margin:4,errorCorrectionLevel:'M'});
 for(const side of [260]){const code=await sharp(source).resize(side,side).rotate(6,{background:'white'}).blur(.8).jpeg({quality:75}).toBuffer();await sharp({create:{width:1920,height:1080,channels:3,background:'#777777'}}).composite([{input:code,left:700,top:120}]).jpeg({quality:85}).toFile('work/review-camera-'+side+'-0.8.jpg');
  const grey=await sharp(`work/review-camera-${side}-0.8.jpg`).greyscale().raw().toBuffer();
  const y=Buffer.from(grey.map(v=>Math.round(16+v*219/255))),frame=path.join(root,`work/review-dense-${side}.y4m`);
  await fs.writeFile(frame,Buffer.concat([Buffer.from('YUV4MPEG2 W1920 H1080 F2:1 Ip A1:1 C420jpeg\nFRAME\n'),y,Buffer.alloc(1920*1080/2,128)]));
  const ext=path.join(root,'extension');
  const context=await chromium.launchPersistentContext(path.join(root,'work/review-dense-profile-'+side+'-'+Date.now()),{executablePath:process.env.TOTP_CHROMIUM_PATH||chromium.executablePath(),headless:true,args:[`--disable-extensions-except=${ext}`,`--load-extension=${ext}`,'--use-fake-device-for-media-stream','--use-fake-ui-for-media-stream',`--use-file-for-fake-video-capture=${frame}`]});
  try{
   await context.grantPermissions(['camera']);const worker=context.serviceWorkers()[0]||await context.waitForEvent('serviceworker'),id=worker.url().split('/')[2],page=await context.newPage();
   await page.goto(`chrome-extension://${id}/app.html?full=1`);
   await page.evaluate(async()=>{const h=await(await navigator.storage.getDirectory()).getFileHandle('REVIEW-test.vault',{create:true});await(await import('./vault.js')).attachHandle(h);});await page.reload();await page.locator('#unlock-form').waitFor({state:'visible'});
   await page.locator('#pin-length').selectOption('6');await page.locator('#password').fill('246813');await page.waitForFunction(()=>document.querySelector('#pin-prompt').textContent==='Повторите пароль');await page.locator('#password').fill('246813');await page.locator('#codes-screen').waitFor({state:'visible'});
   await page.evaluate(()=>{const gum=navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);navigator.mediaDevices.getUserMedia=async(...args)=>{const s=await gum(...args);globalThis.cameraTracks=s.getTracks();return s;};globalThis.loaderSeen=false;globalThis.loaderStopped=false;function sample(){if(document.querySelector('#camera-processing').checkVisibility({checkVisibilityCSS:true})){globalThis.loaderSeen=true;globalThis.loaderStopped=cameraTracks.every(t=>t.readyState==='ended');}globalThis.frameCheck=requestAnimationFrame(sample);}sample();});
   await page.locator('#menu-button').click();await page.locator('#menu-add').click();await page.locator('#add-camera').click();
   await page.waitForFunction(()=>document.querySelectorAll('.preview-row').length===10,{},{timeout:15000});
   const state=await page.evaluate(()=>({size:[document.querySelector('video').videoWidth,document.querySelector('video').videoHeight],status:document.querySelector('#camera-status').textContent,error:document.querySelector('#camera-error').textContent,records:document.querySelectorAll('.preview-row').length}));assert.equal(state.records,10);assert.equal(state.error,'');assert.deepEqual(await page.evaluate(()=>{cancelAnimationFrame(frameCheck);return {loaderSeen,loaderStopped,streamCleared:document.querySelector('video').srcObject===null};}),{loaderSeen:true,loaderStopped:true,streamCleared:true});await page.waitForTimeout(100);assert.equal(page.workers().length,0);console.log('PASS Difficult dense camera QR recovers; camera stops before processing loader; worker released, 10 accounts ready');
  }finally{await context.close();}
 }
})().catch(e=>{console.error(e);process.exitCode=1;});
