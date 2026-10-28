const fs = require('node:fs/promises');
const path = require('node:path');
const assert = require('node:assert/strict');
const {chromium} = require('./test-browser.cjs');
const root = path.resolve('.');
const bodies = {
  bitrix: '<form name="form_auth" onsubmit="event.preventDefault();window.submits++"><input name="USER_OTP"><button type="submit">Продолжить</button></form>',
  admin: '<form class="bx-admin-auth-form" name="form_auth" onsubmit="event.preventDefault();window.submits++"><input name="USER_OTP"><input type="submit" name="Login" value="Войти"></form>',
  openai: '<h1>Check your authenticator app</h1><form onsubmit="event.preventDefault();window.submits++"><input name="code" autocomplete="one-time-code" maxlength="6"><button type="submit">Continue</button></form>',
  gosuslugi: '<h1>Введите одноразовый код (TOTP) из приложения</h1><form><button type="button">Войти</button>'+ '<input type="tel" autocomplete="one-time-code">'.repeat(6) + '</form>'
};
(async () => {
  const context = await chromium.launchPersistentContext(path.join(root,'work/strategy-profile-'+Date.now()),{headless:true,executablePath:process.env.TOTP_CHROMIUM_PATH || chromium.executablePath()});
  try {
    let body = '', service = '';
    await context.route('https://**/*',r => r.fulfill({contentType:'text/html',body:'<!doctype html><meta charset="utf-8">'+body}));
    async function fixture(id,html,url) {
      service=id;body=html;
      const page=await context.newPage();
      await page.addInitScript(id=>{
        window.submits=0;window.stats={messages:[],listeners:0,observers:0,timers:0};window.listeners=[];
        const add=document.addEventListener.bind(document);document.addEventListener=(...args)=>{if(['click','keydown','visibilitychange'].includes(args[0]))window.stats.listeners++;return add(...args);};
        const Real=MutationObserver;window.MutationObserver=class extends Real {observe(...args){window.stats.observers++;return super.observe(...args);}};
        const timeout=window.setTimeout.bind(window);window.setTimeout=(...args)=>{window.stats.timers++;return timeout(...args);};
        window.chrome={runtime:{onMessage:{addListener:fn=>window.listeners.push(fn),removeListener:fn=>window.listeners=window.listeners.filter(x=>x!==fn)},sendMessage:async m=>{window.stats.messages.push(m.type);if(m.type==='pending-login')return {ok:false};if(m.type==='login-click')return {ok:true,service:id};if(window.delayReply)await new Promise(resolve=>window.finishReply=resolve);return {ok:true,service:id,code:'123456',validUntil:Date.now()+30000};}}};
      },id);
      await page.goto(url);
      await page.evaluate(source=>{window.stats={messages:[],listeners:0,observers:0,timers:0};(0,eval)(source);},await fs.readFile(path.join(root,'extension/generated',id+'.js'),'utf8'));
      return page;
    }
    for(const [id,html,url] of [
      ['bitrix',bodies.bitrix,'https://tenant.example.test/?login=yes'],
      ['bitrix',bodies.admin,'https://tenant.example.test/bitrix/admin/index.php'],
      ['openai',bodies.openai,'https://auth.openai.com/mfa-challenge/synthetic'],
    ]) {
      const page=await fixture(id,html,url);await page.locator('button,input[type=submit]').click();
      await page.waitForFunction(()=>window.submits===1);
      assert.equal(await page.locator('input:not([type=submit])').inputValue(),'123456');
      assert.equal(await page.evaluate(()=>window.stats.messages.filter(x=>x==='otp-ready').length),1);
      await page.close();
    }
    console.log('PASS ordinary/admin Bitrix and OpenAI: one code request, one submit, no empty initial submit');
    for(const [id,url,html] of [
      ['bitrix','https://tenant.example.test/crm/','<button>Продолжить</button>'],
      ['bitrix','https://tenant.example.test/bitrix/admin/index.php','<h1>Administration</h1>'],
      ['bitrix','https://tenant.example.test/crm/',`<div hidden>${bodies.bitrix}</div>`],
      ['openai','https://auth.openai.com/settings',bodies.openai],
      ['openai','https://other.example.test/mfa-challenge/synthetic',bodies.openai],
      ['gosuslugi','https://esia.gosuslugi.ru/profile/',bodies.gosuslugi],
    ]) {
      const page=await fixture(id,html,url);
      assert.deepEqual(await page.evaluate(()=>window.stats),{messages:[],listeners:0,observers:0,timers:0});await page.close();
    }
    console.log('PASS authenticated/non-login pages: zero listeners, observers, timers and messages');
    const gos=await fixture('gosuslugi',bodies.gosuslugi,'https://esia.gosuslugi.ru/login/');
    await gos.getByRole('button',{name:'Войти'}).click();await gos.waitForFunction(()=>[...document.querySelectorAll('input')].map(el=>el.value).join('')==='123456');assert.equal(await gos.evaluate(()=>window.submits),0);await gos.close();
    console.log('PASS Gosuslugi six cells; no invented submit button');
    const email=await fixture('openai',bodies.openai.replace('Check your authenticator app','Check your email'),'https://auth.openai.com/mfa-challenge/synthetic');
    await email.getByRole('button').click();assert.equal(await email.locator('input').inputValue(),'');assert.equal(await email.evaluate(()=>window.stats.messages.includes('otp-ready')),false);await email.close();
    const external=await fixture('bitrix',bodies.bitrix.replace('<form ','<form action="https://other.example.test/" '),'https://tenant.example.test/?login=yes');await external.getByRole('button').click();assert.equal(await external.locator('input').inputValue(),'');assert.equal(await external.evaluate(()=>window.stats.messages.includes('otp-ready')),false);await external.close();
    console.log('PASS email MFA and cross-origin form action never receive a TOTP');
    const captcha=await fixture('bitrix',bodies.admin.replace('<input type="submit"','<input name="captcha_word"><input type="submit"'),'https://tenant.example.test/bitrix/admin/');await captcha.locator('input[type=submit]').click();await captcha.waitForFunction(()=>document.querySelector('[name=USER_OTP]').value==='123456');assert.equal(await captcha.evaluate(()=>window.submits),0);await captcha.close();
    const selfSubmit=await fixture('bitrix',bodies.bitrix.replace('<input name="USER_OTP">','<input name="USER_OTP" oninput="this.form.requestSubmit()">'),'https://tenant.example.test/?login=yes');await selfSubmit.getByRole('button').click();await selfSubmit.waitForFunction(()=>window.submits===1);assert.equal(await selfSubmit.evaluate(()=>window.submits),1);await selfSubmit.close();
    console.log('PASS empty CAPTCHA prevents submit; site auto-submit is not duplicated');
    const late=await fixture('bitrix',bodies.bitrix,'https://tenant.example.test/?login=yes');await late.evaluate(()=>window.delayReply=true);await late.getByRole('button').click();await late.waitForFunction(()=>!!window.finishReply);await late.evaluate(()=>{window.listeners.forEach(fn=>fn({type:'ga-disable'}));window.finishReply();});assert.equal(await late.locator('input').inputValue(),'');assert.equal(await late.evaluate(()=>window.submits),0);await late.close();
    console.log('PASS disabled mode rejects late response without fill/submit');
  } finally {await context.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
