import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,cp,readFile,writeFile} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {spawnSync} from 'node:child_process';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
test('a new strategy file registers metadata, binding validation and one isolated bundle',async () => {
  await mkdir(path.join(root,'work'),{recursive:true});
  const fixture = await mkdtemp(path.join(root,'work/strategy-build-'));
  await mkdir(path.join(fixture,'scripts'));
  await mkdir(path.join(fixture,'extension'));
  await writeFile(path.join(fixture,'package.json'),' {"type":"module"}');
  for (const file of ['scripts/build-strategies.mjs','extension/core.js','extension/autofill.js']) await cp(path.join(root,file),path.join(fixture,file));
  await cp(path.join(root,'extension/strategy'),path.join(fixture,'extension/strategy'),{recursive:true});
  const source = `export default class SyntheticStrategy {
    static id='synthetic'; static displayName='Synthetic'; static domain='https://auth.example.test'; static customDomain=false;
    static route(url){return url.origin===this.domain && url.pathname==='/auth';}
    isAuthPage(){return false;} fields(){return [];} loginAction(){return false;} authTarget(){return false;} submit(){return null;}
  }`;
  await writeFile(path.join(fixture,'extension/strategy/synthetic.js'),source);
  await writeFile(path.join(fixture,'extension/strategy/unrelated.txt'),'not part of the extension');
  const run = (...args) => spawnSync(process.execPath,['scripts/build-strategies.mjs',...args],{cwd:fixture,encoding:'utf8'});
  assert.equal(run().status,0);
  const registry = await import(pathToFileURL(path.join(fixture,'extension/strategy/registry.js')));
  assert.deepEqual(registry.strategyOptions.find(s => s.id === 'synthetic'),{id:'synthetic',domain:'https://auth.example.test',displayName:'Synthetic',customDomain:false});
  assert.deepEqual(registry.strategyScripts('synthetic'),['generated/synthetic.js']);
  assert.deepEqual(registry.strategyScripts('__proto__'),[]);
  assert.equal(registry.strategyRoute('synthetic',new URL('https://auth.example.test/auth')),true);
  assert.equal(registry.strategyRoute('synthetic',new URL('https://wrong.example.test/auth')),false);
  const {normalizeBinding} = await import(pathToFileURL(path.join(fixture,'extension/core.js')));
  assert.deepEqual(normalizeBinding({service:'synthetic',origin:'https://wrong.example.test'}),{service:'synthetic',origin:'https://auth.example.test'});
  const list = JSON.parse(await readFile(path.join(fixture,'scripts/strategy-files.json'),'utf8'));
  assert.ok(list.files.includes('extension/generated/synthetic.js'));
  assert.ok(list.files.includes('extension/strategy/synthetic.js'));
  assert.ok(!list.files.some(file => file.includes('unrelated')));
  assert.equal(run('--check').status,0);
  for (const file of ['extension/strategy/registry.js','extension/generated/synthetic.js','scripts/strategy-files.json']) {
    const target = path.join(fixture,file);
    await writeFile(target,(await readFile(target,'utf8')).replace(/\r?\n/g,'\r\n'));
  }
  assert.equal(run('--check').status,0,'Windows checkout line endings preserve generated content');
  await writeFile(path.join(fixture,'extension/generated/synthetic.js'),'stale');
  assert.notEqual(run('--check').status,0);
  await writeFile(path.join(fixture,'extension/strategy/synthetic.js'),source.replace('https://auth.example.test','http://auth.example.test'));
  assert.notEqual(run().status,0);
});
