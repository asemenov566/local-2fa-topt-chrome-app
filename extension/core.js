import {getStrategy} from './strategy/registry.js';
// All OTP and import operations are local. No network or logging of user data.
const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export function encode32(bytes) {
  let bits = 0, value = 0, result = '';
  for (const byte of bytes) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { result += alphabet[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits) result += alphabet[(value << (5 - bits)) & 31];
  return result;
}
export function decode32(input) {
  if (typeof input !== 'string') throw new Error('Нужен секретный ключ Base32.');
  const s = input.replace(/[\s-]/g, '').toUpperCase();
  if (!/^[A-Z2-7]+={0,6}$/.test(s) || s.length > 4096) throw new Error('Ключ должен содержать только A–Z и 2–7 (Base32).');
  const raw = s.replace(/=+$/, '');
  if (![0,2,4,5,7].includes(raw.length % 8)) throw new Error('Неполный ключ Base32.');
  const padding = s.length - raw.length;
  if (padding && (s.length % 8 || padding !== (8 - raw.length % 8) % 8)) throw new Error('Повреждённое окончание Base32.');
  let bits = 0, value = 0; const bytes = [];
  for (const c of raw) {
    value = (value << 5) | alphabet.indexOf(c); bits += 5;
    if (bits >= 8) { bytes.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  if ((value & ((1 << bits) - 1)) !== 0 || !bytes.length) throw new Error('Повреждённый ключ Base32.');
  return new Uint8Array(bytes);
}
function label(value, fallback = '') {
  if (typeof value !== 'string') value = fallback;
  value = value.trim();
  if (value.length > 300 || /[\u0000-\u001f\u007f]/u.test(value)) throw new Error('Название слишком длинное или содержит управляющие символы.');
  return value;
}
export function normalizeAccount(a) {
  if (!a || typeof a !== 'object' || Array.isArray(a)) throw new Error('Повреждённая запись аккаунта.');
  if (a.type && a.type !== 'totp') throw new Error('HOTP не поддерживается: запись со счётчиком не будет преобразована в TOTP.');
  const secret = encode32(decode32(a.secret));
  const algorithm = String(a.algorithm ?? 'SHA1').toUpperCase().replace('-', '');
  if (!['SHA1','SHA256','SHA512'].includes(algorithm)) throw new Error('Поддерживаются только SHA1, SHA256 и SHA512.');
  const digits = Number(a.digits ?? 6), period = Number(a.period ?? 30);
  if (![6,8].includes(digits)) throw new Error('Длина кода должна быть 6 или 8 цифр.');
  if (!Number.isInteger(period) || period < 1 || period > 86400) throw new Error('Период должен быть целым числом от 1 до 86400 секунд.');
  const name = label(a.name), issuer = label(a.issuer);
  if (!name && !issuer) throw new Error('Укажите название аккаунта или сервиса.');
  return {id: typeof a.id === 'string' && /^[a-zA-Z0-9-]{1,80}$/.test(a.id) ? a.id : crypto.randomUUID(), type:'totp', name, issuer, secret, algorithm, digits, period, binding:normalizeBinding(a.binding)};
}
export function normalizeBinding(binding) {
  if (!binding || binding.service === 'none') return null;
  const Strategy = getStrategy(binding.service);
  if (!Strategy) throw new Error('Неизвестный сервис автоподстановки.');
  if (!Strategy.customDomain) return {service:Strategy.id,origin:Strategy.domain};
  let u; try { u = new URL(binding.origin); } catch { throw new Error('Введите полный HTTPS-адрес сайта.'); }
  if (u.protocol !== 'https:' || u.username || u.password || u.port || !u.hostname.includes('.') || u.hostname.includes('*')) throw new Error('Нужен HTTPS-адрес без логина, пароля и нестандартного порта.');
  return {service:Strategy.id,origin:u.origin};
}
export function validateBindings(accounts) {
  const seen = new Set();
  for (const a of accounts) if (a.binding) {
    if (seen.has(a.binding.origin)) throw new Error('Для одного сайта можно выбрать только один аккаунт. Сначала отключите привязку у другого.');
    seen.add(a.binding.origin);
  }
}
export async function hotp(secret, counter, algorithm = 'SHA1', digits = 6) {
  const n = BigInt(counter);
  if (n < 0n || n > 0xffffffffffffffffn) throw new Error('Некорректный счётчик.');
  const data = new Uint8Array(8); new DataView(data.buffer).setBigUint64(0, n);
  const key = await crypto.subtle.importKey('raw', decode32(secret), {name:'HMAC', hash:algorithm.replace('SHA','SHA-')}, false, ['sign']);
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, data));
  const offset = mac.at(-1) & 15;
  const value = new DataView(mac.buffer).getUint32(offset) & 0x7fffffff;
  return String(value % (10 ** digits)).padStart(digits,'0');
}
export function totp(a, time = Date.now()) {
  return hotp(a.secret, BigInt(Math.floor(time / 1000 / a.period)), a.algorithm, a.digits);
}
export function parseOtp(uri) {
  let u; try { u = new URL(uri.trim()); } catch { throw new Error('Это не ссылка otpauth.'); }
  if (u.protocol !== 'otpauth:' || !['totp','hotp'].includes(u.hostname) || u.username || u.password || u.port || u.hash) throw new Error('Ожидается ссылка otpauth://totp/…');
  if (u.hostname === 'hotp') throw new Error('HOTP не поддерживается: нужен аутентификатор со счётчиком.');
  for (const key of ['secret','issuer','algorithm','digits','period']) if (u.searchParams.getAll(key).length > 1) throw new Error('В QR повторяются параметры.');
  let full; try { full = decodeURIComponent(u.pathname.slice(1)); } catch { throw new Error('Повреждённое название в QR.'); }
  const colon = full.indexOf(':');
  const prefix = colon >= 0 ? full.slice(0,colon).trim() : '';
  const issuer = u.searchParams.get('issuer') ?? prefix;
  if (prefix && issuer !== prefix) throw new Error('Сервис в названии QR не совпадает с issuer.');
  return normalizeAccount({name:colon >= 0 ? full.slice(colon + 1).trim() : full, issuer, secret:u.searchParams.get('secret'), algorithm:u.searchParams.get('algorithm') ?? 'SHA1', digits:u.searchParams.get('digits') ?? 6, period:u.searchParams.get('period') ?? 30});
}
export function otpUri(a) {
  // ':' separates issuer and account in standard otpauth labels. Preserve local
  // display names; use an unambiguous display separator only in exported URIs.
  const issuer = a.issuer.replaceAll(':',' · '), name = a.name.replaceAll(':',' · ');
  const p = new URLSearchParams({secret:a.secret, algorithm:a.algorithm, digits:String(a.digits), period:String(a.period)});
  if (issuer) p.set('issuer',issuer);
  return `otpauth://totp/${encodeURIComponent(issuer ? `${issuer}:${name}` : name)}?${p}`;
}
export function fingerprint(a) { return [a.type,a.secret,a.algorithm,a.digits,a.period].join('|'); }
export function identity(a) { return `${a.issuer.trim().toLowerCase()}\n${a.name.trim().toLowerCase()}`; }
// A bounded protobuf reader. Unknown fields are skipped; duplicate scalar fields,
// truncated lengths, invalid UTF-8 and unsupported wire types are rejected.
function proto(bytes) {
  let pos = 0; const fields = new Map();
  function varint() {
    let value = 0n;
    for (let i = 0; i < 10; i++) {
      if (pos >= bytes.length) throw new Error('Оборванные данные QR.');
      const b = bytes[pos++];
      if (i === 9 && b > 1) throw new Error('Слишком большое число в QR.');
      value |= BigInt(b & 127) << BigInt(i * 7);
      if (!(b & 128)) return value;
    }
    throw new Error('Повреждённое число в QR.');
  }
  while (pos < bytes.length) {
    const tag = varint();
    if (tag > 0xffffffffn) throw new Error('Повреждённое поле QR.');
    const field = Number(tag >> 3n), wire = Number(tag & 7n);
    if (!field) throw new Error('Повреждённое поле QR.');
    let value;
    if (wire === 0) value = varint();
    else if ([1,2,5].includes(wire)) {
      const size = wire === 2 ? Number(varint()) : wire === 1 ? 8 : 4;
      if (!Number.isSafeInteger(size) || size < 0 || size > bytes.length - pos) throw new Error('Оборванные данные QR.');
      value = bytes.slice(pos,pos + size); pos += size;
    } else throw new Error('Неподдерживаемый формат protobuf.');
    if (!fields.has(field)) fields.set(field,[]);
    fields.get(field).push({wire,value});
  }
  return fields;
}
function single(fields, num, wire, fallback) {
  const values = fields.get(num);
  if (!values) return fallback;
  if (values.length !== 1 || values[0].wire !== wire) throw new Error('Повторяющееся или повреждённое поле QR.');
  return values[0].value;
}
export function parseMigration(uri) {
  let u; try { u = new URL(uri.trim()); } catch { throw new Error('Некорректная ссылка экспорта.'); }
  if (u.protocol !== 'otpauth-migration:' || u.hostname !== 'offline' || u.username || u.password || u.port || u.hash || !['','/'].includes(u.pathname) || u.searchParams.getAll('data').length !== 1) throw new Error('Некорректная ссылка экспорта Google.');
  const data = u.searchParams.get('data');
  // URLSearchParams interprets an unescaped '+' as a space. Google emits base64.
  const b64 = data.replace(/ /g,'+').replace(/-/g,'+').replace(/_/g,'/');
  if (b64.length > 150000 || !/^[A-Za-z0-9+/]+={0,2}$/.test(b64) || b64.length % 4 === 1) throw new Error('Повреждённые данные Base64 в QR.');
  let bytes; try { bytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0)); } catch { throw new Error('Повреждённые данные Base64 в QR.'); }
  const fields = proto(bytes);
  const version = Number(single(fields,2,0,0n)), size = Number(single(fields,3,0,0n)), index = Number(single(fields,4,0,0n)), batch = single(fields,5,0,0n).toString();
  // Migration version is metadata, not a different OTP schema. Validate the
  // actual records below (as Aegis/Ente do), including for omitted version fields.
  if (!Number.isInteger(version) || version < 0 || version > 0x7fffffff) throw new Error('Некорректная версия экспорта Google.');
  if (!Number.isInteger(size) || size < 0 || size > 100 || !Number.isInteger(index) || index < 0 || (size === 0 ? index !== 0 : index >= size)) throw new Error('Некорректные номера частей экспорта.');
  const entries = fields.get(1) ?? [];
  if (!entries.length || entries.length > 500) throw new Error('В QR нет аккаунтов или их слишком много.');
  const accounts = [], warnings = [];
  const decoder = new TextDecoder('utf-8',{fatal:true});
  for (let i = 0; i < entries.length; i++) {
    if (entries[i].wire !== 2) throw new Error('Повреждённая запись экспорта.');
    const f = proto(entries[i].value);
    const str = n => { try { return decoder.decode(single(f,n,2,new Uint8Array())); } catch { throw new Error('Повреждённый текст в QR.'); } };
    const name = str(2), issuer = str(3), type = Number(single(f,6,0,0n)) || 2;
    const algorithm = Number(single(f,4,0,0n)) || 1, digits = Number(single(f,5,0,0n)) || 1;
    const secret = single(f,1,2,new Uint8Array());
    const title = label(issuer || name || `Запись ${i + 1}`);
    if (type === 1) { warnings.push(`${title}: HOTP со счётчиком не поддерживается; запись пропущена.`); continue; }
    if (type !== 2) { warnings.push(`${title}: неизвестный тип OTP; запись пропущена.`); continue; }
    if (![1,2,3].includes(algorithm) || ![1,2].includes(digits)) { warnings.push(`${title}: неподдерживаемый алгоритм или длина; запись пропущена.`); continue; }
    accounts.push(normalizeAccount({name:issuer && name.startsWith(issuer + ':') ? name.slice(issuer.length + 1).trim() : name, issuer, secret:encode32(secret), algorithm:{1:'SHA1',2:'SHA256',3:'SHA512'}[algorithm], digits:digits === 1 ? 6 : 8, period:30}));
  }
  return {version,size,index,batch,accounts,warnings,signature:btoa(Array.from(bytes,b => String.fromCharCode(b)).join(''))};
}
export class MigrationBatch {
  constructor() { this.clear(); }
  clear() { this.parts = new Map(); this.batch = null; this.size = 0; }
  add(part) {
    if (this.batch !== null && (this.batch !== part.batch || this.size !== part.size)) throw new Error('Это другой экспорт. Завершите текущий или нажмите «Очистить импорт».');
    const previous = this.parts.get(part.index);
    if (previous && previous.signature !== part.signature) throw new Error('Конфликт: две разные версии одной части. Очистите импорт и повторите экспорт с iPhone.');
    if (!previous) { this.parts.set(part.index,part); this.batch = part.batch; this.size = part.size; }
    return {duplicate:!!previous, missing:Array.from({length:this.size},(_,i) => i).filter(i => !this.parts.has(i)), complete:this.parts.size === this.size};
  }
  collect() { return [...this.parts.values()].sort((a,b) => a.index - b.index).flatMap(p => p.accounts); }
  warnings() { return [...this.parts.values()].sort((a,b) => a.index - b.index).flatMap(p => p.warnings); }
}
export function parseBackup(text) {
  let data; try { data = JSON.parse(text); } catch { throw new Error('Файл не является JSON.'); }
  if (data.format !== 'chrome-app-totp-plain' || data.version !== 1 || !Array.isArray(data.accounts) || data.accounts.length > 2000) throw new Error('Неизвестный формат резервной копии.');
  return data.accounts.map(normalizeAccount);
}
export function exportText(accounts) {
  return '# CHROME-APP-TOTP — ОТКРЫТЫЕ СЕКРЕТЫ. Храните в безопасном месте.\r\n' + accounts.map(a => `\r\nСервис: ${a.issuer}\r\nАккаунт: ${a.name}\r\nСекрет: ${a.secret}\r\nТип: TOTP; алгоритм: ${a.algorithm}; цифр: ${a.digits}; период: ${a.period} с\r\n${otpUri(a)}\r\n`).join('');
}
