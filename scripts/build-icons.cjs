const fs = require('node:fs/promises');
const path = require('node:path');
const sharp = require('sharp');
const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128" viewBox="0 0 128 128"><rect width="128" height="128" rx="29" fill="#f1f3f4"/><g fill="none" stroke-width="13" stroke-linecap="round"><path d="M37 37a38 38 0 0 1 50 0" stroke="#ea4335"/><path d="M93 43a38 38 0 0 1 0 42" stroke="#4285f4"/><path d="M86 92a38 38 0 0 1-44 0" stroke="#34a853"/><path d="M34 84a38 38 0 0 1 0-40" stroke="#fbbc04"/></g><path d="M64 43v23l16 10" fill="none" stroke="#5f6368" stroke-width="10" stroke-linecap="round" stroke-linejoin="round"/><circle cx="64" cy="66" r="7" fill="#5f6368"/></svg>`;
(async()=>{ const dir=path.resolve('extension/icons'); await fs.writeFile(path.join(dir,'source.svg'),svg); for(const size of [16,32,48,128]) await sharp(Buffer.from(svg)).resize(size,size).png().toFile(path.join(dir,size+'.png')); console.log('Icons generated'); })();
