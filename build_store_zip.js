// build_store_zip.js - Собирает ZIP для загрузки в Chrome Web Store.
// Ноль зависимостей: формат ZIP пишется руками поверх zlib, как generate_icons.js
// делает с PNG. В архив попадают только файлы самого расширения — тесты,
// генераторы и документация в магазине не нужны и вызывают вопросы на ревью.

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

// Всё, что Chrome реально загружает, плюс лицензия
const INCLUDE = [
  'manifest.json',
  'background.js',
  'content.js',
  'content.css',
  'popup.html',
  'popup.css',
  'popup.js',
  'trusted_roots.json',
  'LICENSE'
];
const INCLUDE_DIRS = ['icons'];

const crcTable = new Uint32Array(256);
for (let i = 0; i < 256; i++) {
  let c = i;
  for (let j = 0; j < 8; j++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
  crcTable[i] = c;
}
function crc32(buf) {
  let crc = -1;
  for (let i = 0; i < buf.length; i++) crc = (crc >>> 8) ^ crcTable[(crc ^ buf[i]) & 0xFF];
  return (crc ^ -1) >>> 0;
}

// ZIP хранит время в формате MS-DOS
function dosTime(d) {
  return ((d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1)) & 0xFFFF;
}
function dosDate(d) {
  return (((d.getFullYear() - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate()) & 0xFFFF;
}

function collect() {
  const files = [];
  for (const f of INCLUDE) {
    const p = path.join(__dirname, f);
    if (!fs.existsSync(p)) throw new Error('Нет файла ' + f);
    files.push({ name: f, data: fs.readFileSync(p) });
  }
  for (const dir of INCLUDE_DIRS) {
    for (const f of fs.readdirSync(path.join(__dirname, dir)).sort()) {
      files.push({ name: dir + '/' + f, data: fs.readFileSync(path.join(__dirname, dir, f)) });
    }
  }
  return files;
}

function buildZip(files) {
  const now = new Date();
  const time = dosTime(now);
  const date = dosDate(now);
  const locals = [];
  const centrals = [];
  let offset = 0;

  for (const file of files) {
    const name = Buffer.from(file.name, 'utf8');
    const raw = file.data;
    const deflated = zlib.deflateRawSync(raw, { level: 9 });
    // Если сжатие не помогло, кладём как есть
    const useDeflate = deflated.length < raw.length;
    const body = useDeflate ? deflated : raw;
    const method = useDeflate ? 8 : 0;
    const crc = crc32(raw);

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0x0800, 6); // имена в UTF-8
    local.writeUInt16LE(method, 8);
    local.writeUInt16LE(time, 10);
    local.writeUInt16LE(date, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(body.length, 18);
    local.writeUInt32LE(raw.length, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(0, 28);
    locals.push(local, name, body);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0x0800, 8);
    central.writeUInt16LE(method, 10);
    central.writeUInt16LE(time, 12);
    central.writeUInt16LE(date, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(body.length, 20);
    central.writeUInt32LE(raw.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE(0, 38); // внешние атрибуты
    central.writeUInt32LE(offset, 42);
    centrals.push(central, name);

    offset += local.length + name.length + body.length;
  }

  const cd = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(files.length, 8);
  end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(cd.length, 12);
  end.writeUInt32LE(offset, 16);

  return Buffer.concat([...locals, cd, end]);
}

const version = JSON.parse(fs.readFileSync(path.join(__dirname, 'manifest.json'), 'utf8')).version;
const files = collect();
const zip = buildZip(files);
const out = path.join(__dirname, 'dist', 'ca-trust-indicator-' + version + '.zip');

fs.mkdirSync(path.join(__dirname, 'dist'), { recursive: true });
fs.writeFileSync(out, zip);

console.log('Файлов в архиве: ' + files.length);
for (const f of files) console.log('  ' + f.name);
console.log('\n' + out);
console.log('Размер: ' + (zip.length / 1024).toFixed(0) + ' КБ');
