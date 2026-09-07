// bump_version.js - синхронно поднимает версию во всех трёх местах, где она указана.
// Использование: node bump_version.js 1.3.1
const fs = require('fs');

const next = process.argv[2];
if (!/^\d+\.\d+\.\d+$/.test(next || '')) {
  console.error('Использование: node bump_version.js <major.minor.patch>');
  process.exit(1);
}

const m = JSON.parse(fs.readFileSync('manifest.json', 'utf8'));
const prev = m.version;
if (prev === next) {
  console.error('Версия уже ' + next);
  process.exit(1);
}

const html = fs.readFileSync('popup.html', 'utf8');
if (!html.includes('CA Indicator v' + prev)) {
  console.error('popup.html: не найден футер "CA Indicator v' + prev + '", версия не изменена');
  process.exit(1);
}

m.name = m.name.split('v' + prev).join('v' + next);
m.version = next;
fs.writeFileSync('manifest.json', JSON.stringify(m, null, 2) + '\n');
fs.writeFileSync('popup.html', html.split('CA Indicator v' + prev).join('CA Indicator v' + next));

console.log(prev + ' -> ' + next);
console.log('  manifest.json: version + name');
console.log('  popup.html:    футер');
