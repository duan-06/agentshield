const fs = require('fs');

const TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjMsImlhdCI6MTc3MzkyNjExMywiZXhwIjoxNzc0NTMwOTEzfQ.Zt7I3Znj5SkQJLc-3U63fxhUQzezDCPOfcDyKjp6paY';
const URL = 'http://127.0.0.1:3001/api/tests/evaluate';

function parseCsvLine(line) {
  const cells = [];
  let cur = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') { cur += '"'; i++; }
      else inQuotes = !inQuotes;
      continue;
    }
    if (ch === ',' && !inQuotes) { cells.push(cur); cur = ''; continue; }
    cur += ch;
  }
  cells.push(cur);
  return cells.map(s => s.trim());
}

(async () => {
  const text = fs.readFileSync('datasets/attack_mixed_100.csv', 'utf8');
  const lines = text.split(/\r?\n/).filter(Boolean);
  const header = parseCsvLine(lines[0]).map(h => h.toLowerCase());
  const idx = Object.fromEntries(header.map((h, i) => [h, i]));

  const fns = [];
  for (let i = 1; i < lines.length; i++) {
    const c = parseCsvLine(lines[i]);
    const row = {
      id: c[idx['id']],
      category: c[idx['category']],
      attack_type: c[idx['attack_type']],
      prompt: c[idx['prompt']],
      expected: (c[idx['expected_decision']] || '').toLowerCase(),
    };
    if (row.expected !== 'block') continue;

    const resp = await fetch(URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${TOKEN}`,
      },
      body: JSON.stringify({ categoryId: 1, input: row.prompt }),
    });
    const data = await resp.json();
    const blocked = !!data?.data?.scanResult?.is_blocked;
    if (!blocked) {
      fns.push({ id: row.id, category: row.category, attack_type: row.attack_type, prompt: row.prompt.slice(0, 130) });
    }
  }

  console.log(JSON.stringify({ falseNegativeCount: fns.length, falseNegatives: fns }, null, 2));
})();
