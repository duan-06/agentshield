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

  let TP=0,TN=0,FP=0,FN=0;
  const byCat = {};

  for (let i = 1; i < lines.length; i++) {
    const c = parseCsvLine(lines[i]);
    const row = {
      id: c[idx['id']],
      category: c[idx['category']],
      prompt: c[idx['prompt']],
      expected: (c[idx['expected_decision']] || '').toLowerCase(),
    };

    let blocked = false;
    try {
      const resp = await fetch(URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${TOKEN}`,
        },
        body: JSON.stringify({ categoryId: 1, input: row.prompt }),
      });

      const data = await resp.json();
      if (!resp.ok || !data?.success) {
        throw new Error(`HTTP ${resp.status} ${JSON.stringify(data).slice(0,120)}`);
      }
      blocked = !!data?.data?.scanResult?.is_blocked;
    } catch (e) {
      console.error(`ERR row ${row.id}: ${e.message}`);
      continue;
    }

    if (!byCat[row.category]) byCat[row.category] = { total:0, fn:0, fp:0, blocked:0 };
    byCat[row.category].total += 1;
    if (blocked) byCat[row.category].blocked += 1;

    if (row.expected === 'block' && blocked) TP++;
    else if (row.expected === 'allow' && !blocked) TN++;
    else if (row.expected === 'allow' && blocked) { FP++; byCat[row.category].fp += 1; }
    else if (row.expected === 'block' && !blocked) { FN++; byCat[row.category].fn += 1; }
  }

  const total = TP+TN+FP+FN;
  const acc = total ? (TP+TN)/total*100 : 0;
  const fnr = (TP+FN) ? FN/(TP+FN)*100 : 0;
  const fpr = (FP+TN) ? FP/(FP+TN)*100 : 0;

  const topFn = Object.entries(byCat)
    .map(([k,v]) => ({ category:k, ...v, fnRate: v.total? v.fn/v.total*100:0 }))
    .sort((a,b)=>b.fn-a.fn || b.fnRate-a.fnRate)
    .slice(0,10);

  console.log(JSON.stringify({ total, TP,TN,FP,FN, accuracy:acc, falseNegativeRate:fnr, falsePositiveRate:fpr, topFalseNegativeCategories: topFn }, null, 2));
})();
