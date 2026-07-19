import { readFileSync } from 'node:fs';

const html = readFileSync(new URL('./timetracker-mobile.html', import.meta.url), 'utf8');

// Validate EVERY inline application script, not just the first. A non-global regex
// (the previous approach) silently skipped every block after the first, so a syntax
// error in a later block could ship unnoticed.
const BLOCK = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;

let checked = 0;
for (const m of html.matchAll(BLOCK)) {
  const attrs = m[1] || '';
  const body = m[2] || '';
  if (/\bsrc\s*=/.test(attrs)) continue; // external script, no inline body to parse
  // Skip non-JavaScript blocks (e.g. <script type="application/ld+json">).
  if (/\btype\s*=/.test(attrs) && !/\btype\s*=\s*["']?(?:text\/javascript|application\/javascript|module)/i.test(attrs)) {
    continue;
  }
  if (body.trim() === '') continue;
  // Parsing through Function catches syntax errors without executing the app.
  new Function(body);
  checked += 1;
}

if (checked === 0) {
  throw new Error('No inline application script found');
}
console.log(`Frontend JavaScript syntax is valid (${checked} inline script block(s)).`);
