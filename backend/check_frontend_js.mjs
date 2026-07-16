import { readFileSync } from 'node:fs';

const html = readFileSync(new URL('./timetracker-mobile.html', import.meta.url), 'utf8');
const match = html.match(/<script>([\s\S]*?)<\/script>/);

if (!match) {
  throw new Error('No inline application script found');
}

// Parsing through Function catches syntax errors without executing the app.
new Function(match[1]);
console.log('Frontend JavaScript syntax is valid.');
