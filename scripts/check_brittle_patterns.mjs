#!/usr/bin/env node
// Scan for brittle / fragile-heuristic code patterns.
//
// Warn-first by design: with no flag it prints findings and exits 0 (a report,
// not a gate). Pass --strict to make it exit 1 when findings exist — flip the CI
// job to --strict once the existing backlog is triaged (see AUDIT_PROTOCOL.md).
//
// Patterns are intentionally high-signal / low-noise; each names why it is
// brittle. This is a linter for the specific fragilities this codebase has hit,
// not a general style checker.
//
// Usage: node scripts/check_brittle_patterns.mjs [--strict] <file> [more...]

import { readFileSync } from 'node:fs';

const strict = process.argv.includes('--strict');
const files = process.argv.slice(2).filter((a) => a !== '--strict');

if (files.length === 0) {
  console.error('usage: check_brittle_patterns.mjs [--strict] <file> [more...]');
  process.exit(2);
}

// Each rule: id, why, and a test(line, lines, i) -> boolean.
const RULES = [
  {
    id: 'empty-js-catch',
    why: 'catch block swallows the error silently — failures vanish with no log',
    test: (line) => /catch\s*\([^)]*\)\s*\{\s*\}/.test(line) || /\.catch\s*\(\s*\(\s*\)\s*=>\s*\{\s*\}\s*\)/.test(line),
  },
  {
    id: 'py-broad-except-pass',
    why: 'broad except (bare/Exception/BaseException) with a bare pass swallows every error silently — narrow typed excepts are fine and are not flagged',
    test: (line, lines, i) => {
      // Only BROAD excepts: `except:`, `except Exception`, `except BaseException`.
      if (!/^\s*except\s*(:|(\(?\s*(Exception|BaseException)\b))/.test(line)) return false;
      for (let j = i + 1; j < lines.length; j++) {
        const n = lines[j].trim();
        if (n === '' || n.startsWith('#')) continue;
        return n === 'pass';
      }
      return false;
    },
  },
  {
    id: 'string-split-heuristic',
    why: "parsing meaning out of a display string via split(' - ') breaks when the format changes",
    test: (line) => /\.split\(\s*['"] - ['"]\s*\)/.test(line),
  },
  {
    id: 'prefix-string-heuristic',
    why: 'branching on a hardcoded string prefix (e.g. startsWith("GPS ")) is fragile to copy changes',
    test: (line) => /\.startsWith\(\s*['"]GPS /.test(line),
  },
];

let total = 0;
const perFile = [];

for (const path of files) {
  let lines;
  try {
    lines = readFileSync(path, 'utf8').split(/\r?\n/);
  } catch (err) {
    console.error(`skip ${path}: ${err.code || err.message}`);
    continue;
  }
  const hits = [];
  lines.forEach((line, i) => {
    for (const rule of RULES) {
      if (rule.test(line, lines, i)) {
        hits.push({ line: i + 1, id: rule.id, why: rule.why, text: line.trim().slice(0, 100) });
      }
    }
  });
  if (hits.length) {
    perFile.push({ path, hits });
    total += hits.length;
  }
}

if (total === 0) {
  console.log(`No brittle patterns found in ${files.length} file(s).`);
  process.exit(0);
}

const summary = [];
summary.push(`Brittle-pattern report: ${total} finding(s) across ${perFile.length} file(s).`);
for (const { path, hits } of perFile) {
  for (const h of hits) {
    summary.push(`  ${path}:${h.line} [${h.id}] ${h.why}`);
    summary.push(`      ${h.text}`);
  }
}
const out = summary.join('\n');
console.log(out);

// Surface in the GitHub Actions job summary when available.
if (process.env.GITHUB_STEP_SUMMARY) {
  try {
    const { appendFileSync } = await import('node:fs');
    appendFileSync(process.env.GITHUB_STEP_SUMMARY, '### Brittle-pattern report\n\n```\n' + out + '\n```\n');
  } catch (_) {
    /* summary is best-effort */
  }
}

process.exit(strict ? 1 : 0);
