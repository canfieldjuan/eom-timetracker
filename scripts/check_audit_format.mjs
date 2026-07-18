#!/usr/bin/env node
// Enforce the FORM of AUDIT_PROTOCOL.md on findings documents.
//
// This checks structure and citations, NOT truth. A reviewer still judges whether
// a finding is correct. What it hard-fails:
//   1. Missing any of the three required bucket headings
//      (Confirmed / Contradicted / Could-not-determine).
//   2. Any list item under "Confirmed" that carries no citation.
//
// A citation is a `file:line` token (e.g. time_tracker_api.py:1113), a bare line
// ref (:1113 or :1113-1120), or a markdown link. An item that says only "none"
// is exempt (an empty bucket is allowed).
//
// Usage: node scripts/check_audit_format.mjs <file.md> [more.md ...]
// Exit 0 = all pass, 1 = at least one violation, 2 = bad invocation.

import { readFileSync } from 'node:fs';

const CITATION = /(?:[\w./-]+\.\w+:\d+(?:-\d+)?)|(?::\d+(?:-\d+)?\b)|(?:\]\()/;
const BUCKETS = ['confirmed', 'contradicted', 'could-not-determine'];
const isHeading = (l) => /^#{1,6}\s/.test(l) || /^\s*###?\s/.test(l);
const headingText = (l) => l.replace(/^[#\s]+/, '').trim().toLowerCase();
const isListItem = (l) => /^\s*(?:[-*]|\d+\.)\s/.test(l);
const stripItem = (l) => l.replace(/^\s*(?:[-*]|\d+\.)\s*(?:\[[ xX]\]\s*)?/, '').trim();
const looksEmpty = (t) => t === '' || /^none\.?$/i.test(t) || /^n\/?a$/i.test(t);

function checkFile(path) {
  const errors = [];
  let lines;
  try {
    lines = readFileSync(path, 'utf8').split(/\r?\n/);
  } catch (err) {
    return [`${path}: cannot read (${err.code || err.message})`];
  }

  const foundBuckets = new Set();
  // Track which bucket (if any) each line belongs to.
  let current = null; // 'confirmed' | 'contradicted' | 'could-not-determine' | null

  lines.forEach((line, i) => {
    if (isHeading(line)) {
      const text = headingText(line);
      const match = BUCKETS.find((b) => text.includes(b));
      current = match || null;
      if (match) foundBuckets.add(match);
      return;
    }
    if (current === 'confirmed' && isListItem(line)) {
      const body = stripItem(line);
      if (looksEmpty(body)) return;
      if (!CITATION.test(line)) {
        errors.push(
          `${path}:${i + 1}: Confirmed item has no file:line citation -> ${body.slice(0, 80)}`
        );
      }
    }
  });

  const missing = BUCKETS.filter((b) => !foundBuckets.has(b));
  if (missing.length) {
    errors.push(
      `${path}: missing required heading(s): ${missing.join(', ')} ` +
        `(include all three buckets; write "None" for empty ones)`
    );
  }
  return errors;
}

const files = process.argv.slice(2);
if (files.length === 0) {
  console.error('usage: check_audit_format.mjs <file.md> [more.md ...]');
  process.exit(2);
}

let allErrors = [];
for (const f of files) allErrors = allErrors.concat(checkFile(f));

if (allErrors.length) {
  console.error('audit-format check FAILED:\n' + allErrors.map((e) => '  ' + e).join('\n'));
  console.error(
    '\nSee AUDIT_PROTOCOL.md. Every Confirmed claim needs a file:line citation, ' +
      'and all three buckets (Confirmed / Contradicted / Could-not-determine) must be present.'
  );
  process.exit(1);
}
console.log(`audit-format check passed for: ${files.join(', ')}`);
