import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

test('sidebar css rules guarantee vertical scrollability on all viewports', () => {
  const cssPath = path.resolve(import.meta.dirname, '../src/styles.css');
  const cssContent = fs.readFileSync(cssPath, 'utf8');

  // Verify base .sidebar has vertical scrolling and gutter stability enabled
  const sidebarMatch = cssContent.match(/\.sidebar\s*\{([^}]+)\}/);
  assert.ok(sidebarMatch, '.sidebar class must exist in styles.css');
  const sidebarBody = sidebarMatch[1];

  assert.match(sidebarBody, /overflow-y:\s*auto/, '.sidebar must specify overflow-y: auto');
  assert.match(sidebarBody, /overflow-x:\s*hidden/, '.sidebar must specify overflow-x: hidden');
  assert.match(sidebarBody, /position:\s*fixed/, '.sidebar must be fixed positioned');
  assert.match(sidebarBody, /scrollbar-gutter:\s*stable/, '.sidebar should have stable scrollbar gutter');
});
