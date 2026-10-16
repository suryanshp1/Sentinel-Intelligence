# Sidebar Scroll & Viewport Responsiveness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix and harden sidebar scrollability and visual affordance across all desktop and laptop screen heights, ensuring all navigation links, ingestion status widgets, and user controls remain accessible.

**Architecture:** Refactor the sidebar flex layout in `frontend/src/styles.css` to guarantee a scrollable container with stable scrollbar gutters (`scrollbar-gutter: stable`) and adaptive spacing. Eliminate excessive top padding in `.sidebar-bottom` on compact viewports, add automated style regression testing in `frontend/tests/`, and rebuild the Docker image with cache busting to guarantee production container alignment.

**Tech Stack:** React 19, TypeScript, Vite 7, Tailwind CSS v4 / Vanilla CSS tokens, Docker Compose, Node.js test runner.

## Global Constraints
- Preserve existing `.sidebar` width (228px desktop, 205px tablet, 228px mobile drawer).
- Keep all existing routes, navigation counts, and status widgets intact.
- Follow existing code patterns and `.editorconfig`.
- Automated tests must run deterministically via `node --test` without external dependencies.
- Zero breaking changes to API proxying or Nginx reverse proxy configuration.

---

### Task 1: Refactor Sidebar CSS Layout & Scroll Affordance

**Files:**
- Modify: `frontend/src/styles.css:148-166`
- Modify: `frontend/src/styles.css:288-292`
- Modify: `frontend/src/styles.css:3290-3298`

**Interfaces:**
- Consumes: CSS class `.sidebar`, `.sidebar-bottom`, `.user` in `frontend/src/App.tsx`.
- Produces: CSS rules with `overflow-y: auto`, `overflow-x: hidden`, `overscroll-behavior: contain`, `scrollbar-gutter: stable`, and compact gap management.

- [ ] **Step 1: Update `.sidebar` and `.sidebar-bottom` in `frontend/src/styles.css`**
Add `scrollbar-gutter: stable`, reduce excessive padding on `.sidebar-bottom` from 45px to 20px when space is constrained, and ensure smooth touch/wheel scrolling.

```css
.sidebar {
  width: 228px;
  position: fixed;
  inset: 0 auto 0 0;
  border-right: 1px solid var(--theme-border, #222);
  background: var(--theme-canvas, #0c0c0c);
  padding: 24px 14px max(16px, env(safe-area-inset-bottom));
  display: flex;
  flex-direction: column;
  overflow-y: auto;
  overflow-x: hidden;
  overscroll-behavior-y: contain;
  scrollbar-width: thin;
  scrollbar-color: var(--theme-border-strong, #444) transparent;
  scrollbar-gutter: stable;
  z-index: 40;
}
.sidebar > * {
  flex-shrink: 0;
}
```

And update `.sidebar-bottom`:
```css
.sidebar-bottom {
  margin-top: auto;
  padding-top: 24px;
}
```

- [ ] **Step 2: Verify desktop & media query consistency in `frontend/src/styles.css`**
Ensure that media queries (`@media (max-width: 1200px)` and `@media (max-width: 760px)`) do not inadvertently override `overflow-y` to `visible` or introduce unwanted horizontal scrollbars.

- [ ] **Step 3: Run frontend build to verify CSS compilation**
Run: `npm --prefix frontend run build`
Expected: Output bundle in `frontend/dist/` with zero TypeScript or Vite errors.

- [ ] **Step 4: Commit CSS changes**
```bash
git add frontend/src/styles.css
git commit -m "fix(frontend): harden sidebar scrollability and gutter stability"
```

---

### Task 2: Automated Layout Regression Coverage

**Files:**
- Create: `frontend/tests/sidebar-layout.test.mjs`

**Interfaces:**
- Consumes: `frontend/src/styles.css`
- Produces: Node test asserting `.sidebar` contains `overflow-y: auto`, `overflow-x: hidden`, `scrollbar-gutter: stable`, and valid positioning.

- [ ] **Step 1: Write the unit test for CSS scroll declarations**
Create `frontend/tests/sidebar-layout.test.mjs`:

```javascript
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

test('sidebar css rules guarantee vertical scrollability on all viewports', () => {
  const cssPath = path.resolve('frontend/src/styles.css');
  const cssContent = fs.readFileSync(cssPath, 'utf8');

  // Verify base .sidebar has vertical scrolling enabled
  const sidebarMatch = cssContent.match(/\.sidebar\s*\{([^}]+)\}/);
  assert.ok(sidebarMatch, '.sidebar class must exist in styles.css');
  const sidebarBody = sidebarMatch[1];

  assert.match(sidebarBody, /overflow-y:\s*auto/, '.sidebar must specify overflow-y: auto');
  assert.match(sidebarBody, /overflow-x:\s*hidden/, '.sidebar must specify overflow-x: hidden');
  assert.match(sidebarBody, /position:\s*fixed/, '.sidebar must be fixed positioned');
  assert.match(sidebarBody, /scrollbar-gutter:\s*stable/, '.sidebar should have stable scrollbar gutter');
});
```

- [ ] **Step 2: Run test to verify it passes**
Run: `npm --prefix frontend test`
Expected: PASS with all tests passing (including `ui-data.test.mjs` and `sidebar-layout.test.mjs`).

- [ ] **Step 3: Commit regression test**
```bash
git add frontend/tests/sidebar-layout.test.mjs
git commit -m "test(frontend): add regression test for sidebar scroll styles"
```

---

### Task 3: Container Rebuild & Live End-to-End Verification

**Files:**
- Modify: Local container deployment state

- [ ] **Step 1: Rebuild the `vi-web` container image**
Run: `docker compose build vi-web && docker compose up -d vi-web`
Expected: Docker build succeeds and replaces container `threat-intel-vi-web-1` with status `Up (healthy)`.

- [ ] **Step 2: Verify served bundle hash and content**
Run:
```bash
curl -s http://localhost:3000/ | grep -o 'assets/index-[^"]*\.css'
```
Verify the newly served CSS bundle contains `.sidebar` with `overflow` rules.

- [ ] **Step 3: Live Chrome CDP verification**
Run headless Chrome check to verify:
`scrollHeight > clientHeight` and programmatic scrolling (`scrollTop = 250`) correctly offsets the sidebar.

- [ ] **Step 4: Final verification check**
Confirm reverse proxy `http://localhost:3000/health` returns `200 OK` and web assets load cleanly.
