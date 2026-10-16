import test from "node:test";
import assert from "node:assert/strict";
import { activitySeries, vulnerabilityExport, sourceDescription } from "../src/ui-data.ts";

test("export traverses every page, preserves constraints, and restarts at the beginning", async () => {
  const records = Array.from({ length: 235 }, (_, i) => ({ id: `CVE-${i}`, title: `Record ${i}` }));
  const filter = { text_search: "server", conditions: [{ field: "seen_wild", operator: "eq", value: true }], cursor: "current-ui-page", sort_by: "cvss" };
  const calls = [], progress = [];
  const result = await vulnerabilityExport(filter, new AbortController().signal, p => progress.push(p), async body => {
    calls.push(body);
    const offset = Number(body.cursor || 0);
    return { results: records.slice(offset, offset + 100), total: 235, next_cursor: offset + 100 < records.length ? String(offset + 100) : null };
  });
  assert.equal(calls.length, 3);
  assert.equal(calls[0].cursor, undefined);
  for (const call of calls) {
    assert.equal(call.text_search, filter.text_search);
    assert.deepEqual(call.conditions, filter.conditions);
    assert.equal(call.sort_by, "id");
    assert.equal(call.sort_order, "asc");
  }
  assert.deepEqual(JSON.parse(await result.blob.text()), records);
  assert.equal(result.count, 235);
  assert.deepEqual(progress.map(p => p.count), [100, 200, 235]);
  assert.equal(filter.cursor, "current-ui-page");
});

test("failed export never returns a misleading partial file", async () => {
  let requests = 0;
  await assert.rejects(vulnerabilityExport({}, new AbortController().signal, () => {}, async () => {
    if (requests++) throw new Error("Source unavailable");
    return { results: [{ id: "CVE-1" }], total: 200, next_cursor: "second-page" };
  }), /Source unavailable/);
});

test("export cancellation stops pagination", async () => {
  const controller = new AbortController();
  let requests = 0;
  await assert.rejects(vulnerabilityExport({}, controller.signal, () => controller.abort(), async () => {
    requests++;
    return { results: [{ id: "CVE-1" }], total: 200, next_cursor: "second-page" };
  }), { name: "AbortError" });
  assert.equal(requests, 1);
});

test("export rejects a cursor cycle instead of duplicating pages forever", async () => {
  await assert.rejects(vulnerabilityExport({}, new AbortController().signal, () => {}, async () => ({
    results: [{ id: "CVE-1" }], total: 200, next_cursor: "same-cursor",
  })), /stopped advancing/);
});

test("an empty export is valid JSON", async () => {
  const result = await vulnerabilityExport({}, new AbortController().signal, () => {}, async () => ({
    results: [], total: 0, next_cursor: null,
  }));
  assert.deepEqual(JSON.parse(await result.blob.text()), []);
  assert.equal(result.count, 0);
});

test("history aggregates months into calendar years and fills missing years", () => {
  assert.deepEqual(activitySeries([
    { month: "2022-01", total: 2, kev: 1 },
    { month: "2022-12", total: 3, kev: 0 },
    { month: "2024-04", total: 4, kev: 2 },
    { month: "invalid", total: 500, kev: 500 },
  ], "All history"), [
    { month: "2022", total: 5, kev: 1 },
    { month: "2023", total: 0, kev: 0 },
    { month: "2024", total: 4, kev: 2 },
  ]);
});

test("last twelve months is a calendar window, including months with no records", () => {
  const series = activitySeries([
    { month: "2025-10", total: 99, kev: 0 },
    { month: "2025-11", total: 3, kev: 1 },
    { month: "2026-10", total: 5, kev: 2 },
    { month: "2026-11", total: 99, kev: 0 },
  ], "Last 12 months", new Date(2026, 9, 16));
  assert.equal(series.length, 12);
  assert.deepEqual(series[0], { month: "2025-11", total: 3, kev: 1 });
  assert.deepEqual(series[1], { month: "2025-12", total: 0, kev: 0 });
  assert.deepEqual(series[11], { month: "2026-10", total: 5, kev: 2 });
  assert.equal(series.reduce((sum, point) => sum + point.total, 0), 8);
  assert.deepEqual(activitySeries([], "All history"), []);
});

test("source citations are retained separately without corrupting Markdown links", () => {
  assert.deepEqual(sourceDescription("[APT](https://attack.mitre.org/groups/G1) is active. (Citation: source_one) (Citation: source_one)"), {
    body: "[APT](https://attack.mitre.org/groups/G1) is active.", citations: ["source_one"],
  });
});
