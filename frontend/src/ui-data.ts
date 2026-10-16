import { api, type FilterResult, type Stats } from "./types.ts";

export type ExportProgress = { count: number; total: number };

// Build the file page by page without retaining a second copy of the catalog.
// Sorting by ID keeps cursor traversal stable when enrichment changes scores.
export async function vulnerabilityExport(
  filter: Record<string, unknown>,
  signal: AbortSignal,
  onProgress: (progress: ExportProgress) => void,
  fetchPage = (body: Record<string, unknown>, signal: AbortSignal) =>
    api<FilterResult>("/api/v2/vulnerabilities/filter", body, signal),
) {
  const chunks: BlobPart[] = ["["];
  const cursors = new Set<string>();
  let cursor: string | undefined;
  let count = 0;
  do {
    signal.throwIfAborted();
    const page = await fetchPage({
      ...filter, cursor, limit: 100, sort_by: "id", sort_order: "asc",
    }, signal);
    signal.throwIfAborted();
    if (page.results.length) {
      chunks.push(count ? "," : "", JSON.stringify(page.results).slice(1, -1));
      count += page.results.length;
    }
    onProgress({ count, total: page.total });
    cursor = page.next_cursor || undefined;
    if (cursor && (!page.results.length || cursors.has(cursor))) {
      throw new Error("Export pagination stopped advancing. Please retry.");
    }
    if (cursor) cursors.add(cursor);
  } while (cursor);
  chunks.push("]");
  return { blob: new Blob(chunks, { type: "application/json" }), count };
}

export function activitySeries(
  activity: Stats["activity"],
  period: string,
  now = new Date(),
) {
  const valid = activity.filter(p => /^\d{4}-(0[1-9]|1[0-2])$/.test(p.month));
  if (!valid.length) return [];
  const monthly = period === "Last 12 months";
  const totals = new Map<string, { total: number; kev: number }>();
  for (const point of valid) {
    const key = monthly ? point.month : point.month.slice(0, 4);
    const previous = totals.get(key) || { total: 0, kev: 0 };
    totals.set(key, { total: previous.total + point.total, kev: previous.kev + point.kev });
  }
  if (monthly) {
    return Array.from({ length: 12 }, (_, i) => {
      const date = new Date(now.getFullYear(), now.getMonth() - 11 + i, 1);
      const month = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}`;
      return { month, ...(totals.get(month) || { total: 0, kev: 0 }) };
    });
  }
  const years = [...totals.keys()].sort();
  const first = Number(years[0]);
  const last = Number(years[years.length - 1]);
  return Array.from({ length: last - first + 1 }, (_, i) => {
    const month = String(first + i);
    return { month, ...(totals.get(month) || { total: 0, kev: 0 }) };
  });
}

export function sourceDescription(text: string) {
  const citations = new Set<string>();
  const body = text.replace(/\(Citation:\s*([^)]*)\)/g, (_, citation: string) => {
    citations.add(citation.trim());
    return "";
  }).replace(/ {2,}/g, " ").trim();
  return { body, citations: [...citations] };
}
