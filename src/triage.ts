import type { FindingDisposition, FindingDispositionStatus, ScanResult, TriageSummary } from "./contracts.js";

const statuses: FindingDispositionStatus[] = ["open", "acknowledged", "false-positive", "accepted-risk", "fixed", "wont-fix"];

export function summarizeDispositions(dispositions: readonly FindingDisposition[]): TriageSummary {
  const byStatus = Object.fromEntries(statuses.map((status) => [status, 0])) as Record<FindingDispositionStatus, number>;
  for (const disposition of dispositions) byStatus[disposition.status] += 1;
  return { byStatus, total: dispositions.length };
}

export function validateDispositions(value: unknown): FindingDisposition[] {
  if (!Array.isArray(value)) throw new Error("处置文件必须是 JSON 数组。");
  return value.map((item, index) => {
    if (!item || typeof item !== "object") throw new Error(`处置记录第 ${index + 1} 项不是对象。`);
    const record = item as Partial<FindingDisposition>;
    if (typeof record.fingerprint !== "string" || !record.fingerprint) throw new Error(`处置记录第 ${index + 1} 项缺少 fingerprint。`);
    if (!record.status || !statuses.includes(record.status)) throw new Error(`处置记录第 ${index + 1} 项 status 无效。`);
    if (typeof record.updatedAt !== "string" || Number.isNaN(Date.parse(record.updatedAt))) throw new Error(`处置记录第 ${index + 1} 项 updatedAt 无效。`);
    return {
      fingerprint: record.fingerprint,
      status: record.status,
      updatedAt: record.updatedAt,
      ...(record.note === undefined ? {} : { note: record.note }),
      ...(record.updatedBy === undefined ? {} : { updatedBy: record.updatedBy }),
    };
  });
}

export function attachDispositions(result: ScanResult, dispositions: readonly FindingDisposition[]): ScanResult {
  const active = new Set(result.findings.map((finding) => finding.fingerprint));
  const applicable = dispositions.filter((item) => active.has(item.fingerprint));
  return { ...result, dispositions: [...applicable], triage: summarizeDispositions(applicable) };
}
