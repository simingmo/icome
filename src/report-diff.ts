import type { Finding, ScanResult } from "./contracts.js";

export interface FindingChange {
  previous: Finding;
  current: Finding;
  fields: Array<"severity" | "message" | "location" | "suggestion">;
}

export interface DispositionChange {
  fingerprint: string;
  previous?: string;
  current?: string;
}

export interface ScanDiff {
  added: Finding[];
  fixed: Finding[];
  unchanged: Finding[];
  changed: FindingChange[];
  dispositionChanged: DispositionChange[];
  previousStatus: ScanResult["status"];
  currentStatus: ScanResult["status"];
}

export function diffScanResults(previous: ScanResult, current: ScanResult): ScanDiff {
  const previousByFingerprint = new Map(previous.findings.map((finding) => [finding.fingerprint, finding]));
  const currentByFingerprint = new Map(current.findings.map((finding) => [finding.fingerprint, finding]));
  const previousDispositions = new Map((previous.dispositions ?? []).map((item) => [item.fingerprint, item.status]));
  const currentDispositions = new Map((current.dispositions ?? []).map((item) => [item.fingerprint, item.status]));
  const changed: FindingChange[] = [];
  const changedFingerprints = new Set<string>();
  for (const finding of current.findings) {
    const old = previousByFingerprint.get(finding.fingerprint);
    if (!old) continue;
    const fields: FindingChange["fields"] = [];
    if (old.severity !== finding.severity) fields.push("severity");
    if (old.message !== finding.message) fields.push("message");
    if (old.file !== finding.file || old.line !== finding.line || old.column !== finding.column) fields.push("location");
    if (old.suggestion !== finding.suggestion) fields.push("suggestion");
    if (fields.length) {
      changed.push({ previous: old, current: finding, fields });
      changedFingerprints.add(finding.fingerprint);
    }
  }
  const dispositionFingerprints = new Set([...previousDispositions.keys(), ...currentDispositions.keys()]);
  const dispositionChanged: DispositionChange[] = [];
  for (const fingerprint of dispositionFingerprints) {
    const old = previousDispositions.get(fingerprint);
    const next = currentDispositions.get(fingerprint);
    if (old !== next) dispositionChanged.push({ fingerprint, ...(old ? { previous: old } : {}), ...(next ? { current: next } : {}) });
  }
  return {
    added: current.findings.filter((finding) => !previousByFingerprint.has(finding.fingerprint)),
    fixed: previous.findings.filter((finding) => !currentByFingerprint.has(finding.fingerprint)),
    unchanged: current.findings.filter((finding) => previousByFingerprint.has(finding.fingerprint) && !changedFingerprints.has(finding.fingerprint)),
    changed,
    dispositionChanged,
    previousStatus: previous.status,
    currentStatus: current.status,
  };
}
