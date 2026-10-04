import path from "node:path";
import type { Finding, ScannerModule } from "../contracts.js";
import type { ExternalScanner, ExternalScanResult } from "../external-scanner.js";
import { refs } from "../standards.js";
import { auditFinding, auditSeverity, fileExists, runAuditCommand } from "./project-audit-utils.js";

const references = [refs.cwe("CWE-1104"), refs.ssdf("RV.1"), refs.samm("Implementation/Secure Build")];

const SEVERITY_RANK: Record<string, number> = { info: 0, low: 1, medium: 2, moderate: 2, high: 3, critical: 4 };

function maxSeverity(a: string | undefined, b: string | undefined): string | undefined {
  const rankA = a ? SEVERITY_RANK[a.toLowerCase()] ?? 0 : 0;
  const rankB = b ? SEVERITY_RANK[b.toLowerCase()] ?? 0 : 0;
  return rankA >= rankB ? a : b;
}

function extractAdvisoryId(entry: unknown): { id: string; title: string } | undefined {
  if (!entry || typeof entry !== "object") return undefined;
  const advisory = entry as { title?: string; url?: string; source?: string };
  const text = `${advisory.source ?? ""} ${advisory.url ?? ""}`;
  const ghsa = text.match(/GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}/i);
  if (ghsa) return { id: ghsa[0].toUpperCase(), title: advisory.title ?? ghsa[0] };
  const cve = text.match(/CVE-\d{4}-\d+/i);
  if (cve) return { id: cve[0].toUpperCase(), title: advisory.title ?? cve[0] };
  return undefined;
}

interface AdvisoryGroup {
  id: string;
  title: string;
  severity: string | undefined;
  packages: { name: string; range: string }[];
  fixAvailable: boolean;
}

export function npmFindings(report: unknown): Finding[] {
  if (!report || typeof report !== "object" || !("vulnerabilities" in report)) return [];
  const vulnerabilities = (report as { vulnerabilities?: Record<string, unknown> }).vulnerabilities ?? {};
  const byId = new Map<string, AdvisoryGroup>();

  const resolveAdvisory = (name: string, seen = new Set<string>()): { id: string; title: string } | undefined => {
    if (seen.has(name)) return undefined;
    seen.add(name);
    const item = vulnerabilities[name] as { severity?: string; via?: unknown[] } | undefined;
    if (!item) return undefined;
    const direct = item.via?.map(extractAdvisoryId).find(Boolean);
    if (direct) return direct;
    for (const reference of item.via ?? []) {
      if (typeof reference === "string") {
        const upstream = resolveAdvisory(reference, seen);
        if (upstream) return upstream;
      }
    }
    return undefined;
  };

  for (const [name, raw] of Object.entries(vulnerabilities)) {
    if (!raw || typeof raw !== "object") continue;
    const item = raw as { severity?: string; via?: unknown[]; range?: string; fixAvailable?: unknown };
    const advisory = resolveAdvisory(name);
    if (!advisory) {
      // 无 GHSA/CVE 公告 id：保持原有逐包行为，避免改变既有输出
      byId.set(`pkg:${name}`, {
        id: "advisory",
        title: item.via?.map((entry) => (typeof entry === "object" && entry ? (entry as { title?: string }).title : undefined)).find(Boolean) ?? "npm 依赖存在已知漏洞",
        severity: item.severity,
        packages: [{ name, range: item.range ?? "" }],
        fixAvailable: Boolean(item.fixAvailable),
      });
      continue;
    }
    const existing = byId.get(advisory.id);
    if (existing) {
      existing.packages.push({ name, range: item.range ?? "" });
      existing.fixAvailable ||= Boolean(item.fixAvailable);
      existing.severity = maxSeverity(existing.severity, item.severity);
    } else {
      byId.set(advisory.id, {
        id: advisory.id,
        title: advisory.title,
        severity: item.severity,
        packages: [{ name, range: item.range ?? "" }],
        fixAvailable: Boolean(item.fixAvailable),
      });
    }
  }

  return [...byId.values()].map(({ id, title, severity, packages, fixAvailable }) => auditFinding({
    ruleId: id === "advisory" ? "dependency/npm-audit" : `dependency/npm-audit/${id}`,
    message: `${packages.map((pkg) => pkg.name).join(", ")}: ${title}`,
    severity: auditSeverity(severity ?? "medium"),
    confidence: "high",
    category: "dependency",
    file: "package-lock.json",
    line: 1,
    column: 1,
    evidence: packages.map((pkg) => `${pkg.name} ${pkg.range}`.trim()).join(", "),
    suggestion: fixAvailable ? "运行 npm audit fix，并复核升级造成的兼容性变化。" : "升级或替换受影响依赖，并确认上游安全公告。",
    references,
  }));
}

export function composerFindings(report: unknown): Finding[] {
  if (!report || typeof report !== "object") return [];
  const advisories = (report as { advisories?: Record<string, unknown[]> }).advisories ?? {};
  return Object.entries(advisories).flatMap(([name, entries]) => (entries ?? []).flatMap((raw) => {
    if (!raw || typeof raw !== "object") return [];
    const item = raw as { advisoryId?: string; title?: string; affectedVersions?: string; severity?: string };
    return [auditFinding({
      ruleId: `dependency/composer-audit/${item.advisoryId ?? "advisory"}`,
      message: `${name}: ${item.title ?? "Composer 依赖存在已知漏洞"}`,
      severity: auditSeverity(item.severity), confidence: "high", category: "dependency",
      file: "composer.lock", line: 1, column: 1,
      evidence: `${name} ${item.affectedVersions ?? ""}`.trim(),
      suggestion: "使用 composer update 升级至不受影响的版本，并复核变更。",
      references,
    })];
  }));
}

export const npmAuditScanner: ExternalScanner = {
  id: "npm-audit", version: "0.3.0",
  async scan(context): Promise<ExternalScanResult> {
    if (!await fileExists(path.join(context.cwd, "package-lock.json"))) return { findings: [], executedRules: [] };
    const result = await runAuditCommand(process.platform === "win32" ? "npm.cmd" : "npm", ["audit", "--json", "--omit=dev"], context.cwd, 120_000, context.signal);
    if (!result?.stdout) return { findings: [], executedRules: ["dependency/npm-audit"], status: "failed", diagnostics: [{ code: "DEPENDENCY_AUDIT_UNAVAILABLE", level: "error", phase: "external-scanner", scannerId: "npm-audit", message: "npm audit 未产生可解析报告。", recoverable: true }] };
    try {
      const report = JSON.parse(result.stdout) as { vulnerabilities?: unknown; error?: unknown };
      if (result.code !== 0 && !report.vulnerabilities) {
        return { findings: [], executedRules: ["dependency/npm-audit"], status: "failed", diagnostics: [{ code: "DEPENDENCY_AUDIT_INVALID_REPORT", level: "error", phase: "external-scanner", scannerId: "npm-audit", message: "npm audit 返回了失败或不完整的报告。", recoverable: true }] };
      }
      if (!report.vulnerabilities || typeof report.vulnerabilities !== "object") throw new Error("invalid report");
      return { findings: npmFindings(report), executedRules: ["dependency/npm-audit"], status: "succeeded" };
    } catch { return { findings: [], executedRules: ["dependency/npm-audit"], status: "failed", diagnostics: [{ code: "DEPENDENCY_AUDIT_INVALID_REPORT", level: "error", phase: "external-scanner", scannerId: "npm-audit", message: "npm audit 返回了无法解析的报告。", recoverable: true }] }; }
  },
};

export const composerAuditScanner: ExternalScanner = {
  id: "composer-audit", version: "0.3.0",
  async scan(context): Promise<ExternalScanResult> {
    if (!await fileExists(path.join(context.cwd, "composer.lock"))) return { findings: [], executedRules: [] };
    const result = await runAuditCommand(process.platform === "win32" ? "composer.bat" : "composer", ["audit", "--format=json", "--no-interaction"], context.cwd, 120_000, context.signal);
    if (!result?.stdout) return { findings: [], executedRules: ["dependency/composer-audit"], status: "failed", diagnostics: [{ code: "DEPENDENCY_AUDIT_UNAVAILABLE", level: "error", phase: "external-scanner", scannerId: "composer-audit", message: "Composer audit 未产生可解析报告。", recoverable: true }] };
    try {
      const report = JSON.parse(result.stdout) as { advisories?: unknown; abandoned?: unknown };
      if (result.code !== 0 && !report.advisories) {
        return { findings: [], executedRules: ["dependency/composer-audit"], status: "failed", diagnostics: [{ code: "DEPENDENCY_AUDIT_INVALID_REPORT", level: "error", phase: "external-scanner", scannerId: "composer-audit", message: "Composer audit 返回了失败或不完整的报告。", recoverable: true }] };
      }
      if (!report.advisories || typeof report.advisories !== "object") throw new Error("invalid report");
      return { findings: composerFindings(report), executedRules: ["dependency/composer-audit"], status: "succeeded" };
    } catch { return { findings: [], executedRules: ["dependency/composer-audit"], status: "failed", diagnostics: [{ code: "DEPENDENCY_AUDIT_INVALID_REPORT", level: "error", phase: "external-scanner", scannerId: "composer-audit", message: "Composer audit 返回了无法解析的报告。", recoverable: true }] }; }
  },
};

export const dependencyAuditModule: ScannerModule = {
  id: "@lego-scan/dependency-audit",
  version: "0.3.0",
  rules: [],
  scanners: [npmAuditScanner, composerAuditScanner],
};
