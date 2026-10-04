import path from "node:path";
import type { Finding, ScannerModule } from "../contracts.js";
import type { ExternalScanner, ExternalScanResult } from "../external-scanner.js";
import { refs } from "../standards.js";
import { auditFinding, auditSeverity, readJson } from "./project-audit-utils.js";

interface PackageCoordinate { ecosystem: "npm" | "Packagist"; name: string; version: string; file: string; }
interface OSVVulnerability { id?: string; summary?: string; database_specific?: { severity?: string } }
const references = [refs.cwe("CWE-1104"), refs.ssdf("RV.1"), refs.samm("Implementation/Secure Build")];

export function mergeOsvFindings(packages: PackageCoordinate[], results: { vulns?: OSVVulnerability[] }[]): Finding[] {
  const byVuln = new Map<string, { vulnerability: OSVVulnerability; affected: PackageCoordinate[] }>();
  results.forEach((result, index) => {
    const pkg = packages[index];
    if (!pkg) return;
    for (const vulnerability of result.vulns ?? []) {
      const id = vulnerability.id ?? "unknown";
      const entry = byVuln.get(id);
      if (entry) entry.affected.push(pkg);
      else byVuln.set(id, { vulnerability, affected: [pkg] });
    }
  });
  return [...byVuln.values()].map(({ vulnerability, affected }) => {
    const id = vulnerability.id ?? "vulnerability";
    const names = affected.map((pkg) => pkg.name);
    const primary = affected[0]!;
    return auditFinding({
      ruleId: `dependency/osv/${id}`,
      message: `${names.join(", ")}: ${vulnerability.summary ?? id}`,
      severity: auditSeverity(vulnerability.database_specific?.severity),
      confidence: "high",
      category: "dependency",
      file: primary.file,
      line: 1,
      column: 1,
      evidence: affected.map((pkg) => `${pkg.name}@${pkg.version}`).join(", "),
      suggestion: "根据 OSV 公告升级到已修复版本，无法升级时评估缓解措施。",
      references,
    });
  });
}

export async function packageCoordinates(cwd: string): Promise<PackageCoordinate[]> {
  const coordinates: PackageCoordinate[] = [];
  const packageLock = await readJson(path.join(cwd, "package-lock.json"));
  if (packageLock && typeof packageLock === "object") {
    const lock = packageLock as {
      packages?: Record<string, { name?: string; version?: string }>;
      dependencies?: Record<string, { version?: string; dependencies?: Record<string, unknown> }>;
    };
    const packages = lock.packages ?? {};
    for (const [key, value] of Object.entries(packages)) {
      const name = value.name ?? key.replace(/^node_modules\//, "");
      if (key && name && value.version && key !== "") coordinates.push({ ecosystem: "npm", name, version: value.version, file: "package-lock.json" });
    }
    if (!Object.keys(packages).length) {
      const visit = (items: Record<string, { version?: string; dependencies?: Record<string, unknown> }>): void => {
        for (const [name, value] of Object.entries(items)) {
          if (value.version) coordinates.push({ ecosystem: "npm", name, version: value.version, file: "package-lock.json" });
          if (value.dependencies && typeof value.dependencies === "object") visit(value.dependencies as Record<string, { version?: string; dependencies?: Record<string, unknown> }>);
        }
      };
      visit(lock.dependencies ?? {});
    }
  }
  const composerLock = await readJson(path.join(cwd, "composer.lock"));
  if (composerLock && typeof composerLock === "object") {
    const production = (composerLock as { packages?: { name?: string; version?: string }[] }).packages ?? [];
    const development = (composerLock as { "packages-dev"?: { name?: string; version?: string }[] })["packages-dev"] ?? [];
    for (const item of [...production, ...development]) {
      if (item.name && item.version) coordinates.push({ ecosystem: "Packagist", name: item.name, version: item.version.replace(/^v/, ""), file: "composer.lock" });
    }
  }
  return coordinates;
}

export const osvScanner: ExternalScanner = {
  id: "osv", version: "0.3.0",
  async scan(context): Promise<ExternalScanResult> {
    const packages = await packageCoordinates(context.cwd);
    if (!packages.length) return { findings: [], executedRules: [] };
    if (typeof fetch !== "function") return { findings: [], executedRules: ["dependency/osv"], status: "failed", diagnostics: [{ code: "OSV_CLIENT_UNAVAILABLE", level: "error", phase: "external-scanner", scannerId: "osv", message: "当前运行时不支持 OSV 网络查询。", recoverable: true }] };
    try {
      const response = await fetch("https://api.osv.dev/v1/querybatch", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ queries: packages.map((item) => ({ package: { ecosystem: item.ecosystem, name: item.name }, version: item.version })) }),
        signal: AbortSignal.timeout(20_000),
      });
      if (!response.ok) return { findings: [], executedRules: ["dependency/osv"], status: "failed", diagnostics: [{ code: "OSV_REQUEST_FAILED", level: "error", phase: "external-scanner", scannerId: "osv", message: `OSV 查询失败，HTTP ${response.status}。`, recoverable: true }] };
      const payload = await response.json() as { results?: unknown };
      if (!Array.isArray(payload.results) || payload.results.length !== packages.length) {
        return { findings: [], executedRules: ["dependency/osv"], status: "failed", diagnostics: [{ code: "OSV_INVALID_REPORT", level: "error", phase: "external-scanner", scannerId: "osv", message: "OSV 返回的报告结构与依赖数量不匹配。", recoverable: true }] };
      }
      const results = payload.results as { vulns?: OSVVulnerability[] }[];
      return { findings: mergeOsvFindings(packages, results), executedRules: ["dependency/osv"], status: "succeeded" };
    } catch (error) { return { findings: [], executedRules: ["dependency/osv"], status: "failed", diagnostics: [{ code: "OSV_REQUEST_FAILED", level: "error", phase: "external-scanner", scannerId: "osv", message: `OSV 查询异常：${error instanceof Error ? error.name : "UnknownError"}。`, recoverable: true }] }; }
  },
};

export const osvModule: ScannerModule = {
  id: "@lego-scan/osv",
  version: "0.3.0",
  rules: [],
  scanners: [osvScanner],
};
