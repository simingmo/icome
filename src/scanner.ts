import { lstat, readFile, realpath, stat } from "node:fs/promises";
import path from "node:path";
import fg from "fast-glob";
import type {
  FileContext,
  Finding,
  RuleCategory,
  ScanOptions,
  ScanResult,
  ScanSummary,
  Severity,
  StandardName,
  ScanCoverage,
  ScanModuleReport,
  ScanStage,
} from "./contracts.js";
import { languageFromFile } from "./scan-coverage.js";
import { ModuleResolutionError } from "./module-errors.js";
import { resolveScanConfiguration } from "./scan-configuration.js";

const DEFAULT_INCLUDE = ["**/*.{js,jsx,mjs,cjs,ts,tsx,mts,cts}"];
export const TEST_EXCLUDE = [
  "**/tests/**",
  "**/__tests__/**",
  "**/test/**",
  "**/spec/**",
  "**/*.test.*",
  "**/*.spec.*",
];
export const DEFAULT_EXCLUDE = [
  "**/node_modules/**",
  "**/.venv/**",
  "**/venv/**",
  "**/.venv*/**",
  "**/venv*/**",
  "**/env/**",
  "**/virtualenv*/**",
  "**/site-packages/**",
  "**/dist-packages/**",
  "**/.tox/**",
  "**/__pycache__/**",
  "**/*.egg-info/**",
  "**/bower_components/**",
  "**/vendor/**",
  "**/dist/**",
  "**/build/**",
  "**/coverage/**",
  "**/.git/**",
];
const TEST_PATTERN = /(?:^|\/)(?:tests?|__tests__)(?:\/|$)|\.(?:test|spec)\.[cm]?[jt]sx?$/i;

export function isTestPath(file: string): boolean {
  return TEST_PATTERN.test(file.replaceAll("\\", "/"));
}
const severityOrder: Severity[] = ["info", "low", "medium", "high", "critical"];
const DEFAULT_MAX_FILES = 10_000;
const DEFAULT_MAX_FILE_BYTES = 10 * 1024 * 1024;
const DEFAULT_MAX_TOTAL_BYTES = 256 * 1024 * 1024;
const DEFAULT_MAX_DEPTH = 40;

function isWithin(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative));
}

function toContext(cwd: string, relativePath: string, source: string): FileContext {
  const normalized = relativePath.replaceAll("\\", "/");
  return {
    absolutePath: path.resolve(cwd, relativePath),
    relativePath: normalized,
    source,
    lines: source.split(/\r?\n/),
    isTest: isTestPath(normalized),
  };
}

function matches(value: string, patterns: string[] | undefined): boolean {
  return patterns?.some((pattern) => pattern === value || (pattern.endsWith("*") && value.startsWith(pattern.slice(0, -1)))) ?? false;
}

function errorCode(error: unknown): string | undefined {
  return typeof error === "object" && error !== null && "code" in error && typeof error.code === "string" ? error.code : undefined;
}

export function summarize(findings: Finding[]): ScanSummary {
  const bySeverity = Object.fromEntries(severityOrder.map((severity) => [severity, 0])) as Record<Severity, number>;
  const byCategory: Partial<Record<RuleCategory, number>> = {};
  const byRule: Record<string, number> = {};
  const byStandard: Partial<Record<StandardName, number>> = {};
  for (const finding of findings) {
    bySeverity[finding.severity] += 1;
    byCategory[finding.category] = (byCategory[finding.category] ?? 0) + 1;
    byRule[finding.ruleId] = (byRule[finding.ruleId] ?? 0) + 1;
    for (const reference of finding.references) {
      byStandard[reference.standard] = (byStandard[reference.standard] ?? 0) + 1;
    }
  }
  return { bySeverity, byCategory, byRule, byStandard };
}

export async function scan(options: ScanOptions): Promise<ScanResult> {
  const startedAt = performance.now();
  const startedAtIso = new Date().toISOString();
  const cwd = path.resolve(options.cwd);
  const configuration = resolveScanConfiguration(options);
  const allRules = configuration.modules.flatMap((module) => module.rules);
  const duplicated = allRules.find((rule, index) => allRules.findIndex((candidate) => candidate.id === rule.id) !== index);
  if (duplicated) {
    throw new ModuleResolutionError("DUPLICATE_RULE", `规则 ID 重复：${duplicated.id}`, { ruleId: duplicated.id });
  }
  const externalScanners = configuration.modules.flatMap((module) => module.scanners ?? []);
  const duplicatedScanner = externalScanners.find((scanner, index) => externalScanners.findIndex((candidate) => candidate.id === scanner.id) !== index);
  if (duplicatedScanner) {
    throw new ModuleResolutionError("DUPLICATE_SCANNER", `外部扫描器 ID 重复：${duplicatedScanner.id}`, { scannerId: duplicatedScanner.id });
  }

  const selectedRules = allRules.filter((rule) => {
    if (matches(rule.id, configuration.rules?.exclude)) return false;
    if (configuration.rules?.include?.length && !matches(rule.id, configuration.rules.include)) return false;
    if (configuration.standards?.length && !rule.references.some((item) => configuration.standards?.includes(item.standard))) return false;
    return true;
  });
  const maxFiles = Math.max(1, Math.trunc(options.maxFiles ?? DEFAULT_MAX_FILES));
  const maxFileBytes = Math.max(1, Math.trunc(options.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES));
  const maxTotalBytes = Math.max(maxFileBytes, Math.trunc(options.maxTotalBytes ?? DEFAULT_MAX_TOTAL_BYTES));
  const maxDepth = Math.max(1, Math.trunc(options.maxDepth ?? DEFAULT_MAX_DEPTH));
  const findings: Finding[] = [];
  const diagnostics: ScanResult["diagnostics"] = [];
  const files: string[] = [];
  const skippedFiles = new Set<string>();
  const failedFiles = new Set<string>();
  const languageStats = new Map<string, { discovered: number; scanned: number; skipped: number; failed: number }>();
  let totalBytes = 0;
  const stages: ScanStage[] = [{ phase: "configuration", status: "succeeded" }, { phase: "discovery", status: "succeeded" }, { phase: "read", status: "succeeded" }, { phase: "rule", status: "succeeded" }, { phase: "external-scanner", status: "succeeded" }];
  const root = await realpath(cwd);
  const discoveredFiles: string[] = [];
  const discoveryOptions = {
    cwd,
    absolute: false as const,
    onlyFiles: true,
    unique: true,
    deep: maxDepth,
    followSymbolicLinks: false,
    ignore: [...DEFAULT_EXCLUDE, ...(options.includeTests ? [] : TEST_EXCLUDE), ...(options.exclude ?? [])],
  };
  const collectDiscovered = async (suppressErrors: boolean): Promise<void> => {
    const discovery = fg.stream(options.include ?? DEFAULT_INCLUDE, { ...discoveryOptions, suppressErrors });
    for await (const entry of discovery as AsyncIterable<string | Buffer>) {
      discoveredFiles.push(String(entry));
      if (discoveredFiles.length > maxFiles) {
        throw new Error(`扫描文件数量超过安全限制（最多 ${maxFiles} 个）`);
      }
    }
  };
  try {
    await collectDiscovered(false);
  } catch (error) {
    const code = errorCode(error);
    if (code !== "EPERM" && code !== "EACCES") throw error;
    diagnostics.push({ code: "DISCOVERY_PERMISSION_DENIED", level: "warning", phase: "discovery", message: `部分目录无法访问，已跳过：${error instanceof Error ? error.message : String(error)}`, recoverable: true, details: { root: cwd, reason: code } });
    const stage = stages.find((item) => item.phase === "discovery");
    if (stage) stage.status = "partial";
    // 权限拒绝不应中断文件发现：抑制错误重新遍历，跳过无权限目录继续收集
    discoveredFiles.length = 0;
    await collectDiscovered(true);
  }
  const trackLanguage = (file: string, kind: "discovered" | "scanned" | "skipped" | "failed"): void => {
    const language = languageFromFile(file);
    const current = languageStats.get(language) ?? { discovered: 0, scanned: 0, skipped: 0, failed: 0 };
    current[kind] += 1;
    languageStats.set(language, current);
  };

  for (const relativePath of discoveredFiles.sort()) {
    trackLanguage(relativePath, "discovered");
    const absolutePath = path.resolve(cwd, relativePath);
    try {
      const linkMetadata = await lstat(absolutePath);
      if (linkMetadata.isSymbolicLink()) {
        skippedFiles.add(relativePath);
        trackLanguage(relativePath, "skipped");
        diagnostics.push({ code: "SYMLINK_SKIPPED", level: "warning", phase: "discovery", message: `已跳过符号链接：${relativePath}`, recoverable: true, details: { file: relativePath } });
        continue;
      }
      const realFile = await realpath(absolutePath);
      if (!isWithin(root, realFile)) {
        skippedFiles.add(relativePath);
        trackLanguage(relativePath, "skipped");
        diagnostics.push({ code: "PATH_ESCAPE_BLOCKED", level: "warning", phase: "discovery", message: `已阻止超出扫描根目录的文件：${relativePath}`, recoverable: true, details: { file: relativePath } });
        continue;
      }
      const metadata = await stat(realFile);
      if (!metadata.isFile()) continue;
      if (metadata.size > maxFileBytes) {
        skippedFiles.add(relativePath);
        trackLanguage(relativePath, "skipped");
        diagnostics.push({ code: "FILE_TOO_LARGE", level: "warning", phase: "read", message: `文件超过 ${maxFileBytes} 字节安全限制：${relativePath}`, recoverable: true, details: { file: relativePath, bytes: metadata.size } });
        continue;
      }
      if (totalBytes + metadata.size > maxTotalBytes) {
        throw new Error(`扫描文件总大小超过安全限制（最多 ${maxTotalBytes} 字节）`);
      }
      const data = await readFile(realFile);
      if (data.subarray(0, Math.min(data.length, 8192)).includes(0)) {
        skippedFiles.add(relativePath);
        trackLanguage(relativePath, "skipped");
        diagnostics.push({ code: "BINARY_FILE_SKIPPED", level: "warning", phase: "read", message: `已跳过疑似二进制文件：${relativePath}`, recoverable: true, details: { file: relativePath } });
        continue;
      }
      const source = data.toString("utf8");
      totalBytes += metadata.size;
      files.push(relativePath);
      trackLanguage(relativePath, "scanned");
      const context = toContext(cwd, relativePath, source);
      for (const rule of selectedRules) {
        if (!rule.supports(context)) continue;
        try {
          const ruleFindings = await rule.scan(context);
          findings.push(...ruleFindings);
        } catch (error) {
          diagnostics.push({ code: "RULE_SCAN_FAILED", level: "error", phase: "rule", message: `规则执行失败：${rule.id}（${relativePath}）`, ruleId: rule.id, recoverable: true, details: { file: relativePath, reason: error instanceof Error ? error.name : "UnknownError" } });
        }
      }
    } catch (error) {
      if (error instanceof Error && error.message.startsWith("扫描文件总大小超过安全限制")) throw error;
      failedFiles.add(relativePath);
      trackLanguage(relativePath, "failed");
      diagnostics.push({ code: "FILE_READ_FAILED", level: "warning", phase: "read", message: `无法安全读取文件：${relativePath}`, recoverable: true, details: { file: relativePath, reason: error instanceof Error ? error.name : "UnknownError" } });
    }
  }

  const externalRuleIds: string[] = [];
  const externalScannerStatuses = new Map<string, "succeeded" | "partial" | "failed">();
  let externalScannerIncomplete = false;
  for (const externalScanner of externalScanners) {
    try {
      const result = await externalScanner.scan({ cwd, files: files.map((file) => file.replaceAll("\\", "/")) });
      externalScannerStatuses.set(externalScanner.id, result.status ?? "succeeded");
      findings.push(...result.findings);
      externalRuleIds.push(...(result.executedRules ?? result.findings.map((finding) => finding.ruleId)));
      const externalDiagnostics = result.diagnostics ?? [];
      diagnostics.push(...externalDiagnostics);
      if (result.status === "failed" || result.status === "partial" || externalDiagnostics.some((item) => item.level === "error")) {
        externalScannerIncomplete = true;
        const stage = stages.find((item) => item.phase === "external-scanner");
        if (stage) stage.status = "partial";
      }
    } catch (error) {
      diagnostics.push({
        code: "EXTERNAL_SCANNER_FAILED",
        level: "error",
        phase: "external-scanner",
        message: error instanceof Error ? error.message : String(error),
        scannerId: externalScanner.id,
        recoverable: true,
      });
      externalScannerStatuses.set(externalScanner.id, "failed");
      const stage = stages.find((item) => item.phase === "external-scanner");
      if (stage) stage.status = "partial";
    }
  }

  for (const stage of stages) {
    if (stage.phase === "read" && failedFiles.size > 0) stage.status = "partial";
    if (stage.phase === "rule" && diagnostics.some((item) => item.phase === "rule" && item.level === "error")) stage.status = "partial";
  }

  const overrides = configuration.rules?.severityOverrides;
  if (overrides) {
    for (let index = 0; index < findings.length; index += 1) {
      const finding = findings[index];
      if (!finding) continue;
      const override = overrides[finding.ruleId];
      if (override) findings[index] = { ...finding, severity: override };
    }
  }
  findings.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line || a.column - b.column || a.ruleId.localeCompare(b.ruleId));
  const finishedAtIso = new Date().toISOString();
  const coverage: ScanCoverage = {
    discoveredFiles: discoveredFiles.length,
    scannedFiles: files.length,
    skippedFiles: skippedFiles.size,
    failedFiles: failedFiles.size,
    scannedBytes: totalBytes,
    byLanguage: Object.fromEntries([...languageStats.entries()].sort(([a], [b]) => a.localeCompare(b))),
  };
  const modules: ScanModuleReport[] = configuration.modules.map((module) => {
    const scannerIds = (module.scanners ?? []).map((scanner) => scanner.id);
    const moduleDiagnostics = diagnostics.filter((item) => (item.scannerId && scannerIds.includes(item.scannerId)) || (item.phase === "rule" && item.ruleId && module.rules.some((rule) => rule.id === item.ruleId)));
    const scannerStatuses = scannerIds.map((id) => externalScannerStatuses.get(id)).filter((status): status is "succeeded" | "partial" | "failed" => Boolean(status));
    const moduleStatus = moduleDiagnostics.some((item) => item.level === "error") || scannerStatuses.includes("failed") ? "failed" : moduleDiagnostics.length || scannerStatuses.includes("partial") ? "partial" : "succeeded";
    return {
      id: module.id,
      version: module.version,
      status: moduleStatus,
      rules: module.rules.filter((rule) => selectedRules.includes(rule)).map((rule) => rule.id).sort(),
      externalScanners: scannerIds.sort(),
    };
  });
  return {
    schemaVersion: "0.4",
    scanner: { name: "lego-security-scanner", version: "0.3.0" },
    scannedFiles: files.length,
    executedRules: [...new Set([...selectedRules.map((rule) => rule.id), ...externalRuleIds])].sort(),
    findings,
    summary: summarize(findings),
    durationMs: Math.round(performance.now() - startedAt),
    status: diagnostics.some((item) => item.level === "error") || externalScannerIncomplete || failedFiles.size > 0 || stages.some((stage) => stage.status === "partial") ? "partial" : "succeeded",
    diagnostics,
    metadata: {
      target: cwd,
      startedAt: startedAtIso,
      finishedAt: finishedAtIso,
      configuration: {
        include: [...(options.include ?? DEFAULT_INCLUDE)],
        exclude: [...DEFAULT_EXCLUDE, ...(options.includeTests ? [] : TEST_EXCLUDE), ...(options.exclude ?? [])],
        includeTests: options.includeTests ?? false,
        standards: [...(configuration.standards ?? [])],
      },
    },
    coverage,
    scannedFileList: files,
    stages,
    modules,
  };
}

export interface MultiScanOptions extends Omit<ScanOptions, "cwd"> {
  roots: readonly string[];
}

function combineStatus(results: readonly ScanResult[]): ScanResult["status"] {
  return results.some((result) => result.status === "failed") ? "failed" : results.some((result) => result.status === "partial") ? "partial" : "succeeded";
}

export function mergeScanResults(roots: readonly string[], results: readonly ScanResult[]): ScanResult {
  if (!roots.length || roots.length !== results.length) throw new Error("扫描根目录与扫描结果数量不一致");
  const findings = results.flatMap((result, index) => {
    const root = roots[index]!;
    return result.findings.map((finding) => ({ ...finding, root }));
  });
  const coverage = results.reduce<ScanCoverage>((total, result) => {
    const current = result.coverage;
    if (!current) return total;
    total.discoveredFiles += current.discoveredFiles;
    total.scannedFiles += current.scannedFiles;
    total.skippedFiles += current.skippedFiles;
    total.failedFiles += current.failedFiles;
    total.scannedBytes += current.scannedBytes;
    for (const [language, stats] of Object.entries(current.byLanguage ?? {})) {
      const existing = total.byLanguage![language] ?? { discovered: 0, scanned: 0, skipped: 0, failed: 0 };
      total.byLanguage![language] = { discovered: existing.discovered + stats.discovered, scanned: existing.scanned + stats.scanned, skipped: existing.skipped + stats.skipped, failed: existing.failed + stats.failed };
    }
    return total;
  }, { discoveredFiles: 0, scannedFiles: 0, skippedFiles: 0, failedFiles: 0, scannedBytes: 0, byLanguage: {} });
  const modules = [...new Map(results.flatMap((result) => result.modules ?? []).map((module) => [module.id, module])).values()];
  const first = results[0]!;
  return {
    schemaVersion: first.schemaVersion,
    scanner: first.scanner,
    scannedFiles: results.reduce((total, result) => total + result.scannedFiles, 0),
    executedRules: [...new Set(results.flatMap((result) => result.executedRules))].sort(),
    findings,
    summary: summarize(findings),
    durationMs: results.reduce((total, result) => total + result.durationMs, 0),
    status: combineStatus(results),
    diagnostics: results.flatMap((result, index) => result.diagnostics.map((diagnostic) => ({ ...diagnostic, details: { ...diagnostic.details, root: roots[index] } }))),
    ...(first.metadata ? { metadata: { ...first.metadata, target: roots.join(", "), roots: [...roots] } } : {}),
    coverage,
    scannedFileList: results.flatMap((result, index) => (result.scannedFileList ?? []).map((file) => (roots.length > 1 ? `${roots[index]}::${file}` : file))),
    stages: results.flatMap((result) => result.stages ?? []),
    modules,
  };
}

export async function scanRoots(options: MultiScanOptions): Promise<ScanResult> {
  const results: ScanResult[] = [];
  for (const root of options.roots) results.push(await scan({ ...options, cwd: root }));
  return mergeScanResults(options.roots, results);
}
