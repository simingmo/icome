import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { Finding, ScanResult, Severity } from "../src/contracts.js";
import { diffScanResults } from "../src/report-diff.js";
import { hasFindingAtOrAbove, renderConsole, renderJson } from "../src/reporters.js";
import { detectProjectLanguages, includePatternsForLanguages, languageFromFile } from "../src/scan-coverage.js";
import { attachDispositions, validateDispositions } from "../src/triage.js";

const directories: string[] = [];
afterEach(async () => Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true }))));

function finding(fingerprint: string, severity: Severity = "high"): Finding {
  return { ruleId: "security/test", message: "issue", severity, confidence: "high", category: "security", file: "src/app.ts", line: 2, column: 3, evidence: "sample", suggestion: "fix", references: [], fingerprint };
}
function result(findings: Finding[]): ScanResult {
  return { schemaVersion: "0.3", scanner: { name: "lego-security-scanner", version: "0.3.0" }, scannedFiles: 1, executedRules: ["security/test"], findings, summary: { bySeverity: { info: 0, low: 0, medium: 0, high: 0, critical: 0 }, byCategory: {}, byRule: {}, byStandard: {} }, durationMs: 10, status: "succeeded", diagnostics: [] };
}

describe("报告和差异", () => {
  it("按严重度阈值判断退出条件", () => {
    const findings = [finding("a", "medium")];
    expect(hasFindingAtOrAbove(findings, "low")).toBe(true);
    expect(hasFindingAtOrAbove(findings, "medium")).toBe(true);
    expect(hasFindingAtOrAbove(findings, "high")).toBe(false);
    expect(hasFindingAtOrAbove([], "info")).toBe(false);
  });

  it("生成可读控制台报告和可回读 JSON", () => {
    const scanResult = result([finding("a")]);
    expect(renderConsole(scanResult)).toContain("src/app.ts:2:3");
    expect(renderConsole(scanResult)).toContain("扫描 1 个文件");
    expect(JSON.parse(renderJson(scanResult))).toEqual(scanResult);
  });

  it("正确划分新增、修复和未变化问题", () => {
    const diff = diffScanResults(result([finding("fixed"), finding("same")]), result([finding("same"), finding("added")]));
    expect(diff.fixed.map((item) => item.fingerprint)).toEqual(["fixed"]);
    expect(diff.unchanged.map((item) => item.fingerprint)).toEqual(["same"]);
    expect(diff.added.map((item) => item.fingerprint)).toEqual(["added"]);
    expect(diff).toMatchObject({ changed: [], dispositionChanged: [], previousStatus: "succeeded", currentStatus: "succeeded" });
  });

  it("变化问题不应同时归入未变化", () => {
    const previous = result([finding("changed", "medium")]);
    const current = result([finding("changed", "high")]);
    const diff = diffScanResults(previous, current);
    expect(diff.changed.map((item) => item.current.fingerprint)).toEqual(["changed"]);
    expect(diff.unchanged).toEqual([]);
  });

  it("校验并关联漏洞处置状态", () => {
    const dispositions = validateDispositions([{ fingerprint: "a", status: "accepted-risk", note: "临时缓解", updatedAt: "2026-10-02T00:00:00.000Z", updatedBy: "security-team" }]);
    const attached = attachDispositions(result([finding("a"), finding("b")]), dispositions);
    expect(attached.dispositions).toEqual(dispositions);
    expect(attached.triage).toMatchObject({ total: 1, byStatus: { "accepted-risk": 1 } });
  });

  it("报告差异包含处置变化", () => {
    const previous = attachDispositions(result([finding("a")]), validateDispositions([{ fingerprint: "a", status: "open", updatedAt: "2026-10-01T00:00:00.000Z" }]));
    const current = attachDispositions(result([finding("a")]), validateDispositions([{ fingerprint: "a", status: "fixed", updatedAt: "2026-10-02T00:00:00.000Z" }]));
    expect(diffScanResults(previous, current).dispositionChanged).toEqual([{ fingerprint: "a", previous: "open", current: "fixed" }]);
  });
});

describe("扫描语言和范围", () => {
  it("根据项目清单识别多语言", async () => {
    const cwd = await mkdtemp(path.join(tmpdir(), "lego-language-"));
    directories.push(cwd);
    await writeFile(path.join(cwd, "package.json"), JSON.stringify({ devDependencies: { typescript: "latest" } }), "utf8");
    await writeFile(path.join(cwd, "composer.json"), "{}", "utf8");
    await expect(detectProjectLanguages(cwd)).resolves.toEqual(expect.arrayContaining(["javascript", "typescript", "php"]));
  });

  it("未知项目仍包含配置和锁文件检查范围", () => {
    const include = includePatternsForLanguages(["unknown"]);
    expect(include).toEqual(expect.arrayContaining(["**/.env*", "**/{Dockerfile,Containerfile,package-lock.json,composer.lock}"]));
  });

  it.each([
    ["app.ts", "typescript"], ["app.js", "javascript"], ["app.php", "php"], ["Main.java", "java"],
    ["Program.cs", "csharp"], ["main.cpp", "cpp"], ["app.py", "python"], ["README.md", "unknown"],
  ] as const)("识别文件语言 %s", (file, language) => expect(languageFromFile(file)).toBe(language));
});
