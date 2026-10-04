import { execFile } from "node:child_process";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, it, vi } from "vitest";
import { composerAuditScanner, composerFindings, npmAuditScanner, npmFindings } from "../src/modules/dependency-audit-module.js";
import { gitHistoryScanner, parseGitHistory } from "../src/modules/git-history-module.js";

const execFileAsync = promisify(execFile);
import { osvScanner, packageCoordinates } from "../src/modules/osv-module.js";

const directories: string[] = [];
afterEach(async () => {
  vi.unstubAllGlobals();
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

async function fixture(files: Record<string, unknown>): Promise<string> {
  const cwd = await mkdtemp(path.join(tmpdir(), "lego-audit-"));
  directories.push(cwd);
  await Promise.all(Object.entries(files).map(async ([name, value]) => {
    const target = path.join(cwd, name);
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, typeof value === "string" ? value : JSON.stringify(value), "utf8");
  }));
  return cwd;
}

describe("依赖审计解析", () => {
  it("解析 npm 漏洞、严重度和修复建议", () => {
    const findings = npmFindings({ vulnerabilities: {
      lodash: { severity: "critical", range: "<4.17.21", fixAvailable: true, via: [{ title: "Prototype Pollution" }] },
      ignored: null,
    } });
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: "dependency/npm-audit", severity: "critical", file: "package-lock.json" });
    expect(findings[0]?.message).toContain("Prototype Pollution");
    expect(findings[0]?.suggestion).toContain("npm audit fix");
  });

  it("同一 GHSA 公告跨多个 npm 包合并为一条，并归集传递依赖", () => {
    const findings = npmFindings({ vulnerabilities: {
      vitest: { severity: "high", range: "<2.1.9", fixAvailable: true, via: [{ title: "Sandbox escape", url: "https://github.com/advisories/GHSA-82fw-gwwq-j7x9" }] },
      "@vitest/mocker": { severity: "high", range: "<2.1.9", fixAvailable: true, via: [{ title: "Sandbox escape", url: "https://github.com/advisories/GHSA-82fw-gwwq-j7x9" }] },
      "@vitest/spy": { severity: "high", range: "<2.1.9", fixAvailable: false, via: ["@vitest/mocker"] },
    } });
    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe("dependency/npm-audit/GHSA-82FW-GWWQ-J7X9");
    expect(findings[0]?.message).toContain("vitest");
    expect(findings[0]?.message).toContain("@vitest/mocker");
    expect(findings[0]?.message).toContain("@vitest/spy");
    expect(findings[0]?.severity).toBe("high");
    expect(findings[0]?.suggestion).toContain("npm audit fix");
  });

  it("无 GHSA/CVE 公告 id 时仍按包逐条，保持既有输出", () => {
    const findings = npmFindings({ vulnerabilities: {
      lodash: { severity: "critical", range: "<4.17.21", fixAvailable: true, via: [{ title: "Prototype Pollution" }] },
    } });
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: "dependency/npm-audit", severity: "critical", file: "package-lock.json" });
    expect(findings[0]?.message).toContain("Prototype Pollution");
  });

  it("兼容 Composer 多公告和缺失严重度", () => {
    const findings = composerFindings({ advisories: { "vendor/pkg": [
      { advisoryId: "CVE-1", title: "Issue", affectedVersions: "<2", severity: "high" },
      { title: "Unknown severity" },
    ] } });
    expect(findings.map((finding) => finding.ruleId)).toEqual([
      "dependency/composer-audit/CVE-1",
      "dependency/composer-audit/advisory",
    ]);
    expect(findings.map((finding) => finding.severity)).toEqual(["high", "medium"]);
  });

  it("锁文件不存在时跳过外部命令", async () => {
    const cwd = await fixture({});
    await expect(npmAuditScanner.scan({ cwd, files: [] })).resolves.toEqual({ findings: [], executedRules: [] });
    await expect(composerAuditScanner.scan({ cwd, files: [] })).resolves.toEqual({ findings: [], executedRules: [] });
  });
});

describe("OSV 审计", () => {
  it("从 npm 和 Composer 锁文件提取坐标", async () => {
    const cwd = await fixture({
      "package-lock.json": { packages: { "": { name: "root", version: "1.0.0" }, "node_modules/@scope/pkg": { version: "2.1.0" } } },
      "composer.lock": { packages: [{ name: "vendor/prod", version: "v1.2.3" }], "packages-dev": [{ name: "vendor/dev", version: "2.0.0" }] },
    });
    await expect(packageCoordinates(cwd)).resolves.toEqual([
      { ecosystem: "npm", name: "@scope/pkg", version: "2.1.0", file: "package-lock.json" },
      { ecosystem: "Packagist", name: "vendor/prod", version: "1.2.3", file: "composer.lock" },
      { ecosystem: "Packagist", name: "vendor/dev", version: "2.0.0", file: "composer.lock" },
    ]);
  });

  it("兼容 npm lockfile v1 的依赖坐标", async () => {
    const cwd = await fixture({ "package-lock.json": { lockfileVersion: 1, dependencies: { lodash: { version: "4.17.20", dependencies: { minimist: { version: "1.2.5" } } } } } });
    await expect(packageCoordinates(cwd)).resolves.toEqual([
      { ecosystem: "npm", name: "lodash", version: "4.17.20", file: "package-lock.json" },
      { ecosystem: "npm", name: "minimist", version: "1.2.5", file: "package-lock.json" },
    ]);
  });

  it("发送批量查询并映射漏洞", async () => {
    const cwd = await fixture({ "package-lock.json": { packages: { "node_modules/pkg": { version: "1.0.0" } } } });
    const fetchMock = vi.fn(async (_input: string | URL | Request, _init?: RequestInit) => new Response(JSON.stringify({ results: [{ vulns: [{ id: "OSV-1", summary: "Known issue", database_specific: { severity: "HIGH" } }] }] }), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const result = await osvScanner.scan({ cwd, files: [] });
    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe("https://api.osv.dev/v1/querybatch");
    expect(JSON.parse(String(init?.body))).toEqual({ queries: [{ package: { ecosystem: "npm", name: "pkg" }, version: "1.0.0" }] });
    expect(result.findings[0]).toMatchObject({ ruleId: "dependency/osv/OSV-1", severity: "high", evidence: "pkg@1.0.0" });
  });

  it("网络失败时明确标记审计失败，避免误判为零漏洞", async () => {
    const cwd = await fixture({ "package-lock.json": { packages: { "node_modules/pkg": { version: "1.0.0" } } } });
    vi.stubGlobal("fetch", vi.fn(async () => { throw new Error("offline"); }));
    const result = await osvScanner.scan({ cwd, files: [] });
    expect(result).toMatchObject({ findings: [], executedRules: ["dependency/osv"], status: "failed" });
    expect(result.diagnostics).toEqual([expect.objectContaining({ code: "OSV_REQUEST_FAILED", level: "error", scannerId: "osv" })]);
  });
});

describe("Git 历史解析", () => {
  it("定位文件和提交并始终脱敏", () => {
    const findings = parseGitHistory([
      "commit:1234567890abcdef",
      "+++ b/config/app.env",
      "+API_TOKEN=abcdefghijklmnop",
      "+const safe = true;",
      "commit:fedcba0987654321",
      "+++ b/key.pem",
      "+-----BEGIN PRIVATE KEY-----",
    ].join("\n"));
    expect(findings).toHaveLength(2);
    expect(findings[0]).toMatchObject({ file: "config/app.env", severity: "critical", evidence: "[REDACTED] commit 1234567890ab" });
    expect(findings[1]?.evidence).not.toContain("PRIVATE KEY");
  });

  it("在凭据已从工作区删除后仍扫描到历史提交", async () => {
    const cwd = await fixture({});
    try {
      await execFileAsync("git", ["init"], { cwd });
    } catch {
      return;
    }
    await execFileAsync("git", ["config", "user.email", "scanner@example.test"], { cwd });
    await execFileAsync("git", ["config", "user.name", "Scanner Test"], { cwd });
    await writeFile(path.join(cwd, "secret.env"), "API_TOKEN=abcdefghijklmnop\n", "utf8");
    await execFileAsync("git", ["add", "secret.env"], { cwd });
    await execFileAsync("git", ["commit", "-m", "add secret"], { cwd });
    await writeFile(path.join(cwd, "secret.env"), "SAFE=true\n", "utf8");
    await execFileAsync("git", ["add", "secret.env"], { cwd });
    await execFileAsync("git", ["commit", "-m", "remove secret"], { cwd });

    const result = await gitHistoryScanner.scan({ cwd, files: ["secret.env"] });
    expect(result.findings).toEqual([expect.objectContaining({ file: "secret.env", evidence: expect.stringContaining("[REDACTED] commit") })]);
    expect(result.findings[0]?.evidence).not.toContain("abcdefghijklmnop");
  }, 20_000);
});
