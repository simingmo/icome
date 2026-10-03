import { access, mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it, vi } from "vitest";
import AdmZip from "adm-zip";
import type { ScanOptions, ScanResult } from "../src/contracts.js";
import { createPanelServer, resolveScanPath } from "../src/panel.js";

const cleanup: Array<() => Promise<void> | void> = [];
// Windows 上报告文件句柄释放有延迟，需重试删除避免 ENOTEMPTY 偶发失败
const rmTree = (dir: string): Promise<void> => rm(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
afterEach(async () => {
  vi.restoreAllMocks();
  await Promise.all(cleanup.splice(0).map(async (task) => task()));
});

function emptyResult(status: ScanResult["status"] = "succeeded"): ScanResult {
  return {
    schemaVersion: "0.3",
    scanner: { name: "lego-security-scanner", version: "0.3.0" },
    scannedFiles: 0,
    executedRules: [],
    findings: [],
    summary: { bySeverity: { info: 0, low: 0, medium: 0, high: 0, critical: 0 }, byCategory: {}, byRule: {}, byStandard: {} },
    durationMs: 1,
    status,
    diagnostics: status === "failed" ? [{ code: "TEST_FAILURE", level: "error", phase: "external-scanner", message: "simulated failure", recoverable: false }] : [],
  };
}

describe("Panel HTTP 黑盒", () => {
  it("保留 Windows 跨盘和 UNC 绝对路径", () => {
    expect(resolveScanPath("E:\\兴趣爱好", "C:\\panel")).toBe("E:\\兴趣爱好");
    expect(resolveScanPath('  "F:\\temp"  ', "C:\\panel")).toBe("F:\\temp");
    expect(resolveScanPath("\\\\server\\share\\project", "C:\\panel")).toBe("\\\\server\\share\\project");
  });

  it("默认拒绝允许根目录之外的扫描目标", async () => {
    const panelCwd = await mkdtemp(path.join(tmpdir(), "lego-panel-root-"));
    const targetCwd = await mkdtemp(path.join(tmpdir(), "lego-panel-target-"));
    await writeFile(path.join(targetCwd, "app.ts"), "const safe = true;", "utf8");
    cleanup.push(() => rmTree(panelCwd));
    cleanup.push(() => rmTree(targetCwd));
    const { server } = createPanelServer({ cwd: panelCwd, reportsDir: path.join(panelCwd, "reports"), scanRunner: vi.fn(async () => emptyResult()) });
    await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
    cleanup.push(() => new Promise<void>((resolve) => server.close(() => resolve())));
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const response = await fetch(`${base}/api/scans`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ cwd: targetCwd }) });
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: expect.stringContaining("扫描目标超出允许的本地目录范围") });
  });

  it("allowAll 时允许扫描本机任意路径", async () => {
    const panelCwd = await mkdtemp(path.join(tmpdir(), "lego-panel-root-"));
    const targetCwd = await mkdtemp(path.join(tmpdir(), "lego-panel-target-"));
    await writeFile(path.join(targetCwd, "app.ts"), "eval(userInput);", "utf8");
    cleanup.push(() => rmTree(panelCwd));
    cleanup.push(() => rmTree(targetCwd));
    const scanRunner = vi.fn(async () => emptyResult());
    const { server } = createPanelServer({ cwd: panelCwd, allowAll: true, reportsDir: path.join(panelCwd, "reports"), scanRunner });
    await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
    cleanup.push(() => new Promise<void>((resolve) => server.close(() => resolve())));
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const response = await fetch(`${base}/api/scans`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ cwd: targetCwd }) });
    expect(response.status).toBe(202);
    for (let attempt = 0; attempt < 100 && scanRunner.mock.calls.length === 0; attempt += 1) await new Promise((resolve) => setTimeout(resolve, 10));
    expect(scanRunner).toHaveBeenCalledWith(expect.objectContaining({ cwd: await (await import("node:fs/promises")).realpath(targetCwd) }));
  });

  it("允许显式配置额外根目录，但阻止其外部的链接逃逸", async () => {
    const panelCwd = await mkdtemp(path.join(tmpdir(), "lego-panel-root-"));
    const allowedCwd = await mkdtemp(path.join(tmpdir(), "lego-panel-allowed-"));
    const outsideCwd = await mkdtemp(path.join(tmpdir(), "lego-panel-outside-"));
    await writeFile(path.join(allowedCwd, "app.ts"), "const safe = true;", "utf8");
    await writeFile(path.join(outsideCwd, "secret.ts"), "eval(secret);", "utf8");
    cleanup.push(() => rmTree(panelCwd));
    cleanup.push(() => rmTree(allowedCwd));
    cleanup.push(() => rmTree(outsideCwd));
    try { await symlink(outsideCwd, path.join(allowedCwd, "linked"), "junction"); } catch (error) { if ((error as NodeJS.ErrnoException).code === "EPERM") return; throw error; }
    const scanRunner = vi.fn(async () => emptyResult());
    const { server } = createPanelServer({ cwd: panelCwd, allowedRoots: [allowedCwd], reportsDir: path.join(panelCwd, "reports"), scanRunner });
    await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
    cleanup.push(() => new Promise<void>((resolve) => server.close(() => resolve())));
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const escaped = await fetch(`${base}/api/scans`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ cwd: path.join(allowedCwd, "linked") }) });
    expect(escaped.status).toBe(400);
    expect(await escaped.json()).toMatchObject({ error: expect.stringContaining("扫描目标超出允许的本地目录范围") });
    const response = await fetch(`${base}/api/scans`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ cwd: allowedCwd }) });
    expect(response.status).toBe(202);
    for (let attempt = 0; attempt < 100 && scanRunner.mock.calls.length === 0; attempt += 1) await new Promise((resolve) => setTimeout(resolve, 10));
    expect(scanRunner).toHaveBeenCalledWith(expect.objectContaining({ cwd: await (await import("node:fs/promises")).realpath(allowedCwd) }));
  });

  it("使用访问令牌保护全部 API 并脱敏任务结果", async () => {
    const cwd = await mkdtemp(path.join(tmpdir(), "lego-panel-auth-"));
    await writeFile(path.join(cwd, "app.ts"), "const secret = true;", "utf8");
    cleanup.push(() => rmTree(cwd));
    const token = "test-panel-token";
    const scanRunner = vi.fn(async () => ({ ...emptyResult(), scannedFiles: 1, findings: [{ ruleId: "test/secret", message: "问题", severity: "medium" as const, confidence: "high" as const, category: "security" as const, file: "app.ts", line: 1, column: 1, evidence: "private-value", suggestion: "修复", references: [], fingerprint: "secret" }] }));
    const { server } = createPanelServer({ cwd, authToken: token, reportsDir: path.join(cwd, "reports"), scanRunner });
    await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
    cleanup.push(() => new Promise<void>((resolve) => server.close(() => resolve())));
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    expect((await fetch(`${base}/api/config`)).status).toBe(401);
    expect((await fetch(`${base}/api/config`, { headers: { authorization: "Bearer wrong" } })).status).toBe(401);
    const config = await fetch(`${base}/api/config`, { headers: { authorization: `Bearer ${token}` } });
    expect(await config.json()).toEqual({ currentDirectory: path.resolve(cwd) });
    const created = await fetch(`${base}/api/scans`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${token}` }, body: JSON.stringify({ cwd }) });
    const createdJob = await created.json() as { id: string };
    expect(JSON.stringify(createdJob)).not.toContain(cwd);
    let job: Record<string, unknown> = { status: "queued" };
    for (let attempt = 0; attempt < 100 && ["queued", "running"].includes(String(job.status)); attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 10));
      job = await (await fetch(`${base}/api/scans/${createdJob.id}`, { headers: { authorization: `Bearer ${token}` } })).json() as Record<string, unknown>;
    }
    expect(JSON.stringify(job)).not.toContain(cwd);
    expect(JSON.stringify(job)).not.toContain("private-value");
    expect(JSON.stringify(job)).toContain("[REDACTED]");
  });

  it("创建任务、查询状态并聚合仪表盘", async () => {
    const cwd = await mkdtemp(path.join(tmpdir(), "lego-panel-"));
    const reportsDir = path.join(cwd, "reports");
    await writeFile(path.join(cwd, "package.json"), "{}", "utf8");
    await writeFile(path.join(cwd, "app.ts"), "eval(userInput);", "utf8");
    cleanup.push(() => rmTree(cwd));

    const { server } = createPanelServer({ cwd, reportsDir });
    await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
    cleanup.push(() => new Promise<void>((resolve) => server.close(() => resolve())));
    const port = (server.address() as AddressInfo).port;
    const base = `http://127.0.0.1:${port}`;

    const page = await fetch(base);
    expect(page.status).toBe(200);
    const pageHtml = await page.text();
    expect(pageHtml).toContain("LEGO Security Panel");
    expect(pageHtml).toContain("可扫描目录、单个源码或配置文件");
    expect(pageHtml).toContain("ZIP、APK、JAR");
    expect(pageHtml).toContain("恢复当前目录");
    expect(pageHtml).toContain("扫描失败");

    const config = await (await fetch(`${base}/api/config`)).json() as { currentDirectory: string };
    expect(config.currentDirectory).toBe(path.resolve(cwd));

    const tools = await (await fetch(`${base}/api/tools`)).json() as { tools: Array<{ id: string; available: boolean }> };
    expect(tools.tools.find((tool) => tool.id === "seay")).toMatchObject({ available: false });

    const rejected = await fetch(`${base}/api/scans`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ cwd, tools: ["seay"] }) });
    expect(rejected.status).toBe(400);
    expect(await rejected.json()).toMatchObject({ error: expect.stringContaining("Seay") });

    const created = await fetch(`${base}/api/scans`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ cwd, tools: [] }) });
    expect(created.status).toBe(202);
    const job = await created.json() as { id: string };

    let status = "queued";
    for (let attempt = 0; attempt < 100 && (status === "queued" || status === "running"); attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 25));
      const response = await fetch(`${base}/api/scans/${job.id}`);
      status = ((await response.json()) as { status: string }).status;
    }
    expect(status).toBe("succeeded");

    const dashboard = await (await fetch(`${base}/api/dashboard?scope=latest`)).json() as {
      jobs: number;
      findings: number;
      high: number;
      reports: Array<{ reportName: string; scanPath: string; filePath: string; reportPath: string }>;
    };
    expect(dashboard.jobs).toBe(1);
    expect(dashboard.findings).toBeGreaterThanOrEqual(1);
    expect(dashboard.high).toBeGreaterThanOrEqual(1);
    expect(dashboard.reports[0]?.reportName).toBe(`${job.id}.result.json`);
    expect(dashboard.reports[0]?.scanPath?.toLowerCase()).toBe(cwd.toLowerCase());
    expect(dashboard.reports[0]?.filePath).toContain("app.ts:1:");
    expect(dashboard.reports[0]?.reportPath).toBe(`${job.id}.result.json`);
    expect(dashboard.reports[0]?.filePath).not.toContain(cwd);

    const missing = await fetch(`${base}/api/scans/missing`);
    expect(missing.status).toBe(404);
  });

  it("限制并发并让后续任务保持排队", async () => {
    const cwd = await mkdtemp(path.join(tmpdir(), "lego-panel-queue-"));
    await writeFile(path.join(cwd, "app.ts"), "const safe = true;", "utf8");
    cleanup.push(() => rmTree(cwd));
    let releaseFirst!: () => void;
    const first = new Promise<void>((resolve) => { releaseFirst = resolve; });
    let calls = 0;
    const scanRunner = vi.fn(async () => {
      calls += 1;
      if (calls === 1) await first;
      return emptyResult();
    });
    const { server } = createPanelServer({ cwd, reportsDir: path.join(cwd, "reports"), maxConcurrency: 1, scanRunner });
    await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
    cleanup.push(() => new Promise<void>((resolve) => server.close(() => resolve())));
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const create = async () => (await (await fetch(`${base}/api/scans`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ cwd }) })).json()) as { id: string };
    const job1 = await create();
    const job2 = await create();
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect((await (await fetch(`${base}/api/scans/${job1.id}`)).json() as { status: string }).status).toBe("running");
    expect((await (await fetch(`${base}/api/scans/${job2.id}`)).json() as { status: string }).status).toBe("queued");
    expect(scanRunner).toHaveBeenCalledTimes(1);
    const scanOptions = (scanRunner.mock.calls as unknown as Array<[{ exclude?: string[] }]>)[0]?.[0];
    expect(scanOptions?.exclude).toEqual(["**/.scan-reports/**", "**/coverage/**", "**/test-results*.json", "**/tools/**"]);
    releaseFirst();
    for (let attempt = 0; attempt < 100 && scanRunner.mock.calls.length < 2; attempt += 1) await new Promise((resolve) => setTimeout(resolve, 10));
    expect(scanRunner).toHaveBeenCalledTimes(2);
  });

  it("没有可检查文件时明确提示且不生成结果报告", async () => {
    const cwd = await mkdtemp(path.join(tmpdir(), "lego-panel-clean-"));
    const reportsDir = path.join(cwd, "reports");
    await writeFile(path.join(cwd, "app.ts"), "const safe = true;", "utf8");
    cleanup.push(() => rmTree(cwd));
    const { server } = createPanelServer({ cwd, reportsDir, scanRunner: vi.fn(async () => emptyResult()) });
    await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
    cleanup.push(() => new Promise<void>((resolve) => server.close(() => resolve())));
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const created = await (await fetch(`${base}/api/scans`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ cwd }) })).json() as { id: string };
    let status = "queued";
    for (let attempt = 0; attempt < 100 && ["queued", "running"].includes(status); attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 10));
      status = ((await (await fetch(`${base}/api/scans/${created.id}`)).json()) as { status: string }).status;
    }
    expect(status).toBe("no-files");
    await expect(access(path.join(reportsDir, `${created.id}.result.json`))).rejects.toThrow();
    const dashboard = await (await fetch(`${base}/api/dashboard?scope=latest`)).json() as { reports: Array<{ reportName: string; reportPath: string; error: string; status: string }> };
    expect(dashboard.reports[0]).toMatchObject({ reportName: "未生成（没有可检查的文件）", reportPath: "", error: "没有找到受支持的源码或配置文件，实际检查 0 个文件", status: "no-files" });
  });

  it("包含测试代码时保持真实任务选项，并由服务端一致筛选报告", async () => {
    const cwd = await mkdtemp(path.join(tmpdir(), "lego-panel-filter-"));
    await writeFile(path.join(cwd, "app.ts"), "const app = true;", "utf8");
    await mkdir(path.join(cwd, "tests"), { recursive: true });
    await writeFile(path.join(cwd, "tests", "app.test.ts"), "const test = true;", "utf8");
    cleanup.push(() => rmTree(cwd));
    const finding = (file: string, fingerprint: string) => ({ ruleId: "test/finding", message: "测试问题", severity: "high" as const, confidence: "high" as const, category: "security" as const, file, line: 1, column: 1, evidence: "secret", suggestion: "修复", references: [], fingerprint });
    const scanRunner = vi.fn(async (_options: ScanOptions) => ({ ...emptyResult("partial"), scannedFiles: 2, findings: [finding("app.ts", "source"), finding("tests/app.test.ts", "test")] }));
    const { server } = createPanelServer({ cwd, reportsDir: path.join(cwd, "reports"), scanRunner });
    await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
    cleanup.push(() => new Promise<void>((resolve) => server.close(() => resolve())));
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const pageHtml = await (await fetch(base)).text();
    expect(pageHtml).toContain("input[data-tool]:checked");
    const created = await (await fetch(`${base}/api/scans`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ cwd, includeTests: true }) })).json() as { id: string };
    let job: { status: string } = { status: "queued" };
    for (let attempt = 0; attempt < 100 && ["queued", "running"].includes(job.status); attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 10));
      job = await (await fetch(`${base}/api/scans/${created.id}`)).json() as typeof job;
    }
    expect(job.status).toBe("partial");
    expect(scanRunner.mock.calls[0]?.[0]).toMatchObject({ includeTests: true });
    const testDashboard = await (await fetch(`${base}/api/dashboard?scope=latest&type=test`)).json() as { findings: number; reports: Array<{ filePath: string; status: string }> };
    expect(testDashboard.findings).toBe(1);
    expect(testDashboard.reports).toHaveLength(1);
    expect(testDashboard.reports[0]).toMatchObject({ filePath: "tests/app.test.ts:1:1", status: "partial" });
    const sourceDashboard = await (await fetch(`${base}/api/dashboard?scope=latest&type=source`)).json() as { findings: number; reports: Array<{ filePath: string }> };
    expect(sourceDashboard.findings).toBe(1);
    expect(sourceDashboard.reports[0]?.filePath).toBe("app.ts:1:1");
  });

  it("暴露扫描失败状态和错误信息", async () => {
    const cwd = await mkdtemp(path.join(tmpdir(), "lego-panel-failure-"));
    await writeFile(path.join(cwd, "app.ts"), "const safe = true;", "utf8");
    cleanup.push(() => rmTree(cwd));
    const { server } = createPanelServer({ cwd, reportsDir: path.join(cwd, "reports"), scanRunner: vi.fn(async () => emptyResult("failed")) });
    await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
    cleanup.push(() => new Promise<void>((resolve) => server.close(() => resolve())));
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const created = await (await fetch(`${base}/api/scans`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ cwd }) })).json() as { id: string };
    let job: { status: string; error?: string } = { status: "queued" };
    for (let attempt = 0; attempt < 100 && ["queued", "running"].includes(job.status); attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 10));
      job = await (await fetch(`${base}/api/scans/${created.id}`)).json() as typeof job;
    }
    expect(job).toMatchObject({ status: "failed", error: "扫描失败，请查看本地报告" });
    expect(JSON.stringify(job)).not.toContain("simulated failure");
  });
});
