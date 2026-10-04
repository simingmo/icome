import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ScanResult, ScanOptions } from "../src/contracts.js";
import { createPanelServer } from "../src/panel.js";

const cleanup: Array<() => Promise<void> | void> = [];
// Windows 上文件句柄释放有延迟，需重试删除避免 ENOTEMPTY 偶发失败
const rmTree = (dir: string): Promise<void> => rm(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
afterEach(async () => {
  vi.restoreAllMocks();
  await Promise.all(cleanup.splice(0).map(async (task) => task()));
});

function resultWith(fingerprints: string[]): ScanResult {
  return {
    schemaVersion: "0.3",
    scanner: { name: "lego-security-scanner", version: "0.3.0" },
    scannedFiles: fingerprints.length,
    executedRules: [],
    findings: fingerprints.map((fingerprint, index) => ({
      ruleId: `rule/${fingerprint}`,
      message: `问题 ${fingerprint}`,
      severity: "medium",
      confidence: "high",
      category: "security",
      file: "app.ts",
      line: index + 1,
      column: 1,
      evidence: fingerprint,
      suggestion: "请修复。",
      references: [],
      fingerprint,
    })),
    summary: { bySeverity: { info: 0, low: 0, medium: fingerprints.length, high: 0, critical: 0 }, byCategory: {}, byRule: {}, byStandard: {} },
    durationMs: 1,
    status: "succeeded",
    diagnostics: [],
  };
}

async function startPanel(options: Parameters<typeof createPanelServer>[0]) {
  const { server } = createPanelServer(options);
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  cleanup.push(() => new Promise<void>((resolve) => server.close(() => resolve())));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return { server, base };
}

describe("Panel 附加 API", () => {
  it("渲染出的内联脚本语法合法且包含关键函数", async () => {
    const cwd = await mkdtemp(path.join(tmpdir(), "lego-script-"));
    cleanup.push(() => rm(cwd, { recursive: true, force: true }));
    const { base } = await startPanel({ cwd, reportsDir: path.join(cwd, "reports") });
    const html = await (await fetch(base)).text();
    const script = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((match) => match[1]).join("\n;\n");
    expect(script).toContain("function updateTarget()");
    expect(script).toContain("function isTestPath(");
    expect(() => new Function(script)).not.toThrow();
  });

  it("根据允许目录识别项目语言，并拒绝探测范围外目录", async () => {
    const cwd = await mkdtemp(path.join(tmpdir(), "lego-lang-"));
    const outside = await mkdtemp(path.join(tmpdir(), "lego-lang-outside-"));
    cleanup.push(() => rm(cwd, { recursive: true, force: true }));
    cleanup.push(() => rm(outside, { recursive: true, force: true }));
    await writeFile(path.join(cwd, "main.py"), "print('hi')", "utf8");
    await writeFile(path.join(outside, "secret.ts"), "const secret = true;", "utf8");
    const { base } = await startPanel({ cwd, reportsDir: path.join(cwd, "reports") });
    const response = await fetch(`${base}/api/languages?cwd=${encodeURIComponent(cwd)}`);
    const data = await response.json() as { languages: string[]; include: string[] };
    expect(response.status).toBe(200);
    expect(data.languages).toContain("python");
    expect(data.include.some((pattern) => pattern.includes("*.py"))).toBe(true);
    const rejected = await fetch(`${base}/api/languages?cwd=${encodeURIComponent(outside)}`);
    expect(rejected.status).toBe(400);
    expect(await rejected.json()).toMatchObject({ error: expect.stringContaining("扫描目标超出允许的本地目录范围") });
  });

  it("少于两次扫描时差异接口给出提示", async () => {
    const cwd = await mkdtemp(path.join(tmpdir(), "lego-diff-"));
    cleanup.push(() => rm(cwd, { recursive: true, force: true }));
    const { base } = await startPanel({ cwd, reportsDir: path.join(cwd, "reports"), scanRunner: vi.fn(async () => resultWith(["a"])) });
    const data = await (await fetch(`${base}/api/diff`)).json() as { message: string };
    expect(data.message).toContain("两次成功扫描");
  });

  it("dependencyAudit 任务装配依赖漏洞审计积木并回显选项", async () => {
    const cwd = await mkdtemp(path.join(tmpdir(), "lego-dep-audit-"));
    cleanup.push(() => rm(cwd, { recursive: true, force: true }));
    await writeFile(path.join(cwd, "app.ts"), "const safe = true;", "utf8");
    const scanRunner = vi.fn(async (_options: ScanOptions) => resultWith([]));
    const { base } = await startPanel({ cwd, reportsDir: path.join(cwd, "reports"), scanRunner });
    const created = await (await fetch(`${base}/api/scans`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ cwd, dependencyAudit: true }) })).json() as { id: string; dependencyAudit?: boolean };
    expect(created.dependencyAudit).toBe(true);
    let status = "queued";
    for (let attempt = 0; attempt < 100 && ["queued", "running"].includes(status); attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 10));
      status = ((await (await fetch(`${base}/api/scans/${created.id}`)).json()) as { status: string }).status;
    }
    expect(scanRunner).toHaveBeenCalledTimes(1);
    const moduleIds = (scanRunner.mock.calls[0]?.[0] as { moduleIds?: string[] }).moduleIds ?? [];
    expect(moduleIds).toEqual(expect.arrayContaining([
      "@lego-scan/dependency-audit",
      "@lego-scan/osv",
      "@lego-scan/git-history",
    ]));
    // 未开启时不应装配漏洞审计积木
    const plain = await (await fetch(`${base}/api/scans`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ cwd }) })).json() as { id: string; dependencyAudit?: boolean };
    expect(plain.dependencyAudit).toBeUndefined();
  });

  it("对比两次扫描计算新增与修复", async () => {
    const cwd = await mkdtemp(path.join(tmpdir(), "lego-diff-2-"));
    cleanup.push(() => rm(cwd, { recursive: true, force: true }));
    let calls = 0;
    const scanRunner = vi.fn(async () => {
      calls += 1;
      return resultWith(calls === 1 ? ["keep", "removed"] : ["keep"]);
    });
    const { base } = await startPanel({ cwd, reportsDir: path.join(cwd, "reports"), scanRunner });
    const create = async () => (await (await fetch(`${base}/api/scans`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ cwd }) })).json()) as { id: string };
    const wait = async (id: string) => {
      let status = "queued";
      for (let attempt = 0; attempt < 100 && ["queued", "running"].includes(status); attempt += 1) {
        await new Promise((resolve) => setTimeout(resolve, 10));
        status = ((await (await fetch(`${base}/api/scans/${id}`)).json()) as { status: string }).status;
      }
    };
    const first = await create();
    await wait(first.id);
    const second = await create();
    await wait(second.id);
    const diff = await (await fetch(`${base}/api/diff`)).json() as { added: Array<{ fingerprint: string }>; fixed: Array<{ fingerprint: string }>; unchanged: Array<{ fingerprint: string }> };
    expect(diff.added.map((item) => item.fingerprint)).toEqual([]);
    expect(diff.fixed.map((item) => item.fingerprint)).toEqual(["removed"]);
    expect(diff.unchanged.map((item) => item.fingerprint)).toEqual(["keep"]);
  });

  it("浏览器静默恢复输入值后最终扫描目标同步更新", async () => {
    const cwd = await mkdtemp(path.join(tmpdir(), "lego-target-sync-"));
    cleanup.push(() => rm(cwd, { recursive: true, force: true }));
    const { base } = await startPanel({ cwd, reportsDir: path.join(cwd, "reports") });
    const html = await (await fetch(base)).text();
    const script = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((match) => match[1]).join("\n;\n");
    const initialValue = /<input id="cwd" value="([^"]*)"/.exec(html)?.[1] ?? "";
    expect(initialValue).toBe(path.resolve(cwd));

    interface FakeElement { value: string; textContent: string; innerHTML: string; checked: boolean; }
    const elements = new Map<string, FakeElement>();
    const querySelector = (selector: string): FakeElement => {
      const existing = elements.get(selector);
      if (existing) return existing;
      const created: FakeElement = { value: "", textContent: "", innerHTML: "", checked: false };
      elements.set(selector, created);
      return created;
    };
    querySelector("#scope").value = "latest";
    querySelector("#type").value = "all";
    querySelector("#cwd").value = initialValue;
    const documentStub = { querySelector, querySelectorAll: () => [], addEventListener: () => {} };
    const windowStub = { addEventListener: () => {} };
    type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;
    const loadPanel = new Function("document", "window", "fetch", "setInterval", `${script};return { load };`) as (
      document: typeof documentStub,
      window: typeof windowStub,
      fetch: FetchLike,
      setInterval: () => number,
    ) => { load: () => Promise<void> };

    const panel = loadPanel(documentStub, windowStub, (input, init) => fetch(`${base}${input}`, init), () => 0);
    await panel.load();
    expect(querySelector("#target").textContent).toBe(`最终扫描目标：${initialValue}`);

    // 模拟浏览器在页面加载后静默恢复输入值：不派发 input 事件，目标文案也必须跟上
    querySelector("#cwd").value = "D:\\个人\\game";
    await panel.load();
    expect(querySelector("#target").textContent).toBe("最终扫描目标：D:\\个人\\game");
  });
});
