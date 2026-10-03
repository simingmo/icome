import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createCommandScanner, type ExternalScanner } from "../src/external-scanner.js";
import type { ScannerModule } from "../src/contracts.js";
import { scan } from "../src/scanner.js";

const directories: string[] = [];

afterEach(async () => {
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

async function project(): Promise<string> {
  const cwd = await mkdtemp(path.join(tmpdir(), "lego-external-"));
  directories.push(cwd);
  await writeFile(path.join(cwd, "app.php"), "<?php echo $_GET['name'];", "utf8");
  return cwd;
}

function moduleWith(scanner: ExternalScanner): ScannerModule {
  return { id: "@company/external", version: "1.0.0", rules: [], scanners: [scanner] };
}

describe("项目级外部扫描器", () => {
  it("每个项目仅调用一次并合并标准化问题", async () => {
    const cwd = await project();
    const execute = vi.fn<ExternalScanner["scan"]>().mockResolvedValue({
      findings: [{
        ruleId: "rips/sql-injection",
        message: "可能的 SQL 注入",
        severity: "high",
        confidence: "high",
        category: "security",
        file: "app.php",
        line: 1,
        column: 1,
        evidence: "$_GET",
        suggestion: "使用参数化查询",
        references: [],
        fingerprint: "fixture",
      }],
      executedRules: ["rips/sql-injection"],
    });
    const scanner: ExternalScanner = { id: "rips", version: "1.0.0", scan: execute };
    const result = await scan({
      cwd,
      include: ["**/*.php"],
      modules: [moduleWith(scanner)],
      moduleIds: ["@company/external"],
      rules: { severityOverrides: { "rips/sql-injection": "critical" } },
    });
    expect(execute).toHaveBeenCalledTimes(1);
    expect(execute.mock.calls[0]?.[0].files).toEqual(["app.php"]);
    expect(result.executedRules).toEqual(["rips/sql-injection"]);
    expect(result.findings[0]?.severity).toBe("critical");
    expect(result.summary.bySeverity.critical).toBe(1);
  });

  it("拒绝重复外部扫描器 ID", async () => {
    const cwd = await project();
    const scanner: ExternalScanner = { id: "seay", version: "1", async scan() { return { findings: [] }; } };
    const first = moduleWith(scanner);
    const second: ScannerModule = { id: "@company/external-two", version: "1.0.0", rules: [], scanners: [scanner] };
    await expect(scan({ cwd, modules: [first, second], moduleIds: [first.id, second.id] })).rejects.toThrow("外部扫描器 ID 重复");
  });

  it.each([
    ["命令缺失", { command: path.join(tmpdir(), "missing-lego-scanner"), args: [] }, "无法启动"],
    ["非零退出码", { command: process.execPath, args: ["-e", "process.stderr.write('boom');process.exit(7)"] }, "退出码 7"],
    ["执行超时", { command: process.execPath, args: ["-e", "setTimeout(()=>{},10000)"], timeoutMs: 20 }, "超时"],
  ])("将%s记录为可观察诊断", async (_name, command, expected) => {
    const cwd = await project();
    const scanner = createCommandScanner({ id: "faulty", ...command });
    const result = await scan({ cwd, include: ["**/*.php"], modules: [moduleWith(scanner)], moduleIds: ["@company/external"] });
    expect(result.status).toBe("partial");
    expect(result.findings).toEqual([]);
    expect(result.diagnostics).toEqual([expect.objectContaining({
      code: "EXTERNAL_SCANNER_FAILED",
      scannerId: "faulty",
      recoverable: true,
      message: expect.stringContaining(expected),
    })]);
  });
});
