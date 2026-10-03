import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);
const root = path.resolve(import.meta.dirname, "..");
const cli = path.join(root, "dist", "cli.js");
const directories: string[] = [];

beforeAll(async () => {
  await execFileAsync(process.execPath, [path.join(root, "node_modules", "typescript", "bin", "tsc"), "-p", path.join(root, "tsconfig.json")], { cwd: root });
}, 30_000);

afterAll(async () => Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true }))));

async function fixture(source: string): Promise<string> {
  const cwd = await mkdtemp(path.join(tmpdir(), "lego-cli-"));
  directories.push(cwd);
  await writeFile(path.join(cwd, "app.ts"), source, "utf8");
  return cwd;
}

async function run(args: string[]): Promise<{ stdout: string; stderr: string; code: number }> {
  try {
    const result = await execFileAsync(process.execPath, [cli, ...args], { cwd: root, windowsHide: true });
    return { stdout: result.stdout, stderr: result.stderr, code: 0 };
  } catch (error) {
    const failure = error as { stdout?: string; stderr?: string; code?: number };
    return { stdout: failure.stdout ?? "", stderr: failure.stderr ?? "", code: failure.code ?? -1 };
  }
}

describe("CLI 黑盒", () => {
  it("输出帮助并以 0 退出", async () => {
    const result = await run(["--help"]);
    expect(result.code).toBe(0);
    expect(result.stdout).toContain("lego-scan [目录|文件|压缩包 ...] [选项]");
  });

  it("--audit 启用全量审计预设", async () => {
    const cwd = await fixture("eval(userInput);");
    const result = await run([cwd, "--audit", "--format", "json"]);
    const report = JSON.parse(result.stdout) as { findings: Array<{ ruleId: string }>; executedRules: string[] };
    expect(report.findings.map((finding) => finding.ruleId)).toContain("security/no-eval");
    expect(report.executedRules).toContain("security/git-history-secret");
  });

  it("支持直接指定单个源码文件扫描", async () => {
    const cwd = await fixture("eval(userInput);\nconst safe = true;");
    const result = await run([path.join(cwd, "app.ts"), "--format", "json"]);
    expect(result.code).toBe(1);
    const report = JSON.parse(result.stdout) as { findings: Array<{ ruleId: string; file: string }>; scannedFiles: number };
    expect(report.findings.map((finding) => finding.ruleId)).toContain("security/no-eval");
    expect(report.scannedFiles).toBe(1);
  });

  it("不支持扫描的文件类型给出明确错误", async () => {
    const cwd = await fixture("const safe = true;");
    const target = path.join(cwd, "notes.md");
    await writeFile(target, "# hello", "utf8");
    const result = await run([target]);
    expect(result.code).toBe(2);
    expect(result.stderr).toContain("不属于源码或配置文件");
  });

  it("以 JSON 输出扫描结果并按阈值返回 1", async () => {
    const cwd = await fixture("eval(userInput);");
    const result = await run([cwd, "--format", "json"]);
    expect(result.code).toBe(1);
    const report = JSON.parse(result.stdout) as { schemaVersion: string; findings: Array<{ ruleId: string }> };
    expect(report.schemaVersion).toBe("0.4");
    expect(report.findings.map((finding) => finding.ruleId)).toContain("security/no-eval");
  });

  it("较高失败阈值允许中危结果以 0 退出", async () => {
    const cwd = await fixture("APP_DEBUG=true");
    const result = await run([cwd, "--format", "json", "--fail-on", "critical"]);
    expect(result.code).toBe(0);
  });

  it("将报告写入文件", async () => {
    const cwd = await fixture("const safe = true;");
    const output = path.join(cwd, "report.json");
    const result = await run([cwd, "--format", "json", "--output", output]);
    expect(result.code).toBe(0);
    expect(result.stdout).toContain("报告已写入");
    expect(JSON.parse(await readFile(output, "utf8"))).toMatchObject({ schemaVersion: "0.4", status: "succeeded" });
  });

  it("合并多个扫描目录的结果", async () => {
    const first = await fixture("eval(firstInput);");
    const second = await fixture("eval(secondInput);");
    const result = await run([first, second, "--format", "json"]);
    expect(result.code).toBe(1);
    const report = JSON.parse(result.stdout) as { metadata?: { roots?: string[] }; findings: Array<{ root?: string }> };
    expect(report.metadata?.roots).toEqual([first, second]);
    expect(report.findings).toHaveLength(2);
    expect(report.findings.map((finding) => finding.root)).toEqual([first, second]);
  });

  it("拒绝未知参数并以 2 退出", async () => {
    const result = await run(["--unknown"]);
    expect(result.code).toBe(2);
    expect(result.stderr).toContain("未知参数");
  });
});
