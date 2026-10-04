import { existsSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { runCommand, type CommandRunResult } from "../src/command-runner.js";
const root = path.resolve(import.meta.dirname, "..");
const directories: string[] = [];

function resolveNpm(): { command: string; prefix: string[] } | undefined {
  const npmExecPath = process.env.npm_execpath;
  if (npmExecPath && existsSync(npmExecPath)) return { command: process.execPath, prefix: [npmExecPath] };
  const executable = process.platform === "win32" ? "npm.cmd" : "npm";
  const separator = process.platform === "win32" ? ";" : ":";
  for (const directory of (process.env.PATH ?? "").split(separator)) {
    if (directory && existsSync(path.join(directory, executable))) return { command: path.join(directory, executable), prefix: [] };
  }
  return undefined;
}

const npm = resolveNpm();

async function execute(command: string, args: string[], cwd: string, timeoutMs = 120_000): Promise<CommandRunResult> {
  const result = await runCommand({ command, args, cwd, timeoutMs });
  if (result.code !== 0) throw new Error(`命令执行失败（${result.code ?? "unknown"}）：${result.stderr}`);
  return result;
}

afterAll(async () => Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true }))));

describe("npm 发布包冒烟", () => {
  it.skipIf(!npm)("打包后可安装、导入并启动命令", async () => {
    await execute(process.execPath, [path.join(root, "node_modules", "typescript", "bin", "tsc"), "-p", path.join(root, "tsconfig.json")], root);
    const packDir = await mkdtemp(path.join(tmpdir(), "lego-pack-"));
    const consumer = await mkdtemp(path.join(tmpdir(), "lego-consumer-"));
    directories.push(packDir, consumer);
    const packed = await execute(npm!.command, [...npm!.prefix, "pack", "--json", "--ignore-scripts", "--pack-destination", packDir], root);
    const metadata = JSON.parse(packed.stdout) as Array<{ filename: string }>;
    const tarball = path.join(packDir, metadata[0]!.filename);
    await writeFile(path.join(consumer, "package.json"), JSON.stringify({ name: "package-smoke", private: true, type: "module" }), "utf8");
    await execute(npm!.command, [...npm!.prefix, "install", "--ignore-scripts", "--no-audit", "--no-fund", tarball], consumer, 60_000);
    const imported = await execute(process.execPath, ["--input-type=module", "-e", "import('lego-security-scanner').then(m=>console.log(typeof m.scan))"], consumer);
    expect(imported.stdout.trim()).toBe("function");
    const cli = path.join(consumer, "node_modules", ".bin", process.platform === "win32" ? "lego-scan.cmd" : "lego-scan");
    const help = await execute(cli, ["--help"], consumer);
    expect(help.stdout).toContain("lego-scan [目录|文件|压缩包 ...] [选项]");
  }, 90_000);
});
