#!/usr/bin/env node
import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { ScanResult, Severity, StandardName } from "./contracts.js";
import { renderConsole, renderFileReport, renderSingleFileReport, renderJson, hasFindingAtOrAbove } from "./reporters.js";
import { mergeScanResults, scan, summarize } from "./scanner.js";
import { startPanel } from "./panel.js";
import { attachDispositions, validateDispositions } from "./triage.js";
import { auditWindowsSystem } from "./windows-audit.js";
import { cleanupScanTarget, prepareScanTarget } from "./scan-target.js";
import { detectProjectLanguages, includePatternsForLanguages } from "./scan-coverage.js";

interface CliOptions {
  targets: string[];
  wholeComputer: boolean;
  windowsAudit: boolean;
  audit: boolean;
  format: "console" | "json" | "file-report";
  output?: string;
  reportDir?: string;
  failOn: Severity;
  failOnStatus: "never" | "partial" | "failed";
  panel: boolean;
  port: number;
  allow: string[];
  allowAll: boolean;
  include: string[];
  exclude: string[];
  includeTests: boolean;
  modules: string[];
  standards: StandardName[];
  preset?: string;
  dispositions?: string;
}

function usage(): string {
  return `lego-scan [目录|文件|压缩包 ...] [选项]\n\n选项：\n  --audit                     一键全量审计：代码审计 + 依赖漏洞审计（npm/composer audit、OSV、Git 历史）\n  --format console|json|file-report  报告格式，默认 console（file-report 为按文件分组的 Markdown 检验报告）\n  --output <文件>             写入报告文件\n  --report-dir <目录>         配合 file-report：每个被扫描文件单独生成一份检验报告（路径、结果、建议）\n  --fail-on <严重等级>        info|low|medium|high|critical，默认 high\n  --fail-on-status <状态>     never|partial|failed，默认 partial\n  --include <glob>            增加扫描范围，可重复使用\n  --exclude <glob>            增加排除范围，可重复使用\n  --include-tests             纳入测试文件\n  --module <模块 ID>          指定模块，可重复使用\n  --preset <预设 ID>          指定扫描预设\n  --standard <标准>           nist-ssdf|owasp-asvs|owasp-wstg|owasp-samm|mitre-cwe\n  --dispositions <JSON 文件>  关联漏洞确认、误报、风险接受和修复状态\n  --whole-computer            扫描 Windows 本机所有固定磁盘
  --windows-audit              执行 Windows 基础安全审查（只读）
    --panel                     启动本地 Web 面板\n  --port <端口>               面板端口，默认 4173\n  --allow <路径>              面板额外允许扫描的根目录，可重复使用\n  --allow-all                 允许面板扫描本机任意路径（放开目录限制）\n  --help                      显示帮助`;
}

function parseArgs(args: string[]): CliOptions {
  const options: CliOptions = { targets: [], wholeComputer: false, windowsAudit: false, audit: false, format: "console", failOn: "high", failOnStatus: "partial", panel: false, port: 4173, allow: [], allowAll: false, include: [], exclude: [], includeTests: false, modules: [], standards: [] };
  const severities: Severity[] = ["info", "low", "medium", "high", "critical"];
  const standards: StandardName[] = ["nist-ssdf", "owasp-asvs", "owasp-wstg", "owasp-samm", "mitre-cwe"];
  const nextValue = (name: string, index: number): string => {
    const candidate = args[index + 1];
    if (!candidate || candidate.startsWith("--")) throw new Error(`${name} 缺少参数`);
    return candidate;
  };
  for (let index = 0; index < args.length; index += 1) {
    const value = args[index];
    if (!value) continue;
    if (value === "--help") { console.log(usage()); process.exit(0); }
    if (value === "--whole-computer") options.wholeComputer = true;
    else if (value === "--windows-audit") options.windowsAudit = true;
    else if (value === "--audit") options.audit = true;
    else if (value === "--panel") options.panel = true;
    else if (value === "--allow-all") options.allowAll = true;
    else if (value === "--allow") options.allow.push(nextValue("--allow", index++));
    else if (value === "--include-tests") options.includeTests = true;
    else if (value === "--port") {
      const port = Number(nextValue("--port", index)); index += 1;
      if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("--port 端口无效");
      options.port = port;
    } else if (value === "--format") {
      const format = nextValue("--format", index); index += 1;
      if (format !== "console" && format !== "json" && format !== "file-report") throw new Error("--format 仅支持 console、json 或 file-report");
      options.format = format;
    } else if (value === "--output") options.output = nextValue("--output", index++);
    else if (value === "--report-dir") options.reportDir = nextValue("--report-dir", index++);
    else if (value === "--include") options.include.push(nextValue("--include", index++));
    else if (value === "--exclude") options.exclude.push(nextValue("--exclude", index++));
    else if (value === "--module") options.modules.push(nextValue("--module", index++));
    else if (value === "--preset") options.preset = nextValue("--preset", index++);
    else if (value === "--dispositions") options.dispositions = nextValue("--dispositions", index++);
    else if (value === "--standard") {
      const standard = nextValue("--standard", index++) as StandardName;
      if (!standards.includes(standard)) throw new Error("--standard 标准无效");
      options.standards.push(standard);
    } else if (value === "--fail-on-status") {
      const status = nextValue("--fail-on-status", index++);
      if (status !== "never" && status !== "partial" && status !== "failed") throw new Error("--fail-on-status 状态无效");
      options.failOnStatus = status;
    } else if (value === "--fail-on") {
      const severity = nextValue("--fail-on", index++) as Severity;
      if (!severities.includes(severity)) throw new Error("--fail-on 严重等级无效");
      options.failOn = severity;
    } else if (!value.startsWith("--")) options.targets.push(value);
    else throw new Error(`未知参数：${value}`);
  }
  if (!options.targets.length) options.targets.push(".");
  if (options.wholeComputer && options.targets.length > 1) throw new Error("--whole-computer 不能与多个目录同时使用");
  if (options.modules.length && options.preset) throw new Error("--module 与 --preset 不能同时使用");
  if (options.audit) {
    if (options.modules.length || options.preset) throw new Error("--audit 不能与 --module 或 --preset 同时使用");
    options.preset = "@lego-scan/audit";
  }
  return options;
}

async function availableWindowsDrives(): Promise<string[]> {
  if (os.platform() !== "win32") throw new Error("--whole-computer 当前仅支持 Windows");
  const drives: string[] = [];
  for (const letter of "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
    const root = `${letter}:\\`;
    try { if ((await stat(root)).isDirectory()) drives.push(root); } catch { /* 无法访问的盘符跳过 */ }
  }
  return drives;
}

async function main(): Promise<void> {
  try {
    const options = parseArgs(process.argv.slice(2));
    const targets = options.wholeComputer ? await availableWindowsDrives() : options.targets;
    if (!targets.length) throw new Error("没有发现可扫描的磁盘");
    if (options.panel) {
      if (targets.length !== 1) throw new Error("Web 面板一次只能扫描一个目录，请直接指定盘符或目录（命令行扫描支持单个文件或压缩包）");
      const panelTarget = targets[0]!;
      const panel = await startPanel({ cwd: panelTarget, port: options.port, ...(options.allow.length ? { allowedRoots: options.allow } : {}), allowAll: options.allowAll });
      console.log(`面板已启动：${panel.url}`);
      await new Promise<void>(() => undefined);
      return;
    }
    const scanOptions = {
      ...(options.include.length ? { include: options.include } : {}),
      ...(options.exclude.length ? { exclude: options.exclude } : {}),
      ...(options.modules.length ? { moduleIds: options.modules } : {}),
      ...(options.standards.length ? { standards: options.standards } : {}),
      ...(options.preset ? { preset: options.preset } : {}),
      includeTests: options.includeTests,
    };
    // 目标可以是目录、单个源码/配置文件或 ZIP 系压缩包，与面板共用同一套目标解析
    const prepared = [];
    for (const target of targets) prepared.push(await prepareScanTarget(target));
    let result: ScanResult;
    try {
      const results: ScanResult[] = [];
      for (const target of prepared) {
        let include = [...options.include, ...(target.include ?? [])];
        if (!include.length) {
          // 未显式指定范围时与面板一致：按项目语言自动选择扫描范围（php/java/xml 等）
          try { include = includePatternsForLanguages(await detectProjectLanguages(target.scanCwd)); } catch { include = []; }
        }
        results.push(await scan({ ...scanOptions, cwd: target.scanCwd, ...(include.length ? { include } : {}) }));
      }
      result = prepared.length === 1 ? results[0]! : mergeScanResults(targets, results);
    } finally {
      for (const target of prepared) await cleanupScanTarget(target);
    }
    if (options.windowsAudit) {
      const audit = await auditWindowsSystem();
      result = {
        ...result,
        findings: [...result.findings, ...audit.findings],
        executedRules: [...new Set([...result.executedRules, ...audit.executedRules])].sort(),
        summary: summarize([...result.findings, ...audit.findings]),
        status: result.status === "failed" || audit.status === "partial" ? "partial" : result.status,
        diagnostics: [...result.diagnostics, ...audit.diagnostics],
      };
    }
    if (options.dispositions) {
      const dispositionPath = path.resolve(options.dispositions);
      const dispositions = validateDispositions(JSON.parse(await readFile(dispositionPath, "utf8")));
      result = attachDispositions(result, dispositions);
    }
    const reportRoot = targets.length === 1 ? (prepared[0]!.kind === "file" ? path.dirname(path.resolve(targets[0]!)) : prepared[0]!.kind === "archive" ? undefined : path.resolve(targets[0]!)) : undefined;
    const report = options.format === "json" ? renderJson(result) : options.format === "file-report" ? renderFileReport(result, reportRoot) : renderConsole(result);
    if (options.output) { await writeFile(path.resolve(options.output), report, "utf8"); console.log(`报告已写入 ${path.resolve(options.output)}`); }
    else console.log(report);
    if (options.format === "file-report" && options.reportDir) {
      const dir = path.resolve(options.reportDir);
      await mkdir(dir, { recursive: true });
      const byFile = new Map<string, typeof result.findings>();
      for (const finding of result.findings) {
        const key = finding.file.replaceAll("\\", "/");
        byFile.set(key, [...(byFile.get(key) ?? []), finding]);
      }
      const scanned = result.scannedFileList ?? [];
      const safeName = (name: string) => name.replace(/[\\/:*?"<>|]/g, "_");
      let index = 0;
      for (const relative of scanned) {
        index += 1;
        const key = relative.replaceAll("\\", "/");
        const name = `${String(index).padStart(4, "0")}${(byFile.get(key)?.length ?? 0) > 0 ? "-有问题" : "-通过"}-${safeName(path.basename(key))}.md`;
        await writeFile(path.join(dir, name), renderSingleFileReport(key, byFile.get(key) ?? [], reportRoot), "utf8");
      }
      await writeFile(path.join(dir, "0000-汇总检验报告.md"), renderFileReport(result, reportRoot), "utf8");
      console.log(`已生成 ${index} 份文件检验报告 + 1 份汇总：${dir}`);
    }
    const statusFailed = options.failOnStatus === "partial"
      ? result.status !== "succeeded"
      : options.failOnStatus === "failed" && result.status === "failed";
    process.exitCode = statusFailed || hasFindingAtOrAbove(result.findings, options.failOn) ? 1 : 0;
  } catch (error) { console.error(error instanceof Error ? error.message : String(error)); process.exitCode = 2; }
}

await main();
