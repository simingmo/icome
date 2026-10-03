import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import path from "node:path";
import type { Confidence, Finding, RuleCategory, ScanDiagnostic, Severity, StandardReference } from "./contracts.js";

export interface ProjectScanContext {
  cwd: string;
  files: readonly string[];
}

export interface ExternalScanResult {
  findings: Finding[];
  executedRules?: string[];
  diagnostics?: ScanDiagnostic[];
  status?: "succeeded" | "partial" | "failed";
}

export interface ExternalScanner {
  readonly id: string;
  readonly version: string;
  scan(context: ProjectScanContext): Promise<ExternalScanResult>;
}

export interface ExternalToolRecord {
  ruleId?: string;
  message: string;
  severity?: string;
  confidence?: string;
  category?: string;
  file: string;
  line?: number;
  column?: number;
  evidence?: string;
  suggestion?: string;
  references?: StandardReference[];
}

export interface CommandScannerOptions {
  id: string;
  version?: string;
  command: string;
  args?: string[];
  timeoutMs?: number;
  environment?: Record<string, string>;
}

const severities = new Set<Severity>(["info", "low", "medium", "high", "critical"]);
const confidences = new Set<Confidence>(["low", "medium", "high"]);
const categories = new Set<RuleCategory>(["security", "testing", "configuration", "dependency", "process"]);
const MAX_TOOL_OUTPUT_BYTES = 16 * 1024 * 1024;

function fingerprint(parts: readonly unknown[]): string {
  return createHash("sha256").update(JSON.stringify(parts)).digest("hex");
}

function normalizeRelativePath(cwd: string, file: string): string {
  const absolute = path.resolve(cwd, file);
  const relative = path.relative(cwd, absolute).replaceAll("\\", "/");
  if (relative === ".." || relative.startsWith("../") || path.isAbsolute(relative)) {
    throw new Error(`外部扫描结果指向项目目录外部：${file}`);
  }
  return relative || ".";
}

function mapSeverity(value: string | undefined): Severity {
  const normalized = value?.toLowerCase();
  if (normalized && severities.has(normalized as Severity)) return normalized as Severity;
  if (normalized === "warning" || normalized === "moderate") return "medium";
  if (normalized === "error") return "high";
  return "medium";
}

function normalizeRecord(scannerId: string, cwd: string, record: ExternalToolRecord): Finding {
  const file = normalizeRelativePath(cwd, record.file);
  const line = Math.max(1, Math.trunc(record.line ?? 1));
  const column = Math.max(1, Math.trunc(record.column ?? 1));
  const nativeRule = record.ruleId?.trim() || "finding";
  const ruleId = `${scannerId}/${nativeRule}`;
  const confidence = record.confidence?.toLowerCase() as Confidence | undefined;
  const category = record.category?.toLowerCase() as RuleCategory | undefined;
  return {
    ruleId,
    message: record.message,
    severity: mapSeverity(record.severity),
    confidence: confidence && confidences.has(confidence) ? confidence : "medium",
    category: category && categories.has(category) ? category : "security",
    file,
    line,
    column,
    evidence: record.evidence ?? "",
    suggestion: record.suggestion ?? "请结合工具原始报告复核并修复。",
    references: record.references ?? [],
    fingerprint: fingerprint([ruleId, file, line, column, record.message]),
  };
}

function parseRecords(stdout: string): ExternalToolRecord[] {
  const parsed: unknown = JSON.parse(stdout);
  const records = Array.isArray(parsed)
    ? parsed
    : typeof parsed === "object" && parsed !== null && "findings" in parsed
      ? (parsed as { findings: unknown }).findings
      : undefined;
  if (!Array.isArray(records)) throw new Error("外部工具必须输出 JSON 数组或包含 findings 数组的对象。注：可使用包装脚本转换原生报告。");
  return records.map((item, index) => {
    if (typeof item !== "object" || item === null) throw new Error(`外部报告第 ${index + 1} 项不是对象。`);
    const record = item as Partial<ExternalToolRecord>;
    if (typeof record.message !== "string" || typeof record.file !== "string") {
      throw new Error(`外部报告第 ${index + 1} 项缺少 message 或 file。`);
    }
    return record as ExternalToolRecord;
  });
}

function forceKill(child: { kill(signal?: NodeJS.Signals | number): boolean }): void {
  for (const signal of ["SIGKILL", "SIGTERM"] as const) {
    try { if (!child.kill(signal)) return; } catch { return; }
  }
}

async function runCommand(options: CommandScannerOptions, context: ProjectScanContext): Promise<string> {
  return await new Promise((resolve, reject) => {
    const args = (options.args ?? []).map((arg) => arg.replaceAll("{cwd}", context.cwd));
    // Windows 上 .cmd/.bat 需要经由 shell 才能被 spawn（Node 安全限制），参数仅来自模块配置
    const needsShell = process.platform === "win32" && /\.(cmd|bat)$/i.test(options.command);
    const child = spawn(options.command, args, {
      cwd: context.cwd,
      env: { ...process.env, ...options.environment },
      shell: needsShell,
      windowsHide: true,
    });
    let stdout = "";
    let stderr = "";
    let settled = false;
    let timedOut = false;
    const finish = (action: () => void): void => {
      if (settled) return;
      settled = true;
      action();
    };
    const timeoutMs = options.timeoutMs ?? 120_000;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill();
    }, timeoutMs);
    const hardKill = setTimeout(() => {
      if (!settled) forceKill(child);
    }, timeoutMs + 5_000);
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      stdout += chunk;
      if (Buffer.byteLength(stdout) > MAX_TOOL_OUTPUT_BYTES) { child.kill(); finish(() => reject(new Error(`外部扫描器 ${options.id} 输出超过 16 MB 安全限制。`))); }
    });
    child.stderr.on("data", (chunk: string) => {
      stderr += chunk;
      if (Buffer.byteLength(stderr) > MAX_TOOL_OUTPUT_BYTES) { child.kill(); finish(() => reject(new Error(`外部扫描器 ${options.id} 错误输出超过 16 MB 安全限制。`))); }
    });
    child.on("error", (error) => {
      clearTimeout(timer);
      clearTimeout(hardKill);
      finish(() => reject(new Error(`无法启动外部扫描器 ${options.id}：${error.message}`)));
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      clearTimeout(hardKill);
      finish(() => {
        if (timedOut) reject(new Error(`外部扫描器 ${options.id} 超时（${timeoutMs}ms）。`));
        else if (code !== 0) reject(new Error(`外部扫描器 ${options.id} 退出码 ${code ?? "unknown"}：${stderr.trim()}`));
        else resolve(stdout);
      });
    });
  });
}

export function createCommandScanner(options: CommandScannerOptions): ExternalScanner {
  return {
    id: options.id,
    version: options.version ?? "external",
    async scan(context) {
      const stdout = await runCommand(options, context);
      const findings = parseRecords(stdout).map((record) => normalizeRecord(options.id, context.cwd, record));
      return { findings, executedRules: [...new Set(findings.map((finding) => finding.ruleId))] };
    },
  };
}
