import { spawn } from "node:child_process";

export interface CommandRunOptions {
  command: string;
  args?: readonly string[];
  cwd: string;
  timeoutMs?: number;
  environment?: Record<string, string>;
  maxOutputBytes?: number;
}

export interface CommandRunResult {
  stdout: string;
  stderr: string;
  code: number | null;
  timedOut: boolean;
  outputLimitExceeded: "stdout" | "stderr" | undefined;
}

const DEFAULT_TIMEOUT_MS = 120_000;
const DEFAULT_MAX_OUTPUT_BYTES = 16 * 1024 * 1024;

function killProcess(child: { kill(signal?: NodeJS.Signals | number): boolean }): void {
  for (const signal of ["SIGTERM", "SIGKILL"] as const) {
    try {
      if (!child.kill(signal)) return;
    } catch {
      return;
    }
  }
}

export async function runCommand(options: CommandRunOptions): Promise<CommandRunResult> {
  return await new Promise((resolve, reject) => {
    const needsShell = process.platform === "win32" && /\.(cmd|bat)$/i.test(options.command);
    const child = spawn(options.command, [...(options.args ?? [])], {
      cwd: options.cwd,
      env: { ...process.env, ...options.environment },
      shell: needsShell,
      windowsHide: true,
    });
    const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const maxOutputBytes = options.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES;
    let stdout = "";
    let stderr = "";
    let settled = false;
    let timedOut = false;
    let outputLimitExceeded: CommandRunResult["outputLimitExceeded"];
    const finish = (action: () => void): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      clearTimeout(hardKill);
      action();
    };
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill();
    }, timeoutMs);
    const hardKill = setTimeout(() => {
      if (!settled) killProcess(child);
    }, timeoutMs + 5_000);
    const append = (current: string, chunk: string, stream: "stdout" | "stderr"): string => {
      if (outputLimitExceeded) return current;
      const next = current + chunk;
      if (Buffer.byteLength(next, "utf8") <= maxOutputBytes) return next;
      outputLimitExceeded = stream;
      killProcess(child);
      return current;
    };
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      stdout = append(stdout, chunk, "stdout");
    });
    child.stderr.on("data", (chunk: string) => {
      stderr = append(stderr, chunk, "stderr");
    });
    child.on("error", (error) => finish(() => reject(error)));
    child.on("close", (code) => finish(() => resolve({ stdout, stderr, code, timedOut, outputLimitExceeded })));
  });
}

export function commandFailureMessage(id: string, result: CommandRunResult, timeoutMs: number): string | undefined {
  if (result.timedOut) return `外部扫描器 ${id} 超时（${timeoutMs}ms）。`;
  if (result.outputLimitExceeded === "stdout") return `外部扫描器 ${id} 输出超过安全限制。`;
  if (result.outputLimitExceeded === "stderr") return `外部扫描器 ${id} 错误输出超过安全限制。`;
  if (result.code !== 0) return `外部扫描器 ${id} 退出码 ${result.code ?? "unknown"}：${result.stderr.trim()}`;
  return undefined;
}
