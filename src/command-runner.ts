import crossSpawn from "cross-spawn";

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
const FORCE_KILL_DELAY_MS = 5_000;

function validatePositiveInteger(name: string, value: number): void {
  if (!Number.isSafeInteger(value) || value <= 0) throw new RangeError(`${name} 必须是正整数。`);
}

function killProcess(child: { kill(signal?: NodeJS.Signals | number): boolean }, signal: NodeJS.Signals): void {
  try {
    child.kill(signal);
  } catch {
    // Process may already have exited between the state check and signal delivery.
  }
}

export async function runCommand(options: CommandRunOptions): Promise<CommandRunResult> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxOutputBytes = options.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES;
  validatePositiveInteger("timeoutMs", timeoutMs);
  validatePositiveInteger("maxOutputBytes", maxOutputBytes);
  if (!options.command.trim()) throw new Error("command 不能为空。");

  return await new Promise((resolve, reject) => {
    const child = crossSpawn(options.command, [...(options.args ?? [])], {
      cwd: options.cwd,
      env: { ...process.env, ...options.environment },
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });
    const stdoutStream = child.stdout;
    const stderrStream = child.stderr;
    if (!stdoutStream || !stderrStream) {
      killProcess(child, "SIGTERM");
      reject(new Error("无法捕获命令输出。"));
      return;
    }
    let stdout = "";
    let stderr = "";
    let settled = false;
    let timedOut = false;
    let hardKill: NodeJS.Timeout | undefined;
    let outputLimitExceeded: CommandRunResult["outputLimitExceeded"];
    const finish = (action: () => void): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (hardKill) clearTimeout(hardKill);
      action();
    };
    const terminate = (): void => {
      killProcess(child, "SIGTERM");
      hardKill ??= setTimeout(() => {
        if (!settled) killProcess(child, "SIGKILL");
      }, FORCE_KILL_DELAY_MS);
      hardKill.unref();
    };
    const timer = setTimeout(() => {
      timedOut = true;
      terminate();
    }, timeoutMs);
    timer.unref();
    const append = (current: string, chunk: string, stream: "stdout" | "stderr"): string => {
      if (outputLimitExceeded) return current;
      const next = current + chunk;
      if (Buffer.byteLength(next, "utf8") <= maxOutputBytes) return next;
      outputLimitExceeded = stream;
      terminate();
      return current;
    };
    stdoutStream.setEncoding("utf8");
    stderrStream.setEncoding("utf8");
    stdoutStream.on("data", (chunk: string) => {
      stdout = append(stdout, chunk, "stdout");
    });
    stderrStream.on("data", (chunk: string) => {
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
