import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { access, readFile } from "node:fs/promises";
import type { Finding, Severity } from "../contracts.js";

export interface CommandResult { stdout: string; stderr: string; code: number | null; }

export function auditFinding(input: Omit<Finding, "fingerprint">): Finding {
  const fingerprint = createHash("sha256")
    .update(JSON.stringify([input.ruleId, input.file, input.line, input.column, input.message]))
    .digest("hex")
    .slice(0, 24);
  return { ...input, fingerprint };
}

export function auditSeverity(value: unknown): Severity {
  const normalized = String(value ?? "").toLowerCase();
  if (normalized === "critical" || normalized === "high" || normalized === "medium" || normalized === "low") return normalized;
  return normalized === "moderate" ? "medium" : "medium";
}

export async function fileExists(file: string): Promise<boolean> {
  try { await access(file); return true; } catch { return false; }
}

export async function readJson(file: string): Promise<unknown | undefined> {
  try { return JSON.parse(await readFile(file, "utf8")); } catch { return undefined; }
}

export async function runAuditCommand(command: string, args: string[], cwd: string, timeoutMs = 120_000): Promise<CommandResult | undefined> {
  return await new Promise((resolve) => {
    // Node 20.12+/22+ 在 Windows 上禁止不带 shell 直接 spawn .cmd/.bat（EINVAL），参数固定无注入风险
    const needsShell = process.platform === "win32" && /\.(cmd|bat)$/i.test(command);
    const child = spawn(command, args, { cwd, windowsHide: true, shell: needsShell, env: process.env });
    let stdout = "";
    let stderr = "";
    let settled = false;
    const finish = (result: CommandResult | undefined): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    };
    const timer = setTimeout(() => { child.kill(); finish(undefined); }, timeoutMs);
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => { stdout += chunk; });
    child.stderr.on("data", (chunk: string) => { stderr += chunk; });
    child.on("error", () => finish(undefined));
    child.on("close", (code) => finish({ stdout, stderr, code }));
  });
}
