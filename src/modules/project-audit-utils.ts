import { createHash } from "node:crypto";
import { access, readFile } from "node:fs/promises";
import { runCommand } from "../command-runner.js";
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
  try {
    const result = await runCommand({ command, args, cwd, timeoutMs });
    return { stdout: result.stdout, stderr: result.stderr, code: result.code };
  } catch {
    return undefined;
  }
}
