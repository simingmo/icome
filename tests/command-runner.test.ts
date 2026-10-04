import { describe, expect, it } from "vitest";
import { commandFailureMessage, runCommand } from "../src/command-runner.js";

describe("command runner", () => {
  it("返回命令输出和退出状态", async () => {
    const result = await runCommand({
      command: process.execPath,
      args: ["-e", "process.stdout.write('ok')"],
      cwd: process.cwd(),
    });

    expect(result).toMatchObject({ stdout: "ok", stderr: "", code: 0, timedOut: false });
    expect(result.outputLimitExceeded).toBeUndefined();
  });

  it("限制标准输出并返回可观察错误", async () => {
    const result = await runCommand({
      command: process.execPath,
      args: ["-e", "process.stdout.write('x'.repeat(1024))"],
      cwd: process.cwd(),
      maxOutputBytes: 16,
    });

    expect(result.outputLimitExceeded).toBe("stdout");
    expect(Buffer.byteLength(result.stdout, "utf8")).toBeLessThanOrEqual(16);
    expect(commandFailureMessage("fixture", result, 120_000)).toContain("输出超过安全限制");
  });

  it("标记超时命令", async () => {
    const timeoutMs = 20;
    const result = await runCommand({
      command: process.execPath,
      args: ["-e", "setTimeout(() => {}, 10000)"],
      cwd: process.cwd(),
      timeoutMs,
    });

    expect(result.timedOut).toBe(true);
    expect(commandFailureMessage("fixture", result, timeoutMs)).toContain("超时");
  });
});
