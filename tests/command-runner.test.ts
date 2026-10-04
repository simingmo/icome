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

  it("限制标准错误并返回可观察错误", async () => {
    const result = await runCommand({
      command: process.execPath,
      args: ["-e", "process.stderr.write('x'.repeat(1024))"],
      cwd: process.cwd(),
      maxOutputBytes: 16,
    });

    expect(result.outputLimitExceeded).toBe("stderr");
    expect(Buffer.byteLength(result.stderr, "utf8")).toBeLessThanOrEqual(16);
    expect(commandFailureMessage("fixture", result, 120_000)).toContain("错误输出超过安全限制");
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

  it("拒绝无效的执行预算和空命令", async () => {
    await expect(runCommand({ command: " ", cwd: process.cwd() })).rejects.toThrow("command 不能为空");
    await expect(runCommand({ command: process.execPath, cwd: process.cwd(), timeoutMs: 0 })).rejects.toThrow("timeoutMs 必须是正整数");
    await expect(runCommand({ command: process.execPath, cwd: process.cwd(), maxOutputBytes: -1 })).rejects.toThrow("maxOutputBytes 必须是正整数");
  });

  it("在启动前和运行中响应取消", async () => {
    const preCancelled = new AbortController();
    preCancelled.abort(new Error("pre-cancelled"));
    await expect(runCommand({ command: process.execPath, cwd: process.cwd(), signal: preCancelled.signal })).rejects.toThrow("pre-cancelled");

    const controller = new AbortController();
    const running = runCommand({
      command: process.execPath,
      args: ["-e", "setTimeout(() => {}, 10000)"],
      cwd: process.cwd(),
      signal: controller.signal,
    });
    controller.abort();
    await expect(running).rejects.toMatchObject({ name: "AbortError" });
  });

  it.runIf(process.platform === "win32")("无需 shell 即可执行 Windows 命令 shim", async () => {
    const result = await runCommand({
      command: "npm.cmd",
      args: ["--version"],
      cwd: process.cwd(),
    });

    expect(result.code).toBe(0);
    expect(result.stdout.trim()).toMatch(/^\d+\.\d+\.\d+/);
  });
});
