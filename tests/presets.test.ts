import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import type { ScannerModule } from "../src/contracts.js";
import { patternRule } from "../src/rule-utils.js";
import { scan } from "../src/scanner.js";

async function project(source: string): Promise<string> {
  const cwd = await mkdtemp(path.join(tmpdir(), "lego-modules-"));
  await writeFile(path.join(cwd, "app.ts"), source, "utf8");
  return cwd;
}

describe("预设和显式积木选择", () => {
  it("默认推荐预设保持全部内置规则", async () => {
    const cwd = await project("const password = 'abcdefgh12345678';");
    try {
      const result = await scan({ cwd });
      expect(result.executedRules).toContain("security/no-hardcoded-secret");
      expect(result.executedRules).toContain("testing/no-focused-test");
    } finally {
      await rm(cwd, { recursive: true, force: true });
    }
  });

  it("审计预设装配代码审计与漏洞审计积木", async () => {
    const cwd = await project("eval(userInput);");
    try {
      const result = await scan({ cwd, preset: "@lego-scan/audit" });
      expect(result.executedRules).toContain("security/no-eval");
      // 漏洞审计外部扫描器在无锁文件时静默跳过，但模块应参与装配
      expect(result.diagnostics.filter((item) => item.code.startsWith("OSV_"))).toEqual([]);
    } finally {
      await rm(cwd, { recursive: true, force: true });
    }
  });

  it("允许独立选择凭据模块", async () => {
    const cwd = await project("const password = 'abcdefgh12345678'; eval(userInput);");
    try {
      const result = await scan({ cwd, moduleIds: ["@lego-scan/credentials"] });
      expect(result.executedRules).toEqual(expect.arrayContaining([
        "security/no-hardcoded-secret",
        "security/no-private-key",
        "security/no-cloud-access-key",
      ]));
      expect(result.executedRules).not.toContain("security/no-eval");
      expect(result.findings.map((item) => item.ruleId)).toEqual(["security/no-hardcoded-secret"]);
    } finally {
      await rm(cwd, { recursive: true, force: true });
    }
  });

  it("显式选择测试积木时不装配安全积木", async () => {
    const cwd = await project("const password = 'abcdefgh12345678';");
    try {
      const result = await scan({ cwd, moduleIds: ["@lego-scan/testing"] });
      expect(result.executedRules.every((id) => id.startsWith("testing/"))).toBe(true);
      expect(result.findings).toEqual([]);
    } finally {
      await rm(cwd, { recursive: true, force: true });
    }
  });

  it("支持自定义积木模块", async () => {
    const cwd = await project("debugger;");
    const custom: ScannerModule = {
      id: "@company/debug",
      version: "1.0.0",
      rules: [patternRule({
        id: "company/no-debugger",
        description: "禁止 debugger",
        severity: "medium",
        category: "security",
        pattern: /debugger/,
        message: "发现 debugger",
        suggestion: "移除 debugger",
      })],
    };
    try {
      const result = await scan({ cwd, modules: [custom], moduleIds: [custom.id] });
      expect(result.executedRules).toEqual(["company/no-debugger"]);
      expect(result.findings).toHaveLength(1);
    } finally {
      await rm(cwd, { recursive: true, force: true });
    }
  });
});
