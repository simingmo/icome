import { mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { ModuleRegistry, ScannerModule, ScannerPlugin } from "../src/contracts.js";
import { ScannerModuleRegistry } from "../src/module-registry.js";
import { patternRule } from "../src/rule-utils.js";
import { mergeScanResults, scan, scanRoots } from "../src/scanner.js";

const directories: string[] = [];

afterEach(async () => {
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

async function fixture(files: Record<string, string>): Promise<string> {
  const directory = await mkdtemp(path.join(tmpdir(), "lego-scan-"));
  directories.push(directory);
  await Promise.all(Object.entries(files).map(async ([name, content]) => {
    const target = path.join(directory, name);
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, content, "utf8");
  }));
  return directory;
}

describe("scan", () => {
  it("合并多个扫描根目录并保留根目录信息", async () => {
    const first = await fixture({ "src/app.ts": "eval(firstInput);" });
    const second = await fixture({ "src/app.ts": "eval(secondInput);" });
    const result = await scanRoots({ roots: [first, second] });
    expect(result.status).toBe("succeeded");
    expect(result.scannedFiles).toBe(2);
    expect(result.metadata?.roots).toEqual([first, second]);
    expect(result.findings).toHaveLength(2);
    expect(result.findings.map((finding) => finding.root)).toEqual([first, second]);
  });

  it("拒绝空的扫描根目录", () => {
    expect(() => mergeScanResults([], [])).toThrow("扫描根目录与扫描结果数量不一致");
  });

  it("输出版本化报告、标准映射和脱敏证据", async () => {
    const cwd = await fixture({ "src/app.ts": "const apiKey = 'abcdefgh12345678';\n" + "ev" + "al(userInput);\n" });
    const result = await scan({ cwd });
    expect(result.schemaVersion).toBe("0.4");
    expect(result.scanner.version).toBe("0.3.0");
    expect(result.coverage).toMatchObject({ discoveredFiles: 1, scannedFiles: 1, skippedFiles: 0, failedFiles: 0 });
    expect(result.metadata?.configuration.includeTests).toBe(false);
    expect(result.modules?.map((module) => module.id)).toEqual(expect.arrayContaining(["@lego-scan/security", "@lego-scan/credentials"]));
    expect(result.findings.map((item) => item.ruleId)).toEqual([
      "security/no-hardcoded-secret",
      "security/no-eval",
    ]);
    expect(result.findings[0]?.evidence).toContain("[REDACTED]");
    expect(result.findings[0]?.references.some((item) => item.control === "CWE-798")).toBe(true);
    expect(result.summary.bySeverity.high).toBe(2);
  });

  it("测试夹具字符串不会被误判为真实聚焦测试", async () => {
    const cwd = await fixture({
      "tests/app.test.ts": "const sample = \"test.only('fixture', () => {})\";\ntest.only('focused', () => {});\ntest.skip('later', () => {});",
    });
    const result = await scan({ cwd, includeTests: true });
    const testingRules = result.findings.filter((item) => item.category === "testing");
    expect(testingRules.map((item) => item.ruleId)).toEqual([
      "testing/no-focused-test",
      "testing/no-skipped-test",
    ]);
  });

  it("扫描凭据和高风险配置文件", async () => {
    const cwd = await fixture({
      ".env": "APP_DEBUG=true\nAPI_TOKEN=abcdefgh12345678\n",
      "config/app.yaml": "Access-Control-Allow-Origin: '*'\n",
      "keys.txt": "-----BEGIN PRIVATE KEY-----\n",
    });
    const result = await scan({ cwd, include: ["**/.env*", "**/*.{yaml,txt}"] });
    expect(result.findings.map((item) => item.ruleId)).toEqual(expect.arrayContaining([
      "security/no-hardcoded-secret",
      "security/no-private-key",
      "configuration/no-debug-mode",
      "configuration/no-wildcard-cors",
    ]));
    expect(result.findings.find((item) => item.ruleId === "security/no-private-key")?.evidence).toBe("[REDACTED PRIVATE KEY]");
  });

  it("默认排除虚拟环境与依赖目录，不扫描其中的第三方代码", async () => {
    const cwd = await fixture({
      "src/app.ts": "const apiKey = 'abcdefgh12345678';\n",
      "youxi/venv/Lib/site-packages/pip/_internal/network/auth.py": "const apiKey = 'abcdefgh12345678';\n",
      "youxi/venv1/Lib/site-packages/pip/_internal/network/auth.py": "const apiKey = 'abcdefgh12345678';\n",
      "node_modules/lib/index.js": "const apiKey = 'abcdefgh12345678';\n",
    });
    const result = await scan({ cwd });
    const files = result.findings.map((item) => item.file);
    expect(files.every((file) => !/venv|site-packages|node_modules/i.test(file))).toBe(true);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.file).toBe("src/app.ts");
  });

  it("默认排除测试目录，开启 includeTests 后纳入", async () => {
    const cwd = await fixture({
      "src/app.ts": "const apiKey = 'abcdefgh12345678';\n",
      "tests/app.test.ts": "const apiKey = 'abcdefgh12345678';\n",
    });
    const excluded = await scan({ cwd });
    expect(excluded.scannedFiles).toBe(1);
    expect(excluded.findings.filter((item) => /tests?[\/\\]/i.test(item.file) || /\.test\./i.test(item.file))).toHaveLength(0);
    expect(excluded.findings).toHaveLength(1);
    expect(excluded.findings[0]?.file).toBe("src/app.ts");

    const included = await scan({ cwd, includeTests: true });
    expect(included.scannedFiles).toBe(2);
  });

  it("禁止通过目录符号链接读取扫描根目录外的文件", async () => {
    const cwd = await fixture({ "src/app.ts": "const safe = true;\n" });
    const outside = await fixture({ "secret.ts": "eval(outsideInput);\n" });
    try {
      await symlink(outside, path.join(cwd, "linked"), "junction");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EPERM") return;
      throw error;
    }
    const result = await scan({ cwd });
    expect(result.scannedFiles).toBe(1);
    expect(result.findings.some((item) => item.file.includes("secret.ts"))).toBe(false);
  });

  it("跳过超大文件和伪装成源码的二进制文件", async () => {
    const cwd = await fixture({ "large.ts": "eval(input);", "binary.ts": "\u0000x", "safe.ts": "x" });
    const result = await scan({ cwd, maxFileBytes: 8 });
    expect(result.scannedFiles).toBe(1);
    expect(result.diagnostics.map((item) => item.code)).toEqual(expect.arrayContaining(["FILE_TOO_LARGE", "BINARY_FILE_SKIPPED"]));
  });

  it("在文件数量超过预算时停止扫描", async () => {
    const cwd = await fixture({ "a.ts": "const a = 1;", "b.ts": "const b = 2;" });
    await expect(scan({ cwd, maxFiles: 1 })).rejects.toThrow("扫描文件数量超过安全限制");
  });

  it("支持规则过滤、标准过滤和严重度覆盖", async () => {
    const cwd = await fixture({ "src/app.ts": "ev" + "al(userInput);\n" });
    const result = await scan({
      cwd,
      standards: ["mitre-cwe"],
      rules: { include: ["security/no-eval"], severityOverrides: { "security/no-eval": "critical" } },
    });
    expect(result.executedRules).toEqual(["security/no-eval"]);
    expect(result.findings[0]?.severity).toBe("critical");
  });

  it("外部扫描器失败时顶层报告为部分完成", async () => {
    const cwd = await fixture({ "src/app.ts": "const safe = true;\n" });
    const module: ScannerModule = {
      id: "test/external",
      version: "1.0.0",
      rules: [],
      scanners: [{ id: "test-scanner", version: "1.0.0", async scan() { return { findings: [], executedRules: ["test/rule"], status: "failed" }; } }],
    };
    const result = await scan({ cwd, modules: [module], moduleIds: [module.id] });
    expect(result.status).toBe("partial");
    expect(result.stages?.find((stage) => stage.phase === "external-scanner")?.status).toBe("partial");
    expect(result.modules?.find((item) => item.id === module.id)?.status).toBe("failed");
  });

  it("合并多根目录时保留同一模块的失败状态和阶段根目录", async () => {
    const first = await fixture({ "src/app.ts": "const safe = true;\n" });
    const second = await fixture({ "src/app.ts": "const safe = true;\n" });
    const module: ScannerModule = {
      id: "test/multi-root",
      version: "1.0.0",
      rules: [],
      scanners: [{ id: "test/multi-root-scanner", version: "1.0.0", async scan(context) {
        if (context.cwd === first) return { findings: [], status: "failed" };
        return { findings: [], status: "succeeded" };
      } }],
    };
    const result = await scanRoots({ roots: [first, second], modules: [module], moduleIds: [module.id] });
    expect(result.modules?.find((item) => item.id === module.id)?.status).toBe("failed");
    expect(result.stages?.filter((stage) => stage.phase === "external-scanner").map((stage) => stage.root)).toEqual([first, second]);
  });

  it("同一个 registry 可以重复执行扫描且不被扫描配置污染", async () => {
    const cwd = await fixture({ "src/app.ts": "const safe = true;\n" });
    const registry: ModuleRegistry = new ScannerModuleRegistry();
    const before = { modules: registry.listModules(), presets: registry.listPresets() };
    await scan({ cwd, registry });
    await expect(scan({ cwd, registry })).resolves.toMatchObject({ status: "succeeded" });
    expect(registry.listModules()).toEqual(before.modules);
    expect(registry.listPresets()).toEqual(before.presets);
  });

  it("拒绝重复规则 ID", async () => {
    const cwd = await fixture({ "src/app.ts": "debugger;" });
    const plugin: ScannerPlugin = {
      name: "duplicate",
      version: "1.0.0",
      rules: [patternRule({
        id: "security/no-eval",
        description: "duplicate",
        severity: "low",
        category: "security",
        pattern: /debugger/,
        message: "duplicate",
        suggestion: "remove",
      })],
    };
    await expect(scan({ cwd, plugins: [plugin] })).rejects.toThrow("规则 ID 重复");
  });
});
