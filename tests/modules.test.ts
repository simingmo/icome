import { describe, expect, it } from "vitest";
import type { ScannerModule } from "../src/contracts.js";
import { ModuleResolutionError } from "../src/module-errors.js";
import { ScannerModuleRegistry } from "../src/module-registry.js";
import { resolveModules } from "../src/module-resolver.js";
import { builtinModules } from "../src/modules/builtin-modules.js";

const moduleOf = (id: string, dependencies: ScannerModule["dependencies"] = []): ScannerModule => ({
  id,
  version: "1.0.0",
  dependencies,
  rules: [],
});

describe("乐高模块装配", () => {
  it("按依赖优先顺序装配积木", () => {
    const registry = new ScannerModuleRegistry();
    registry.registerModule(moduleOf("base"));
    registry.registerModule(moduleOf("security", [{ id: "base", version: "^1.0.0" }]));
    registry.registerModule(moduleOf("company", [{ id: "security" }]));
    expect(resolveModules(registry, ["company"]).map((item) => item.id)).toEqual(["base", "security", "company"]);
  });

  it("拒绝循环依赖", () => {
    const registry = new ScannerModuleRegistry();
    registry.registerModule(moduleOf("a", [{ id: "b" }]));
    registry.registerModule(moduleOf("b", [{ id: "a" }]));
    expect(() => resolveModules(registry, ["a"])).toThrowError(ModuleResolutionError);
    expect(() => resolveModules(registry, ["a"])).toThrow("a -> b -> a");
  });

  it("拒绝冲突模块和不兼容依赖版本", () => {
    const conflicts = new ScannerModuleRegistry();
    conflicts.registerModule({ ...moduleOf("strict"), conflicts: ["legacy"] });
    conflicts.registerModule(moduleOf("legacy"));
    expect(() => resolveModules(conflicts, ["strict", "legacy"])).toThrow("模块冲突");

    const versions = new ScannerModuleRegistry();
    versions.registerModule(moduleOf("base"));
    versions.registerModule(moduleOf("consumer", [{ id: "base", version: "^2.0.0" }]));
    expect(() => resolveModules(versions, ["consumer"])).toThrow("实际为 1.0.0");
  });

  it("将依赖、OSV、Git、配置和凭据注册为独立模块", () => {
    const ids = builtinModules.map((module) => module.id);
    expect(ids).toEqual(expect.arrayContaining([
      "@lego-scan/dependency-audit",
      "@lego-scan/osv",
      "@lego-scan/git-history",
      "@lego-scan/configuration",
      "@lego-scan/credentials",
    ]));
    const ruleIds = builtinModules.flatMap((module) => module.rules.map((rule) => rule.id));
    expect(new Set(ruleIds).size).toBe(ruleIds.length);
    const scannerIds = builtinModules.flatMap((module) => (module.scanners ?? []).map((scanner) => scanner.id));
    expect(scannerIds).toEqual(expect.arrayContaining(["npm-audit", "composer-audit", "osv", "git-history"]));
    expect(new Set(scannerIds).size).toBe(scannerIds.length);
  });

  it("拒绝重复模块和预设", () => {
    const registry = new ScannerModuleRegistry();
    registry.registerModule(moduleOf("base"));
    expect(() => registry.registerModule(moduleOf("base"))).toThrow("模块 ID 重复");
    registry.registerPreset({ id: "recommended", modules: ["base"] });
    expect(() => registry.registerPreset({ id: "recommended", modules: [] })).toThrow("预设 ID 重复");
  });
});
