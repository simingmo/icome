import { describe, expect, it } from "vitest";
import { createAuditSuiteModule } from "../src/modules/audit-suite-module.js";

const command = {
  command: "tool-wrapper",
  args: ["--target", "{cwd}"],
};

describe("统一审计套件模块", () => {
  it("将 Seay、RIPS 和 VCG 封装为单一模块", () => {
    const module = createAuditSuiteModule({
      seay: command,
      rips: command,
      vcg: command,
    });
    expect(module.id).toBe("@lego-scan/audit-suite");
    expect(module.rules).toEqual([]);
    expect(module.scanners?.map((scanner) => scanner.id)).toEqual(["seay", "rips", "vcg"]);
  });

  it("支持按需启用部分工具", () => {
    const module = createAuditSuiteModule({ seay: false, rips: command, vcg: false });
    expect(module.scanners?.map((scanner) => scanner.id)).toEqual(["rips"]);
  });

  it("拒绝未配置任何工具的空套件", () => {
    expect(() => createAuditSuiteModule({})).toThrow("至少需要启用");
  });
});
