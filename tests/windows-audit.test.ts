import { describe, expect, it } from "vitest";
import { auditWindowsSystem } from "../src/windows-audit.js";


describe("Windows 系统审查", () => {
  it("在当前平台返回结构化结果，不抛出异常", async () => {
    const result = await auditWindowsSystem();
    expect(["succeeded", "partial"]).toContain(result.status);
    expect(result.findings).toEqual(expect.any(Array));
    expect(result.diagnostics).toEqual(expect.any(Array));
    for (const finding of result.findings) {
      expect(finding.scope).toBe("machine");
      expect(finding.location?.value).toBeTruthy();
      expect(finding.file).toBe("[Windows system]");
    }
  }, 40_000);
});
