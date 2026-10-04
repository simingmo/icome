import { describe, expect, it } from "vitest";
import { auditWindowsSystem, evaluateWindowsChecks, type AuditCheck } from "../src/windows-audit.js";

const check = (status: AuditCheck["status"], id = "windows/test"): AuditCheck => ({
  id,
  title: "测试检查",
  severity: "high",
  category: "security",
  location: { kind: "system", value: "Test" },
  status,
  message: "检查未通过或无法确认",
  suggestion: "修复测试配置",
});

describe("Windows 系统审查", () => {
  it("通过检查返回 succeeded 且不产生发现", () => {
    const result = evaluateWindowsChecks([check("pass")]);
    expect(result.status).toBe("succeeded");
    expect(result.findings).toHaveLength(0);
    expect(result.diagnostics).toHaveLength(0);
  });

  it("无法确认的检查返回 partial、诊断和低置信度发现", () => {
    const result = evaluateWindowsChecks([check("unknown")]);
    expect(result.status).toBe("partial");
    expect(result.diagnostics[0]?.code).toBe("WINDOWS_CHECK_UNKNOWN");
    expect(result.findings[0]?.confidence).toBe("low");
  });

  it("在当前平台返回结构化结果，不抛出异常", async () => {
    const result = await auditWindowsSystem();
    expect(["succeeded", "partial"]).toContain(result.status);
    expect(result.findings).toEqual(expect.any(Array));
    expect(result.diagnostics).toEqual(expect.any(Array));
    for (const finding of result.findings) {
      expect(finding.scope).toBe("machine");
      expect(finding.location).toEqual({ kind: expect.any(String), value: expect.any(String) });
      expect(finding.location?.value).not.toBe("");
      expect(finding.file).toBe("[Windows system]");
    }
  }, 40_000);
});
