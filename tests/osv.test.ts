import { describe, expect, it } from "vitest";
import { mergeOsvFindings } from "../src/modules/osv-module.js";

describe("mergeOsvFindings", () => {
  it("同一公告跨多包合并为一条，不同公告各自保留", () => {
    const packages = [
      { ecosystem: "npm", name: "vitest", version: "1.0.0", file: "package-lock.json" },
      { ecosystem: "npm", name: "@vitest/mocker", version: "1.0.0", file: "package-lock.json" },
      { ecosystem: "npm", name: "adm-zip", version: "0.5.0", file: "package-lock.json" },
    ] as Parameters<typeof mergeOsvFindings>[0];
    const results = [
      { vulns: [{ id: "GHSA-82fw-gwwq-j7x9", summary: "示例漏洞", database_specific: { severity: "high" } }] },
      { vulns: [{ id: "GHSA-82fw-gwwq-j7x9", summary: "示例漏洞", database_specific: { severity: "high" } }] },
      { vulns: [{ id: "GHSA-xxxx-yyyy-zzzz", summary: "压缩包漏洞", database_specific: { severity: "medium" } }] },
    ] as Parameters<typeof mergeOsvFindings>[1];

    const findings = mergeOsvFindings(packages, results);
    expect(findings).toHaveLength(2);

    const merged = findings.find((finding) => finding.ruleId === "dependency/osv/GHSA-82fw-gwwq-j7x9");
    expect(merged?.message).toContain("vitest");
    expect(merged?.message).toContain("@vitest/mocker");
    expect(merged?.evidence).toContain("vitest@1.0.0");
    expect(merged?.evidence).toContain("@vitest/mocker@1.0.0");
  });

  it("无漏洞时返回空列表", () => {
    const packages = [{ ecosystem: "npm", name: "left-pad", version: "1.3.0", file: "package-lock.json" }] as Parameters<typeof mergeOsvFindings>[0];
    const results = [{ vulns: [] }] as Parameters<typeof mergeOsvFindings>[1];
    expect(mergeOsvFindings(packages, results)).toEqual([]);
  });
});
