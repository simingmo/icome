import type { ScanPreset } from "../contracts.js";

export const auditPreset: ScanPreset = {
  id: "@lego-scan/audit",
  description: "装配全部内置积木：静态代码审计 + 依赖漏洞审计（npm/composer audit、OSV、Git 历史）",
  modules: [
    "@lego-scan/security",
    "@lego-scan/credentials",
    "@lego-scan/configuration",
    "@lego-scan/testing",
    "@lego-scan/dependency-audit",
    "@lego-scan/osv",
    "@lego-scan/git-history",
  ],
};
