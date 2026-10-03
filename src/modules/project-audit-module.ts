import type { ScannerModule } from "../contracts.js";
import { dependencyAuditModule } from "./dependency-audit-module.js";
import { gitHistoryModule } from "./git-history-module.js";
import { osvModule } from "./osv-module.js";

/** @deprecated 请优先分别启用 dependencyAuditModule、osvModule 和 gitHistoryModule。 */
export const projectAuditModule: ScannerModule = {
  id: "@lego-scan/project-audit",
  version: "0.3.0",
  rules: [],
  scanners: [
    ...(dependencyAuditModule.scanners ?? []),
    ...(osvModule.scanners ?? []),
    ...(gitHistoryModule.scanners ?? []),
  ],
};
