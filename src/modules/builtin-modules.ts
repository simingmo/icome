import type { ScannerModule } from "../contracts.js";
import { builtinPlugin } from "../builtin-plugin.js";
import { configurationModule } from "./configuration-module.js";
import { credentialRuleIds, credentialsModule } from "./credentials-module.js";
import { dependencyAuditModule } from "./dependency-audit-module.js";
import { gitHistoryModule } from "./git-history-module.js";
import { osvModule } from "./osv-module.js";

const rules = builtinPlugin.rules;

export const securityModule: ScannerModule = {
  id: "@lego-scan/security",
  version: "0.3.0",
  rules: rules.filter((rule) => rule.category === "security" && !credentialRuleIds.has(rule.id)),
};

export { configurationModule, credentialsModule, dependencyAuditModule, osvModule, gitHistoryModule };

export const testingModule: ScannerModule = {
  id: "@lego-scan/testing",
  version: "0.3.0",
  rules: rules.filter((rule) => rule.category === "testing"),
};

export const builtinModules: readonly ScannerModule[] = [
  securityModule,
  configurationModule,
  testingModule,
  credentialsModule,
  dependencyAuditModule,
  osvModule,
  gitHistoryModule,
];
