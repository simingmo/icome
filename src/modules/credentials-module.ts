import type { ScannerModule } from "../contracts.js";
import { builtinPlugin } from "../builtin-plugin.js";

export const credentialRuleIds = new Set([
  "security/no-hardcoded-secret",
  "security/no-private-key",
  "security/no-cloud-access-key",
]);

export const credentialsModule: ScannerModule = {
  id: "@lego-scan/credentials",
  version: "0.3.0",
  rules: builtinPlugin.rules.filter((rule) => credentialRuleIds.has(rule.id)),
};
