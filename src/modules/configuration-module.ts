import type { ScannerModule } from "../contracts.js";
import { builtinPlugin } from "../builtin-plugin.js";

export const configurationModule: ScannerModule = {
  id: "@lego-scan/configuration",
  version: "0.3.0",
  rules: builtinPlugin.rules.filter((rule) => rule.category === "configuration"),
};
