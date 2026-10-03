import type { ScanPreset } from "../contracts.js";

export const recommendedPreset: ScanPreset = {
  id: "@lego-scan/recommended",
  description: "装配内置安全、凭据、配置与测试积木",
  modules: ["@lego-scan/security", "@lego-scan/credentials", "@lego-scan/configuration", "@lego-scan/testing"],
};
