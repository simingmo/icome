import type { ScannerModule, ScannerPlugin } from "./contracts.js";

export function pluginToModule(plugin: ScannerPlugin): ScannerModule {
  return { id: plugin.name, version: plugin.version, rules: plugin.rules };
}
