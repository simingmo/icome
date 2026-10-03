import type { ScannerModule } from "../contracts.js";
import { createCommandScanner, type CommandScannerOptions } from "../external-scanner.js";

export type ExternalToolModuleOptions = Omit<CommandScannerOptions, "id">;

function createExternalToolModule(id: string, scannerId: string, options: ExternalToolModuleOptions): ScannerModule {
  return {
    id,
    version: "0.3.0",
    rules: [],
    scanners: [createCommandScanner({ id: scannerId, ...options })],
  };
}

export function createSeayModule(options: ExternalToolModuleOptions): ScannerModule {
  return createExternalToolModule("@lego-scan/seay", "seay", options);
}

export function createRipsModule(options: ExternalToolModuleOptions): ScannerModule {
  return createExternalToolModule("@lego-scan/rips", "rips", options);
}

export function createVcgModule(options: ExternalToolModuleOptions): ScannerModule {
  return createExternalToolModule("@lego-scan/vcg", "vcg", options);
}
