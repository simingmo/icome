import type { ScanOptions, ScanResult, ScannerModule } from "../contracts.js";
import type { ExternalToolModuleOptions } from "./external-tool-modules.js";
import { createRipsModule, createSeayModule, createVcgModule } from "./external-tool-modules.js";
import { scan } from "../scanner.js";
import { builtinModules } from "./builtin-modules.js";

export interface AuditSuiteOptions {
  seay?: ExternalToolModuleOptions | false;
  rips?: ExternalToolModuleOptions | false;
  vcg?: ExternalToolModuleOptions | false;
}

export interface AuditSuiteScanOptions extends Omit<ScanOptions, "modules" | "moduleIds"> {
  tools: AuditSuiteOptions;
  modules?: ScannerModule[];
}

export function createAuditSuiteModule(options: AuditSuiteOptions): ScannerModule {
  const scanners = [
    ...(options.seay ? createSeayModule(options.seay).scanners ?? [] : []),
    ...(options.rips ? createRipsModule(options.rips).scanners ?? [] : []),
    ...(options.vcg ? createVcgModule(options.vcg).scanners ?? [] : []),
  ];
  if (scanners.length === 0) throw new Error("审计套件至少需要启用 Seay、RIPS 或 VCG 中的一个工具。");
  return {
    id: "@lego-scan/audit-suite",
    version: "0.3.0",
    rules: [],
    scanners,
  };
}

export async function scanWithAuditSuite(options: AuditSuiteScanOptions): Promise<ScanResult> {
  const suite = createAuditSuiteModule(options.tools);
  const modules = [...builtinModules, ...(options.modules ?? []), suite];
  return await scan({
    ...options,
    modules,
    moduleIds: [...builtinModules.map((module) => module.id), ...(options.modules ?? []).map((module) => module.id), suite.id],
  });
}
