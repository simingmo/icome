import type { RuleSelection, ScanOptions, ScanPreset, ScannerModule } from "./contracts.js";
import { ModuleResolutionError } from "./module-errors.js";
import { ScannerModuleRegistry } from "./module-registry.js";
import { resolveModules } from "./module-resolver.js";
import { pluginToModule } from "./plugin-adapter.js";
import { builtinModules } from "./modules/builtin-modules.js";
import { auditPreset } from "./presets/audit-preset.js";
import { recommendedPreset } from "./presets/recommended-preset.js";

export interface ResolvedScanConfiguration {
  modules: readonly ScannerModule[];
  rules?: RuleSelection;
  standards?: ScanOptions["standards"];
}

function mergeRules(preset: RuleSelection | undefined, explicit: RuleSelection | undefined): RuleSelection | undefined {
  if (!preset) return explicit;
  if (!explicit) return preset;
  return {
    ...(preset.include ? { include: [...preset.include] } : {}),
    ...(explicit.include ? { include: [...explicit.include] } : {}),
    exclude: [...(preset.exclude ?? []), ...(explicit.exclude ?? [])],
    severityOverrides: { ...(preset.severityOverrides ?? {}), ...(explicit.severityOverrides ?? {}) },
  };
}

export function resolveScanConfiguration(options: ScanOptions): ResolvedScanConfiguration {
  const registry = options.registry ?? new ScannerModuleRegistry();
  const registered = new Set(registry.listModules().map((module) => module.id));
  for (const module of builtinModules) if (!registered.has(module.id)) registry.registerModule(module);
  const presetIds = new Set(registry.listPresets().map((preset) => preset.id));
  if (!presetIds.has(recommendedPreset.id)) registry.registerPreset(recommendedPreset);
  if (!presetIds.has(auditPreset.id)) registry.registerPreset(auditPreset);
  for (const module of options.modules ?? []) registry.registerModule(module);
  for (const plugin of options.plugins ?? []) registry.registerModule(pluginToModule(plugin));

  let preset: ScanPreset | undefined;
  if (typeof options.preset === "string") {
    preset = registry.getPreset(options.preset);
    if (!preset) throw new ModuleResolutionError("UNKNOWN_PRESET", `预设不存在：${options.preset}`, { presetId: options.preset });
  } else if (options.preset) {
    preset = options.preset;
  } else if (!options.moduleIds) {
    preset = recommendedPreset;
  }

  const requested = [
    ...(options.moduleIds ?? preset?.modules ?? []),
    ...(options.plugins ?? []).map((plugin) => plugin.name),
  ];
  const rules = mergeRules(preset?.rules, options.rules);
  const standards = options.standards ?? preset?.standards;
  return {
    modules: resolveModules(registry, requested),
    ...(rules ? { rules } : {}),
    ...(standards ? { standards: [...standards] } : {}),
  };
}
