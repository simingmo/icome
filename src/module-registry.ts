import type { ModuleRegistry, ScanPreset, ScannerModule } from "./contracts.js";
import { ModuleResolutionError } from "./module-errors.js";

export class ScannerModuleRegistry implements ModuleRegistry {
  private readonly modules = new Map<string, ScannerModule>();
  private readonly presets = new Map<string, ScanPreset>();

  registerModule(module: ScannerModule): void {
    if (!module.id.trim()) throw new ModuleResolutionError("DUPLICATE_MODULE", "模块 ID 不能为空");
    if (this.modules.has(module.id)) {
      throw new ModuleResolutionError("DUPLICATE_MODULE", `模块 ID 重复：${module.id}`, { moduleId: module.id });
    }
    this.modules.set(module.id, module);
  }

  registerPreset(preset: ScanPreset): void {
    if (this.presets.has(preset.id)) {
      throw new ModuleResolutionError("DUPLICATE_PRESET", `预设 ID 重复：${preset.id}`, { presetId: preset.id });
    }
    this.presets.set(preset.id, preset);
  }

  getModule(id: string): ScannerModule | undefined { return this.modules.get(id); }
  getPreset(id: string): ScanPreset | undefined { return this.presets.get(id); }
  listModules(): readonly ScannerModule[] { return [...this.modules.values()]; }
  listPresets(): readonly ScanPreset[] { return [...this.presets.values()]; }
}
