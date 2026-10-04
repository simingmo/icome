import semver from "semver";
import type { ModuleRegistry, ScannerModule } from "./contracts.js";
import { ModuleResolutionError } from "./module-errors.js";

export function resolveModules(registry: ModuleRegistry, requested: readonly string[]): readonly ScannerModule[] {
  const result: ScannerModule[] = [];
  const state = new Map<string, "visiting" | "visited">();
  const stack: string[] = [];

  const visit = (id: string, requiredBy?: string): void => {
    if (state.get(id) === "visited") return;
    if (state.get(id) === "visiting") {
      const start = stack.indexOf(id);
      const cycle = [...stack.slice(start), id];
      throw new ModuleResolutionError("CIRCULAR_DEPENDENCY", `模块存在循环依赖：${cycle.join(" -> ")}`, { cycle });
    }
    const module = registry.getModule(id);
    if (!module) {
      const code = requiredBy ? "MISSING_DEPENDENCY" : "MISSING_MODULE";
      throw new ModuleResolutionError(code, requiredBy ? `模块 ${requiredBy} 缺少依赖：${id}` : `模块不存在：${id}`, { moduleId: id, requiredBy });
    }
    state.set(id, "visiting");
    stack.push(id);
    for (const dependency of module.dependencies ?? []) {
      const target = registry.getModule(dependency.id);
      if (target && dependency.version && !semver.satisfies(target.version, dependency.version)) {
        throw new ModuleResolutionError(
          "INCOMPATIBLE_DEPENDENCY_VERSION",
          `模块 ${module.id} 要求 ${dependency.id}@${dependency.version}，实际为 ${target.version}`,
          { moduleId: module.id, dependencyId: dependency.id },
        );
      }
      visit(dependency.id, module.id);
    }
    stack.pop();
    state.set(id, "visited");
    result.push(module);
  };

  for (const id of [...new Set(requested)]) visit(id);
  const enabled = new Set(result.map((module) => module.id));
  for (const module of result) {
    const conflict = module.conflicts?.find((id) => enabled.has(id));
    if (conflict) {
      throw new ModuleResolutionError("MODULE_CONFLICT", `模块冲突：${module.id} 与 ${conflict} 不能同时启用`, { moduleId: module.id, conflict });
    }
  }
  return result;
}
