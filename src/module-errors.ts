export type ModuleErrorCode =
  | "DUPLICATE_MODULE"
  | "DUPLICATE_PRESET"
  | "UNKNOWN_PRESET"
  | "MISSING_MODULE"
  | "MISSING_DEPENDENCY"
  | "INCOMPATIBLE_DEPENDENCY_VERSION"
  | "CIRCULAR_DEPENDENCY"
  | "MODULE_CONFLICT"
  | "DUPLICATE_RULE"
  | "DUPLICATE_SCANNER";

export class ModuleResolutionError extends Error {
  constructor(
    readonly code: ModuleErrorCode,
    message: string,
    readonly details: Readonly<Record<string, unknown>> = {},
  ) {
    super(message);
    this.name = "ModuleResolutionError";
  }
}
