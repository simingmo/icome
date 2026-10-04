export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Confidence = "low" | "medium" | "high";
export type RuleCategory = "security" | "testing" | "configuration" | "dependency" | "process";
export type StandardName = "nist-ssdf" | "owasp-asvs" | "owasp-wstg" | "owasp-samm" | "mitre-cwe";

export interface StandardReference {
  standard: StandardName;
  version: string;
  control: string;
}

export interface Finding {
  ruleId: string;
  message: string;
  severity: Severity;
  confidence: Confidence;
  category: RuleCategory;
  file: string;
  root?: string;
  scope?: "project" | "machine";
  location?: { kind: "file" | "registry" | "service" | "policy" | "account" | "system" | "network"; value: string };
  line: number;
  column: number;
  evidence: string;
  suggestion: string;
  references: readonly StandardReference[];
  fingerprint: string;
}

export interface FileContext {
  absolutePath: string;
  relativePath: string;
  source: string;
  lines: string[];
  isTest: boolean;
}

export interface ScanRule {
  readonly id: string;
  readonly description: string;
  readonly defaultSeverity: Severity;
  readonly defaultConfidence: Confidence;
  readonly category: RuleCategory;
  readonly tags: readonly string[];
  readonly references: readonly StandardReference[];
  supports(context: FileContext): boolean;
  scan(context: FileContext): Finding[] | Promise<Finding[]>;
}

export interface ScannerPlugin {
  readonly name: string;
  readonly version: string;
  readonly rules: readonly ScanRule[];
}

export interface ModuleDependency {
  readonly id: string;
  readonly version?: string;
}

export interface ScannerModule {
  readonly id: string;
  readonly version: string;
  readonly dependencies?: readonly ModuleDependency[];
  readonly conflicts?: readonly string[];
  readonly rules: readonly ScanRule[];
  readonly scanners?: readonly import("./external-scanner.js").ExternalScanner[];
}

export interface ScanPreset {
  readonly id: string;
  readonly description?: string;
  readonly modules: readonly string[];
  readonly rules?: RuleSelection;
  readonly standards?: readonly StandardName[];
}

export interface RuleSelection {
  include?: string[];
  exclude?: string[];
  severityOverrides?: Record<string, Severity>;
}

export interface ScanOptions {
  cwd: string;
  include?: string[];
  exclude?: string[];
  includeTests?: boolean;
  plugins?: ScannerPlugin[];
  modules?: ScannerModule[];
  moduleIds?: string[];
  preset?: string | ScanPreset;
  registry?: ModuleRegistry;
  rules?: RuleSelection;
  standards?: StandardName[];
  maxFiles?: number;
  maxFileBytes?: number;
  maxTotalBytes?: number;
  maxDepth?: number;
}

export interface ModuleRegistry {
  registerModule(module: ScannerModule): void;
  registerPreset(preset: ScanPreset): void;
  getModule(id: string): ScannerModule | undefined;
  getPreset(id: string): ScanPreset | undefined;
  listModules(): readonly ScannerModule[];
  listPresets(): readonly ScanPreset[];
}

export type FindingDispositionStatus = "open" | "acknowledged" | "false-positive" | "accepted-risk" | "fixed" | "wont-fix";

export interface FindingDisposition {
  fingerprint: string;
  status: FindingDispositionStatus;
  note?: string;
  updatedAt: string;
  updatedBy?: string;
}

export interface TriageSummary {
  byStatus: Record<FindingDispositionStatus, number>;
  total: number;
}

export interface ScanCoverage {
  discoveredFiles: number;
  scannedFiles: number;
  skippedFiles: number;
  failedFiles: number;
  scannedBytes: number;
  byLanguage?: Record<string, { discovered: number; scanned: number; skipped: number; failed: number }>;
}

export interface ScanStage {
  phase: ScanDiagnostic["phase"];
  status: "succeeded" | "partial" | "failed" | "skipped";
  durationMs?: number;
  message?: string;
}

export interface ScanModuleReport {
  id: string;
  version: string;
  status: "succeeded" | "partial" | "failed";
  rules: string[];
  externalScanners: string[];
}

export interface ScanMetadata {
  target: string;
  roots?: string[];
  startedAt: string;
  finishedAt: string;
  configuration: {
    include: string[];
    exclude: string[];
    includeTests: boolean;
    standards: StandardName[];
  };
}

export interface ScanSummary {
  bySeverity: Record<Severity, number>;
  byCategory: Partial<Record<RuleCategory, number>>;
  byRule: Record<string, number>;
  byStandard: Partial<Record<StandardName, number>>;
}

export interface ScanDiagnostic {
  code: string;
  level: "info" | "warning" | "error";
  phase: "configuration" | "discovery" | "read" | "rule" | "external-scanner" | "report";
  message: string;
  scannerId?: string;
  ruleId?: string;
  recoverable: boolean;
  details?: Record<string, unknown>;
}

export interface ScanResult {
  schemaVersion: "0.3" | "0.4";
  scanner: { name: "lego-security-scanner"; version: "0.3.0" };
  scannedFiles: number;
  executedRules: string[];
  findings: Finding[];
  summary: ScanSummary;
  durationMs: number;
  status: "succeeded" | "partial" | "failed";
  diagnostics: ScanDiagnostic[];
  metadata?: ScanMetadata;
  coverage?: ScanCoverage;
  scannedFileList?: string[];
  stages?: ScanStage[];
  modules?: ScanModuleReport[];
  triage?: TriageSummary;
  dispositions?: FindingDisposition[];
}
