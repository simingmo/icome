import type { IncomingMessage } from "node:http";
import type { AiAnalyzer } from "./ai.js";
import type { ScanResult, ScanOptions } from "./contracts.js";
import type { ProjectLanguage } from "./scan-coverage.js";
import type { ScanTargetKind } from "./scan-target.js";

export type SeverityName = "info" | "low" | "medium" | "high" | "critical";
export type JobStatus = "queued" | "running" | "succeeded" | "partial" | "no-files" | "failed";

export interface PanelOptions {
  host?: string;
  port?: number;
  reportsDir?: string;
  cwd?: string;
  allowedRoots?: string[];
  allowAll?: boolean;
  openBrowser?: boolean;
  maxConcurrency?: number;
  maxQueuedJobs?: number;
  maxRetainedJobs?: number;
  authToken?: string;
  scanRunner?: (options: ScanOptions) => Promise<ScanResult>;
  aiAnalyzer?: AiAnalyzer;
}

export interface Job {
  id: string;
  status: JobStatus;
  createdAt: string;
  sequence: number;
  finishedAt?: string;
  cwd: string;
  scanCwd: string;
  targetKind: ScanTargetKind;
  include?: string[];
  includeTests?: boolean;
  dependencyAudit?: boolean;
  cleanupPath?: string;
  reportsDir: string;
  tools: string[];
  totalFiles: number;
  archiveFiles?: string[];
  languages?: ProjectLanguage[];
  result?: ScanResult;
  error?: string;
}

export interface PublicJob {
  id: string;
  status: JobStatus;
  createdAt: string;
  finishedAt?: string;
  target: string;
  targetKind: ScanTargetKind;
  tools: string[];
  dependencyAudit?: boolean;
  totalFiles: number;
  languages?: ProjectLanguage[];
  result?: ScanResult;
  error?: string;
}

export interface ToolStatus {
  id: "seay" | "rips" | "vcg";
  label: string;
  available: boolean;
  reason?: string;
}

export interface DashboardReport {
  id: string;
  fingerprint?: string;
  reportName: string;
  scanPath: string;
  filePath: string;
  reportPath: string;
  severity: SeverityName;
  status: JobStatus;
  problem: string;
  suggestion: string;
  error: string;
}

export interface DashboardPayload {
  scope: "latest" | "all";
  latestJobId: string | undefined;
  jobs: number;
  findings: number;
  high: number;
  files: number;
  totalFiles: number;
  truncated: number;
  page: number;
  pageSize: number;
  totalReports: number;
  severity: Record<SeverityName, number>;
  reports: DashboardReport[];
}

export type AuthorizedRequest = IncomingMessage;
