import path from "node:path";
import type { Finding, ScanResult, Severity } from "./contracts.js";

const rank: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

const severityText: Record<Severity, string> = { critical: "严重", high: "高危", medium: "中危", low: "低危", info: "提示" };

export function renderSingleFileReport(file: string, findings: Finding[], root?: string): string {
  const normalized = file.replaceAll("\\", "/");
  const full = root ? path.join(root, normalized) : normalized;
  const ordered = [...findings].sort((a, b) => rank[b.severity] - rank[a.severity]);
  const lines: string[] = [];
  lines.push(`# 检验报告：${path.basename(full)}`, "");
  lines.push(`- 具体路径：\`${full}\``);
  lines.push(`- 文件：${path.basename(full)}`);
  lines.push(`- 检验结果：${ordered.length ? `发现 ${ordered.length} 个问题（最高 ${severityText[ordered[0]!.severity]}）` : "通过检验，未发现问题"}`);
  lines.push(`- 检验时间：${new Date().toLocaleString("zh-CN")}`, "");
  if (!ordered.length) {
    lines.push("本次扫描的所有规则均未在该文件中发现问题，无需修复。", "");
    return lines.join("\n");
  }
  lines.push("| # | 严重度 | 位置（行:列） | 规则 |", "| --- | --- | --- | --- |");
  ordered.forEach((finding, index) => {
    lines.push(`| ${index + 1} | ${severityText[finding.severity]} | ${finding.line}:${finding.column} | \`${finding.ruleId}\` |`);
  });
  lines.push("", "## 漏洞检验明细与修复建议", "");
  ordered.forEach((finding, index) => {
    const references = finding.references.map((item) => `${item.standard}@${item.version}:${item.control}`).join("、");
    lines.push(`### ${index + 1}. [${severityText[finding.severity]}] ${finding.ruleId}`);
    lines.push(`- 位置：第 ${finding.line} 行，第 ${finding.column} 列`);
    lines.push(`- 问题：${finding.message}`);
    lines.push(`- 建议：${finding.suggestion}`);
    if (references) lines.push(`- 参考标准：${references}`);
    lines.push("");
  });
  return lines.join("\n");
}

export function renderFileReport(result: ScanResult, root?: string): string {
  const lines: string[] = [];
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of result.findings) counts[finding.severity] += 1;
  const full = (relative: string) => (root ? path.join(root, relative.replaceAll("\\", "/")) : relative.replaceAll("\\", "/"));
  // 按文件聚合问题，问题内按严重度排序，文件按最高严重度排序
  const byFile = new Map<string, Finding[]>();
  for (const finding of result.findings) {
    const key = finding.file.replaceAll("\\", "/");
    byFile.set(key, [...(byFile.get(key) ?? []), finding]);
  }
  const sortedFindings = (findings: Finding[]) => [...findings].sort((a, b) => rank[b.severity] - rank[a.severity]);
  const sortedFiles = [...byFile.entries()].sort((a, b) => {
    const top = (items: Finding[]) => rank[items[0]!.severity];
    return top(sortedFindings(b[1])) - top(sortedFindings(a[1]));
  });
  const scanned = result.scannedFileList ?? [];
  const cleanFiles = scanned.filter((file) => !byFile.has(file.replaceAll("\\", "/")));
  const now = new Date();
  lines.push("# 文件检验报告", "");
  lines.push(`- 生成时间：${now.toLocaleString("zh-CN")}`);
  if (root) lines.push(`- 扫描根目录：${root}`);
  lines.push(`- 扫描状态：${result.status}（实际检查 ${result.scannedFiles} 个文件，执行 ${result.executedRules.length} 条规则，耗时 ${result.durationMs}ms）`);
  lines.push(`- 检验结论：${result.findings.length ? `发现 ${result.findings.length} 个问题（严重 ${counts.critical} / 高危 ${counts.high} / 中危 ${counts.medium} / 低危 ${counts.low} / 提示 ${counts.info}），涉及 ${sortedFiles.length} 个文件，${cleanFiles.length} 个文件通过检验` : `全部 ${result.scannedFiles} 个文件通过检验，未发现问题`}`, "");
  if (sortedFiles.length) {
    lines.push("## 有问题的文件", "", "| # | 严重度 | 文件路径 | 问题数 |", "| --- | --- | --- | --- |");
    sortedFiles.forEach(([file, findings], index) => {
      lines.push(`| ${index + 1} | ${severityText[findings[0]!.severity]} | \`${full(file)}\` | ${findings.length} |`);
    });
    lines.push("");
  }
  lines.push("## 文件检验明细", "");
  let index = 0;
  for (const [file, findings] of sortedFiles) {
    index += 1;
    const ordered = sortedFindings(findings);
    lines.push(`### ${index}. \`${full(file)}\``, "");
    lines.push(`**检验结果：${findings.length} 个问题（最高 ${severityText[ordered[0]!.severity]}）**`, "");
    lines.push("| 严重度 | 位置（行:列） | 规则 | 问题描述 |", "| --- | --- | --- | --- |");
    for (const finding of ordered) {
      lines.push(`| ${severityText[finding.severity]} | ${finding.line}:${finding.column} | \`${finding.ruleId}\` | ${finding.message.replaceAll("|", "\\|")} |`);
    }
    lines.push("", "**问题描述与修复建议**", "");
    ordered.forEach((finding, position) => {
      const references = finding.references.map((item) => `${item.standard}@${item.version}:${item.control}`).join("、");
      lines.push(`${position + 1}. **[${severityText[finding.severity]}] ${finding.ruleId}**（第 ${finding.line} 行，第 ${finding.column} 列）`);
      lines.push(`   - 问题：${finding.message}`);
      lines.push(`   - 建议：${finding.suggestion}`);
      if (references) lines.push(`   - 参考标准：${references}`);
      lines.push("");
    });
  }
  if (cleanFiles.length) {
    lines.push("## 通过检验的文件（未发现问题）", "");
    for (const file of cleanFiles) lines.push(`- \`${full(file)}\``);
    lines.push("");
  }
  if (result.diagnostics.length) {
    lines.push("## 扫描诊断", "");
    for (const item of result.diagnostics.filter((entry) => entry.level === "error" || entry.level === "warning").slice(0, 20)) {
      lines.push(`- [${item.level}] ${item.message}`);
    }
    lines.push("");
  }
  return lines.join("\n");
}

export function renderConsole(result: ScanResult): string {
  const rows = result.findings.map((finding) => {
    const references = finding.references.map((item) => `${item.standard}@${item.version}:${item.control}`).join(", ");
    const location = finding.location?.value ?? `${finding.file}:${finding.line}:${finding.column}`;
    return `${location}  ${finding.severity.toUpperCase().padEnd(8)} ${finding.ruleId}\n  ${finding.message}\n  置信度：${finding.confidence}${references ? `\n  参考：${references}` : ""}\n  建议：${finding.suggestion}`;
  });
  const coverage = result.coverage
    ? `发现 ${result.coverage.discoveredFiles} 个候选文件，扫描 ${result.coverage.scannedFiles} 个，跳过 ${result.coverage.skippedFiles} 个，失败 ${result.coverage.failedFiles} 个。`
    : `扫描 ${result.scannedFiles} 个文件。`;
  rows.push(`扫描状态：${result.status}。${coverage}执行 ${result.executedRules.length} 条规则，发现 ${result.findings.length} 个问题，耗时 ${result.durationMs}ms。`);
  if (result.diagnostics.length) rows.push(`诊断：${result.diagnostics.filter((item) => item.level === "error").length} 个错误，${result.diagnostics.filter((item) => item.level === "warning").length} 个警告。`);
  if (result.triage) rows.push(`处置：已关联 ${result.triage.total} 个问题状态。`);
  return rows.join("\n\n");
}

export function renderJson(result: ScanResult): string {
  return JSON.stringify(result, null, 2);
}

export function hasFindingAtOrAbove(findings: Finding[], severity: Severity): boolean {
  return findings.some((finding) => rank[finding.severity] >= rank[severity]);
}
