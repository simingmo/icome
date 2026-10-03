import { createHash } from "node:crypto";
import type {
  Confidence,
  Finding,
  RuleCategory,
  ScanRule,
  Severity,
  StandardReference,
} from "./contracts.js";

export interface PatternRuleOptions {
  id: string;
  description: string;
  severity: Severity;
  confidence?: Confidence;
  category: RuleCategory;
  tags?: readonly string[];
  references?: readonly StandardReference[];
  pattern: RegExp;
  message: string;
  suggestion: string;
  testsOnly?: boolean;
  codeOnly?: boolean;
  redactEvidence?: (evidence: string) => string;
}

function fingerprint(ruleId: string, file: string, line: number, column: number, evidence: string): string {
  return createHash("sha256").update(`${ruleId}\0${file}\0${line}\0${column}\0${evidence}`).digest("hex").slice(0, 16);
}

export function patternRule(options: PatternRuleOptions): ScanRule {
  const confidence = options.confidence ?? "medium";
  const references = options.references ?? [];
  const tags = options.tags ?? [];
  return {
    id: options.id,
    description: options.description,
    defaultSeverity: options.severity,
    defaultConfidence: confidence,
    category: options.category,
    tags,
    references,
    supports(context) {
      if (options.testsOnly && !context.isTest) return false;
      if (options.codeOnly && context.isTest) return false;
      return true;
    },
    scan(context) {
      const findings: Finding[] = [];
      context.lines.forEach((line, index) => {
        const flags = options.pattern.flags.includes("g") ? options.pattern.flags : `${options.pattern.flags}g`;
        const pattern = new RegExp(options.pattern.source, flags);
        for (const match of line.matchAll(pattern)) {
          const rawEvidence = match[0].slice(0, 240);
          const evidence = options.redactEvidence?.(rawEvidence) ?? rawEvidence;
          findings.push({
            ruleId: options.id,
            message: options.message,
            severity: options.severity,
            confidence,
            category: options.category,
            file: context.relativePath,
            line: index + 1,
            column: (match.index ?? 0) + 1,
            evidence,
            suggestion: options.suggestion,
            references,
            fingerprint: fingerprint(options.id, context.relativePath, index + 1, (match.index ?? 0) + 1, evidence),
          });
        }
      });
      return findings;
    },
  };
}
