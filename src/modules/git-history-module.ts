import type { Finding, ScannerModule } from "../contracts.js";
import type { ExternalScanner, ExternalScanResult } from "../external-scanner.js";
import { refs } from "../standards.js";
import { auditFinding, runAuditCommand } from "./project-audit-utils.js";

const secretReferences = [refs.cwe("CWE-798"), refs.ssdf("PW.9"), refs.asvs("V14.3")];
const historySecret = /(?:AKIA[0-9A-Z]{16}|(?:api[_-]?key|secret|token|password)\s*[:=]\s*["']?[A-Za-z0-9_\-/.+=]{12,}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)/i;
const gitHistoryPattern = "AKIA[0-9A-Z]{16}|(api[_-]?key|secret|token|password)[[:space:]]*[:=][[:space:]]*['\"]?[A-Za-z0-9_./+=-]{12,}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----";

export function parseGitHistory(output: string): Finding[] {
  const findings: Finding[] = [];
  let commit = "unknown";
  let file = ".git/history";
  for (const line of output.split(/\r?\n/)) {
    if (line.startsWith("commit:")) commit = line.slice(7, 19);
    else if (line.startsWith("+++ b/")) file = line.slice(6);
    else if (line.startsWith("+") && !line.startsWith("+++") && historySecret.test(line.slice(1))) {
      findings.push(auditFinding({
        ruleId: "security/git-history-secret", message: "Git 历史中发现疑似凭据。",
        severity: "critical", confidence: "medium", category: "security",
        file, line: 1, column: 1, evidence: `[REDACTED] commit ${commit}`,
        suggestion: "立即轮换凭据，并使用 git filter-repo 等工具从完整历史中清除敏感数据。",
        references: secretReferences,
      }));
    }
  }
  return findings;
}

export const gitHistoryScanner: ExternalScanner = {
  id: "git-history", version: "0.3.0",
  async scan(context): Promise<ExternalScanResult> {
    const result = await runAuditCommand("git", ["log", "--all", "-p", "--no-color", "--format=commit:%H", "--extended-regexp", "--regexp-ignore-case", "-G", gitHistoryPattern], context.cwd, 60_000);
    return { findings: result?.stdout ? parseGitHistory(result.stdout) : [], executedRules: ["security/git-history-secret"] };
  },
};

export const gitHistoryModule: ScannerModule = {
  id: "@lego-scan/git-history",
  version: "0.3.0",
  rules: [],
  scanners: [gitHistoryScanner],
};
