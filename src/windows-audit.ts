import { execFile } from "node:child_process";
import { promisify } from "node:util";
import os from "node:os";
import type { Finding, ScanDiagnostic, Severity } from "./contracts.js";

const execFileAsync = promisify(execFile);

export interface WindowsAuditResult {
  findings: Finding[];
  diagnostics: ScanDiagnostic[];
  status: "succeeded" | "partial";
  executedRules: string[];
}

type AuditLocationKind = "system" | "registry" | "service" | "policy" | "account" | "network";

export interface AuditCheck {
  id: string;
  title: string;
  severity: Severity;
  category: "security" | "configuration" | "process";
  location: { kind: AuditLocationKind; value: string };
  status: "pass" | "fail" | "unknown";
  message: string;
  suggestion: string;
}

interface SerializedAuditCheck extends Omit<AuditCheck, "location"> {
  kind: AuditLocationKind;
  location: string;
}

const script = String.raw`
$ErrorActionPreference = 'Stop'
$checks = @()
$osInfo = Get-CimInstance Win32_OperatingSystem
$defender = $null
try { $defender = Get-MpComputerStatus } catch {}
$firewall = Get-NetFirewallProfile | ForEach-Object { $_.Enabled } | Where-Object { -not $_ } | Measure-Object | Select-Object -ExpandProperty Count
$uac = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction Stop)
$rdp = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction Stop).fDenyTSConnections
$smb = (Get-SmbServerConfiguration -ErrorAction SilentlyContinue)
$secureBoot = $null
try { $secureBoot = Confirm-SecureBootUEFI } catch {}
$bitlocker = @(Get-BitLockerVolume -ErrorAction SilentlyContinue | Where-Object { $_.VolumeType -eq 'OperatingSystem' -and $_.ProtectionStatus -ne 1 }).Count
$adminCount = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | Where-Object { $_.PrincipalSource -ne 'Microsoft Entra Group' }).Count
$checks += [pscustomobject]@{ id='windows/firewall-disabled'; title='Windows 防火墙未全部启用'; severity='high'; category='configuration'; kind='system'; location='Windows Firewall'; status=if ($firewall -eq 0) { 'pass' } else { 'fail' }; message='至少一个 Windows 防火墙配置文件未启用'; suggestion='启用所有网络配置文件的 Windows 防火墙' }
$checks += [pscustomobject]@{ id='windows/defender-disabled'; title='Microsoft Defender 实时防护未启用'; severity='high'; category='security'; kind='system'; location='Microsoft Defender'; status=if ($null -eq $defender) { 'unknown' } elseif ($defender.RealTimeProtectionEnabled) { 'pass' } else { 'fail' }; message='无法确认或已关闭 Microsoft Defender 实时防护'; suggestion='启用 Microsoft Defender 实时防护并更新安全情报' }
$checks += [pscustomobject]@{ id='windows/uac-disabled'; title='UAC 未启用'; severity='high'; category='configuration'; kind='registry'; location='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; status=if ($uac.EnableLUA -eq 1) { 'pass' } else { 'fail' }; message='用户账户控制 UAC 未启用'; suggestion='启用 UAC（EnableLUA=1）' }
$checks += [pscustomobject]@{ id='windows/rdp-enabled'; title='远程桌面已启用'; severity='medium'; category='configuration'; kind='service'; location='Remote Desktop'; status=if ($rdp -eq 1) { 'pass' } else { 'fail' }; message='检测到远程桌面服务已允许连接'; suggestion='如非必要请关闭远程桌面，并限制网络访问' }
$checks += [pscustomobject]@{ id='windows/smbv1-enabled'; title='SMBv1 已启用'; severity='high'; category='security'; kind='policy'; location='SMB Server'; status=if ($null -eq $smb) { 'unknown' } elseif ($smb.EnableSMB1Protocol) { 'fail' } else { 'pass' }; message='检测到 SMBv1 协议启用或无法确认状态'; suggestion='禁用 SMBv1，使用 SMBv2 或更高版本' }
$checks += [pscustomobject]@{ id='windows/secure-boot-disabled'; title='安全启动未启用'; severity='medium'; category='configuration'; kind='system'; location='UEFI Secure Boot'; status=if ($null -eq $secureBoot) { 'unknown' } elseif ($secureBoot) { 'pass' } else { 'fail' }; message='检测到安全启动未启用或无法确认'; suggestion='在 UEFI 固件中启用 Secure Boot' }
$checks += [pscustomobject]@{ id='windows/system-drive-unencrypted'; title='系统卷未启用 BitLocker'; severity='high'; category='security'; kind='system'; location='BitLocker (Operating System Volume)'; status=if ($bitlocker -eq 0) { 'pass' } else { 'fail' }; message='检测到系统卷未处于受保护状态'; suggestion='为系统卷启用 BitLocker 并安全保存恢复密钥' }
$checks += [pscustomobject]@{ id='windows/excessive-local-admins'; title='本地管理员组成员较多'; severity='low'; category='configuration'; kind='account'; location='Local Administrators'; status=if ($adminCount -le 2) { 'pass' } else { 'fail' }; message="本地管理员组包含 $adminCount 个成员"; suggestion='按最小权限原则清理不必要的本地管理员账户' }
[pscustomobject]@{ os=$osInfo.Caption; version=$osInfo.Version; checks=@($checks) } | ConvertTo-Json -Depth 6 -Compress
`;

function diagnostic(code: string, message: string, details?: Record<string, unknown>): ScanDiagnostic {
  return { code, level: "warning", phase: "external-scanner", message, recoverable: true, ...(details ? { details } : {}) };
}

function finding(check: AuditCheck): Finding | undefined {
  if (check.status === "pass") return undefined;
  return {
    ruleId: check.id,
    message: check.message,
    severity: check.severity,
    confidence: check.status === "unknown" ? "low" : "medium",
    category: check.category,
    file: "[Windows system]",
    scope: "machine",
    location: { kind: check.location.kind, value: check.location.value },
    line: 1,
    column: 1,
    evidence: "[REDACTED]",
    suggestion: check.suggestion,
    references: [{ standard: "mitre-cwe", version: "4.15", control: "CWE-693" }],
    fingerprint: `windows:${check.id}`,
  };
}

export function evaluateWindowsChecks(checks: AuditCheck[]): WindowsAuditResult {
  const unknown = checks.filter((check) => check.status === "unknown");
  return {
    findings: checks.map(finding).filter((item): item is Finding => Boolean(item)),
    diagnostics: unknown.map((check) => diagnostic("WINDOWS_CHECK_UNKNOWN", `无法确认 Windows 检查项：${check.title}`, { ruleId: check.id })),
    status: unknown.length > 0 ? "partial" : "succeeded",
    executedRules: checks.map((check) => check.id).sort(),
  };
}

export async function auditWindowsSystem(): Promise<WindowsAuditResult> {
  if (os.platform() !== "win32") {
    return { findings: [], diagnostics: [diagnostic("WINDOWS_AUDIT_UNSUPPORTED", "Windows 系统审查仅支持 Windows 平台")], status: "partial", executedRules: [] };
  }
  try {
    const { stdout } = await execFileAsync("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script], { windowsHide: true, timeout: 30_000, maxBuffer: 2 * 1024 * 1024 });
    const payload = JSON.parse(stdout.trim()) as { checks?: SerializedAuditCheck[] };
    const checks = (payload.checks ?? []).map(({ kind, location, ...check }): AuditCheck => ({
      ...check,
      location: { kind, value: location },
    }));
    return evaluateWindowsChecks(checks);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { findings: [], diagnostics: [diagnostic("WINDOWS_AUDIT_FAILED", `Windows 系统审查失败：${message}`)], status: "partial", executedRules: [] };
  }
}
