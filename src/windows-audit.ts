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

interface AuditCheck {
  id: string;
  title: string;
  severity: Severity;
  category: "security" | "configuration" | "process";
  location: { kind: "system" | "registry" | "service" | "policy" | "account" | "network"; value: string };
  pass: boolean;
  message: string;
  suggestion: string;
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
$checks += [pscustomobject]@{ id='windows/firewall-disabled'; title='Windows 防火墙未全部启用'; severity='high'; category='configuration'; kind='system'; location='Windows Firewall'; pass=($firewall -eq 0); message='至少一个 Windows 防火墙配置文件未启用'; suggestion='启用所有网络配置文件的 Windows 防火墙' }
$checks += [pscustomobject]@{ id='windows/defender-disabled'; title='Microsoft Defender 实时防护未启用'; severity='high'; category='security'; kind='system'; location='Microsoft Defender'; pass=($null -eq $defender -or $defender.RealTimeProtectionEnabled); message='无法确认或已关闭 Microsoft Defender 实时防护'; suggestion='启用 Microsoft Defender 实时防护并更新安全情报' }
$checks += [pscustomobject]@{ id='windows/uac-disabled'; title='UAC 未启用'; severity='high'; category='configuration'; kind='registry'; location='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; pass=($uac.EnableLUA -eq 1); message='用户账户控制 UAC 未启用'; suggestion='启用 UAC（EnableLUA=1）' }
$checks += [pscustomobject]@{ id='windows/rdp-enabled'; title='远程桌面已启用'; severity='medium'; category='configuration'; kind='service'; location='Remote Desktop'; pass=($rdp -eq 1); message='检测到远程桌面服务已允许连接'; suggestion='如非必要请关闭远程桌面，并限制网络访问' }
$checks += [pscustomobject]@{ id='windows/smbv1-enabled'; title='SMBv1 已启用'; severity='high'; category='security'; kind='policy'; location='SMB Server'; pass=($null -eq $smb -or -not $smb.EnableSMB1Protocol); message='检测到 SMBv1 协议启用或无法确认状态'; suggestion='禁用 SMBv1，使用 SMBv2 或更高版本' }
$checks += [pscustomobject]@{ id='windows/secure-boot-disabled'; title='安全启动未启用'; severity='medium'; category='configuration'; kind='system'; location='UEFI Secure Boot'; pass=($secureBoot -ne $false); message='检测到安全启动未启用或无法确认'; suggestion='在 UEFI 固件中启用 Secure Boot' }
$checks += [pscustomobject]@{ id='windows/system-drive-unencrypted'; title='系统卷未启用 BitLocker'; severity='high'; category='security'; kind='system'; location='BitLocker (Operating System Volume)'; pass=($bitlocker -eq 0); message='检测到系统卷未处于受保护状态'; suggestion='为系统卷启用 BitLocker 并安全保存恢复密钥' }
$checks += [pscustomobject]@{ id='windows/excessive-local-admins'; title='本地管理员组成员较多'; severity='low'; category='configuration'; kind='account'; location='Local Administrators'; pass=($adminCount -le 2); message="本地管理员组包含 $adminCount 个成员"; suggestion='按最小权限原则清理不必要的本地管理员账户' }
[pscustomobject]@{ os=$osInfo.Caption; version=$osInfo.Version; checks=@($checks) }
`;

function diagnostic(code: string, message: string, details?: Record<string, unknown>): ScanDiagnostic {
  return { code, level: "warning", phase: "external-scanner", message, recoverable: true, ...(details ? { details } : {}) };
}

function finding(check: AuditCheck): Finding | undefined {
  if (check.pass) return undefined;
  return {
    ruleId: check.id,
    message: check.message,
    severity: check.severity,
    confidence: "medium",
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

export async function auditWindowsSystem(): Promise<WindowsAuditResult> {
  if (os.platform() !== "win32") {
    return { findings: [], diagnostics: [diagnostic("WINDOWS_AUDIT_UNSUPPORTED", "Windows 系统审查仅支持 Windows 平台")], status: "partial", executedRules: [] };
  }
  try {
    const { stdout } = await execFileAsync("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script], { windowsHide: true, timeout: 30_000, maxBuffer: 2 * 1024 * 1024 });
    const payload = JSON.parse(stdout.trim()) as { checks?: AuditCheck[] };
    const checks = payload.checks ?? [];
    return { findings: checks.map(finding).filter((item): item is Finding => Boolean(item)), diagnostics: [], status: "succeeded", executedRules: checks.map((check) => check.id).sort() };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { findings: [], diagnostics: [diagnostic("WINDOWS_AUDIT_FAILED", `Windows 系统审查失败：${message}`)], status: "partial", executedRules: [] };
  }
}
