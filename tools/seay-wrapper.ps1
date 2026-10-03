param(
    [Parameter(Mandatory = $true)][string]$Target,
    [string]$Report = ""
)

$ErrorActionPreference = 'Stop'
$seay = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'seay-app\Seay源代码审计系统.exe'
if (-not (Test-Path $seay)) { throw "Seay executable not found: $seay" }
if ([string]::IsNullOrWhiteSpace($Report)) {
    $Report = Join-Path (Resolve-Path $Target).Path '.seay-report.json'
}

Write-Error 'Seay 2.1 is a Windows GUI application and does not expose a verified headless CLI export contract.'
Write-Error "Run Seay manually, export its report, then convert it to the unified JSON schema at: $Report"
exit 2
