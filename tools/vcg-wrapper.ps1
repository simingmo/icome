param(
    [Parameter(Mandatory = $true)][string]$Target,
    [ValidateSet('CPP','PLSQL','JAVA','CS','VB','PHP','COBOL','R')][string]$Language = 'PHP'
)

$ErrorActionPreference = 'Stop'
$tools = Split-Path -Parent $MyInvocation.MyCommand.Path
$vcg = Join-Path $tools 'vcg-app\VisualCodeGrepper.exe'
if (-not (Test-Path $vcg)) { throw "VCG executable not found: $vcg" }
$targetPath = (Resolve-Path $Target).Path
$report = Join-Path ([System.IO.Path]::GetTempPath()) ("vcg-{0}.xml" -f [guid]::NewGuid())
try {
    $process = Start-Process -FilePath $vcg -ArgumentList @('-c','-t',"`"$targetPath`"",'-l',$Language,'-x',"`"$report`"") -Wait -PassThru -WindowStyle Hidden
    if ($process.ExitCode -ne 0) { throw "VCG exited with code $($process.ExitCode)" }
    if (-not (Test-Path $report)) { throw 'VCG did not generate an XML report.' }
    [xml]$xml = Get-Content -LiteralPath $report -Raw
    $findings = @($xml.CodeIssueCollection.CodeIssue | ForEach-Object {
        $file = [string]$_.FileName
        if ([System.IO.Path]::IsPathRooted($file)) { $file = [System.IO.Path]::GetRelativePath($targetPath, $file) }
        [ordered]@{
            ruleId = (([string]$_.Title).ToLowerInvariant() -replace '[^a-z0-9]+','-').Trim('-')
            message = [string]$_.Title
            severity = ([string]$_.Severity).ToLowerInvariant()
            confidence = 'medium'
            category = 'security'
            file = $file
            line = [Math]::Max(1, [int]$_.Line)
            column = 1
            evidence = [string]$_.CodeLine
            suggestion = [string]$_.Description
            references = @()
        }
    })
    @{ findings = $findings } | ConvertTo-Json -Depth 6
} finally {
    Remove-Item -LiteralPath $report -Force -ErrorAction SilentlyContinue
}
