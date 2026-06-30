# gate-hunt.ps1 - periodically check for a WhatsApp client version the server accepts, and retry
# the wapair registration. The 405 "client outdated" gate opens when Meta's accepted version moves
# and (usually) whatsmeow bumps its pinned waVersion to match. We watch that signal + trackers.
#
# Usage:  powershell -File tools\gate-hunt.ps1
# Logs to gate-hunt.log; on success writes GATE-OPEN.txt and saves the QR output.

param([string]$RepoRoot = (Split-Path -Parent $PSScriptRoot))

$ErrorActionPreference = 'Continue'
$log = Join-Path $RepoRoot 'gate-hunt.log'
$triedFile = Join-Path $RepoRoot '.gate-tried.txt'
function Log($m) { $line = "[{0}] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $m; $line | Tee-Object -FilePath $log -Append }

Log "=== gate-hunt run start ==="

$candidates = New-Object System.Collections.Generic.List[string]

# 1) whatsmeow main pinned waVersion (the maintainer bumps this to the accepted value)
try {
    $cp = (Invoke-WebRequest "https://raw.githubusercontent.com/tulir/whatsmeow/main/store/clientpayload.go" -UseBasicParsing -TimeoutSec 30).Content
    $m = [regex]::Match($cp, 'waVersion = WAVersionContainer\{(\d+),\s*(\d+),\s*(\d+)\}')
    if ($m.Success) { $candidates.Add(("{0}.{1}.{2}" -f $m.Groups[1].Value, $m.Groups[2].Value, $m.Groups[3].Value)) }
} catch { Log ("whatsmeow fetch failed: " + $_.Exception.Message) }

# 2) wppconnect tracker - newest 2.3000.x (strip alpha/beta), take a few highest
try {
    $names = @()
    1..3 | ForEach-Object {
        $page = Invoke-RestMethod "https://api.github.com/repos/wppconnect-team/wa-version/contents/html?per_page=100&page=$_" -Headers @{ 'User-Agent' = 'wa-rs-gate-hunt' } -TimeoutSec 30
        $names += $page.name
    }
    $vers = $names | Where-Object { $_ -match '^2\.3000\.' } |
        ForEach-Object { ($_ -replace '\.html$', '') -replace '-(alpha|beta)$', '' } |
        Sort-Object { [decimal]((($_) -split '\.')[2]) } -Unique
    $vers | Select-Object -Last 3 | ForEach-Object { $candidates.Add($_) }
} catch { Log ("wppconnect fetch failed: " + $_.Exception.Message) }

$tried = @{}
if (Test-Path $triedFile) { Get-Content $triedFile | ForEach-Object { $tried[$_] = $true } }
$fresh = $candidates | Sort-Object -Unique | Where-Object { -not $tried.ContainsKey($_) }

if (-not $fresh) {
    Log ("no new candidate versions since last run (tried " + $tried.Count + "); will recheck next cycle.")
    Log "=== run end ==="
    return
}

Log ("new candidates to try: " + ($fresh -join ', '))

foreach ($v in $fresh) {
    Remove-Item (Join-Path $RepoRoot 'wapair-session.json') -Force -ErrorAction SilentlyContinue
    $env:WAPAIR_VERSION = $v
    $env:WAPAIR_PLATFORM = '14'
    Log ("trying version " + $v + " ...")
    Push-Location $RepoRoot
    $out = (& cargo run -q -p wapair 2>&1 | Out-String)
    Pop-Location
    Add-Content $triedFile $v

    # Check FAILURE first: a 405 run still prints the "waiting for pair-device" status line, so a
    # naive 'pair-device' match would false-positive. Real success = the QR markers below.
    if ($out -match 'reason="405"|client out of date|<failure') {
        Log ("  still 405 (client outdated) with " + $v)
    }
    elseif ($out -match 'got pair-device with \d|wa\.me/settings/linked_devices') {
        Log ("*** GATE OPEN *** version " + $v + " ACCEPTED - pair-device received!")
        ("GATE OPEN with version " + $v + " at " + (Get-Date)) | Out-File (Join-Path $RepoRoot 'GATE-OPEN.txt')
        $out | Out-File (Join-Path $RepoRoot 'gate-open-output.txt')
        Log "QR output saved to gate-open-output.txt"
        Log "=== run end (SUCCESS) ==="
        return
    }
    else {
        $snip = ($out -replace '\s+', ' ')
        if ($snip.Length -gt 240) { $snip = $snip.Substring(0, 240) }
        Log ("  unexpected result with " + $v + ": " + $snip)
    }
}
Log ("gate still closed after trying " + $fresh.Count + " candidate(s).")
Log "=== run end ==="
