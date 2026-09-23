<#
.SYNOPSIS
    Generates BITS job telemetry: job creation, notify command-line configuration, transfer
    attempt/completion and the process creation from the BITS notify command.
.DESCRIPTION
    Self-contained replacement for the Atomic Red Team test with GUID 62a06ec5 (T1197) which
    shells out to bitsadmin.exe and downloads from the internet.

    No internet access is required: the tool serves a file from a local HTTP listener and has
    BITS download it, so the transfer completes on an offline endpoint.

    IMPORTANT: by design, the BITS service requires the job owner to be logged on interactively
    before files can be added and transfers can proceed. Running this tool from a non-interactive
    context (service, WinRM/network logon) fails with 0x800704DD. Run the generator from an
    interactive session on the endpoint, which is the normal execution model.
.NOTES
    Requires the BitsTransfer module (in-box). Part of the Windows Telemetry Generator toolkit.
#>
[CmdletBinding()]
param(
    [string]$JobName = 'AtomicBITS',
    [string]$NotifyCommand = "$env:SystemRoot\System32\notepad.exe",
    [int]$Port = 8123,
    [int]$FileSizeMB = 16,
    [int]$HoldSeconds = 8,
    [switch]$SkipCleanup
)

$ErrorActionPreference = 'Stop'
$err = $false

Write-Host "[*] BITS job telemetry generator (T1197), job name: $JobName"

if (-not (Get-Command Start-BitsTransfer -ErrorAction SilentlyContinue)) {
    throw "The BitsTransfer module is not available on this host."
}
Import-Module BitsTransfer -ErrorAction Stop

$work = Join-Path $env:TEMP 'bits-telemetry'
New-Item -ItemType Directory -Path $work -Force | Out-Null
$src = Join-Path $work 'payload.bin'
$dst = Join-Path $work 'downloaded.bin'

Write-Host "[*] Pre-clean of leftover jobs named $JobName"
Get-BitsTransfer -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq $JobName } | ForEach-Object {
    try { Remove-BitsTransfer -BitsJob $_ -ErrorAction Stop; Write-Host "[*] Removed leftover job $($_.JobId)" }
    catch { Write-Host "[!] Could not remove leftover job $($_.JobId): $($_.Exception.Message)" }
}
Remove-Item $dst -ErrorAction SilentlyContinue

if (-not (Test-Path $src) -or (Get-Item $src).Length -ne ($FileSizeMB * 1MB)) {
    Write-Host "[*] Creating $FileSizeMB MB source file"
    $fs = [IO.File]::Open($src, [IO.FileMode]::Create, [IO.FileAccess]::Write)
    $blk = New-Object byte[] 1048576
    (New-Object Random).NextBytes($blk)
    for ($i = 0; $i -lt $FileSizeMB; $i++) { $fs.Write($blk, 0, $blk.Length) }
    $fs.Close()
}

Write-Host "[*] Starting throttled HTTP server job on port $Port"
$serve = Start-Job -ScriptBlock {
    param($port, $src)
    $l = New-Object System.Net.HttpListener
    $l.Prefixes.Add("http://127.0.0.1:$port/")
    $l.Start()
    for ($r = 0; $r -lt 6; $r++) {
        try { $ctx = $l.GetContext() } catch { break }
        $b = [IO.File]::ReadAllBytes($src)
        $ctx.Response.ContentLength64 = $b.Length
        $ctx.Response.StatusCode = 200
        for ($o = 0; $o -lt $b.Length; $o += 262144) {
            $len = [Math]::Min(262144, $b.Length - $o)
            try { $ctx.Response.OutputStream.Write($b, $o, $len) } catch { break }
            [void]$ctx.Response.OutputStream.Flush()
            Start-Sleep -Milliseconds 150
        }
        try { $ctx.Response.OutputStream.Close(); $ctx.Response.Close() } catch {}
    }
    $l.Stop()
} -ArgumentList $Port, $src
Start-Sleep -Seconds 1

$notepadBefore = @(Get-Process notepad -ErrorAction SilentlyContinue).Count

try {
    Write-Host "[*] Creating BITS job (asynchronous localhost transfer)"
    $job = $null
    try {
        $job = Start-BitsTransfer -Source "http://127.0.0.1:$Port/payload.bin" -Destination $dst -DisplayName $JobName -Asynchronous -ProxyUsage NoProxy -ErrorAction Stop
    }
    catch {
        $job = Start-BitsTransfer -Source "http://127.0.0.1:$Port/payload.bin" -Destination $dst -DisplayName $JobName -Asynchronous -ErrorAction Stop
    }
    Write-Host "[+] Job created: $($job.JobId)"

    Write-Host "[*] Setting notify command line: $NotifyCommand"
    try { $job = Set-BitsTransfer -BitsJob $job -NotifyCmdLine $NotifyCommand, 'NULL' -ErrorAction Stop }
    catch { $job = Set-BitsTransfer -BitsJob $job -NotifyCmdLine $NotifyCommand -ErrorAction Stop }

    Write-Host "[*] Waiting for the transfer to complete"
    $deadline = (Get-Date).AddSeconds(90)
    $state = ''
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 500
        $cur = Get-BitsTransfer -JobId $job.JobId -ErrorAction SilentlyContinue
        if (-not $cur) { $state = 'gone'; break }
        $state = "$($cur.JobState)"
        if ($state -eq 'Transferred' -or $state -eq 'Error' -or $state -eq 'TransientError') { break }
    }
    Write-Host "[*] Transfer state: $state"
    if ($state -ne 'Transferred') { throw "BITS transfer did not complete (state: $state)" }

    Start-Sleep -Seconds 2
    $notepadAfter = @(Get-Process notepad -ErrorAction SilentlyContinue).Count
    Write-Host "[*] Notepad process count before/after: $notepadBefore / $notepadAfter"

    $cur = Get-BitsTransfer -JobId $job.JobId -ErrorAction SilentlyContinue
    if ($cur) { Complete-BitsTransfer -BitsJob $cur -ErrorAction Stop }
    Write-Host "[+] Job completed (BITS runs the notify command on completion)"
    Write-Host "[*] Downloaded file size: $(if (Test-Path $dst) { (Get-Item $dst).Length } else { 'missing' })"
}
catch {
    $msg = $_.Exception.Message
    Write-Host "[!] BITS transfer failed: $msg" -ForegroundColor Red
    if ($msg -match '800704DD' -or $msg -match 'has not logged on') {
        Write-Host "[!] BITS requires the job owner to be logged on interactively. Run the generator in an interactive session on the endpoint." -ForegroundColor Red
    }
    $err = $true
}
finally {
    Write-Host "[*] Holding for $HoldSeconds seconds"
    Start-Sleep -Seconds $HoldSeconds
    if (-not $SkipCleanup) {
        Get-BitsTransfer -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq $JobName } | ForEach-Object {
            try { Remove-BitsTransfer -BitsJob $_ -ErrorAction Stop; Write-Host "[*] Job removed" }
            catch { Write-Host "[!] Could not remove job: $($_.Exception.Message)" }
        }
    }
    Get-Process notepad -ErrorAction SilentlyContinue |
        Where-Object { $_.StartTime -gt (Get-Date).AddMinutes(-5) } |
        Stop-Process -Force -ErrorAction SilentlyContinue
    Stop-Job $serve -ErrorAction SilentlyContinue
    Remove-Job $serve -Force -ErrorAction SilentlyContinue
    Remove-Item $dst -ErrorAction SilentlyContinue
    Remove-Item $src -ErrorAction SilentlyContinue
}

if ($err) { exit 1 }
Write-Host "[*] BITS telemetry generation complete"
exit 0
