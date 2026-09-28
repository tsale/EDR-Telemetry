<#
.SYNOPSIS
    Generates driver modification telemetry by changing a disposable, never-loaded copy of a
    kernel driver image and then restoring it.
.DESCRIPTION
    The tool copies a stock in-box driver to a uniquely named image in the Windows drivers
    directory and registers it as a stopped demand-start kernel service, so the file is a real
    registered driver image. It records the file identity (size and SHA-256), appends a fixed
    benign eight-byte marker to the stopped file (a real content change of the .sys image),
    verifies the new identity against a local modification oracle, and holds so that sensors
    can observe the change. The copy is never started or loaded, and the source driver and its
    service are never touched.

    Afterwards the original bytes are restored from the in-box source, the restored hash is
    confirmed to match, and the service and the copy are removed. Cleanup always runs, also
    when the transaction fails part-way.

    Exit codes:
      0 = modification executed, verified, restored and cleaned up
      1 = the transaction or its cleanup failed (details are printed and, when -ResultPath is
          used, recorded in the JSON result)
.NOTES
    Requires administrator rights. Part of the Windows Telemetry Generator toolkit.
#>
[CmdletBinding()]
param(
    [string]$SourceDriverPath,
    [string]$TargetPath,
    [string]$ServiceName,
    [int]$HoldSeconds = 20,
    [string]$ResultPath
)

$ErrorActionPreference = 'Stop'

$suffix = -join ((97..122) | Get-Random -Count 6 | ForEach-Object { [char]$_ })
if (-not $ServiceName) { $ServiceName = "hpa_drvmod_$suffix" }
$driversDir = Join-Path $env:SystemRoot 'System32\drivers'
if (-not $TargetPath) { $TargetPath = Join-Path $driversDir "hpa_drvmod_$suffix.sys" }

# In-box sources; the unload-capable set first for consistency with the load/unload script.
# Any stock .sys image works here: the copy is never started or loaded.
$candidateDrivers = @('wimmount.sys', 'applockerfltr.sys', 'ndisuio.sys', 'wcnfs.sys', 'hidbth.sys', 'hidir.sys', 'btha2dp.sys', 'sfloppy.sys', 'flpydisk.sys', 'swenum.sys', 'parport.sys', 'mskssrv.sys', 'mspclock.sys', 'mspqm.sys', 'FsDepends.sys', 'scfilter.sys', 'rdpbus.sys', 'tsusbhub.sys')
if (-not $SourceDriverPath) {
    $SourceDriverPath = $candidateDrivers |
        ForEach-Object { Join-Path $driversDir $_ } |
        Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
        Select-Object -First 1
}
if (-not $SourceDriverPath -or -not (Test-Path -LiteralPath $SourceDriverPath -PathType Leaf)) {
    Write-Host "[!] No source driver image found" -ForegroundColor Red
    exit 1
}

# Fixed benign marker: ASCII "TELEMGEN".
$marker = [byte[]](0x54, 0x45, 0x4C, 0x45, 0x4D, 0x47, 0x45, 0x4E)

$log = [ordered]@{
    hostname   = $env:COMPUTERNAME
    source     = $SourceDriverPath
    target     = $TargetPath
    service    = $ServiceName
    start_utc  = (Get-Date).ToUniversalTime().ToString('o')
    operations = @()
    cleanup    = @()
}
$createdService = $false
$createdFile = $false
$failed = $false
$cleanupOk = $true
$sourceHash = $null

Write-Host "[*] Driver modification telemetry generator, service name: $ServiceName"
Write-Host "[*] Source driver: $SourceDriverPath"
Write-Host "[*] Disposable copy: $TargetPath"

try {
    if (Test-Path -LiteralPath $TargetPath) { throw "the unique target path already exists: $TargetPath" }
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) { throw "the unique service already exists: $ServiceName" }
    if (Get-CimInstance Win32_SystemDriver -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue) { throw "the unique driver service already exists: $ServiceName" }

    $sourceHash = (Get-FileHash -LiteralPath $SourceDriverPath -Algorithm SHA256).Hash
    Copy-Item -LiteralPath $SourceDriverPath -Destination $TargetPath -ErrorAction Stop
    $createdFile = $true
    $copyHash = (Get-FileHash -LiteralPath $TargetPath -Algorithm SHA256).Hash
    if ($copyHash -ne $sourceHash) { throw 'copy hash mismatch after Copy-Item' }
    $log.operations += @{ action = 'create_disposable_copy'; time_utc = (Get-Date).ToUniversalTime().ToString('o'); sha256 = $copyHash }

    $binPath = $TargetPath
    $driversPrefix = Join-Path $env:SystemRoot 'System32\drivers\'
    if ($binPath.StartsWith($driversPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        $binPath = '\SystemRoot\System32\drivers\' + (Split-Path $binPath -Leaf)
    }
    $createOut = & sc.exe create $ServiceName type= kernel start= demand binPath= $binPath DisplayName= $ServiceName 2>&1
    $createExit = $LASTEXITCODE
    $log.operations += @{ action = 'register_stopped_demand_start_service'; time_utc = (Get-Date).ToUniversalTime().ToString('o'); exit = $createExit; output = ($createOut | Out-String).Trim() }
    if ($createExit -ne 0) { throw "service creation failed with exit code $createExit" }
    $createdService = $true

    $svc = Get-CimInstance Win32_SystemDriver -Filter "Name='$ServiceName'"
    if (-not $svc -or $svc.StartMode -ne 'Manual' -or $svc.State -ne 'Stopped') { throw 'the disposable driver service is not stopped/manual; refusing to modify the image' }

    $beforeHash = (Get-FileHash -LiteralPath $TargetPath -Algorithm SHA256).Hash
    $beforeBytes = (Get-Item -LiteralPath $TargetPath).Length
    Write-Host "[*] Appending benign marker 'TELEMGEN' to the stopped copy"
    $stream = [IO.File]::Open($TargetPath, [IO.FileMode]::Append, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try { $stream.Write($marker, 0, $marker.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    $modifyUtc = (Get-Date).ToUniversalTime().ToString('o')
    $afterHash = (Get-FileHash -LiteralPath $TargetPath -Algorithm SHA256).Hash
    $afterBytes = (Get-Item -LiteralPath $TargetPath).Length
    if ($afterHash -eq $beforeHash -or $afterBytes -ne ($beforeBytes + $marker.Length)) {
        throw 'modification oracle failed: the file identity did not change as expected'
    }
    $log.before = @{ sha256 = $beforeHash; bytes = $beforeBytes }
    $log.after = @{ sha256 = $afterHash; bytes = $afterBytes }
    $log.modify_utc = $modifyUtc
    $log.operations += @{ action = 'append_marker_to_stopped_driver_copy'; time_utc = $modifyUtc; marker_base64 = [Convert]::ToBase64String($marker) }
    Write-Host "[+] Driver copy modified: +$($marker.Length) bytes; sha256 $beforeHash -> $afterHash"

    Write-Host "[*] Holding for $HoldSeconds seconds"
    Start-Sleep -Seconds $HoldSeconds
}
catch {
    $failed = $true
    $log.error = $_.Exception.Message
    Write-Host "[!] $($_.Exception.Message)" -ForegroundColor Red
}
finally {
    if ($createdFile -and (Test-Path -LiteralPath $TargetPath)) {
        try {
            Copy-Item -LiteralPath $SourceDriverPath -Destination $TargetPath -Force -ErrorAction Stop
            $restored = (Get-FileHash -LiteralPath $TargetPath -Algorithm SHA256).Hash
            $log.cleanup += @{ action = 'restore_original_bytes'; time_utc = (Get-Date).ToUniversalTime().ToString('o'); sha256 = $restored; matches_source = ($restored -eq $sourceHash) }
        }
        catch {
            $cleanupOk = $false
            $log.cleanup += @{ action = 'restore_failed'; error = $_.Exception.Message }
        }
    }
    if ($createdService) {
        try {
            $state = (Get-CimInstance Win32_SystemDriver -Filter "Name='$ServiceName'").State
            if ($state -ne 'Stopped') { throw "unsafe service state $state" }
            $delOut = & sc.exe delete $ServiceName 2>&1
            $log.cleanup += @{ action = 'delete_disposable_service'; exit = $LASTEXITCODE; output = ($delOut | Out-String).Trim() }
        }
        catch {
            $cleanupOk = $false
            $log.cleanup += @{ action = 'service_cleanup_failed'; error = $_.Exception.Message }
        }
    }
    if ($createdFile) {
        try {
            Remove-Item -LiteralPath $TargetPath -Force -ErrorAction Stop
            $log.cleanup += @{ action = 'delete_disposable_copy'; absent = (-not (Test-Path -LiteralPath $TargetPath)) }
        }
        catch {
            $cleanupOk = $false
            $log.cleanup += @{ action = 'copy_cleanup_failed'; error = $_.Exception.Message }
        }
    }
    $log.final_utc = (Get-Date).ToUniversalTime().ToString('o')
}

if ($ResultPath) { ($log | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath $ResultPath }
$log | ConvertTo-Json -Depth 8 -Compress | Write-Host

if ($failed -or -not $cleanupOk) {
    Write-Host "[!] Driver modification telemetry generation failed (exit 1)" -ForegroundColor Red
    exit 1
}
Write-Host "[*] Driver modification telemetry generation complete (modified, restored and cleaned up)"
exit 0
