<#
.SYNOPSIS
    Generates driver load telemetry by loading a stock in-box kernel driver through the service
    control manager (SCM).
.DESCRIPTION
    Self-contained replacement for the Atomic Red Team test with GUID 24a12b91 (mislabeled
    T1562.001; the driver lifecycle technique) which downloads Backstab64.exe from GitHub.

    The tool creates a kernel-mode service for an in-box driver and starts it, which produces
    Driver Loaded telemetry, then attempts to stop it (Driver Unloaded telemetry) and deletes
    the service.

    Most Windows 11 in-box drivers do not implement an unload routine: the stop attempt fails with
    error 1052 ("the requested control is not valid for this service") and the loaded driver stays
    resident until the next reboot. rdpdr.sys is the exception and is the first default candidate,
    so a default run produces a real load+unload cycle. Point -DriverPath at a lab-signed driver
    for other cases.
.NOTES
    Requires administrator rights. Part of the Windows Telemetry Generator toolkit.
#>
[CmdletBinding()]
param(
    [string]$DriverPath,
    [string]$ServiceName,
    [int]$HoldSeconds = 5,
    [switch]$SkipCleanup
)

$ErrorActionPreference = 'Stop'

if (-not $ServiceName) {
    $suffix = -join ((97..122) | Get-Random -Count 6 | ForEach-Object { [char]$_ })
    $ServiceName = "hpa_telemetry_$suffix"
}

$src = @"
using System;
using System.Runtime.InteropServices;
public static class HpaTelemetryScm {
    [StructLayout(LayoutKind.Sequential)]
    public struct SERVICE_STATUS { public uint dwServiceType; public uint dwCurrentState; public uint dwControlsAccepted; public uint dwWin32ExitCode; public uint dwServiceSpecificExitCode; public uint dwCheckPoint; public uint dwWaitHint; }
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)] private static extern IntPtr OpenSCManager(string machine, string database, uint access);
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)] private static extern IntPtr CreateService(IntPtr hSCM, string name, string display, uint access, uint type, uint start, uint err, string bin, string group, IntPtr tag, string deps, string user, string pw);
    [DllImport("advapi32.dll", SetLastError=true)] private static extern bool StartService(IntPtr h, uint n, IntPtr args);
    [DllImport("advapi32.dll", SetLastError=true)] private static extern bool ControlService(IntPtr h, uint ctrl, ref SERVICE_STATUS st);
    [DllImport("advapi32.dll", SetLastError=true)] private static extern bool DeleteService(IntPtr h);
    [DllImport("advapi32.dll", SetLastError=true)] private static extern bool CloseServiceHandle(IntPtr h);
    public static IntPtr OpenSCMLocal(uint access) { return OpenSCManager(null, null, access); }
    public static IntPtr CreateDriver(IntPtr scm, string name, string display, string binPath) {
        return CreateService(scm, name, display, 0xF01FFu, 0x1u, 0x3u, 0x1u, binPath, null, IntPtr.Zero, null, null, null);
    }
    public static bool Start(IntPtr h) { return StartService(h, 0, IntPtr.Zero); }
    public static bool Stop(IntPtr h) { SERVICE_STATUS s = new SERVICE_STATUS(); return ControlService(h, 0x1u, ref s); }
    public static bool Delete(IntPtr h) { return DeleteService(h); }
    public static bool Close(IntPtr h) { return CloseServiceHandle(h); }
    public static int LastErr() { return Marshal.GetLastWin32Error(); }
}
"@
Add-Type -TypeDefinition $src -ErrorAction Stop

Write-Host "[*] Driver telemetry generator (T1685), service name: $ServiceName"

$candidateDrivers = @('rdpdr.sys', 'hidbth.sys', 'hidir.sys', 'btha2dp.sys', 'sfloppy.sys', 'flpydisk.sys', 'swenum.sys', 'parport.sys', 'mskssrv.sys', 'mspclock.sys', 'mspqm.sys', 'wimmount.sys', 'FsDepends.sys', 'scfilter.sys', 'rdpbus.sys', 'tsusbhub.sys')
$driversDir = Join-Path $env:SystemRoot 'System32\drivers'
if ($DriverPath) {
    $drivers = @($DriverPath)
}
else {
    $drivers = @($candidateDrivers | ForEach-Object { Join-Path $driversDir $_ } | Where-Object { Test-Path $_ })
}
if ($drivers.Count -eq 0) {
    Write-Host "[!] No usable driver image found" -ForegroundColor Red
    exit 1
}

$loaded = $false
$handle = [IntPtr]::Zero
$scm = [IntPtr]::Zero
$loadedDriver = ''

foreach ($driver in $drivers) {
    Write-Host "[*] Trying driver: $driver"
    $scm = [HpaTelemetryScm]::OpenSCMLocal(0x2)
    if ($scm -eq [IntPtr]::Zero) {
        Write-Host "[!] OpenSCManager failed err=$([HpaTelemetryScm]::LastErr())" -ForegroundColor Red
        exit 1
    }
    $handle = [HpaTelemetryScm]::CreateDriver($scm, $ServiceName, 'Windows Telemetry Generator driver test', $driver)
    if ($handle -eq [IntPtr]::Zero) {
        Write-Host "[!] CreateService failed err=$([HpaTelemetryScm]::LastErr()) for $driver" -ForegroundColor Yellow
        [HpaTelemetryScm]::Close($scm) | Out-Null
        continue
    }
    Write-Host "[+] Kernel service created"
    if ([HpaTelemetryScm]::Start($handle)) {
        Write-Host "[+] Driver loaded (Driver Loaded telemetry)"
        $loaded = $true
        $loadedDriver = $driver
        break
    }
    Write-Host "[!] StartService failed err=$([HpaTelemetryScm]::LastErr()) for $driver" -ForegroundColor Yellow
    [HpaTelemetryScm]::Delete($handle) | Out-Null
    [HpaTelemetryScm]::Close($handle) | Out-Null
    [HpaTelemetryScm]::Close($scm) | Out-Null
    $handle = [IntPtr]::Zero
    $scm = [IntPtr]::Zero
}

if (-not $loaded) {
    Write-Host "[!] Could not load any candidate driver" -ForegroundColor Red
    exit 1
}
Write-Host "[*] Loaded driver: $loadedDriver"

Write-Host "[*] Holding for $HoldSeconds seconds"
Start-Sleep -Seconds $HoldSeconds
Start-Sleep -Seconds 2

Write-Host "[*] Attempting unload (Driver Unloaded telemetry)"
if ([HpaTelemetryScm]::Stop($handle)) {
    Write-Host "[+] Driver unloaded"
    Start-Sleep -Seconds 2
}
else {
    Write-Host "[!] StopService failed err=$([HpaTelemetryScm]::LastErr()) - in-box drivers do not support dynamic unload; the driver stays loaded until reboot" -ForegroundColor Yellow
}

if (-not $SkipCleanup) {
    $deleted = [HpaTelemetryScm]::Delete($handle)
    Write-Host "[*] Service delete requested: $deleted"
    [HpaTelemetryScm]::Close($handle) | Out-Null
    [HpaTelemetryScm]::Close($scm) | Out-Null
}

Write-Host "[*] Driver telemetry generation complete"
exit 0
