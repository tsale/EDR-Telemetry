<#
.SYNOPSIS
    Generates driver load/unload telemetry by loading a kernel driver image through the service
    control manager (SCM) and stopping it again.
.DESCRIPTION
    Self-contained replacement for the Atomic Red Team test with GUID 24a12b91 (mislabeled
    T1562.001; the driver lifecycle technique) which downloads Backstab64.exe from GitHub.

    The tool starts a candidate kernel driver image, verifies with an independent kernel module
    snapshot (NtQuerySystemInformation / SystemModuleInformation) that the image is actually
    resident (Driver Loaded telemetry), then stops it and verifies the image is gone again
    (Driver Unloaded telemetry). A successful service control call therefore cannot masquerade
    as a kernel image transition.

    Candidates whose image is already resident are skipped: loading a second service for an
    already-loaded image does not produce a fresh image-load transition. The default candidate
    list starts with in-box driver images verified to support dynamic unload - the stop
    succeeds and the image disappears from the kernel module list: wimmount.sys,
    applockerfltr.sys, ndisuio.sys and wcnfs.sys. For those, the driver's own stopped service
    is used when present and is left in place afterwards. All other candidates are fallbacks
    that still produce Driver Loaded telemetry: most of them do not implement an unload
    routine, so their stop fails with error 1052 and the resident image stays until reboot
    (exit 2, Driver Loaded telemetry only).

    rdpdr.sys is deliberately not in the default candidate list: stopping it can disrupt
    active RDP sessions. Pass -DriverPath to test a specific image instead. Endpoint
    protection products with kernel driver-load protection (for example Sophos) can block or
    quarantine non-in-box driver images, so prefer the in-box candidates on such endpoints.

    Exit codes:
      0 = driver image load and unload were both verified (full telemetry generated)
      1 = no candidate driver could be loaded (nothing generated)
      2 = driver image loaded but the stop did not unload it; the image stays resident until
          the next reboot (Driver Loaded telemetry only)
.NOTES
    Requires administrator rights. Part of the Windows Telemetry Generator toolkit.
#>
[CmdletBinding()]
param(
    [string]$DriverPath,
    [string]$ServiceName,
    [int]$HoldSeconds = 20,
    [switch]$SkipCleanup
)

$ErrorActionPreference = 'Stop'

if (-not $ServiceName) {
    $suffix = -join ((97..122) | Get-Random -Count 6 | ForEach-Object { [char]$_ })
    $ServiceName = "hpa_telemetry_$suffix"
}

$src = @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
public static class HpaTelemetryScm {
    [StructLayout(LayoutKind.Sequential)] public struct SERVICE_STATUS { public uint dwServiceType; public uint dwCurrentState; public uint dwControlsAccepted; public uint dwWin32ExitCode; public uint dwServiceSpecificExitCode; public uint dwCheckPoint; public uint dwWaitHint; }
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)] private static extern IntPtr OpenSCManager(string machine, string database, uint access);
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)] private static extern IntPtr CreateService(IntPtr hSCM, string name, string display, uint access, uint type, uint start, uint err, string bin, string group, IntPtr tag, string deps, string user, string pw);
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)] private static extern IntPtr OpenService(IntPtr hSCM, string name, uint access);
    [DllImport("advapi32.dll", SetLastError=true)] private static extern bool StartService(IntPtr h, uint n, IntPtr args);
    [DllImport("advapi32.dll", SetLastError=true)] private static extern bool ControlService(IntPtr h, uint ctrl, ref SERVICE_STATUS st);
    [DllImport("advapi32.dll", SetLastError=true)] private static extern bool DeleteService(IntPtr h);
    [DllImport("advapi32.dll", SetLastError=true)] private static extern bool CloseServiceHandle(IntPtr h);
    public static IntPtr OpenSCMLocal(uint access) { return OpenSCManager(null, null, access); }
    public static IntPtr CreateDriver(IntPtr scm, string name, string display, string binPath) {
        return CreateService(scm, name, display, 0xF01FFu, 0x1u, 0x3u, 0x1u, binPath, null, IntPtr.Zero, null, null, null);
    }
    public static IntPtr OpenExisting(IntPtr scm, string name) { return OpenService(scm, name, 0x34u); }
    public static bool Start(IntPtr h) { return StartService(h, 0, IntPtr.Zero); }
    public static bool Stop(IntPtr h) { SERVICE_STATUS s = new SERVICE_STATUS(); return ControlService(h, 0x1u, ref s); }
    public static bool Delete(IntPtr h) { return DeleteService(h); }
    public static bool Close(IntPtr h) { return CloseServiceHandle(h); }
    public static int LastErr() { return Marshal.GetLastWin32Error(); }
}
public static class HpaTelemetryModules {
    [DllImport("ntdll.dll")] private static extern int NtQuerySystemInformation(int cls, IntPtr buffer, int size, out int needed);
    public static string[] Names() {
        int size = 1048576, needed = 0; IntPtr mem = IntPtr.Zero;
        try {
            for (int attempt = 0; attempt < 5; attempt++) {
                mem = Marshal.AllocHGlobal(size);
                int status = NtQuerySystemInformation(11, mem, size, out needed);
                if (status == 0) { break; }
                Marshal.FreeHGlobal(mem); mem = IntPtr.Zero;
                if (unchecked((uint)status) != 0xC0000004) { throw new Exception("NtQuerySystemInformation NTSTATUS " + status.ToString("X8")); }
                size = Math.Max(needed + 65536, size * 2);
            }
            if (mem == IntPtr.Zero) { throw new Exception("module buffer unavailable"); }
            int count = Marshal.ReadInt32(mem);
            if (count < 0 || count > 10000) { throw new Exception("invalid module count " + count); }
            int offset = IntPtr.Size == 8 ? 8 : 4;
            int stride = IntPtr.Size == 8 ? 296 : 284;
            int pathOffset = IntPtr.Size == 8 ? 40 : 28;
            var names = new List<string>();
            for (int i = 0; i < count; i++) {
                var item = IntPtr.Add(mem, offset + i * stride + pathOffset);
                var bytes = new byte[256]; Marshal.Copy(item, bytes, 0, 256);
                int end = Array.IndexOf(bytes, (byte)0); if (end < 0) { end = 256; }
                names.Add(Encoding.ASCII.GetString(bytes, 0, end));
            }
            return names.ToArray();
        } finally { if (mem != IntPtr.Zero) { Marshal.FreeHGlobal(mem); } }
    }
}
"@
Add-Type -TypeDefinition $src -ErrorAction Stop

function Get-ModuleNames([string]$pattern) {
    return @([HpaTelemetryModules]::Names() | Where-Object { $_ -like $pattern })
}

function Get-DriverBinPath([string]$path) {
    $driversPrefix = Join-Path $env:SystemRoot 'System32\drivers\'
    if ($path.StartsWith($driversPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        return '\SystemRoot\System32\drivers\' + (Split-Path $path -Leaf)
    }
    return $path
}

Write-Host "[*] Driver telemetry generator (T1685), temporary service name: $ServiceName"

# In-box images verified to support dynamic unload come first; the rest are load-only fallbacks.
$candidateDrivers = @(
    'wimmount.sys',
    'applockerfltr.sys',
    'ndisuio.sys',
    'wcnfs.sys',
    'hidbth.sys',
    'flpydisk.sys',
    'sfloppy.sys',
    'serenum.sys',
    'swenum.sys',
    'parport.sys',
    'mskssrv.sys',
    'mspclock.sys',
    'mspqm.sys',
    'FsDepends.sys',
    'scfilter.sys',
    'rdpbus.sys',
    'tsusbhub.sys'
)
$driversDir = Join-Path $env:SystemRoot 'System32\drivers'
if ($DriverPath) {
    if (-not (Test-Path -LiteralPath $DriverPath -PathType Leaf)) {
        Write-Host "[!] -DriverPath image not found: $DriverPath" -ForegroundColor Red
        exit 1
    }
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
$imageName = ''
$activeServiceName = ''
$usingExistingService = $false
$tempServiceCreated = $false

foreach ($driver in $drivers) {
    $candidateImage = Split-Path $driver -Leaf
    $driverName = [IO.Path]::GetFileNameWithoutExtension($candidateImage)
    Write-Host "[*] Trying driver: $driver"

    $pre = Get-ModuleNames "*$candidateImage"
    if ($pre.Count -gt 0) {
        Write-Host "[!] $candidateImage is already resident; skipping (an already-loaded image cannot demonstrate a fresh load/unload transition)" -ForegroundColor Yellow
        continue
    }
    if ($candidateImage -ieq 'rdpdr.sys') {
        Write-Host "[!] Note: stopping rdpdr.sys can disrupt active RDP sessions" -ForegroundColor Yellow
    }

    $ownSvc = Get-CimInstance Win32_SystemDriver -Filter ("Name='{0}'" -f $driverName.Replace("'", "''")) -ErrorAction SilentlyContinue
    $useExisting = ($ownSvc -and $ownSvc.State -eq 'Stopped' -and $ownSvc.StartMode -ne 'Disabled')

    $scm = [HpaTelemetryScm]::OpenSCMLocal(0x3)
    if ($scm -eq [IntPtr]::Zero) {
        Write-Host "[!] OpenSCManager failed err=$([HpaTelemetryScm]::LastErr())" -ForegroundColor Red
        exit 1
    }

    if ($useExisting) {
        $handle = [HpaTelemetryScm]::OpenExisting($scm, $driverName)
        if ($handle -eq [IntPtr]::Zero) {
            Write-Host "[!] OpenService failed err=$([HpaTelemetryScm]::LastErr()) for $driverName" -ForegroundColor Yellow
            [HpaTelemetryScm]::Close($scm) | Out-Null
            continue
        }
        Write-Host "[+] Using the driver's existing service '$driverName' (it is left in place afterwards)"
        $activeServiceName = $driverName
        $usingExistingService = $true
        $tempServiceCreated = $false
    }
    else {
        $binPath = Get-DriverBinPath -path $driver
        $handle = [HpaTelemetryScm]::CreateDriver($scm, $ServiceName, 'Windows Telemetry Generator driver test', $binPath)
        if ($handle -eq [IntPtr]::Zero) {
            Write-Host "[!] CreateService failed err=$([HpaTelemetryScm]::LastErr()) for $driver" -ForegroundColor Yellow
            [HpaTelemetryScm]::Close($scm) | Out-Null
            continue
        }
        Write-Host "[+] Kernel service created"
        $activeServiceName = $ServiceName
        $usingExistingService = $false
        $tempServiceCreated = $true
    }

    if ([HpaTelemetryScm]::Start($handle)) {
        # Confirm the image is genuinely resident before claiming a load.
        $mods = @()
        $deadline = (Get-Date).AddSeconds(10)
        do {
            $mods = Get-ModuleNames "*$candidateImage"
            if ($mods.Count -gt 0) { break }
            Start-Sleep -Milliseconds 300
        } while ((Get-Date) -lt $deadline)
        if ($mods.Count -gt 0) {
            Write-Host "[+] Driver loaded (Driver Loaded telemetry); image verified in the kernel module list"
            $loaded = $true
            $loadedDriver = $driver
            $imageName = $candidateImage
            break
        }
        Write-Host "[!] StartService reported success but $candidateImage is not in the kernel module list; load not verified" -ForegroundColor Yellow
        [HpaTelemetryScm]::Stop($handle) | Out-Null
        if ($tempServiceCreated) { [HpaTelemetryScm]::Delete($handle) | Out-Null }
        [HpaTelemetryScm]::Close($handle) | Out-Null
        [HpaTelemetryScm]::Close($scm) | Out-Null
        $handle = [IntPtr]::Zero
        $scm = [IntPtr]::Zero
        $tempServiceCreated = $false
        continue
    }
    Write-Host "[!] StartService failed err=$([HpaTelemetryScm]::LastErr()) for $driver" -ForegroundColor Yellow
    if ($tempServiceCreated) { [HpaTelemetryScm]::Delete($handle) | Out-Null }
    [HpaTelemetryScm]::Close($handle) | Out-Null
    [HpaTelemetryScm]::Close($scm) | Out-Null
    $handle = [IntPtr]::Zero
    $scm = [IntPtr]::Zero
    $tempServiceCreated = $false
}

if (-not $loaded) {
    Write-Host "[!] Could not load any candidate driver (missing, already resident, or start failed)" -ForegroundColor Red
    Write-Host "[!] On endpoints with kernel driver-load protection, non-in-box images can be blocked by the protection product" -ForegroundColor Yellow
    exit 1
}
Write-Host "[*] Loaded driver: $loadedDriver (service: $activeServiceName)"

Write-Host "[*] Holding for $HoldSeconds seconds"
Start-Sleep -Seconds $HoldSeconds

Write-Host "[*] Attempting unload (Driver Unloaded telemetry)"
$stopOk = $false
$stopErr = 0
try {
    $stopOk = [HpaTelemetryScm]::Stop($handle)
    $stopErr = [HpaTelemetryScm]::LastErr()
}
catch {
    $stopOk = $false
    $stopErr = -1
}

$unloaded = $false
if ($stopOk) {
    $deadline = (Get-Date).AddSeconds(15)
    do {
        $mods = Get-ModuleNames "*$imageName"
        if ($mods.Count -eq 0) { $unloaded = $true; break }
        Start-Sleep -Milliseconds 300
    } while ((Get-Date) -lt $deadline)
    if ($unloaded) {
        Write-Host "[+] Driver unloaded (Driver Unloaded telemetry); image verified gone from the kernel module list"
    }
    else {
        Write-Host "[!] Stop reported success but $imageName is still resident; unload not verified" -ForegroundColor Yellow
    }
}
else {
    Write-Host "[!] StopService failed err=$stopErr - this driver does not support dynamic unload; the loaded image stays resident until reboot" -ForegroundColor Yellow
}

if (-not $SkipCleanup) {
    if ($tempServiceCreated) {
        $deleted = [HpaTelemetryScm]::Delete($handle)
        Write-Host "[*] Service delete requested: $deleted"
    }
    else {
        Write-Host "[*] Driver's own service '$activeServiceName' left in place (not created by this script)"
    }
}
[HpaTelemetryScm]::Close($handle) | Out-Null
[HpaTelemetryScm]::Close($scm) | Out-Null

if ($unloaded) {
    Write-Host "[*] Driver telemetry generation complete (load and unload verified)"
    exit 0
}

Write-Host "[!] Driver Loaded telemetry was generated but the unload could not be verified (exit 2)" -ForegroundColor Yellow
Write-Host "[!] The image stays resident until reboot. Pass -DriverPath with an unload-capable image for a controlled unload cycle" -ForegroundColor Yellow
exit 2
