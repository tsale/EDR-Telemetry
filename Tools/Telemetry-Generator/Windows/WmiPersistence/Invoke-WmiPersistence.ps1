<#
.SYNOPSIS
    Generates WMI event subscription telemetry: event filter, CommandLineEventConsumer and
    filter-to-consumer binding.
.DESCRIPTION
    Self-contained replacement for the Atomic Red Team test with GUID 3c64f177
    (T1546.003) which depends on Invoke-AtomicRedTeam and leaves the subscription behind.
    No external tools or internet access are required.

    One run produces telemetry for the WmiEventFilter, WmiEventConsumer and
    WmiEventConsumerToFilter feature rows:
      1. removes any leftovers from previous runs (idempotent),
      2. creates the __EventFilter, CommandLineEventConsumer and __FilterToConsumerBinding,
      3. verifies all three objects exist,
      4. the filter fires shortly afterwards and the consumer launches its command line,
         which produces process creation telemetry as well,
      5. holds the subscription for -HoldSeconds so endpoint telemetry can capture it,
      6. removes the subscription again unless -SkipCleanup is used.

    The filter query uses the current system uptime to build its firing window. The original
    atomic used a fixed boot-time window, so it never fired on hosts that had been up for a
    while.
.NOTES
    Requires administrator rights. Part of the Windows Telemetry Generator toolkit.
#>
[CmdletBinding()]
param(
    [string]$Name = 'AtomicRedTeam-WMIPersistence-CommandLineEventConsumer-Example',
    [string]$ConsumerCommandLine = "$env:SystemRoot\System32\notepad.exe",
    [int]$HoldSeconds = 20,
    [switch]$SkipCleanup,
    [switch]$CleanupOnly
)

$ErrorActionPreference = 'Stop'
$Namespace = 'root/subscription'

function Remove-Artifacts {
    Get-CimInstance -Namespace $Namespace -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue |
        Where-Object { $_.Filter.Name -eq $Name -or $_.Consumer.Name -eq $Name } | Remove-CimInstance -ErrorAction SilentlyContinue
    Get-CimInstance -Namespace $Namespace -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -eq $Name } | Remove-CimInstance -ErrorAction SilentlyContinue
    Get-CimInstance -Namespace $Namespace -ClassName __EventFilter -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -eq $Name } | Remove-CimInstance -ErrorAction SilentlyContinue
}

function Get-ArtifactCounts {
    $f = @(Get-CimInstance -Namespace $Namespace -ClassName __EventFilter -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $Name }).Count
    $c = @(Get-CimInstance -Namespace $Namespace -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $Name }).Count
    $b = @(Get-CimInstance -Namespace $Namespace -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue | Where-Object { $_.Filter.Name -eq $Name -or $_.Consumer.Name -eq $Name }).Count
    return "$f/$c/$b"
}

function Get-NotepadCount {
    return @(Get-Process notepad -ErrorAction SilentlyContinue).Count
}

Write-Host "[*] WMI event subscription telemetry generator (T1546.003), subscription name: $Name"

Remove-Artifacts
Write-Host "[*] Pre-clean done. filter/consumer/binding = $(Get-ArtifactCounts)"

if ($CleanupOnly) {
    Write-Host "[*] CleanupOnly requested; exiting"
    exit 0
}

$uptime = 0
try {
    $uptime = [int](Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_System -ErrorAction Stop).SystemUpTime
}
catch {
    Write-Host "[!] Could not read system uptime; falling back to a fixed firing window" -ForegroundColor Yellow
}
$windowStart = $uptime + 8
$windowEnd = $uptime + 60
if ($uptime -eq 0) {
    $windowStart = 8
    $windowEnd = 60
}
$filterQuery = "SELECT * FROM __InstanceModificationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= $windowStart AND TargetInstance.SystemUpTime < $windowEnd"
Write-Host "[*] Filter query (fires on system uptime $windowStart-$windowEnd seconds): $filterQuery"

$notepadBefore = Get-NotepadCount

try {
    $filter = New-CimInstance -Namespace $Namespace -ClassName __EventFilter -Property @{
        Name           = $Name
        EventNameSpace = 'root\CimV2'
        QueryLanguage  = 'WQL'
        Query          = $filterQuery
    } -ErrorAction Stop
    Write-Host "[+] Event filter created"

    $consumer = New-CimInstance -Namespace $Namespace -ClassName CommandLineEventConsumer -Property @{
        Name                = $Name
        CommandLineTemplate = $ConsumerCommandLine
    } -ErrorAction Stop
    Write-Host "[+] CommandLineEventConsumer created"

    $binding = New-CimInstance -Namespace $Namespace -ClassName __FilterToConsumerBinding -Property @{
        Filter   = [Ref] $filter
        Consumer = [Ref] $consumer
    } -ErrorAction Stop
    Write-Host "[+] FilterToConsumerBinding created"
}
catch {
    Write-Host "[!] Creation failed: $($_.Exception.Message)" -ForegroundColor Red
    Remove-Artifacts
    exit 1
}

Start-Sleep -Seconds 2
Write-Host "[*] Verified on target: filter/consumer/binding = $(Get-ArtifactCounts)"
Write-Host "[*] Holding the subscription for $HoldSeconds seconds"
Start-Sleep -Seconds $HoldSeconds
Write-Host "[*] Notepad processes before/after (the consumer command line): $notepadBefore / $(Get-NotepadCount)"

if (-not $SkipCleanup) {
    Remove-Artifacts
    Get-Process notepad -ErrorAction SilentlyContinue |
        Where-Object { $_.StartTime -gt (Get-Date).AddMinutes(-5) } |
        Stop-Process -Force -ErrorAction SilentlyContinue
    Write-Host "[*] Cleanup done. filter/consumer/binding = $(Get-ArtifactCounts)"
}
else {
    Write-Host "[*] -SkipCleanup set; subscription left in place"
}
exit 0
