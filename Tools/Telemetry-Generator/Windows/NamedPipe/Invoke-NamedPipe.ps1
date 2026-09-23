<#
.SYNOPSIS
    Generates named pipe telemetry: pipe creation, pipe connection and pipe read activity.
.DESCRIPTION
    Self-contained replacement for the Atomic Red Team named pipe test (GUID bd13b9fc, T1559)
    which requires ExternalPayloads binaries to be downloaded from the internet.

    The tool creates a named pipe server and connects to it from a second PowerShell process.
    The connection is held open for -HoldSeconds so that sensors can observe creation, connect
    and read activity, then both sides are closed and the pipe disappears.

    The client runs in a separate process on purpose: connecting from the same process that
    hosts the pipe server does not complete reliably under PowerShell.
.NOTES
    Part of the Windows Telemetry Generator toolkit. Requires no internet access.
#>
[CmdletBinding()]
param(
    [string]$PipeName = 'AtomicNamedPipe',
    [int]$HoldSeconds = 20,
    [switch]$ClientMode,
    [int]$ClientConnectTimeoutMs = 8000
)

if ($ClientMode) {
    # Child process: connect to the server pipe, send a small payload and hold the connection.
    try {
        $client = New-Object System.IO.Pipes.NamedPipeClientStream('.', $PipeName, [System.IO.Pipes.PipeDirection]::InOut)
        $client.Connect($ClientConnectTimeoutMs)
        $payload = [Text.Encoding]::ASCII.GetBytes('named pipe telemetry payload')
        $client.Write($payload, 0, $payload.Length)
        $client.Flush()
        Start-Sleep -Seconds $HoldSeconds
        $client.Dispose()
        exit 0
    }
    catch {
        Write-Host "[!] Named pipe client failed: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

$ErrorActionPreference = 'Stop'

Write-Host "[*] Named pipe telemetry generator (T1559)"
Write-Host "[*] Creating named pipe server: $PipeName"
$server = New-Object System.IO.Pipes.NamedPipeServerStream($PipeName, [System.IO.Pipes.PipeDirection]::InOut, 1, [System.IO.Pipes.PipeTransmissionMode]::Byte, [System.IO.Pipes.PipeOptions]::Asynchronous)

Write-Host "[*] Starting the pipe client process"
$wait = $server.BeginWaitForConnection($null, $null)
$argumentLine = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -ClientMode -PipeName $PipeName -HoldSeconds $HoldSeconds"
$clientProcess = Start-Process -FilePath "powershell.exe" -ArgumentList $argumentLine -NoNewWindow -PassThru

if (-not $wait.AsyncWaitHandle.WaitOne(15000)) {
    Write-Host "[!] Timed out waiting for the pipe client to connect" -ForegroundColor Red
    try { $server.Dispose() } catch {}
    try { $clientProcess.Kill() } catch {}
    exit 1
}

$server.EndWaitForConnection($wait)
Write-Host "[+] Client connected to the pipe"

$buffer = New-Object byte[] 64
$read = $server.Read($buffer, 0, $buffer.Length)
Write-Host "[*] Read $read bytes from the client"

Write-Host "[*] Holding the pipe connection for $HoldSeconds seconds"
Start-Sleep -Seconds $HoldSeconds

$server.Dispose()
if (-not $clientProcess.HasExited) {
    try { $clientProcess.Kill() } catch {}
}
Write-Host "[*] Named pipe telemetry generation complete"
exit 0
