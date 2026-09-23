# Version 0.1 
 
# Name of Technique to run. Default = All
[CmdletBinding()]
Param(
    [Parameter(Mandatory = $False, Position = 0)]
    [string]$Name = "All",

    [Parameter(Mandatory = $False)]
    [string]$AtomicsPath
    )


# Function that installs Invoke-AtomicRedTeam
function Install-ART(){
    $art_url = 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    try{
        Invoke-Expression (Invoke-WebRequest $art_url -UseBasicParsing);
        Install-AtomicRedTeam -getAtomics -ErrorAction Stop
    }
    catch{
        throw "There was an error installing Invoke-AtomicRedTeam. Check internet access, AV exclusions, and whether Atomic Red Team is already partially installed."
    }
}

function Import-ARTModule() {
    if (Get-Command Invoke-AtomicTest -ErrorAction SilentlyContinue) {
        return
    }

    try {
        Import-Module Invoke-AtomicRedTeam -Force -ErrorAction Stop
        return
    }
    catch {
    }

    $candidateModulePaths = @(
        'C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1',
        (Join-Path $HOME 'AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1')
    )

    foreach ($candidateModulePath in $candidateModulePaths) {
        if (Test-Path $candidateModulePath) {
            Import-Module $candidateModulePath -Force -ErrorAction Stop
            return
        }
    }

    throw "Invoke-AtomicRedTeam is not available in this PowerShell session."
}

function Resolve-ARTAtomicsPath([string]$RequestedPath) {
    $candidatePaths = @()

    if ($RequestedPath) {
        $candidatePaths += $RequestedPath
    }

    if ($PSDefaultParameterValues -and $PSDefaultParameterValues.ContainsKey('Invoke-AtomicTest:PathToAtomicsFolder')) {
        $candidatePaths += $PSDefaultParameterValues['Invoke-AtomicTest:PathToAtomicsFolder']
    }

    $candidatePaths += @(
        'C:\AtomicRedTeam\atomics',
        (Join-Path $HOME 'AtomicRedTeam\atomics')
    )

    foreach ($candidatePath in ($candidatePaths | Where-Object { $_ } | Select-Object -Unique)) {
        if (Test-Path $candidatePath) {
            return (Resolve-Path $candidatePath).ProviderPath
        }
    }

    return $null
}

function Ensure-ART([string]$RequestedPath) {
    $moduleAvailable = [bool](Get-Command Invoke-AtomicTest -ErrorAction SilentlyContinue)
    $resolvedAtomicsPath = Resolve-ARTAtomicsPath -RequestedPath $RequestedPath

    if (-not $moduleAvailable -and -not $resolvedAtomicsPath) {
        Install-ART
    }

    Import-ARTModule

    $resolvedAtomicsPath = Resolve-ARTAtomicsPath -RequestedPath $RequestedPath
    if (-not $resolvedAtomicsPath) {
        throw "Could not locate the Atomic Red Team atomics folder. Install it to C:\AtomicRedTeam\atomics or pass -AtomicsPath with the correct folder."
    }

    return $resolvedAtomicsPath
}

# Atomic Red Team is resolved lazily on first use. Runs that only execute the self-contained
# toolkit scripts (the "Custom" sections in config.json) do not need Atomic Red Team, the
# atomics folder or internet access.
function Get-AtomicsPath {
    if (-not $script:ResolvedAtomicsPath) {
        $script:ResolvedAtomicsPath = Ensure-ART -RequestedPath $AtomicsPath
        Write-Host "[*] Using atomics folder: $($script:ResolvedAtomicsPath)" -ForegroundColor Cyan
    }
    return $script:ResolvedAtomicsPath
}

function Write-AtomicFailure([string]$Phase, [string]$AtomicTechnique, [System.Management.Automation.ErrorRecord]$ErrorRecord) {
    Write-Host "There was an error while $Phase for atomic $AtomicTechnique" -ForegroundColor Red

    $details = @()
    if ($ErrorRecord.Exception.Message) {
        $details += $ErrorRecord.Exception.Message
    }
    if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
        $details += $ErrorRecord.ErrorDetails.Message
    }
    if ($ErrorRecord.InvocationInfo -and $ErrorRecord.InvocationInfo.PositionMessage) {
        $details += $ErrorRecord.InvocationInfo.PositionMessage.Trim()
    }

    foreach ($detail in ($details | Where-Object { $_ } | Select-Object -Unique)) {
        Write-Host "    $detail" -ForegroundColor DarkRed
    }
}

# Writes a run log row for a self-contained toolkit script, using the same columns as the
# Atomic Red Team Default-ExecutionLogger so the results can be fused into one CSV.
function Write-CustomResultRow {
    param(
        [string]$Key1,
        [string]$Technique,
        [string]$TestName,
        [string]$GuidValue,
        [int]$ProcessIdValue,
        [int]$ExitCodeValue,
        [datetime]$StartTime
    )

    # Sanitize the sub-category name: names like "Key/Value Creation" are invalid as file names.
    $safeKey1 = $Key1 -replace '[\\/:*?"<>|]', '-'
    $executionLogPath = Join-Path $scriptPath "$safeKey1.csv"
    $ipAddress = ""
    try {
        $ipAddress = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object { $_.InterfaceAlias -notlike "*Loopback*" -and $_.PrefixOrigin -ne "WellKnown" } |
            Select-Object -First 1).IPAddress
    }
    catch {
        $ipAddress = ""
    }

    $row = [PSCustomObject][ordered]@{
        "Execution Time (UTC)"   = $StartTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        "Execution Time (Local)" = $StartTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
        "Technique"              = $Technique
        "Test Number"            = "custom"
        "Test Name"              = $TestName
        "Hostname"               = $env:COMPUTERNAME
        "IP Address"             = $ipAddress
        "Username"               = "$env:USERDOMAIN\$env:USERNAME"
        "GUID"                   = $GuidValue
        "ProcessId"              = $ProcessIdValue
        "ExitCode"               = $ExitCodeValue
    }

    $row | Export-Csv -Path $executionLogPath -NoTypeInformation -Append
    Write-Host "[*] Wrote run log row to $executionLogPath"
}

#Function that checks if cleanup exists inside the dictionary. (Some sub-categories require to be 'cleaned up/deleted' to generate the telemetry)
function CheckCleanupValue($value) {
  if ($value.PSobject.Properties.Name -contains "Cleanup") {
      return $true
  }
}

function CSV-Concat([datetime]$Since) {
    # Only fuse the CSV files produced by this run. The generator directory also contains the
    # telemetry mapping file and the aggregate output of previous runs, and those must not leak
    # into the current results.
    $csvFiles = Get-ChildItem -Path $scriptPath -Filter *.csv | Where-Object {
        $_.Name -ne "All_telem_results.csv" -and
        $_.Name -ne "telemetry-mappings.csv" -and
        $_.LastWriteTime -ge $Since
    }

    # Initialize an empty array to store the combined CSV data
    $combinedCsvData = @()

    # Iterate through each CSV file
    foreach ($csvFile in $csvFiles) {
        # Import the CSV file data
        $csvData = Import-Csv -Path $csvFile.FullName

        # Add the CSV data to the combined array
        $combinedCsvData += $csvData
    }

    # Export the combined CSV data to a new file with headers
    $combinedCsvData | Export-Csv -Path "$scriptPath\All_telem_results.csv" -NoTypeInformation
    Write-Host "[*] Fused $($csvFiles.Count) result file(s) into All_telem_results.csv" -ForegroundColor Cyan
}

# Iterate through all categories and execute the sub-categories specified. It generates a CSV for the results of each sub-category.
function Executor($Name) {
  foreach ($key1 in $json.$Name.PSobject.Properties.Name) {
      $errorCheckPrereqs = $false
      $errorExecution = $false
      $subCategory = $json.$Name.$key1
      $subProperties = $subCategory.PSobject.Properties.Name
      Write-Host ""
      Write-Host "====================================" -ForegroundColor Yellow
      Write-Host "[*] Executing tests for $key1" -ForegroundColor Magenta
      Write-Host "====================================" -ForegroundColor Yellow
      Write-Host ""

      if ($subProperties -contains "Custom") {
          # Self-contained toolkit script: no Atomic Red Team and no internet access required.
          $customScript = Join-Path $scriptPath $subCategory.Custom.Script
          $customTechnique = "custom"
          if ($subCategory.Custom.PSobject.Properties.Name -contains "Technique") {
              $customTechnique = $subCategory.Custom.Technique
          }
          $customArguments = @()
          if ($subCategory.Custom.PSobject.Properties.Name -contains "Arguments") {
              $customArguments = @($subCategory.Custom.Arguments)
          }

          if (-not (Test-Path $customScript)) {
              Write-Host "[!] Custom telemetry script not found: $customScript" -ForegroundColor Red
              $errorExecution = $true
          }
          else {
              # Truncate earlier runs' rows (the run-log writer appends).
              $safeCustomKey = $key1 -replace '[\\/:*?"<>|]', '-'
              Remove-Item (Join-Path $scriptPath "$safeCustomKey.csv") -Force -ErrorAction SilentlyContinue
              Write-Host "[*] Running custom telemetry script: $($subCategory.Custom.Script)" -ForegroundColor Cyan
              $customStartTime = Get-Date
              try {
                  $argumentLine = "-NoProfile -ExecutionPolicy Bypass -File `"$customScript`""
                  if ($customArguments.Count -gt 0) {
                      $argumentLine = "$argumentLine $($customArguments -join ' ')"
                  }
                  $customProcess = Start-Process -FilePath "powershell.exe" -ArgumentList $argumentLine -NoNewWindow -PassThru -Wait -ErrorAction Stop
                  Write-Host "[*] Custom script exit code: $($customProcess.ExitCode)"
                  Write-CustomResultRow -Key1 $key1 -Technique $customTechnique -TestName $subCategory.Custom.Script -GuidValue "custom:$($subCategory.Custom.Script)" -ProcessIdValue $customProcess.Id -ExitCodeValue $customProcess.ExitCode -StartTime $customStartTime
                  if ($customProcess.ExitCode -ne 0) {
                      Write-Host "[!] Custom telemetry script reported failure (exit code $($customProcess.ExitCode))" -ForegroundColor Red
                      $errorExecution = $true
                  }
              }
              catch {
                  Write-AtomicFailure -Phase "running the custom telemetry script" -AtomicTechnique $subCategory.Custom.Script -ErrorRecord $_
                  $errorExecution = $true
              }
          }
      }
      elseif ($subProperties -contains "Atomics") {
          $atomic = $subCategory.Atomics.PSobject.Properties.Name
          $GUID = $subCategory.Atomics.PSobject.Properties.Value
          $safeKey1 = $key1 -replace '[\\/:*?"<>|]', '-'
          $executionLogPath = Join-Path $scriptPath "$safeKey1.csv"
          # Truncate any results from earlier runs: the Atomic execution logger APPENDS to the log file,
          # so without this the fused output would accumulate rows across runs.
          Remove-Item $executionLogPath -Force -ErrorAction SilentlyContinue
          $atomicsPath = $null
          try {
              $atomicsPath = Get-AtomicsPath
          }
          catch {
              Write-AtomicFailure -Phase "locating Atomic Red Team" -AtomicTechnique $atomic -ErrorRecord $_
              $errorCheckPrereqs = $true
              $errorExecution = $true
          }
          if ($atomicsPath) {
              try {
                Invoke-AtomicTest -AtomicTechnique $atomic -TestGuids $GUID -PathToAtomicsFolder $atomicsPath -GetPrereqs -Confirm:$false -ErrorAction Stop
              }
              Catch {
                Write-AtomicFailure -Phase "checking the prerequisites" -AtomicTechnique $atomic -ErrorRecord $_
                $errorCheckPrereqs = $true
              }
              try {
                Invoke-AtomicTest -AtomicTechnique $atomic -TestGuids $GUID -PathToAtomicsFolder $atomicsPath -ExecutionLogPath $executionLogPath -Confirm:$false -ErrorAction Stop
              }
              Catch {
                Write-AtomicFailure -Phase "running the test" -AtomicTechnique $atomic -ErrorRecord $_
                $errorExecution = $true
              }
          }
      }
      else {
          Write-Host "[!] No 'Atomics' or 'Custom' definition found for $key1; skipping" -ForegroundColor Yellow
          continue
      }

      if ( -not $errorCheckPrereqs -and -not $errorExecution){
        if (($subProperties -contains "Atomics") -and (CheckCleanupValue($subCategory))) {
            Write-Host ""
            Write-Host "==> Cleaning up and then sleeping for 7 seconds " -ForegroundColor Green -BackgroundColor DarkGray
            Write-Host ""
            Start-Sleep -Seconds 3
            Invoke-AtomicTest -AtomicTechnique $subCategory.Atomics.PSobject.Properties.Name -TestGuids $subCategory.Atomics.PSobject.Properties.Value -PathToAtomicsFolder $script:ResolvedAtomicsPath -Cleanup -Confirm:$false
        }
        Start-Sleep -Seconds 7
      }
      }
}

Write-Host @"
 _____    _                     _                     _____                           _             
|_   _|  | |                   | |                   |  __ \                         | |            
  | | ___| | ___ _ __ ___   ___| |_ _ __ _   _ ______| |  \/ ___ _ __   ___ _ __ __ _| |_ ___  _ __ 
  | |/ _ \ |/ _ \ '_ ` _ \ / _ \ __| '__| | | |______| | __ / _ \ '_ \ / _ \ '__/ _` | __/ _ \| '__|
  | |  __/ |  __/ | | | | |  __/ |_| |  | |_| |      | |_\ \  __/ | | |  __/ | | (_| | || (_) | |   
  \_/\___|_|\___|_| |_| |_|\___|\__|_|   \__, |       \____/\___|_| |_| \___|_|  \__,_|\__\___/|_|   
                                          __/ |                                                     
                                         |___/                                                      

"@

# Get the path of the running script
$scriptPath = $PSScriptRoot

# Parse the configuration file
$json_file = Get-Content -Path "$scriptPath\config.json" -Raw
$json = ConvertFrom-Json $json_file

# Atomic Red Team is resolved lazily and only when an "Atomics" section is reached.
$script:ResolvedAtomicsPath = $null

# Only CSV files produced by the current run are fused afterwards.
$runStart = Get-Date

# Main Execution loop. In this case, the argument -Name would have been set to default which is to run All available event categories.
if ($Name -eq "All"){
    foreach ($key in $json.PSobject.Properties.Name) {
        Executor($key)
    }
}
else {
    Executor($Name)
} 

# Fuse all the CSV files into one
CSV-Concat -Since $runStart
