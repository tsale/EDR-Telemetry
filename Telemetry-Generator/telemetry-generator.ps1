# Version 0.1 
 
# Name of Technique to run. Default = All
[CmdletBinding()]
Param(
    [Parameter(Mandatory = $False, Position = 0)]
    [string]$Name = "All"
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
        Write-Host "There was an error during the installation please check your AV or internet connection"
    }
}

#Function that checks if cleanup exists inside the dictionary. (Some sub-categories require to be 'cleaned up/deleted' to generate the telemetry)
function CheckCleanupValue($value) {
  if ($value.PSobject.Properties.Name -contains "Cleanup") {
      return $true
  }
}

function CSV-Concat() {
    # Get all CSV files in the folder
    $csvFiles = Get-ChildItem -Path $scriptPath -Filter *.csv

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
}

# Iterate through all categories and execute the sub-categories specified. It generates a CSV for the results of each sub-category.
function Executor($Name) {
  foreach ($key1 in $json.$Name.PSobject.Properties.Name) {
      $errorCheckPrereqs = $false
      $errorExecution = $false
      $atomic = $json.$Name.$key1.Atomics.PSobject.Properties.Name
      $GUID = $json.$Name.$key1.Atomics.PSobject.Properties.Value
      Write-Host ""
      Write-Host "====================================" -ForegroundColor Yellow
      Write-Host "[*] Executing tests for $key1" -ForegroundColor Magenta
      Write-Host "====================================" -ForegroundColor Yellow
      Write-Host ""
      # TODO: Add more error handling for edge cases
      try {
        Invoke-AtomicTest -AtomicTechnique $atomic -TestGuids $GUID -GetPrereqs -ErrorAction SilentlyContinue
      }
      Catch {
        Write-Host "There was an error while checking the prerequisites for atomic $atomic" -ForegroundColor Red
        $errorCheckPrereqs = $true
      }
      try {
        Invoke-AtomicTest -AtomicTechnique $atomic -TestGuids $GUID -ExecutionLogPath "$key1.csv" -ErrorAction SilentlyContinue
      }
      Catch {
        Write-Host "There was an error while running the test for atomic $atomic" -ForegroundColor Red
        $errorExecution = $true
      }

      if ( -not $errorCheckPrereqs -and -not $errorExecution){
        if (CheckCleanupValue($json.$Name.$key1)) {
            Write-Host ""
            Write-Host "==> Cleaning up and then sleeping for 7 seconds " -ForegroundColor Green -BackgroundColor DarkGray
            Write-Host ""
            Start-Sleep -Seconds 3
            Invoke-AtomicTest -AtomicTechnique $atomic -TestGuids $GUID -Cleanup
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
  \_/\___|_|\___|_| |_| |_|\___|\__|_|   \__, |       \____/\___|_| |_|\___|_|  \__,_|\__\___/|_|   
                                          __/ |                                                     
                                         |___/                                                      

"@

# Install Invoke-Atomic
Install-ART()

# Get the path of the running script
$scriptPath = $PSScriptRoot

# Parse the configuration file
$json_file = Get-Content -Path "$scriptPath\config.json" -Raw
$json = ConvertFrom-Json $json_file

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
CSV-Concat()