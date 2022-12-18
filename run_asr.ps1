<#
Name: run_asr.ps1 [Helper Script]
Author: Lorenzo J. Ireland
Date: 17 Dec 2022
Usage: 
    Local: powershell.exe -Command .\run_asr.ps1 -Rule 'd4f940ab-401b-4efc-aadc-ad5f3c50688a','c1db55ab-c21a-4637-bb3f-a12568109d35' -Mode 'Warn'
    Remote: called via Invoke-AzVMRunCommand in azureASR.ps1
#>
Param (
    [Parameter(Mandatory = $false)]  
    [String] $Mode = 'Disabled',
    
    [Parameter(Mandatory = $false)] 
    [String] $Rule = $null
)


$asr_rules = @(
    '56a863a9-875e-4185-98a7-b882c64b5ce5', # Block abuse of vuln signed drivers
    '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c', # Block Adobe Reader from creating child processes
    'd4f940ab-401b-4efc-aadc-ad5f3c50688a', # Block all Office apps from creating child processes
    '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2', # Block credential stealing from LSASS.EXE
    'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550', # Block executable content from email client & webmail
    '01443614-cd74-433a-b99e-2ecdc07bfc25', # Block executable files from running unless they meet criteria
    '5beb7efe-fd9a-4556-801d-275e5ffc04cc', # Block execution of potentially obfuscated scripts
    'd3e037e1-3eb8-44c8-a917-57927947596d', # Block Javascript | VBScript from launching downloaded executable content
    '3b576869-a4ec-4529-8536-b80a7769e899', # Block Office apps from creating executable content
    '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84', # Block Office apps from injecting code into other processes
    '26190899-1602-49e8-8b27-eb1d0a1ce869', # Block Office communication application from creating child processes
    'e6db77e5-3df2-4cf1-b95a-636979351e5b', # Block persistence through WMI event subscription
    'd1e49aac-8f56-4280-b9ba-993a6d77406c', # Block process creations originating from PSExec & WMI commands
    'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4', # Block untrusted & unsigned processes that run from USB
    '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b', # Block Win32 API calls from Office macros
    'c1db55ab-c21a-4637-bb3f-a12568109d35'  # Use advanced protection against ransomware
)
    
[String]$file = "C:\tmp\asr_debug.txt"
[int]$cntr = 0
$Rules = @()
$Rules = $Rule.Split(',')
$Rules | ForEach-Object {
    Write-Output "RULES FROM RUN_ASR() -> $_" | Out-File -FilePath $file -Append
}

if ([String]::IsNullOrEmpty($Rule)) {
   
    Write-Host "[$env:COMPUTERNAME] ::: Applying $(($asr_rules).count) ASR Rules -> MODE::[$Mode] to the Endpoint" | Out-File -FilePath $file -Append
    $asr_rules | ForEach-Object {
        Add-MpPreference -AttackSurfaceReductionRules_Ids $_ -AttackSurfaceReductionRules_Actions $Mode
        Write-Host "Rule[$cntr]: $_ -> Mode: $Mode" -ForegroundColor Yellow
        $cntr++
    }
} else {

    Write-Host "[$env:COMPUTERNAME] ::: Applying $(($Rules).count) ASR Rules -> MODE::[$Mode] to the Endpoint" | Out-File -FilePath $file -Append
    $Rules | ForEach-Object {
        Add-MpPreference -AttackSurfaceReductionRules_Ids $_ -AttackSurfaceReductionRules_Actions $Mode
    }
}
        
#TODO: Create log file and write results of each machine's ASR state
$asr_ids = (Get-MpPreference).AttackSurfaceReductionRules_Ids
$asr_mode = (Get-MpPreference).AttackSurfaceReductionRules_Actions

$cntr = 0
foreach ($id in $asr_ids) {
    Write-Output "ASR ID [$cntr]: $id <-> $($asr_mode[$cntr])" | Out-File -FilePath $file -Append
    $cntr++
}
