<#
Name: run_asrrules_on_endpoint.ps1 [Helper Script]
Author: Lorenzo J. Ireland
Date: 17 Dec 2022

Purpose:
--------
This is the helper script that gets ran on the actual remote endpoint via Invoke-AzVMRunCommand

Usage: 
    Local: powershell.exe -Command .\run_asr.ps1 -Rule 'd4f940ab-401b-4efc-aadc-ad5f3c50688a','c1db55ab-c21a-4637-bb3f-a12568109d35' -Mode 'Warn'
    Remote: called via Invoke-AzVMRunCommand in azureASR.ps1
#>

Param (
    [Parameter(Mandatory = $true)]  
    [String] $Mode = 'Disabled',
    
    [Parameter(Mandatory = $false)] 
    [String] $Rule = $null
)

Begin {
    # Inspired from: https://github.com/Kaidja/Defender-for-Endpoint
    #Attack Surface Reduction Rules JSON File
    $URL = "https://raw.githubusercontent.com/dcodev1702/azure_asr_rules/main/AttackSurfaceReductionRules.json"

    #Convert ASR Rules from JSON
    $ASRRulesObj = (Invoke-WebRequest -Uri $URL -UseBasicParsing).Content | ConvertFrom-Json


    [String]$debug_dir = "$env:SystemDrive\Temp"
    [String]$debug_file = 'ASR_Debug.txt'
    if (-not (Test-Path -Path $debug_dir)) {
        New-Item -Path $debug_dir -ItemType Directory
    }

    [String]$file = "$debug_dir\$debug_file"
    [int]$cntr = 0
    $Rules = @()
    $Rules = $Rule.Split(',')
    $Rules | ForEach-Object {
        Write-Output "$(Get-Date -Format G) :: HELPER SCRIPT | ASR RULES :: $_ -> MODE [$Mode]" | Out-File -FilePath $file -Append
    }
}

Process {

    $asrRules = $null

    # If $Rule is null, no ASR rule(s) was/were provided, thus APPLY ALL RULES
    # with the provided ASR mode '$Mode'
    if ([String]::IsNullOrEmpty($Rule)) {
        $asrRules = $ASRRulesObj
    } else {
        
        # Create an array of objects with a GUID property
        $jsonArray = @()
        foreach ($asrRule in $Rule) {
            $obj = [pscustomobject]@{
                GUID = $asrRule
            }
            $jsonArray += $obj
        }

        # Convert the array of objects to a JSON object
        $asrRules = $jsonArray | ConvertTo-Json | ConvertFrom-Json

    }

    Write-Output "[$env:COMPUTERNAME] ::: Applying $($asrRules.count) ASR Rules -> MODE::[$Mode] to the Endpoint" | Out-File -FilePath $file -Append
    $asrRules | ForEach-Object {
        Add-MpPreference -AttackSurfaceReductionRules_Ids $_.GUID -AttackSurfaceReductionRules_Actions $Mode
    }
}

End {
        
    # Log and write results of each machine's ASR state
    $asr_ids = (Get-MpPreference).AttackSurfaceReductionRules_Ids
    $asr_mode = (Get-MpPreference).AttackSurfaceReductionRules_Actions

    $cntr = 0
    foreach ($id in $asr_ids) {
        Write-Output "ASR ID [$cntr]: $id <-> $($asr_mode[$cntr])" | Out-File -FilePath $file -Append
        $cntr++
    }
}