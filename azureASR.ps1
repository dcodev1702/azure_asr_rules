<########################################################
    Automation of Attack Surface Reduction Rules
    - Disable = 0
    - Block = 1
    - Audit = 2
    - Warn = 6
  
    Author: Lorenzo J. Ireland
    Date: 16 Dec 2022
  
    Usage:
    ------
    Import the PowerShell script:
    . ./azureASR.ps1
    
    Basic Example [enable an ASR rule for AuditMode]:
    Set-ASRRules -ResourceGroup 'VMTESTRG' -Mode 2 -VirtualMachine 'WinZo10-VM-ENT -Rules 'c1db55ab-c21a-4637-bb3f-a12568109d35'
    
    Enable ALL VMs:       
        CMD: Set-ASRRules -ResourceGroup 'VMTESTRG' -Mode 2 -All
    
    Enable specified VMs: 
        CMD: Set-ASRRules -ResourceGroup 'VMTESTRG' -Mode 2 -VirtualMachine 'Host-1','Host-2','Host-3'
    
    Enable specified VMs and user provided rule:
        CMD: Set-ASRRules -ResourceGroup 'VMTESTRG' -Mode 0 -VirtualMachine 'WinZo10-VM-ENT','WinZo10-VM3-ENT' \
        -Rules 'c1db55ab-c21a-4637-bb3f-a12568109d35'
    
    Enable specified Rules: 
        CMD: Set-ASRRules -ResourceGroup 'VMTESTRG' -Mode 6 -VirtualMachine 'WinZo10-VM-ENT' \
        -Rules "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2,01443614-cd74-433a-b99e-2ecdc07bfc25,d1e49aac-8f56-4280-b9ba-993a6d77406c"

    Enable specified Rules (BAD Rule supplied [last rule, last character]):
        CMD: Set-ASRRules -ResourceGroup 'VMTESTRG' -Mode 6 -VirtualMachine 'WinZo10-VM-ENT' \
        -Rules "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c,d4f940ab-401b-4efc-aadc-ad5f3c50688b"

    TODO:
    -- Enhance error handling (input validation), logging, and STDOUT messages

    WORKS CITED:
    -- Inspiration for using ASR Rules in JSON format
       + https://github.com/Kaidja/Defender-for-Endpoint
    -- ASR
       + https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/overview-attack-surface-reduction?view=o365-worldwide
    -- Azure Authentication and Module code comes from:
       + https://github.com/Azure/Azure-Sentinel/blob/master/Tools/Sentinel-All-In-One/Powershell/DeleteConnectors.ps1
###########################################################>
<#
Warn mode isn't supported for three attack surface reduction rules when you configure them in Microsoft Endpoint Manager. (If you use Group Policy to configure your attack surface reduction rules, warn mode is supported.) The three rules that do not support warn mode when you configure them in Microsoft Endpoint Manager are as follows:

Block JavaScript or VBScript from launching downloaded executable content (GUID d3e037e1-3eb8-44c8-a917-57927947596d)
Block persistence through WMI event subscription (GUID e6db77e5-3df2-4cf1-b95a-636979351e5b)
Use advanced protection against ransomware (GUID c1db55ab-c21a-4637-bb3f-a12568109d35)
#>

# This feature requires PS >= 4.0
#Requires -RunAsAdministrator

function Get-AzureSubscription() {

    # Test to see if there's an active login session to the Azure tenant
    # Returns null of no login session exists 
    $context = Get-AzContext

    if(!$context){
        # Check to see if Resource Group specified exists within the provided Azure Subscription
        Write-Host "`r`nYou will be asked to log in to your Azure environment if a session does not already exist. `nGlobal Admin or Security Admin credentials are required. `nThis will allow the script to interact with Azure as required.`r`n" -BackgroundColor Magenta
        Read-Host -Prompt "Press enter to continue or CTRL+C to quit the script"
     
        Connect-AzAccount
        $context = Get-AzContext
    }

    $SubscriptionId = $context.Subscription.Id

}

function Check-AzModules() {

    # Make sure any modules we depend on are installed
    # Credit to: Koos Goossens @ Wortell.
    $modulesToInstall = @(
        'Az.Accounts',
        'Az.Compute',
        'Az.ConnectedMachine'
    )

    Write-Host "Installing/Importing PowerShell modules..." -ForegroundColor Green
    $modulesToInstall | ForEach-Object {
        if (-not (Get-Module -ListAvailable $_)) {
            Write-Host "  ┖─ Module [$_] not found, installing..." -ForegroundColor Green
            Install-Module $_ -Force
        } else {
            Write-Host "  ┖─ Module [$_] already installed." -ForegroundColor Green
        }
    }

    $modulesToInstall | ForEach-Object {
        if (-not (Get-InstalledModule $_)) {
            Write-Host "  ┖─ Module [$_] not loaded, importing..." -ForegroundColor Green
            Import-Module $_ -Force
        } else {
            Write-Host "  ┖─ Module [$_] already loaded." -ForegroundColor Green
        }
    }
}

# MAYBE: Add Azure Subscriptions before iterating over Resource Groups
function Set-ASRRules {
    [CmdletBinding()] 
    Param (
        [Parameter(Mandatory = $true)]
        [String] $ResourceGroup,
        
        [Parameter(Mandatory = $false)]
        [String] $Rules = $null,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet(0,1,2,6)] [int] $Mode = 2,
        
        [Parameter(Mandatory = $false)]
        [String[]] $VirtualMachine = $null,
        
        [Parameter(Mandatory = $false)]
        [Switch] $AllVMs = $false,

        [Parameter(Mandatory = $false)]
        [Switch] $CheckAzModules = $false
    )

    Begin {

        # List of ASR Rules - Dated 18 DEC 2022
        # https://github.com/MicrosoftDocs/microsoft-365-docs/blob/public/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference.md
        
        # Cite and inspired from: https://github.com/Kaidja/Defender-for-Endpoint

        # If access to GitHub is permitted, pull from repo, else pull the ASR Rules locally
        # Attack Surface Reduction Rules JSON File
        $URL = "https://raw.githubusercontent.com/dcodev1702/azure_asr_rules/main/AttackSurfaceReductionRules.json"
        $ASRWebReq = Invoke-WebRequest -Uri $URL -UseBasicParsing
        if ($ASRWebReq.StatusCode -eq 200) {
            $ASRRules = $ASRWebReq.Content | ConvertFrom-Json
        } else {
            # GitHub is inaccessible, acquire ASR Rules (JSON format) locally.
            $ASRRules = Get-Content -Raw ./AttackSurfaceReductionRules.json | ConvertFrom-Json
        }
        
        
        # Use a flag -CheckAzModules to enable checking of required modules
        if ($CheckAzModules) { Check-AzModules }

        #Before querying Azure, ensure we are logged in
        Get-AzureSubscription

        #Check Resource Group Existing or not
        Get-AzResourceGroup -Name $ResourceGroup -ErrorVariable RGNotPresent -ErrorAction SilentlyContinue | Out-Null
        
        if ($RGNotPresent){        
            Write-Host "ResourceGroup `"$($ResourceGroup)`" associated to your Azure subscription was not found..." -ForegroundColor Red
            Write-Host "Exiting, goodbye..." -ForegroundColor Red
            break
        } else {
            Write-Host "[1] Resource Group:[$ResourceGroup] successfully located..." -ForegroundColor Green
        }


        # Validate input recieved and quit the program if a bad value is provided.
        [bool]$VMEnabled = $false
        [String]$ModeType = ""
        switch ( $Mode ) {
            0 { $ModeType = "Disabled" }
            1 { $ModeType = "Enabled" }
            2 { $ModeType = "AuditMode" }
            6 { $ModeType = "Warn" }
        }

        
        if (-not ([String]::IsNullOrEmpty($Rules))) {

            # If specific rules have been provided, validate them before proceeding
            $tmpRules = @()
            $tmpRules = $Rules.Split(',')
            
            $tmpRules | Where-Object -FilterScript { 
                
                if($_ -notin $ASRRules.GUID) { 
                    Write-Host "`nASR Rule:[$_] - not found, goodbye" -ForegroundColor Red
                    break
                } else {
                    # Log and write results of each machine's ASR state
                    Write-Host "`n[2] ASR Rule:[$_] located, processing..." -ForegroundColor Green
                }
            }
        }
        
        # Query Azure subscription and get list of all registered Windows VM's in Azure & Azure ARC
        $azure_vms = Get-AzVM -Status
        $arc_vms = Get-AzConnectedMachine   
    }
    
    Process {

        # Get a list of RUNNING VM's within the registered list of Windows VM's (Azure VM & Azure ARC Servers).
        $totalRunningVMs = @()
        $azure_vms | ForEach-Object {
            if($_.StorageProfile.OsDisk.OsType -eq 'Windows' -and $_.PowerState -eq 'VM running') {
                $totalRunningVMs += $_.Name
                #Write-Output "Running Azure Windows VM: $($_.Name)"
            } 
        }

        $arc_vms | ForEach-Object {
            if($_.Status -eq 'Connected' -and $_.OsType -eq 'windows') {
                $totalRunningVMs += $_.Name
                #Write-Output "Running Azure ARC Windows Server: $($_.Name)"
            }
        }

        # If -VirtualMachine is selected, check to see if user provided VM's are 
        # in $totalRunningVMs before ASR rule application/consideration
        if (-not ([String]::IsNullOrEmpty($VirtualMachine))) {
            $VirtualMachine | Where-Object -FilterScript { 
                if($_ -notin $totalRunningVMs) { 
                    Write-Host "`nVirtual Machine:[$_] could not be found! [$_] might be sleeping, goodbye :|" -ForegroundColor Red
                    break
                } else {
                    Write-Host "`n[3] Virtual Machine:[$_] was successfully located..." -ForegroundColor Green
                }
            }
            Write-Host "`nRG:[$ResourceGroup] -> ASR:[$ModeType] -> Host:[$VirtualMachine]" -ForegroundColor Magenta
        }
        

        # If -All is toggled, loop through all running Windows VM's and enable/disable ASR accordingly.
        if ($AllVMs) {

            if ($Mode -gt 0) {
                $VMEnabled = $true
                Write-Host "`nEnable ASR ON $(($totalRunningVMs).count) VMs!" -ForegroundColor Green
            } else {
                Write-Host "`nDisable ASR ON $(($totalRunningVMs).count) VMs!" -ForegroundColor Yellow   
            }
            
            $parameters = @{}
            if ([String]::IsNullOrEmpty($Rules)) {
                # Invoke ALL the rules
                $parameters = @{ "Mode" = $ModeType }
            } else {
                # Invoke specific rules provided by the user
                $parameters = @{ "Mode" = $ModeType; "Rules" = $Rules }
            }

            $totalRunningVMs | ForEach-Object {
                Invoke-AzVMRunCommand -ResourceGroup $ResourceGroup -VMName $vm -CommandId RunPowerShellScript -ScriptPath .\run_asrrules_on_endpoint.ps1 -Parameter $parameters | Out-Null
                Start-Sleep -s 1
            }
        
        } else {
        
            # Search VM's to ensure the specified VM(s) exists within the Resource Group!
            Write-Host "`n[4] Total Virtual Machines:[$(($VirtualMachine).count)] to apply ASR rules against..." -ForegroundColor Blue
            foreach ($vm in $VirtualMachine) {
                foreach ($azureVM in $totalRunningVMs) {
                    
                    # Default ALL RULES enabled ..add logic to provide specific rules
                    if ($vm -eq $azureVM) {

                        if ($Mode -gt 0) { $VMEnabled = $true }

                        if ([String]::IsNullOrEmpty($Rules)) {
                            # Invoke ALL the rules
                            $parameters = @{ "Mode" = $ModeType }
                        } else {
                            # Invoke specific validated rules
                            $parameters = @{ "Mode" = $ModeType; "Rules" = $Rules }
                        }
                        Invoke-AzVMRunCommand -ResourceGroup $ResourceGroup -VMName $vm -CommandId RunPowerShellScript -ScriptPath .\run_asrrules_on_endpoint.ps1 -Parameter $parameters | Out-Null
                    }
                }
            }             
        }
    }

    End {

        if ($VMEnabled) {
            Write-Host "`nEndpoint successfully hardened with Attack Surface Reduction!`n" -ForegroundColor Green
        } else {
            Write-Host "`nAttack Surface Reduction rule(s) successfully `"DISABLED`"...`n" -ForegroundColor Yellow
        }
    }
}
