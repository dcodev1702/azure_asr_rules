<########################################################
  Automation of Attack Surface Reduction Rules
  - Disable = 0
  - Block = 1
  - Audit = 2
  - Warn = 6
  
  Author: Lorenzo J. Ireland
  Date: 16 Dec 2022
  
  Usage: 
    Enable ALL VMs:       Enable-ASR -ResourceGroup 'VMTESTRG' -Mode 2 -All
    Enable specified VMs: Enable-ASR -ResourceGroup 'VMTESTRG' -Mode 2 -VirtualMachine 'Host-1','Host-2','Host-3'
########################################################>
<#
Warn mode isn't supported for three attack surface reduction rules when you configure them in Microsoft Endpoint Manager. (If you use Group Policy to configure your attack surface reduction rules, warn mode is supported.) The three rules that do not support warn mode when you configure them in Microsoft Endpoint Manager are as follows:

Block JavaScript or VBScript from launching downloaded executable content (GUID d3e037e1-3eb8-44c8-a917-57927947596d)
Block persistence through WMI event subscription (GUID e6db77e5-3df2-4cf1-b95a-636979351e5b)
Use advanced protection against ransomware (GUID c1db55ab-c21a-4637-bb3f-a12568109d35)
#>

# MAYBE: Add Azure Subscriptions before iterating over Resource Groups
function Enable-ASR {
    [CmdletBinding()] 
    Param (
        [Parameter(Mandatory = $true)]
        [String] $ResourceGroup = $null,
        
        [Parameter(Mandatory = $false)]
        [String] $Rule = $null,
        
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

        if ($CheckAzModules) {
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

        [bool]$VMEnabled = $false
        [String]$ModeType = ""
        switch ( $Mode ) {
            0 { $ModeType = "Disabled" }
            1 { $ModeType = "Enabled" }
            2 { $ModeType = "AuditMode" }
            6 { $ModeType = "Warn" }
        }

        # Get list of registered Windows VM's in Azure & Azure ARC
        $azure_vms = Get-AzVM -Status
        $arc_vms = Get-AzConnectedMachine   
    }
    
    Process {
        Write-Output("$ResourceGroup : ASR -> $ModeType on Host: $VirtualMachine")

        # Get list of RUNNING VM's within the registered list of Windows VM's.
        $totalRunningVMs = @()
        $azure_vms | ForEach-Object {
            if($_.StorageProfile.OsDisk.OsType -eq 'Windows' -and $_.PowerState -eq 'VM running') {
                $totalRunningVMs += $_.Name
                Write-Output "Azure VM: $($_.Name)"
            } 
        }

        $arc_vms | ForEach-Object {
            if($_.Status -eq 'Connected' -and $_.OsType -eq 'windows') {
                $totalRunningVMs += $_.Name
                Write-Output "Azure ARC VM: $($_.Name)"
            }
        }

        # If -All is toggled, loop through all running Windows VM's and enable/disable ASR accordingly
        if ($AllVMs) {
            
            $totalRunningVMs | ForEach-Object {
                if ($Mode -gt 0) {
                    $VMEnabled = $true
                    Write-Output "`nEnable ASR ON $(($totalRunningVMs).count) VMs!"
                    Invoke-AzVMRunCommand -ResourceGroup $ResourceGroup -VMName $_.Name -CommandId RunPowerShellScript -ScriptPath .\run_asr.ps1 -Parameter @{"Mode" = $ModeType}
                    Start-Sleep -s 1
                } else {
                    Write-Output "`nDisable ASR ON $(($totalRunningVMs).count) VMs!"
                    Invoke-AzVMRunCommand -ResourceGroup $ResourceGroup -VMName $_.Name -CommandId RunPowerShellScript -ScriptPath .\run_asr.ps1 -Parameter @{"Mode" = $ModeType}
                    Start-Sleep -s 2
                }
            }
            $totalRunningVMs

        } else {
        
            # Search VM's to ensure the specified VM(s) exists within the Resource Group!
            foreach ($vm in $VirtualMachine) {
                foreach ($azureVM in $totalRunningVMs) {
                    if ($vm -eq $azureVM) {
                        if ($Mode -gt 0) { 
                            $VMEnabled = $true
                            Write-Output "Windows VM [$vm] is now ASR enabled!"
                            Invoke-AzVMRunCommand -ResourceGroup $ResourceGroup -VMName $vm -CommandId RunPowerShellScript -ScriptPath .\run_asr.ps1 -Parameter @{"Mode" = $ModeType}

                        } else {
                            Write-Output "Windows VM [$vm] is now ASR disabled!"
                            Invoke-AzVMRunCommand -ResourceGroup $ResourceGroup -VMName $vm -CommandId RunPowerShellScript -ScriptPath .\run_asr.ps1 -Parameter @{"Mode" = $ModeType}
                        }
                        
                    } else {
                        #Write-Output "Your VM [$vm] could not be found, it may be sleeping :("
                    }   
                }
            }   
        }
    }

    End {

        if ($VMEnabled) {
            Write-Output "`nThank you for enabling Attack Surface Reduction!"
        }
    }
}