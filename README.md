# azure_asr_rules
A no frills script that will iterate over a resource group looking for Azure VMs &amp; Azure Arc Servers (running) to enable/disable ASR rules.

https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction?view=o365-worldwide


Usage:
------
1. Run PowerShell with elevated privileges 

2. Import the PowerShell script:
. ./azureASR.ps1
    
3. Basic Example [enable an ASR rule for AuditMode]:
   Set-ASRRules -ResourceGroup 'YOUR_RG' -Mode 2 -VirtualMachine 'YOUR_AZ_VM' -Rule 'c1db55ab-c21a-4637-bb3f-a12568109d35'

4. Run Set-ASRRules with -CheckAzModules to install the three required Az modules if necessary.
