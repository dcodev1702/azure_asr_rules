# ASR Rule enablement for Azure VMs
A no frills script that will iterate over a resource group looking for Azure VMs to enable/disable ASR rules.

https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction?view=o365-worldwide


Usage:
------
1. Run PowerShell with elevated privileges

2. Ensure your Execution Policy supports importing unsigned PowerShell scripts.
   
   Set-ExecutionPolicy -ExecutionPolicy <value>

3. Import the PowerShell script:

    . ./azureASR.ps1

3. Enable all 16 ASR Rules in AuditMode for all Azure VM's (currently running):

    Set-ASRRules -ResourceGroup 'VMtestRG' -Mode 2 -AllVMs

4. Add/Modify specific ASR Rule(s) :: [enable two ASR rules in AuditMode]:

    Set-ASRRules -ResourceGroup 'VMTESTRG' -Mode 2 -VirtualMachine 'WinZo10-VM-ENT' -Rules "d4f940ab-401b-4efc-aadc-ad5f3c50688a,c1db55ab-c21a-4637-bb3f-a12568109d35"

5. Run the Set-ASRRules CmdLet with -CheckAzModules to install the two required Az modules if necessary.
   - Az.Compute
   - Az.Accounts
