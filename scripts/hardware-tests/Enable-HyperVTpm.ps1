<#
.SYNOPSIS
    Enables a virtual TPM on Hyper-V test VMs, starts each one and takes a
    checkpoint to roll back to after testing.

.DESCRIPTION
    Run on the Hyper-V host, elevated. A vTPM needs a Generation 2 VM; others
    are skipped. Safe to rerun: a VM that already has a key protector or a
    vTPM keeps it - replacing a key protector would make the VM's current TPM
    state unreadable. A running VM is shut down (a guest shutdown) to enable
    its vTPM.

    In each guest, Get-Tpm should then show TpmPresent and TpmReady True,
    manufacturer MSFT.

.PARAMETER VMName
    The VMs to set up. Default: hkdfguard-win-2022, hkdfguard-win-2025.

.PARAMETER CheckpointName
    The checkpoint taken once each VM is running. Default: pre-hkdfguard.
#>
#Requires -RunAsAdministrator
param(
    [string[]]$VMName = @("hkdfguard-win-2022", "hkdfguard-win-2025"),
    [string]$CheckpointName = "pre-hkdfguard"
)
$ErrorActionPreference = "Stop"

foreach ($name in $VMName) {
    Write-Host "== $name"
    $vm = Get-VM -Name $name
    if ($vm.Generation -ne 2) {
        Write-Host "  Generation $($vm.Generation) VM: a vTPM needs Generation 2. Skipped."
        continue
    }

    if ((Get-VMSecurity -VMName $name).TpmEnabled) {
        Write-Host "  vTPM already enabled"
    } else {
        if ($vm.State -ne "Off") {
            Write-Host "  shutting down"
            Stop-VM -Name $name    # guest shutdown; add -Force to answer its prompts, -TurnOff to pull the plug
        }
        $kp = Get-VMKeyProtector -VMName $name
        if (-not $kp -or $kp.Length -le 4) {
            Write-Host "  adding a local key protector"
            Set-VMKeyProtector -VMName $name -NewLocalKeyProtector
        } else {
            Write-Host "  key protector already present"
        }
        Write-Host "  enabling vTPM"
        Enable-VMTPM -VMName $name
    }

    if ((Get-VM -Name $name).State -ne "Running") {
        Write-Host "  starting"
        Start-VM -Name $name
    }
    Write-Host "  checkpoint $CheckpointName"
    Checkpoint-VM -Name $name -SnapshotName $CheckpointName
    Get-VMSecurity -VMName $name | Format-List TpmEnabled, KsdEnabled, Shielded | Out-Host
}
