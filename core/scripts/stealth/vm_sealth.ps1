# vm_stealth_hardening.ps1
<#
.SYNOPSIS
  Stealth‑hardening checklist for Windows VMs running under KVM/QEMU.
  Removes or masks common virtualization artefacts visible to malware.

.DESCRIPTION
  This script must be run **inside** the guest as an Administrator.
  It focuses purely on in‑guest tweaks that complement the external SMBIOS
  spoofing your host already performs.

  The changes are safe for malware‑analysis labs but NOT recommended
  for production systems. Use at your own risk; snapshot first.

  Tested on Windows 10/11 build 19045+.

#>

# ---------------------- Safety checks ---------------------------------------
Write-Host "[*] Stealth hardening – Starting" -ForegroundColor Cyan
if (-not ([bool](New-Object Security.Principal.WindowsPrincipal `
               [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
               [Security.Principal.WindowsBuiltinRole]::Administrator))) {
    Write-Error "Run this script from an elevated PowerShell."
    exit 1
}

# Ask confirmation
$ans = Read-Host "This will modify BIOS registry keys, device descriptions and services. Continue? (y/N)"
if ($ans -ne 'y' -and $ans -ne 'Y') { exit }

# ---------------------- Helper functions ------------------------------------
function Set-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [Microsoft.Win32.RegistryValueKind]$Type = [Microsoft.Win32.RegistryValueKind]::String
    )
    try {
        if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
        Write-Host "    ✔  $Path\$Name = $Value" -ForegroundColor Green
    } catch { Write-Warning "Failed to set $Path\$Name : $_" }
}

function Disable-ServiceAndDriver {
    param([string]$Name)
    try {
        sc.exe config $Name start= disabled | Out-Null
        Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue
        Write-Host "    ✔  Disabled service/driver $Name" -ForegroundColor Green
    } catch { Write-Warning "Could not disable $Name" }
}

# ---------------------- BIOS / SMBIOS spoof fallback ------------------------
# (These keys are read by many malware samples via WMI)
$biosPath = 'HKLM:\HARDWARE\DESCRIPTION\System\BIOS'
Write-Host "[*] Spoofing BIOS strings in registry..."
Set-RegistryValue $biosPath 'BaseBoardManufacturer'  'LENOVO'
Set-RegistryValue $biosPath 'BaseBoardProduct'       '20XWCTO1WW'
Set-RegistryValue $biosPath 'SystemManufacturer'     'LENOVO'
Set-RegistryValue $biosPath 'SystemProductName'      'ThinkPad X1 Carbon Gen 9'
Set-RegistryValue $biosPath 'SystemVersion'          'ThinkPad X1 Carbon Gen 9'
Set-RegistryValue $biosPath 'BIOSVendor'             'LENOVO'
Set-RegistryValue $biosPath 'BIOSVersion'            'N32ET86W (1.64 )'
Set-RegistryValue $biosPath 'BIOSReleaseDate'        '08/17/2023'

# ---------------------- Remove QEMU/RedHat devices --------------------------
Write-Host "[*] Hiding QEMU / Red Hat VirtIO devices..."
$virtualVendors = 'QEMU', 'Red Hat', 'Red Hat', 'VirtIO'
Get-PnpDevice | Where-Object { $_.FriendlyName -match ($virtualVendors -join '|') } |
    ForEach-Object { Disable-PnpDevice -InstanceId $_.InstanceId -Confirm:$false }

# ---------------------- Rename display adapter ------------------------------
Write-Host "[*] Renaming display adapter description..."
$gpuKey = 'HKLM:\SYSTEM\CurrentControlSet\Enum\PCI'
Get-ChildItem -Path $gpuKey -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match 'VEN_1AF4|QEMU|Red Hat' } |
    ForEach-Object {
        Set-RegistryValue ("$($_.PSPath)\Device Parameters") 'FriendlyName' 'Intel(R) UHD Graphics'
    }

# ---------------------- Disable unneeded Windows features -------------------
Write-Host "[*] Disabling built‑in Windows telemetry & Defender..."
$telemetryKeys = @(
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection'
)
foreach ($k in $telemetryKeys) {
    Set-RegistryValue $k 'AllowTelemetry' 0 ([Microsoft.Win32.RegistryValueKind]::DWord)
}
Disable-ServiceAndDriver 'DiagTrack'    # Connected User Experiences & Telemetry
Disable-ServiceAndDriver 'Sense'        # Windows Defender Adv. Threat Protection
Disable-ServiceAndDriver 'WinDefend'    # Windows Defender AV

# ---------------------- Mask Hypervisor evidence ----------------------------
Write-Host "[*] Clearing hypervisor evidence in registry..."
Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation' `
                  'SystemManufacturer' 'LENOVO'
Set-RegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation' `
                  'SystemProductName'  'ThinkPad X1 Carbon Gen 9'

# ---------------------- Cleanup device manager class globally ---------------
Write-Host "[*] Removing virtual NIC description strings..."
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Class' |
  ForEach-Object {
    try {
        $desc = (Get-ItemProperty $_.PSPath -Name 'DriverDesc' -ErrorAction SilentlyContinue).DriverDesc
        if ($desc -match 'Virtual|QEMU|Red Hat|VirtIO') {
            Set-RegistryValue $_.PSPath 'DriverDesc' 'Intel(R) Ethernet Connection'
        }
    } catch {}
  }

# ---------------------- Finish ----------------------------------------------
Write-Host "[✔] Stealth hardening completed. Reboot recommended." -ForegroundColor Cyan
