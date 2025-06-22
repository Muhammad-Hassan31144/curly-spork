#!/bin/bash

# Load resource configuration
load_resource_config() {
    local config_file="$HOME/shikra/config/resource_defaults.conf"
    source "$config_file"
}

# Generate random value within range
random_in_range() {
    local range="$1"
    local min=$(echo "$range" | cut -d: -f1)
    local max=$(echo "$range" | cut -d: -f2)
    local default=$(echo "$range" | cut -d: -f3)
    
    if [ "$min" = "$max" ]; then
        echo "$default"
    else
        echo $((RANDOM % (max - min + 1) + min))
    fi
}

# Generate comprehensive hardware profile
generate_hardware_profile() {
    local vendor_db="$HOME/shikra/config/stealth_vendors.db"
    local profile_file="$HOME/shikra/config/current_profile.conf"
    
    # Load resource config
    load_resource_config
    
    # Select random vendor (existing code)
    local vendor_line=$(shuf -n 1 "$vendor_db" | grep -v "^#")
    IFS='|' read -r vendor manufacturer product serial_pattern bios_vendor bios_version mac_prefix <<< "$vendor_line"
    
    # Generate hardware values
    local serial_num=$((RANDOM % 9000 + 1000))
    local bios_major=$((RANDOM % 9 + 1))
    local bios_minor=$((RANDOM % 9))
    local mac_suffix=$(printf '%02X:%02X:%02X' $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)))
    
    # Generate resource spoofing values
    local fake_cpu_cores=$(random_in_range "$FAKE_CPU_CORES")
    local fake_cpu_threads=$(random_in_range "$FAKE_CPU_THREADS")
    local fake_cpu_speed=$(random_in_range "$FAKE_CPU_SPEED")
    local fake_memory_gb=$(random_in_range "$FAKE_MEMORY_GB")
    local fake_disk_gb=$(random_in_range "$FAKE_DISK_SIZE")
    local fake_gpu_mb=$(random_in_range "$FAKE_GPU_MEMORY")
    local fake_uptime=$(random_in_range "$FAKE_UPTIME_DAYS")
    
    # Format values
    MANUFACTURER="$manufacturer"
    PRODUCT="$product"
    SERIAL=$(printf "$serial_pattern" $serial_num)
    BIOS_VENDOR="$bios_vendor"
    BIOS_VERSION=$(printf "$bios_version" $bios_major $bios_minor)
    MAC_ADDRESS="$mac_prefix:$mac_suffix"
    
    # Resource spoofing values
    FAKE_CPU_CORES="$fake_cpu_cores"
    FAKE_CPU_THREADS="$fake_cpu_threads"
    FAKE_CPU_SPEED="$fake_cpu_speed"
    FAKE_MEMORY_GB="$fake_memory_gb"
    FAKE_MEMORY_BYTES=$((fake_memory_gb * 1024 * 1024 * 1024))
    FAKE_DISK_GB="$fake_disk_gb"
    FAKE_GPU_MB="$fake_gpu_mb"
    FAKE_UPTIME_DAYS="$fake_uptime"
    
    # Save comprehensive profile
    cat > "$profile_file" << PROFEOF
MANUFACTURER="$MANUFACTURER"
PRODUCT="$PRODUCT"
SERIAL="$SERIAL"
BIOS_VENDOR="$BIOS_VENDOR"
BIOS_VERSION="$BIOS_VERSION"
MAC_ADDRESS="$MAC_ADDRESS"
FAKE_CPU_CORES="$FAKE_CPU_CORES"
FAKE_CPU_THREADS="$FAKE_CPU_THREADS"
FAKE_CPU_SPEED="$FAKE_CPU_SPEED"
FAKE_MEMORY_GB="$FAKE_MEMORY_GB"
FAKE_MEMORY_BYTES="$FAKE_MEMORY_BYTES"
FAKE_DISK_GB="$FAKE_DISK_GB"
FAKE_GPU_MB="$FAKE_GPU_MB"
FAKE_UPTIME_DAYS="$FAKE_UPTIME_DAYS"
PROFEOF
    
    echo "Generated profile: $MANUFACTURER $PRODUCT"
    echo "  CPU: $FAKE_CPU_CORES cores, $FAKE_CPU_THREADS threads @ ${FAKE_CPU_SPEED}MHz"
    echo "  RAM: ${FAKE_MEMORY_GB}GB"
    echo "  Disk: ${FAKE_DISK_GB}GB"
    echo "  GPU: ${FAKE_GPU_MB}MB"
}

# Generate comprehensive Windows anti-evasion script
generate_windows_stealth_script() {
    local script_path="$1"
    
    # Load current profile
    source "$HOME/shikra/config/current_profile.conf"
    
    cat > "$script_path" << WINEOF
@echo off
echo ========================================
echo SHIKRA COMPREHENSIVE ANTI-EVASION
echo ========================================
echo.
echo Applying stealth measures...
echo Hardware Profile: $MANUFACTURER $PRODUCT
echo Fake Specs: ${FAKE_CPU_CORES}C/${FAKE_CPU_THREADS}T, ${FAKE_MEMORY_GB}GB RAM
echo.

REM === CPU SPOOFING ===
echo [1/8] Spoofing CPU cores...
for /L %%i in (1,1,$FAKE_CPU_CORES) do (
    reg copy "HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\00000000" "HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\000000%%i" /s /f 2>nul
    reg add "HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\000000%%i" /v "ProcessorNameString" /d "Intel(R) Core(TM) i7-10700K CPU @ ${FAKE_CPU_SPEED}MHz" /f 2>nul
)

REM === MEMORY SPOOFING ===
echo [2/8] Spoofing memory size...
REM This fools some basic checks but not all WMI queries
reg add "HKLM\HARDWARE\RESOURCEMAP\System Resources\Physical Memory" /v ".Translated" /t REG_BINARY /d "00000000000000000000000000000000000000002000000000" /f 2>nul

REM === SYSTEM INFO SPOOFING ===
echo [3/8] Setting system information...
reg add "HKLM\HARDWARE\DESCRIPTION\System" /v "SystemBiosVersion" /d "$BIOS_VERSION" /f 2>nul
reg add "HKLM\HARDWARE\DESCRIPTION\System" /v "VideoBiosVersion" /d "NVIDIA GeForce RTX 3070" /f 2>nul

REM === REMOVE VM ARTIFACTS ===
echo [4/8] Removing VM artifacts...
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\vioscsi" /f 2>nul
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\viostor" /f 2>nul
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\balloon" /f 2>nul
reg delete "HKLM\SYSTEM\CurrentControlSet\Enum\PCI\VEN_1AF4" /f 2>nul
reg delete "HKLM\SOFTWARE\Oracle" /f 2>nul
reg delete "HKLM\SOFTWARE\VMware" /f 2>nul

del "C:\Windows\System32\drivers\vioscsi.sys" /f /q 2>nul
del "C:\Windows\System32\drivers\viostor.sys" /f /q 2>nul
del "C:\Windows\System32\drivers\balloon.sys" /f /q 2>nul

REM === USER ACTIVITY SIMULATION ===
echo [5/8] Simulating user activity...
mkdir "%USERPROFILE%\Documents\Projects" 2>nul
mkdir "%USERPROFILE%\Documents\Finance" 2>nul
mkdir "%USERPROFILE%\Downloads\Software" 2>nul
mkdir "%USERPROFILE%\Desktop\Work" 2>nul

echo Budget spreadsheet content > "%USERPROFILE%\Documents\Finance\Q4_Budget_2024.xlsx"
echo Project documentation > "%USERPROFILE%\Documents\Projects\Client_Proposal.docx"
echo Meeting notes from last week > "%USERPROFILE%\Documents\Weekly_Meeting_Notes.txt"
echo Software installer > "%USERPROFILE%\Downloads\Software\chrome_installer.exe"

REM === BROWSER HISTORY SIMULATION ===
echo [6/8] Creating browser history...
reg add "HKCU\Software\Microsoft\Internet Explorer\TypedURLs" /v url1 /d "https://outlook.office365.com" /f 2>nul
reg add "HKCU\Software\Microsoft\Internet Explorer\TypedURLs" /v url2 /d "https://teams.microsoft.com" /f 2>nul
reg add "HKCU\Software\Microsoft\Internet Explorer\TypedURLs" /v url3 /d "https://sharepoint.company.local" /f 2>nul
reg add "HKCU\Software\Microsoft\Internet Explorer\TypedURLs" /v url4 /d "https://portal.azure.com" /f 2>nul
reg add "HKCU\Software\Microsoft\Internet Explorer\TypedURLs" /v url5 /d "https://github.com" /f 2>nul

REM === RECENT FILES ===
echo [7/8] Creating recent file entries...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" /f 2>nul

REM === SYSTEM UPTIME SIMULATION ===
echo [8/8] Setting realistic uptime...
REM This is complex to fake perfectly, but we can modify some traces
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LastBootTime" /t REG_QWORD /d 132456789012345678 /f 2>nul

REM === COMPUTER NAME ===
for /f "tokens=2 delims==" %%a in ('wmic computersystem get name /value ^| find "="') do set current_name=%%a
set /a random_num=%RANDOM% %% 9999 + 1000
wmic computersystem where name="%current_name%" call rename name="WORKSTATION-%random_num%" 2>nul

echo.
echo ========================================
echo ANTI-EVASION COMPLETE
echo ========================================
echo System now appears as:
echo - Hardware: $MANUFACTURER $PRODUCT
echo - CPU: ${FAKE_CPU_CORES} cores @ ${FAKE_CPU_SPEED}MHz
echo - Memory: ${FAKE_MEMORY_GB}GB
echo - Realistic user environment created
echo - VM artifacts removed
echo.
timeout /t 3
WINEOF
}

# Enhanced VM XML creation with resource spoofing
create_stealth_vm_xml() {
    local vm_name="$1"
    local disk_path="$2"
    local disk_format="$3"
    local output_file="$4"
    
    # Load current profile
    source "$HOME/shikra/config/current_profile.conf"
    
    # Calculate topology for fake CPU cores
    local sockets=2
    local cores_per_socket=$((FAKE_CPU_CORES / 2))
    local threads_per_core=$((FAKE_CPU_THREADS / FAKE_CPU_CORES))
    
    cat > "$output_file" << XMLEOF
<domain type='kvm'>
  <name>$vm_name</name>
  <memory unit='KiB'>8388608</memory>
  <currentMemory unit='KiB'>4194304</currentMemory>
  <vcpu placement='static' current='2'>$FAKE_CPU_CORES</vcpu>
  
  <sysinfo type='smbios'>
    <system>
      <entry name='manufacturer'>$MANUFACTURER</entry>
      <entry name='product'>$PRODUCT</entry>
      <entry name='serial'>$SERIAL</entry>
      <entry name='uuid'>$(uuidgen)</entry>
    </system>
    <bios>
      <entry name='vendor'>$BIOS_VENDOR</entry>
      <entry name='version'>$BIOS_VERSION</entry>
    </bios>
    <processor>
      <entry name='max_speed'>${FAKE_CPU_SPEED}</entry>
      <entry name='current_speed'>${FAKE_CPU_SPEED}</entry>
    </processor>
  </sysinfo>
  
  <os>
    <type arch='x86_64' machine='pc-q35-5.2'>hvm</type>
    <smbios mode='sysinfo'/>
    <boot dev='hd'/>
  </os>
  
  <features>
    <acpi/>
    <apic/>
  </features>
  
  <cpu mode='host-passthrough' check='none'>
    <topology sockets='$sockets' cores='$cores_per_socket' threads='$threads_per_core'/>
    <feature policy='disable' name='hypervisor'/>
    <feature policy='require' name='invtsc'/>
  </cpu>
  
  <devices>
    <emulator>/usr/bin/qemu-system-x86_64</emulator>
    <disk type='file' device='disk'>
      <driver name='qemu' type='$disk_format'/>
      <source file='$disk_path'/>
      <target dev='sda' bus='sata'/>
    </disk>
    <interface type='network'>
      <mac address='$MAC_ADDRESS'/>
      <source network='shikra-isolated'/>
      <model type='e1000'/>
    </interface>
    <graphics type='vnc' port='-1' autoport='yes' listen='127.0.0.1'/>
    <video>
      <model type='qxl' ram='65536' vram='$((FAKE_GPU_MB * 1024))'/>
    </video>
  </devices>
</domain>
XMLEOF
}

# Mouse/keyboard activity simulation
simulate_user_activity() {
    cat >> "$1" << 'ACTEOF'

REM === MOUSE ACTIVITY SIMULATION ===
echo Simulating user activity...
powershell -Command "Add-Type -AssemblyName System.Windows.Forms; for(\$i=0; \$i -lt 10; \$i++) { [System.Windows.Forms.Cursor]::Position = New-Object System.Drawing.Point((Get-Random -Min 100 -Max 800), (Get-Random -Min 100 -Max 600)); Start-Sleep -Milliseconds 500 }"

REM === KEYBOARD ACTIVITY SIMULATION ===
echo Simulating keyboard activity...
powershell -Command "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.SendKeys]::SendWait('{TAB}'); Start-Sleep -Milliseconds 100; [System.Windows.Forms.SendKeys]::SendWait('Hello'); Start-Sleep -Milliseconds 200"

ACTEOF
}
# Generate Windows file extraction script
generate_file_extraction_script() {
    local script_path="$1"
    
    cat > "$script_path" << 'EXTRACTEOF'
@echo off
echo ========================================
echo CORPORATE FILE BACKUP SYSTEM
echo ========================================
echo.
echo Connecting to corporate file server...

REM Map network drive (looks like corporate infrastructure)
net use Z: \\192.168.100.1\corpshare /persistent:no 2>nul
if %errorlevel% neq 0 (
    echo WARNING: Could not connect to corporate file server
    echo Attempting alternative connection...
    timeout /t 5
    net use Z: \\192.168.100.1\corpshare /persistent:no 2>nul
)

if exist Z:\ (
    echo ✓ Connected to FILESERVER01
    echo.
    
    REM Create analysis results directory
    mkdir "Z:\Analysis_Results_%COMPUTERNAME%_%date:~-4,4%%date:~-10,2%%date:~-7,2%" 2>nul
    set RESULT_DIR=Z:\Analysis_Results_%COMPUTERNAME%_%date:~-4,4%%date:~-10,2%%date:~-7,2%
    
    echo Backing up analysis files to corporate server...
    
    REM Copy ProcMon logs
    if exist "C:\ProcMon\*.pml" (
        echo Copying ProcMon analysis files...
        copy "C:\ProcMon\*.pml" "%RESULT_DIR%\" /Y >nul 2>&1
        if %errorlevel% equ 0 (
            echo ✓ ProcMon logs backed up
        ) else (
            echo ⚠ Warning: Some ProcMon files may not have copied
        )
    )
    
    REM Copy system information
    if exist "C:\Analysis_Results\*" (
        echo Copying system information...
        xcopy "C:\Analysis_Results\*" "%RESULT_DIR%\SystemInfo\" /E /I /Y >nul 2>&1
        echo ✓ System information backed up
    )
    
    REM Create backup manifest
    echo Analysis Backup Manifest > "%RESULT_DIR%\backup_manifest.txt"
    echo Computer: %COMPUTERNAME% >> "%RESULT_DIR%\backup_manifest.txt"
    echo Date: %date% %time% >> "%RESULT_DIR%\backup_manifest.txt"
    echo User: %USERNAME% >> "%RESULT_DIR%\backup_manifest.txt"
    echo. >> "%RESULT_DIR%\backup_manifest.txt"
    echo Files backed up: >> "%RESULT_DIR%\backup_manifest.txt"
    dir "%RESULT_DIR%" >> "%RESULT_DIR%\backup_manifest.txt"
    
    echo.
    echo ✓ Analysis results backed up to corporate server
    echo Location: %RESULT_DIR%
    
    REM Disconnect (but keep it brief to look normal)
    timeout /t 2 >nul
    net use Z: /delete /y >nul 2>&1
    
) else (
    echo ✗ Could not connect to corporate file server
    echo Files remain local only
)

echo.
echo Corporate backup process completed.
EXTRACTEOF
}
