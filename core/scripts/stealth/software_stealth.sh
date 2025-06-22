# ================================================================
# software_stealth.sh - Software-level stealth measures  
#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHIKRA_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
CONFIG_DIR="${SHIKRA_ROOT}/config/stealth"

log_info() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] SW-STEALTH: $1"
}

log_error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] SW-ERROR: $1" >&2
}

# Parse software stealth arguments
parse_sw_args() {
    VM_NAME=""
    GUEST_OS=""
    CONFIG_FILE=""
    DRY_RUN=false
    VERBOSE=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            --vm-name)
                VM_NAME="$2"
                shift 2
                ;;
            --guest-os)
                GUEST_OS="$2"
                shift 2
                ;;
            --config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --verbose)
                VERBOSE=true
                shift
                ;;
            *)
                log_error "Unknown software stealth option: $1"
                exit 1
                ;;
        esac
    done
}

# Execute command in VM
vm_exec() {
    local cmd="$1"
    local timeout=${2:-30}
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "DRY RUN - Would execute in VM: $cmd"
        return 0
    fi
    
    # Use appropriate VM execution method based on available tools
    if command -v virsh &> /dev/null; then
        virsh domstate "$VM_NAME" &>/dev/null && {
            echo "$cmd" | virsh console "$VM_NAME" --force 2>/dev/null || {
                log_error "Failed to execute command in VM: $cmd"
                return 1
            }
        }
    else
        log_error "No VM execution method available"
        return 1
    fi
}

# Hide VM tools and services (Windows)
hide_vm_tools_windows() {
    log_info "Hiding VM tools and services (Windows)"
    
    local artifacts_file="${CONFIG_DIR}/detection_signatures/vm_artifacts.json"
    
    # Get VM processes to stop
    local processes=$(jq -r '.process_names.windows[]' "$artifacts_file" 2>/dev/null | head -5)
    
    # Stop VM services
    local services=$(jq -r '.service_names.windows[]' "$artifacts_file" 2>/dev/null | head -5)
    
    for service in $services; do
        log_info "Stopping service: $service"
        vm_exec "sc stop \"$service\" 2>nul" 10
        vm_exec "sc config \"$service\" start=disabled 2>nul" 10
    done
    
    # Hide VM files by renaming
    local files=$(jq -r '.file_paths.windows[]' "$artifacts_file" 2>/dev/null | head -10)
    
    for file in $files; do
        log_info "Hiding file: $file"
        vm_exec "if exist \"$file\" ren \"$file\" \"$(basename "$file").bak\" 2>nul" 15
    done
    
    log_info "VM tools hiding completed (Windows)"
}

# Hide VM tools and services (Linux)
hide_vm_tools_linux() {
    log_info "Hiding VM tools and services (Linux)"
    
    local artifacts_file="${CONFIG_DIR}/detection_signatures/vm_artifacts.json"
    
    # Stop VM services
    local services=$(jq -r '.process_names.linux[]' "$artifacts_file" 2>/dev/null | head -5)
    
    for service in $services; do
        log_info "Stopping service: $service"
        vm_exec "systemctl stop $service 2>/dev/null || service $service stop 2>/dev/null" 10
        vm_exec "systemctl disable $service 2>/dev/null || chkconfig $service off 2>/dev/null" 10
    done
    
    # Hide VM files by renaming
    local files=$(jq -r '.file_paths.linux[]' "$artifacts_file" 2>/dev/null | head -10)
    
    for file in $files; do
        if [[ -n "$file" ]]; then
            log_info "Hiding file: $file"
            vm_exec "if [ -e \"$file\" ]; then mv \"$file\" \"${file}.bak\" 2>/dev/null; fi" 15
        fi
    done
    
    log_info "VM tools hiding completed (Linux)"
}

# Clean VM registry (Windows only)
clean_vm_registry() {
    if [[ "$GUEST_OS" != "windows" ]]; then
        log_info "Registry cleaning not applicable for $GUEST_OS"
        return 0
    fi
    
    log_info "Cleaning VM registry entries"
    
    local artifacts_file="${CONFIG_DIR}/detection_signatures/vm_artifacts.json"
    local registry_keys=$(jq -r '.registry_keys.windows[]' "$artifacts_file" 2>/dev/null | head -10)
    
    for key in $registry_keys; do
        if [[ -n "$key" ]]; then
            log_info "Removing registry key: $key"
            vm_exec "reg delete \"$key\" /f >nul 2>&1" 10
        fi
    done
    
    log_info "Registry cleaning completed"
}

# Install decoy software
install_decoy_software() {
    log_info "Installing decoy software"
    
    if [[ "$GUEST_OS" == "windows" ]]; then
        # Create fake Office installation
        vm_exec "mkdir \"C:\\Program Files\\Microsoft Office\\root\\Office16\" 2>nul" 10
        vm_exec "echo. > \"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\"" 10
        vm_exec "reg add \"HKLM\\SOFTWARE\\Microsoft\\Office\\16.0\\Common\\InstallRoot\" /v \"Path\" /t REG_SZ /d \"C:\\Program Files\\Microsoft Office\\root\\Office16\" /f >nul 2>&1" 15
        
        # Create fake Adobe Reader installation
        vm_exec "mkdir \"C:\\Program Files (x86)\\Adobe\\Acrobat Reader DC\\Reader\" 2>nul" 10
        vm_exec "echo. > \"C:\\Program Files (x86)\\Adobe\\Acrobat Reader DC\\Reader\\AcroRd32.exe\"" 10
        vm_exec "reg add \"HKLM\\SOFTWARE\\Adobe\\Acrobat Reader\\DC\\InstallPath\" /ve /t REG_SZ /d \"C:\\Program Files (x86)\\Adobe\\Acrobat Reader DC\\Reader\" /f >nul 2>&1" 15
        
    else
        # Create fake applications for Linux
        vm_exec "mkdir -p /opt/firefox/bin 2>/dev/null" 10
        vm_exec "touch /opt/firefox/bin/firefox 2>/dev/null" 10
        vm_exec "mkdir -p /usr/local/bin 2>/dev/null" 10
        vm_exec "ln -sf /opt/firefox/bin/firefox /usr/local/bin/firefox 2>/dev/null" 10
    fi
    
    log_info "Decoy software installation completed"
}

# Create software artifacts
create_software_artifacts() {
    log_info "Creating software artifacts"
    
    if [[ "$GUEST_OS" == "windows" ]]; then
        # Create recent documents entries
        vm_exec "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs\" /v \"MRU0\" /t REG_SZ /d \"Document1.docx\" /f >nul 2>&1" 10
        vm_exec "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs\" /v \"MRU1\" /t REG_SZ /d \"Spreadsheet.xlsx\" /f >nul 2>&1" 10
        
        # Create IE typed URLs
        vm_exec "reg add \"HKCU\\Software\\Microsoft\\Internet Explorer\\TypedURLs\" /v \"url1\" /t REG_SZ /d \"http://www.google.com\" /f >nul 2>&1" 10
        vm_exec "reg add \"HKCU\\Software\\Microsoft\\Internet Explorer\\TypedURLs\" /v \"url2\" /t REG_SZ /d \"http://www.wikipedia.org\" /f >nul 2>&1" 10
        
    else
        # Create bash history
        vm_exec "echo 'ls -la' >> ~/.bash_history 2>/dev/null" 10
        vm_exec "echo 'cd /tmp' >> ~/.bash_history 2>/dev/null" 10
        vm_exec "echo 'cat /proc/cpuinfo' >> ~/.bash_history 2>/dev/null" 10
    fi
    
    log_info "Software artifacts creation completed"
}

# Patch VM artifacts
patch_vm_artifacts() {
    log_info "Patching VM-specific artifacts"
    
    local patch_enabled=$(jq -r '.software_stealth.patch_vm_artifacts' "$CONFIG_FILE")
    if [[ "$patch_enabled" != "true" ]]; then
        log_info "VM artifact patching disabled"
        return 0
    fi
    
    if [[ "$GUEST_OS" == "windows" ]]; then
        # Create and execute batch script for renaming VM artifacts
        local batch_script="@echo off
cd /d C:\\Windows\\System32
if exist \"vboxdisp.dll\" ren \"vboxdisp.dll\" \"vboxdisp.dll.bak\" >nul 2>&1
if exist \"vboxhook.dll\" ren \"vboxhook.dll\" \"vboxhook.dll.bak\" >nul 2>&1
cd /d C:\\Windows\\System32\\drivers
if exist \"VBoxGuest.sys\" ren \"VBoxGuest.sys\" \"VBoxGuest.sys.bak\" >nul 2>&1
if exist \"VBoxMouse.sys\" ren \"VBoxMouse.sys\" \"VBoxMouse.sys.bak\" >nul 2>&1"
        
        # Write batch script to VM and execute
        vm_exec "echo '$batch_script' > C:\\Windows\\Temp\\patch_artifacts.bat" 20
        vm_exec "C:\\Windows\\Temp\\patch_artifacts.bat" 30
        vm_exec "del C:\\Windows\\Temp\\patch_artifacts.bat /F /Q 2>nul" 10
        
    else
        # Modify DMI information on Linux
        vm_exec "echo 'Generic PC' > /sys/class/dmi/id/product_name 2>/dev/null || true" 10
        vm_exec "echo 'Standard Manufacturer' > /sys/class/dmi/id/sys_vendor 2>/dev/null || true" 10
    fi
    
    log_info "VM artifact patching completed"
}

# Main software stealth function
main_software() {
    parse_sw_args "$@"
    
    if [[ -z "$VM_NAME" || -z "$GUEST_OS" || -z "$CONFIG_FILE" ]]; then
        log_error "Missing required arguments for software stealth"
        exit 1
    fi
    
    log_info "Applying software stealth for VM: $VM_NAME ($GUEST_OS)"
    
    # Check what software stealth measures are enabled
    local hide_tools=$(jq -r '.software_stealth.hide_vm_tools' "$CONFIG_FILE")
    local clean_registry=$(jq -r '.software_stealth.clean_vm_registry' "$CONFIG_FILE")
    local install_decoy=$(jq -r '.software_stealth.install_decoy_software' "$CONFIG_FILE")
    local patch_artifacts=$(jq -r '.software_stealth.patch_vm_artifacts' "$CONFIG_FILE")
    
    # Apply enabled measures
    if [[ "$hide_tools" == "true" ]]; then
        if [[ "$GUEST_OS" == "windows" ]]; then
            hide_vm_tools_windows
        else
            hide_vm_tools_linux
        fi
    fi
    
    if [[ "$clean_registry" == "true" ]]; then
        clean_vm_registry
    fi
    
    if [[ "$install_decoy" == "true" ]]; then
        install_decoy_software
        create_software_artifacts
    fi
    
    if [[ "$patch_artifacts" == "true" ]]; then
        patch_vm_artifacts
    fi
    
    log_info "Software stealth application completed"
}

# Run software stealth if called directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main_software "$@"
fi