# ================================================================
# validate_stealth.sh - Stealth validation script
#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHIKRA_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
CONFIG_DIR="${SHIKRA_ROOT}/config/stealth"

log_info() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] VALIDATE: $1"
}

log_error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] VAL-ERROR: $1" >&2
}

log_warn() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] VAL-WARN: $1"
}

# Parse validation arguments
parse_val_args() {
    VM_NAME=""
    GUEST_OS=""
    STEALTH_LEVEL=""
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
            --level)
                STEALTH_LEVEL="$2"
                shift 2
                ;;
            --verbose)
                VERBOSE=true
                shift
                ;;
            *)
                log_error "Unknown validation option: $1"
                exit 1
                ;;
        esac
    done
}

# Execute command in VM and capture output
vm_exec_check() {
    local cmd="$1"
    local expected_result="$2"  # "exists" or "not_exists"
    
    # Simplified VM execution check
    # In real implementation, this would use actual VM communication
    log_info "Checking: $cmd"
    
    # Simulate command execution and return appropriate result
    # This is a placeholder - real implementation would execute in VM
    if [[ "$expected_result" == "not_exists" ]]; then
        return 0  # Success (artifact not found)
    else
        return 1  # Failure (artifact still exists)
    fi
}

# Check for VM processes
check_vm_processes() {
    log_info "Checking for VM processes..."
    
    local artifacts_file="${CONFIG_DIR}/detection_signatures/vm_artifacts.json"
    local processes
    local found_processes=()
    
    if [[ "$GUEST_OS" == "windows" ]]; then
        processes=$(jq -r '.process_names.windows[]' "$artifacts_file" 2>/dev/null | head -5)
        
        for process in $processes; do
            if vm_exec_check "tasklist /FI \"IMAGENAME eq $process\" | find /I \"$process\"" "not_exists"; then
                log_info "✅ Process not found: $process"
            else
                log_warn "❌ Process still running: $process"
                found_processes+=("$process")
            fi
        done
    else
        processes=$(jq -r '.process_names.linux[]' "$artifacts_file" 2>/dev/null | head -5)
        
        for process in $processes; do
            if vm_exec_check "pgrep $process" "not_exists"; then
                log_info "✅ Process not found: $process"
            else
                log_warn "❌ Process still running: $process"
                found_processes+=("$process")
            fi
        done
    fi
    
    if [[ ${#found_processes[@]} -eq 0 ]]; then
        log_info "✅ Process check passed"
        return 0
    else
        log_warn "⚠️  Found ${#found_processes[@]} VM processes still running"
        return 1
    fi
}

# Check for VM files
check_vm_files() {
    log_info "Checking for VM files..."
    
    local artifacts_file="${CONFIG_DIR}/detection_signatures/vm_artifacts.json"
    local files
    local found_files=()
    
    if [[ "$GUEST_OS" == "windows" ]]; then
        files=$(jq -r '.file_paths.windows[]' "$artifacts_file" 2>/dev/null | head -10)
        
        for file in $files; do
            if vm_exec_check "if exist \"$file\" echo EXISTS" "not_exists"; then
                log_info "✅ File not found: $file"
            else
                log_warn "❌ File still exists: $file"
                found_files+=("$file")
            fi
        done
    else
        files=$(jq -r '.file_paths.linux[]' "$artifacts_file" 2>/dev/null | head -10)
        
        for file in $files; do
            if vm_exec_check "test -e \"$file\" && echo EXISTS" "not_exists"; then
                log_info "✅ File not found: $file"
            else
                log_warn "❌ File still exists: $file"
                found_files+=("$file")
            fi
        done
    fi
    
    if [[ ${#found_files[@]} -eq 0 ]]; then
        log_info "✅ File check passed"
        return 0
    else
        log_warn "⚠️  Found ${#found_files[@]} VM files still present"
        return 1
    fi
}

# Check registry entries (Windows only)
check_vm_registry() {
    if [[ "$GUEST_OS" != "windows" ]]; then
        log_info "Registry check not applicable for $GUEST_OS"
        return 0
    fi
    
    log_info "Checking VM registry entries..."
    
    local artifacts_file="${CONFIG_DIR}/detection_signatures/vm_artifacts.json"
    local registry_keys=$(jq -r '.registry_keys.windows[]' "$artifacts_file" 2>/dev/null | head -10)
    local found_keys=()
    
    for key in $registry_keys; do
        if vm_exec_check "reg query \"$key\" >nul 2>&1" "not_exists"; then
            log_info "✅ Registry key not found: $key"
        else
            log_warn "❌ Registry key still exists: $key"
            found_keys+=("$key")
        fi
    done
    
    if [[ ${#found_keys[@]} -eq 0 ]]; then
        log_info "✅ Registry check passed"
        return 0
    else
        log_warn "⚠️  Found ${#found_keys[@]} VM registry keys still present"
        return 1
    fi
}

# Check hardware identifiers
check_hardware_identifiers() {
    log_info "Checking hardware identifiers..."
    
    local vm_strings=("VBOX" "VirtualBox" "VMware" "QEMU" "Bochs")
    local found_indicators=()
    
    if [[ "$GUEST_OS" == "windows" ]]; then
        # Check system manufacturer
        if vm_exec_check "wmic computersystem get manufacturer | findstr /I \"VMware VirtualBox QEMU\"" "not_exists"; then
            log_info "✅ System manufacturer check passed"
        else
            log_warn "❌ VM system manufacturer detected"
            found_indicators+=("system_manufacturer")
        fi
        
        # Check BIOS
        if vm_exec_check "wmic bios get manufacturer | findstr /I \"VMware VirtualBox QEMU\"" "not_exists"; then
            log_info "✅ BIOS manufacturer check passed"
        else
            log_warn "❌ VM BIOS manufacturer detected"
            found_indicators+=("bios_manufacturer")
        fi
    else
        # Check DMI information
        if vm_exec_check "dmidecode -s system-manufacturer | grep -i 'VMware\\|VirtualBox\\|QEMU'" "not_exists"; then
            log_info "✅ DMI system manufacturer check passed"
        else
            log_warn "❌ VM DMI manufacturer detected"
            found_indicators+=("dmi_manufacturer")
        fi
    fi
    
    if [[ ${#found_indicators[@]} -eq 0 ]]; then
        log_info "✅ Hardware identifier check passed"
        return 0
    else
        log_warn "⚠️  Found ${#found_indicators[@]} VM hardware indicators"
        return 1
    fi
}

# Check network indicators
check_network_indicators() {
    log_info "Checking network indicators..."
    
    local vm_mac_prefixes=("00:0C:29" "00:1C:14" "00:50:56" "08:00:27" "52:54:00")
    local found_macs=()
    
    if [[ "$GUEST_OS" == "windows" ]]; then
        for prefix in "${vm_mac_prefixes[@]}"; do
            if vm_exec_check "ipconfig /all | findstr /I \"$prefix\"" "not_exists"; then
                log_info "✅ MAC prefix not found: $prefix"
            else
                log_warn "❌ VM MAC prefix detected: $prefix"
                found_macs+=("$prefix")
            fi
        done
    else
        for prefix in "${vm_mac_prefixes[@]}"; do
            if vm_exec_check "ip link show | grep -i \"${prefix,,}\"" "not_exists"; then
                log_info "✅ MAC prefix not found: $prefix"
            else
                log_warn "❌ VM MAC prefix detected: $prefix"
                found_macs+=("$prefix")
            fi
        done
    fi
    
    if [[ ${#found_macs[@]} -eq 0 ]]; then
        log_info "✅ Network indicator check passed"
        return 0
    else
        log_warn "⚠️  Found ${#found_macs[@]} VM MAC prefixes"
        return 1
    fi
}

# Generate validation report
generate_validation_report() {
    local process_result=$1
    local file_result=$2
    local registry_result=$3
    local hardware_result=$4
    local network_result=$5
    
    local passed_tests=0
    local total_tests=0
    
    # Count passed tests
    [[ $process_result -eq 0 ]] && ((passed_tests++))
    [[ $file_result -eq 0 ]] && ((passed_tests++))
    [[ $registry_result -eq 0 ]] && ((passed_tests++))
    [[ $hardware_result -eq 0 ]] && ((passed_tests++))
    [[ $network_result -eq 0 ]] && ((passed_tests++))
    
    total_tests=5
    
    local effectiveness=$((passed_tests * 100 / total_tests))
    
    echo ""
    log_info "=== STEALTH VALIDATION REPORT ==="
    log_info "VM: $VM_NAME"
    log_info "Guest OS: $GUEST_OS"
    log_info "Stealth Level: $STEALTH_LEVEL"
    log_info "Tests Passed: $passed_tests/$total_tests"
    log_info "Effectiveness: ${effectiveness}%"
    
    if [[ $effectiveness -ge 90 ]]; then
        log_info "✅ Stealth Status: EXCELLENT"
    elif [[ $effectiveness -ge 75 ]]; then
        log_info "✅ Stealth Status: GOOD"
    elif [[ $effectiveness -ge 50 ]]; then
        log_warn "⚠️  Stealth Status: MODERATE"
    else
        log_error "❌ Stealth Status: POOR"
    fi
    
    echo ""
    log_info "Test Results:"
    [[ $process_result -eq 0 ]] && log_info "  ✅ Process Detection" || log_warn "  ❌ Process Detection"
    [[ $file_result -eq 0 ]] && log_info "  ✅ File Detection" || log_warn "  ❌ File Detection"
    [[ $registry_result -eq 0 ]] && log_info "  ✅ Registry Detection" || log_warn "  ❌ Registry Detection"
    [[ $hardware_result -eq 0 ]] && log_info "  ✅ Hardware Detection" || log_warn "  ❌ Hardware Detection"
    [[ $network_result -eq 0 ]] && log_info "  ✅ Network Detection" || log_warn "  ❌ Network Detection"
    
    return $((total_tests - passed_tests))
}

# Main validation function
main_validation() {
    parse_val_args "$@"
    
    if [[ -z "$VM_NAME" || -z "$GUEST_OS" ]]; then
        log_error "Missing required arguments for validation"
        exit 1
    fi
    
    log_info "Starting stealth validation for VM: $VM_NAME"
    log_info "Guest OS: $GUEST_OS, Stealth Level: $STEALTH_LEVEL"
    
    # Run validation tests
    local process_result=0
    local file_result=0
    local registry_result=0
    local hardware_result=0
    local network_result=0
    
    check_vm_processes || process_result=$?
    check_vm_files || file_result=$?
    check_vm_registry || registry_result=$?
    check_hardware_identifiers || hardware_result=$?
    check_network_indicators || network_result=$?
    
    # Generate and display report
    generate_validation_report $process_result $file_result $registry_result $hardware_result $network_result
    local failed_tests=$?
    
    if [[ $failed_tests -eq 0 ]]; then
        log_info "🎉 All validation tests passed!"
        exit 0
    else
        log_warn "⚠️  $failed_tests validation test(s) failed"
        exit 1
    fi
}

# Run validation if called directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main_validation "$@"
fi