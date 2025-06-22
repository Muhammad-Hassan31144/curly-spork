#!/bin/bash
# apply_stealth.sh - Main stealth application script

set -e

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHIKRA_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
CONFIG_DIR="${SHIKRA_ROOT}/config/stealth"
LOG_DIR="${SHIKRA_ROOT}/logs/stealth"

# Ensure log directory exists
mkdir -p "$LOG_DIR"

# Logging functions
log_info() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] INFO: $1" | tee -a "${LOG_DIR}/stealth.log"
}

log_error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1" | tee -a "${LOG_DIR}/stealth.log" >&2
}

log_warn() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] WARN: $1" | tee -a "${LOG_DIR}/stealth.log"
}

# Usage function
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Apply stealth measures to VM during creation

OPTIONS:
    --vm-name NAME          VM name (required)
    --level LEVEL          Stealth level 0-4 (default: 3)
    --profile PROFILE      Hardware profile (default: dell_optiplex)
    --hypervisor TYPE      Hypervisor type (qemu|virtualbox|vmware, default: auto)
    --guest-os OS          Guest OS (windows|linux, default: windows) 
    --config-file FILE     Custom stealth configuration file
    --dry-run              Show what would be done without executing
    --verbose              Enable verbose output
    --help                 Show this help message

EXAMPLES:
    $0 --vm-name malware_analysis --level 3 --profile lenovo_thinkpad
    $0 --vm-name test_vm --level 1 --guest-os linux --dry-run
    $0 --vm-name advanced_vm --level 4 --profile hp_elitebook --hypervisor qemu

STEALTH LEVELS:
    0 - Disabled (no stealth measures)
    1 - Basic (minimal VM hiding)
    2 - Standard (balanced stealth vs performance)
    3 - Advanced (comprehensive anti-detection)
    4 - Paranoid (maximum stealth, may impact performance)

HARDWARE PROFILES:
    dell_optiplex    - Dell OptiPlex 7090 Desktop
    lenovo_thinkpad  - Lenovo ThinkPad X1 Carbon Gen 9
    hp_elitebook     - HP EliteBook 840 G8
EOF
}

# Parse command line arguments
parse_args() {
    VM_NAME=""
    STEALTH_LEVEL="3"
    HARDWARE_PROFILE="dell_optiplex"
    HYPERVISOR="auto"
    GUEST_OS="windows"
    CONFIG_FILE=""
    DRY_RUN=false
    VERBOSE=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            --vm-name)
                VM_NAME="$2"
                shift 2
                ;;
            --level)
                STEALTH_LEVEL="$2"
                shift 2
                ;;
            --profile)
                HARDWARE_PROFILE="$2"
                shift 2
                ;;
            --hypervisor)
                HYPERVISOR="$2"
                shift 2
                ;;
            --guest-os)
                GUEST_OS="$2"
                shift 2
                ;;
            --config-file)
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
            --help)
                usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done

    # Validate required arguments
    if [[ -z "$VM_NAME" ]]; then
        log_error "VM name is required (--vm-name)"
        usage
        exit 1
    fi

    # Validate stealth level
    if [[ ! "$STEALTH_LEVEL" =~ ^[0-4]$ ]]; then
        log_error "Invalid stealth level: $STEALTH_LEVEL (must be 0-4)"
        exit 1
    fi

    # Validate hardware profile
    if [[ ! -f "${CONFIG_DIR}/hardware_profiles/${HARDWARE_PROFILE}.json" ]]; then
        log_error "Hardware profile not found: ${HARDWARE_PROFILE}"
        log_error "Available profiles: $(ls "${CONFIG_DIR}/hardware_profiles/"*.json 2>/dev/null | xargs -n1 basename | sed 's/.json$//' | tr '\n' ' ')"
        exit 1
    fi

    # Validate guest OS
    if [[ ! "$GUEST_OS" =~ ^(windows|linux)$ ]]; then
        log_error "Invalid guest OS: $GUEST_OS (must be windows or linux)"
        exit 1
    fi
}

# Load stealth configuration
load_stealth_config() {
    local level_file="${CONFIG_DIR}/levels/${STEALTH_LEVEL}_*.json"
    local profile_file="${CONFIG_DIR}/hardware_profiles/${HARDWARE_PROFILE}.json"
    
    # Find the level configuration file
    LEVEL_CONFIG_FILE=$(ls $level_file 2>/dev/null | head -n1)
    
    if [[ ! -f "$LEVEL_CONFIG_FILE" ]]; then
        log_error "Stealth level configuration not found for level $STEALTH_LEVEL"
        exit 1
    fi
    
    if [[ ! -f "$profile_file" ]]; then
        log_error "Hardware profile not found: $profile_file"
        exit 1
    fi
    
    # Check if stealth is enabled for this level
    local enabled=$(jq -r '.enabled' "$LEVEL_CONFIG_FILE" 2>/dev/null || echo "false")
    if [[ "$enabled" != "true" ]]; then
        log_info "Stealth level $STEALTH_LEVEL is disabled, skipping stealth application"
        exit 0
    fi
    
    PROFILE_CONFIG_FILE="$profile_file"
    
    log_info "Loaded stealth configuration:"
    log_info "  Level: $STEALTH_LEVEL ($(jq -r '.name' "$LEVEL_CONFIG_FILE"))"
    log_info "  Profile: $HARDWARE_PROFILE ($(jq -r '.description' "$PROFILE_CONFIG_FILE"))"
    log_info "  Guest OS: $GUEST_OS"
    log_info "  Hypervisor: $HYPERVISOR"
}

# Apply hardware stealth measures
apply_hardware_stealth() {
    local hw_enabled=$(jq -r '.hardware_stealth.enabled' "$LEVEL_CONFIG_FILE")
    
    if [[ "$hw_enabled" != "true" ]]; then
        log_info "Hardware stealth disabled for this level"
        return 0
    fi
    
    log_info "Applying hardware stealth measures..."
    
    local cmd="${SCRIPT_DIR}/hardware_stealth.sh"
    cmd+=" --vm-name \"$VM_NAME\""
    cmd+=" --profile \"$HARDWARE_PROFILE\""
    cmd+=" --hypervisor \"$HYPERVISOR\""
    cmd+=" --config \"$LEVEL_CONFIG_FILE\""
    
    if [[ "$DRY_RUN" == "true" ]]; then
        cmd+=" --dry-run"
    fi
    
    if [[ "$VERBOSE" == "true" ]]; then
        cmd+=" --verbose"
    fi
    
    if eval "$cmd"; then
        log_info "Hardware stealth applied successfully"
    else
        log_error "Hardware stealth application failed"
        return 1
    fi
}

# Apply software stealth measures
apply_software_stealth() {
    local sw_enabled=$(jq -r '.software_stealth.enabled' "$LEVEL_CONFIG_FILE")
    
    if [[ "$sw_enabled" != "true" ]]; then
        log_info "Software stealth disabled for this level"
        return 0
    fi
    
    log_info "Applying software stealth measures..."
    
    local cmd="${SCRIPT_DIR}/software_stealth.sh"
    cmd+=" --vm-name \"$VM_NAME\""
    cmd+=" --guest-os \"$GUEST_OS\""
    cmd+=" --config \"$LEVEL_CONFIG_FILE\""
    
    if [[ "$DRY_RUN" == "true" ]]; then
        cmd+=" --dry-run"
    fi
    
    if [[ "$VERBOSE" == "true" ]]; then
        cmd+=" --verbose"
    fi
    
    if eval "$cmd"; then
        log_info "Software stealth applied successfully"
    else
        log_error "Software stealth application failed"
        return 1
    fi
}

# Apply behavioral stealth measures
apply_behavioral_stealth() {
    local bh_enabled=$(jq -r '.behavioral_stealth.enabled' "$LEVEL_CONFIG_FILE")
    
    if [[ "$bh_enabled" != "true" ]]; then
        log_info "Behavioral stealth disabled for this level"
        return 0
    fi
    
    log_info "Applying behavioral stealth measures..."
    
    local cmd="${SCRIPT_DIR}/behavioral_stealth.sh"
    cmd+=" --vm-name \"$VM_NAME\""
    cmd+=" --guest-os \"$GUEST_OS\""
    cmd+=" --config \"$LEVEL_CONFIG_FILE\""
    
    if [[ "$DRY_RUN" == "true" ]]; then
        cmd+=" --dry-run"
    fi
    
    if [[ "$VERBOSE" == "true" ]]; then
        cmd+=" --verbose"
    fi
    
    if eval "$cmd"; then
        log_info "Behavioral stealth applied successfully"
    else
        log_warn "Behavioral stealth application had issues (non-critical)"
    fi
}

# Validate stealth application
validate_stealth() {
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "Skipping validation in dry-run mode"
        return 0
    fi
    
    log_info "Validating stealth application..."
    
    local cmd="${SCRIPT_DIR}/validate_stealth.sh"
    cmd+=" --vm-name \"$VM_NAME\""
    cmd+=" --guest-os \"$GUEST_OS\""
    cmd+=" --level \"$STEALTH_LEVEL\""
    
    if [[ "$VERBOSE" == "true" ]]; then
        cmd+=" --verbose"
    fi
    
    if eval "$cmd"; then
        log_info "Stealth validation passed"
    else
        log_warn "Stealth validation had issues (check logs for details)"
    fi
}

# Generate stealth report
generate_report() {
    local report_file="${LOG_DIR}/stealth_report_${VM_NAME}_$(date +%Y%m%d_%H%M%S).json"
    
    cat > "$report_file" << EOF
{
  "vm_name": "$VM_NAME",
  "stealth_level": $STEALTH_LEVEL,
  "hardware_profile": "$HARDWARE_PROFILE",
  "hypervisor": "$HYPERVISOR",
  "guest_os": "$GUEST_OS",
  "timestamp": "$(date -Iseconds)",
  "configuration": {
    "level_config": "$LEVEL_CONFIG_FILE",
    "profile_config": "$PROFILE_CONFIG_FILE"
  },
  "applied_measures": {
    "hardware_stealth": $(jq -r '.hardware_stealth.enabled' "$LEVEL_CONFIG_FILE"),
    "software_stealth": $(jq -r '.software_stealth.enabled' "$LEVEL_CONFIG_FILE"),
    "behavioral_stealth": $(jq -r '.behavioral_stealth.enabled' "$LEVEL_CONFIG_FILE"),
    "network_stealth": $(jq -r '.network_stealth.enabled // false' "$LEVEL_CONFIG_FILE")
  },
  "dry_run": $DRY_RUN
}
EOF
    
    log_info "Stealth report generated: $report_file"
}

# Main execution function
main() {
    echo "🥷 Shikra VM Stealth Application System"
    echo "======================================"
    
    parse_args "$@"
    load_stealth_config
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "DRY RUN MODE - No changes will be made"
    fi
    
    log_info "Starting stealth application for VM: $VM_NAME"
    
    # Apply stealth measures in sequence
    local overall_success=true
    
    if ! apply_hardware_stealth; then
        overall_success=false
    fi
    
    if ! apply_software_stealth; then
        overall_success=false
    fi
    
    if ! apply_behavioral_stealth; then
        # Behavioral stealth failures are non-critical
        log_warn "Behavioral stealth had issues but continuing"
    fi
    
    # Validate stealth application
    validate_stealth
    
    # Generate report
    generate_report
    
    if [[ "$overall_success" == "true" ]]; then
        log_info "✅ Stealth application completed successfully"
        echo ""
        echo "🎯 Stealth Level: $STEALTH_LEVEL applied to VM: $VM_NAME"
        echo "📄 Report: ${LOG_DIR}/stealth_report_${VM_NAME}_$(date +%Y%m%d_%H%M%S).json"
        echo "📋 Logs: ${LOG_DIR}/stealth.log"
        exit 0
    else
        log_error "❌ Stealth application completed with errors"
        echo ""
        echo "⚠️  Some stealth measures failed - check logs for details"
        echo "📋 Logs: ${LOG_DIR}/stealth.log"
        exit 1
    fi
}

# Check dependencies
check_dependencies() {
    local missing_deps=()
    
    # Check for required commands
    for cmd in jq virsh; do
        if ! command -v "$cmd" &> /dev/null; then
            missing_deps+=("$cmd")
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "Missing required dependencies: ${missing_deps[*]}"
        log_error "Please install missing dependencies and try again"
        exit 1
    fi
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    check_dependencies
    main "$@"
fi
