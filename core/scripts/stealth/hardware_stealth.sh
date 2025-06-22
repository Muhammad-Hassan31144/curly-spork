# ================================================================
# hardware_stealth.sh - Hardware-level stealth measures
#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHIKRA_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
CONFIG_DIR="${SHIKRA_ROOT}/config/stealth"

# Import common functions
source "${SCRIPT_DIR}/apply_stealth.sh" 2>/dev/null || true

log_info() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] HW-STEALTH: $1"
}

log_error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] HW-ERROR: $1" >&2
}

# Parse hardware stealth arguments
parse_hw_args() {
    VM_NAME=""
    HARDWARE_PROFILE=""
    HYPERVISOR="auto"
    CONFIG_FILE=""
    DRY_RUN=false
    VERBOSE=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            --vm-name)
                VM_NAME="$2"
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
                log_error "Unknown hardware stealth option: $1"
                exit 1
                ;;
        esac
    done
}

# Generate random MAC address with realistic OUI
generate_mac_address() {
    local profile_file="${CONFIG_DIR}/hardware_profiles/${HARDWARE_PROFILE}.json"
    local oui=$(jq -r '.network.mac_oui' "$profile_file")
    
    # Generate random last 3 octets
    local suffix=$(printf "%02X:%02X:%02X" $((RANDOM % 256)) $((RANDOM % 256)) $((RANDOM % 256)))
    echo "${oui}:${suffix}"
}

# Generate random serial numbers
generate_serial() {
    local length=${1:-12}
    local chars="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    local serial=""
    
    for ((i=0; i<length; i++)); do
        serial+="${chars:$((RANDOM % ${#chars})):1}"
    done
    
    echo "$serial"
}

# Apply QEMU hardware stealth
apply_qemu_stealth() {
    local profile_file="${CONFIG_DIR}/hardware_profiles/${HARDWARE_PROFILE}.json"
    local config_file="$CONFIG_FILE"
    
    log_info "Applying QEMU hardware stealth for profile: $HARDWARE_PROFILE"
    
    # Generate random identifiers
    local new_mac=$(generate_mac_address)
    local system_serial=$(generate_serial 15)
    local mb_serial=$(generate_serial 12)
    local chassis_serial=$(generate_serial 10)
    local disk_serial=$(generate_serial 20)
    local system_uuid=$(uuidgen)
    
    # Extract hardware information from profile
    local sys_manufacturer=$(jq -r '.system.manufacturer' "$profile_file")
    local sys_product=$(jq -r '.system.product_name' "$profile_file")
    local sys_version=$(jq -r '.system.version' "$profile_file")
    local bios_vendor=$(jq -r '.bios.vendor' "$profile_file")
    local bios_version=$(jq -r '.bios.version' "$profile_file")
    local bios_date=$(jq -r '.bios.release_date' "$profile_file")
    local mb_manufacturer=$(jq -r '.motherboard.manufacturer' "$profile_file")
    local mb_product=$(jq -r '.motherboard.product_name' "$profile_file")
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "DRY RUN - Would apply QEMU stealth with:"
        log_info "  MAC Address: $new_mac"
        log_info "  System: $sys_manufacturer $sys_product"
        log_info "  BIOS: $bios_vendor $bios_version ($bios_date)"
        log_info "  Motherboard: $mb_manufacturer $mb_product"
        log_info "  Serials: SYS=$system_serial, MB=$mb_serial, CHASSIS=$chassis_serial"
        return 0
    fi
    
    # Apply QEMU SMBIOS modifications
    local qemu_args=""
    
    # CPU modifications
    local cpu_mods=$(jq -r '.hardware_stealth.cpu_modifications' "$config_file")
    if [[ "$cpu_mods" == "true" ]]; then
        qemu_args+="-cpu host,-hypervisor,+rdrand,+rdseed "
    fi
    
    # SMBIOS type 1 (System Information)
    qemu_args+="-smbios type=1"
    qemu_args+=",manufacturer=\"$sys_manufacturer\""
    qemu_args+=",product=\"$sys_product\""
    qemu_args+=",version=\"$sys_version\""
    qemu_args+=",serial=\"$system_serial\""
    qemu_args+=",uuid=\"$system_uuid\" "
    
    # SMBIOS type 0 (BIOS Information)
    qemu_args+="-smbios type=0"
    qemu_args+=",vendor=\"$bios_vendor\""
    qemu_args+=",version=\"$bios_version\""
    qemu_args+=",date=\"$bios_date\" "
    
    # SMBIOS type 2 (Baseboard Information)
    qemu_args+="-smbios type=2"
    qemu_args+=",manufacturer=\"$mb_manufacturer\""
    qemu_args+=",product=\"$mb_product\""
    qemu_args+=",serial=\"$mb_serial\" "
    
    # Network interface with spoofed MAC
    qemu_args+="-netdev user,id=net0 "
    qemu_args+="-device e1000,netdev=net0,mac=$new_mac "
    
    # Save QEMU arguments to file for VM creation script
    local qemu_args_file="${SHIKRA_ROOT}/config/vm_configs/${VM_NAME}_stealth_args.txt"
    mkdir -p "$(dirname "$qemu_args_file")"
    echo "$qemu_args" > "$qemu_args_file"
    
    log_info "QEMU stealth arguments saved to: $qemu_args_file"
    log_info "Applied hardware spoofing:"
    log_info "  System: $sys_manufacturer $sys_product ($system_serial)"
    log_info "  BIOS: $bios_vendor $bios_version"
    log_info "  MAC: $new_mac"
}

# Apply VirtualBox hardware stealth
apply_virtualbox_stealth() {
    local profile_file="${CONFIG_DIR}/hardware_profiles/${HARDWARE_PROFILE}.json"
    
    log_info "Applying VirtualBox hardware stealth for profile: $HARDWARE_PROFILE"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "DRY RUN - Would modify VirtualBox VM properties"
        return 0
    fi
    
    # Generate identifiers
    local new_mac=$(generate_mac_address)
    local system_serial=$(generate_serial 15)
    local system_uuid=$(uuidgen)
    
    # Extract hardware info
    local sys_manufacturer=$(jq -r '.system.manufacturer' "$profile_file")
    local sys_product=$(jq -r '.system.product_name' "$profile_file")
    
    # Apply VirtualBox modifications
    VBoxManage modifyvm "$VM_NAME" --macaddress1 "${new_mac//:/}"
    VBoxManage setextradata "$VM_NAME" "VBoxInternal/Devices/pcbios/0/Config/DmiSystemVendor" "$sys_manufacturer"
    VBoxManage setextradata "$VM_NAME" "VBoxInternal/Devices/pcbios/0/Config/DmiSystemProduct" "$sys_product"
    VBoxManage setextradata "$VM_NAME" "VBoxInternal/Devices/pcbios/0/Config/DmiSystemSerial" "$system_serial"
    VBoxManage setextradata "$VM_NAME" "VBoxInternal/Devices/pcbios/0/Config/DmiSystemUuid" "$system_uuid"
    
    log_info "Applied VirtualBox hardware modifications"
}

# Main hardware stealth function
main_hardware() {
    parse_hw_args "$@"
    
    if [[ -z "$VM_NAME" || -z "$HARDWARE_PROFILE" || -z "$CONFIG_FILE" ]]; then
        log_error "Missing required arguments for hardware stealth"
        exit 1
    fi
    
    case "$HYPERVISOR" in
        qemu)
            apply_qemu_stealth
            ;;
        virtualbox)
            apply_virtualbox_stealth
            ;;
        auto)
            # Auto-detect hypervisor and apply appropriate stealth
            if command -v virsh &> /dev/null; then
                HYPERVISOR="qemu"
                apply_qemu_stealth
            elif command -v VBoxManage &> /dev/null; then
                HYPERVISOR="virtualbox"
                apply_virtualbox_stealth
            else
                log_error "Could not auto-detect hypervisor"
                exit 1
            fi
            ;;
        *)
            log_error "Unsupported hypervisor: $HYPERVISOR"
            exit 1
            ;;
    esac
}

# Run hardware stealth if called directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main_hardware "$@"
fi
