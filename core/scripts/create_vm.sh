# #!/bin/bash
# # Shikra VM Creation Script
# #
# # Purpose:
# # This script automates the creation and configuration of virtual machines specifically
# # tailored for malware analysis within the Shikra environment.
# #
# # Version: 1.2
# # Last Updated: 2024-06-09

# # --- Script Configuration ---
# SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
# CONFIG_DIR="$PROJECT_ROOT/config"
# VM_PROFILES_DIR="$CONFIG_DIR/vm_profiles"
# LOG_FILE="$PROJECT_ROOT/logs/vm_creation.log"

# # Default VM storage locations. Can be overridden by environment variables.
# VM_STORAGE_DIR="${VM_STORAGE_DIR:-/var/lib/libvirt/images}"
# ISO_STORAGE_DIR="${ISO_STORAGE_DIR:-/root/isos}"
# LIBVIRT_ISO_DIR="/var/lib/libvirt/isos"

# # --- Command Line Arguments (initialized to empty) ---
# VM_NAME=""
# PROFILE_NAME=""
# OS_ISO_PATH=""
# MEMORY_MB=""
# DISK_SIZE_GB=""
# VCPUS=""
# OS_TYPE=""
# NETWORK=""
# ENABLE_STEALTH=false
# FORCE_RECREATE=false
# DRY_RUN=false

# # --- Color Codes ---
# RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

# # --- Utility Functions ---

# log() {
#     mkdir -p "$(dirname "$LOG_FILE")"
#     echo -e "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
# }

# show_usage() {
#     echo "Usage: $0 --name <vm_name> --profile <profile_name> [options]"
#     echo ""
#     echo "Required Arguments:"
#     echo "  --name <name>            Name for the new VM."
#     echo "  --profile <profile>      VM profile to use (from $VM_PROFILES_DIR/)."
#     echo ""
#     echo "Optional Arguments:"
#     echo "  --os-iso <path>          Path to OS installation ISO (place ISOs in $ISO_STORAGE_DIR)."
#     echo "  --memory <mb>            Memory in MB (overrides profile setting)."
#     echo "  --disk <gb>              Disk size in GB (overrides profile setting)."
#     echo "  --force                  Force recreate if VM already exists (deletes existing VM)."
#     echo "  --stealth                Enable stealth/anti-detection features."
#     echo "  --dry-run                Show what would be done without executing."
#     echo "  -h, --help               Show this help message."
#     echo ""
#     echo "ISO Storage:"
#     echo "  Place your ISO files in: $ISO_STORAGE_DIR"
#     echo "  They will be copied to: $LIBVIRT_ISO_DIR"
#     echo ""
#     echo "Available VM Profiles:"
#     # Safely list available profiles.
#     if [[ -d "$VM_PROFILES_DIR" ]]; then
#         ls -1 "$VM_PROFILES_DIR"/*.json 2>/dev/null | sed 's/.*\///;s/\.json$//' | sed 's/^/  - /' || echo "  No profiles found in $VM_PROFILES_DIR"
#     fi
# }

# parse_arguments() {
#     log "${BLUE}Parsing command line arguments...${NC}"
#     if [[ $# -eq 0 ]]; then show_usage; exit 1; fi

#     while [[ $# -gt 0 ]]; do
#         case $1 in
#             --name) VM_NAME="$2"; shift 2 ;;
#             --profile) PROFILE_NAME="$2"; shift 2 ;;
#             --os-iso) OS_ISO_PATH="$2"; shift 2 ;;
#             --memory) MEMORY_MB="$2"; shift 2 ;;
#             --disk) DISK_SIZE_GB="$2"; shift 2 ;;
#             --force) FORCE_RECREATE=true; shift ;;
#             --stealth) ENABLE_STEALTH=true; shift ;;
#             --dry-run) DRY_RUN=true; shift ;;
#             -h|--help) show_usage; exit 0 ;;
#             *) log "${RED}Unknown parameter: $1${NC}"; show_usage; exit 1 ;;
#         esac
#     done

#     if [[ -z "$VM_NAME" ]] || [[ -z "$PROFILE_NAME" ]]; then
#         log "${RED}Error: --name and --profile are required arguments.${NC}"; show_usage; exit 1;
#     fi
# }

# load_vm_profile() {
#     log "${BLUE}Loading VM profile: $PROFILE_NAME${NC}"
#     local profile_file="$VM_PROFILES_DIR/${PROFILE_NAME}.json"

#     if [[ ! -f "$profile_file" ]]; then
#         log "${RED}Error: VM profile not found: $profile_file${NC}"; exit 1;
#     fi

#     # Load profile values, providing sensible defaults if they are missing from the JSON.
#     MEMORY_MB=${MEMORY_MB:-$(jq -r '.vm_config.memory_mb // 4096' "$profile_file")}
#     DISK_SIZE_GB=${DISK_SIZE_GB:-$(jq -r '.vm_config.disk_size_gb // 60' "$profile_file")}
#     VCPUS=$(jq -r '.vm_config.vcpus // 2' "$profile_file")
#     OS_TYPE=$(jq -r '.vm_config.os_type // "generic"' "$profile_file")
#     NETWORK=$(jq -r '.vm_config.network // "shikra-isolated"' "$profile_file")

#     log "Configuration loaded:"
#     log "  - Memory: ${MEMORY_MB}MB, Disk: ${DISK_SIZE_GB}GB, vCPUs: ${VCPUS}"
#     log "  - OS Type: ${OS_TYPE}, Network: ${NETWORK}"
# }

# cleanup_existing_vm() {
#     log "${BLUE}Cleaning up existing VM: $VM_NAME${NC}"
    
#     if [[ "$DRY_RUN" == "true" ]]; then
#         log "Dry run: would cleanup existing VM"
#         return 0
#     fi

#     # Stop VM if running
#     if [[ "$(virsh domstate "$VM_NAME" 2>/dev/null)" == "running" ]]; then
#         log "Stopping running VM..."
#         virsh destroy "$VM_NAME" 2>/dev/null || true
#     fi

#     # Delete all snapshots first
#     log "Removing snapshots..."
#     local snapshots
#     snapshots=$(virsh snapshot-list "$VM_NAME" --name 2>/dev/null || true)
    
#     if [[ -n "$snapshots" ]]; then
#         while IFS= read -r snapshot; do
#             if [[ -n "$snapshot" ]]; then
#                 log "Deleting snapshot: $snapshot"
#                 virsh snapshot-delete "$VM_NAME" "$snapshot" 2>/dev/null || true
#             fi
#         done <<< "$snapshots"
#     fi

#     # Undefine the domain and remove storage
#     log "Undefining VM domain and removing storage..."
#     virsh undefine "$VM_NAME" --remove-all-storage 2>/dev/null || virsh undefine "$VM_NAME" 2>/dev/null || true

#     # Ensure disk file is removed
#     local disk_path="$VM_STORAGE_DIR/${VM_NAME}.qcow2"
#     if [[ -f "$disk_path" ]]; then
#         log "Removing remaining disk file: $disk_path"
#         rm -f "$disk_path"
#     fi

#     log "${GREEN}Existing VM cleaned up successfully${NC}"
# }

# copy_iso_to_libvirt() {
#     if [[ -z "$OS_ISO_PATH" ]]; then
#         return 0
#     fi

#     log "${BLUE}Copying ISO to libvirt storage...${NC}"
    
#     # Create libvirt ISO directory
#     mkdir -p "$LIBVIRT_ISO_DIR"
    
#     # Get just the filename from the path
#     local iso_filename=$(basename "$OS_ISO_PATH")
#     local dest_iso_path="$LIBVIRT_ISO_DIR/$iso_filename"
    
#     if [[ "$DRY_RUN" == "true" ]]; then
#         log "Dry run: would copy $OS_ISO_PATH to $dest_iso_path"
#         return 0
#     fi

#     # Check if source ISO exists
#     if [[ ! -f "$OS_ISO_PATH" ]]; then
#         log "${RED}Error: OS ISO not found at: $OS_ISO_PATH${NC}"
#         log "${YELLOW}Please place your ISO file in $ISO_STORAGE_DIR/${NC}"
#         exit 1
#     fi

#     # Copy ISO if it doesn't already exist or is different
#     if [[ ! -f "$dest_iso_path" ]] || ! cmp -s "$OS_ISO_PATH" "$dest_iso_path"; then
#         log "Copying ISO: $OS_ISO_PATH -> $dest_iso_path"
#         if ! cp "$OS_ISO_PATH" "$dest_iso_path"; then
#             log "${RED}Failed to copy ISO file${NC}"
#             exit 1
#         fi
#         log "${GREEN}ISO copied successfully${NC}"
#     else
#         log "ISO already exists in libvirt storage: $dest_iso_path"
#     fi
    
#     # Update OS_ISO_PATH to point to the copied file
#     OS_ISO_PATH="$dest_iso_path"
# }

# check_prerequisites() {
#     log "${BLUE}Checking prerequisites...${NC}"
#     if [[ $EUID -ne 0 ]]; then log "${RED}This script must be run as root.${NC}"; exit 1; fi
    
#     local commands=("virsh" "virt-install" "qemu-img" "jq")
#     for cmd in "${commands[@]}"; do
#         if ! command -v "$cmd" &> /dev/null; then log "${RED}Required command not found: $cmd${NC}"; exit 1; fi
#     done
    
#     if ! systemctl is-active --quiet libvirtd; then log "${RED}libvirtd service is not running.${NC}"; exit 1; fi
    
#     # Check if VM exists and handle accordingly
#     if virsh dominfo "$VM_NAME" &>/dev/null; then
#         if [[ "$FORCE_RECREATE" == "true" ]]; then
#             cleanup_existing_vm
#         else
#             log "${RED}VM '$VM_NAME' already exists. Use --force to recreate.${NC}"; exit 1;
#         fi
#     fi
    
#     mkdir -p "$VM_STORAGE_DIR"
#     log "${GREEN}Prerequisites check passed.${NC}"
# }

# create_disk_image() {
#     log "${BLUE}Creating disk image for $VM_NAME...${NC}"
#     local disk_path="$VM_STORAGE_DIR/${VM_NAME}.qcow2"
#     local final_disk_size="${DISK_SIZE_GB}G"

#     if [[ "$DRY_RUN" == "true" ]]; then
#         log "Dry run: would create disk image at $disk_path with size $final_disk_size."
#         return
#     fi

#     log "Creating disk: $disk_path ($final_disk_size)"
#     if ! qemu-img create -f qcow2 "$disk_path" "$final_disk_size"; then
#         log "${RED}Failed to create disk image.${NC}"; exit 1;
#     fi
#     log "${GREEN}Disk image created successfully.${NC}"
# }

# install_os() {
#     log "${BLUE}Starting OS installation for $VM_NAME...${NC}"
#     if [[ -z "$OS_ISO_PATH" ]]; then
#         log "${YELLOW}No --os-iso specified. VM will be created without an OS.${NC}"; return;
#     fi

#     local disk_path="$VM_STORAGE_DIR/${VM_NAME}.qcow2"
#     local os_variant="generic" # Default
#     local disk_bus="sata" # Better compatibility for Windows
    
#     case "${OS_TYPE,,}" in
#         windows*|win*) 
#             os_variant="win10"
#             disk_bus="sata" # Windows needs SATA for disk detection
#             ;;
#         ubuntu*) 
#             os_variant="ubuntu22.04"
#             disk_bus="virtio" # Linux works fine with virtio
#             ;;
#         debian*) 
#             os_variant="debian11"
#             disk_bus="virtio"
#             ;;
#     esac

#     local virt_install_cmd=(
#         "virt-install"
#         "--name" "$VM_NAME"
#         "--memory" "$MEMORY_MB"
#         "--vcpus" "$VCPUS"
#         "--disk" "path=$disk_path,format=qcow2,bus=$disk_bus"
#         "--cdrom" "$OS_ISO_PATH"
#         "--network" "network=$NETWORK,model=virtio"
#         "--os-variant" "$os_variant"
#         "--graphics" "vnc,listen=127.0.0.1"
#         "--boot" "menu=on"
#         "--noautoconsole"
#     )

#     if [[ "$DRY_RUN" == "true" ]]; then
#         log "Dry run: would run virt-install with the following command:"
#         log "  ${virt_install_cmd[*]}"
#         return
#     fi

#     log "Starting virt-install with $disk_bus disk bus for better compatibility..."
#     if ! "${virt_install_cmd[@]}"; then
#         log "${RED}virt-install command failed.${NC}"; exit 1;
#     fi
    
#     log "${GREEN}VM '$VM_NAME' created successfully with $disk_bus disk interface.${NC}"
#     log "${YELLOW}To complete installation, connect with: virt-viewer $VM_NAME${NC}"
# }

# create_snapshot() {
#     log "${BLUE}Creating 'clean_baseline' snapshot for $VM_NAME...${NC}"
#     if [[ "$DRY_RUN" == "true" ]]; then
#         log "Dry run: would create 'clean_baseline' snapshot."
#         return
#     fi
    
#     # More robustly wait for the VM to be shut off before snapshotting.
#     local max_wait=60 # Wait up to 60 seconds
#     while [[ "$(virsh domstate "$VM_NAME" 2>/dev/null)" == "running" && $max_wait -gt 0 ]]; do
#         log "VM is running. Waiting for manual shutdown before creating snapshot... ($max_wait s remaining)"
#         sleep 10
#         max_wait=$((max_wait - 10))
#     done

#     if [[ "$(virsh domstate "$VM_NAME" 2>/dev/null)" == "running" ]]; then
#         log "${RED}VM did not shut down. Cannot create snapshot. Please shut down the VM manually.${NC}"
#         return 1
#     fi

#     local snapshot_name="clean_baseline"
#     local snapshot_desc="Clean state after initial OS installation and setup on $(date)"

#     if ! virsh snapshot-create-as --domain "$VM_NAME" --name "$snapshot_name" --description "$snapshot_desc" --atomic; then
#         log "${RED}Failed to create snapshot '$snapshot_name'.${NC}"; return 1;
#     fi
    
#     log "${GREEN}Snapshot '$snapshot_name' created successfully.${NC}"
# }

# cleanup_on_error() {
#     log "${YELLOW}An error occurred. Cleaning up resources for '$VM_NAME'...${NC}"
    
#     # Try to undefine the domain first, which might also remove storage
#     if virsh dominfo "$VM_NAME" &>/dev/null; then
#         log "Undefining VM domain: $VM_NAME..."
#         virsh undefine "$VM_NAME" --remove-all-storage &>/dev/null || virsh undefine "$VM_NAME" &>/dev/null
#     fi
    
#     # Explicitly remove the disk image if it still exists
#     local disk_path="$VM_STORAGE_DIR/${VM_NAME}.qcow2"
#     if [[ -f "$disk_path" ]]; then
#         log "Removing disk image: $disk_path..."
#         rm -f "$disk_path"
#     fi
#     log "Cleanup finished."
# }

# # --- Main Execution ---
# main() {
#     trap cleanup_on_error ERR SIGINT SIGTERM
    
#     log "${GREEN}--- Shikra VM Creation Script Started ---${NC}"
    
#     parse_arguments "$@"
#     load_vm_profile
#     check_prerequisites
#     copy_iso_to_libvirt
#     create_disk_image
#     install_os
    
#     log "${GREEN}--- VM Creation Process Completed for '$VM_NAME' ---${NC}"
#     log "${YELLOW}Please complete the OS installation manually via VNC or virt-viewer.${NC}"
#     log "${YELLOW}After the OS is fully installed and shut down, you can create a clean snapshot by running:${NC}"
#     log "${CYAN}  sudo virsh snapshot-create-as --domain $VM_NAME --name clean_baseline --atomic${NC}"
#     log ""
#     log "To start the VM: virsh start $VM_NAME"
#     log "To connect: virt-viewer $VM_NAME"

#     trap - ERR SIGINT SIGTERM # Disable trap on successful exit
# }

# main "$@"

#!/bin/bash
# Shikra VM Creation Script with Stealth Integration
#
# Purpose:
# This script automates the creation and configuration of virtual machines specifically
# tailored for malware analysis within the Shikra environment with advanced stealth capabilities.
#
# Version: 2.0
# Last Updated: 2025-06-22

# --- Script Configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
CONFIG_DIR="$PROJECT_ROOT/config"
VM_PROFILES_DIR="$CONFIG_DIR/vm_profiles"
STEALTH_CONFIG_DIR="$CONFIG_DIR/stealth"
STEALTH_SCRIPTS_DIR="$PROJECT_ROOT/core/scripts/stealth"
LOG_FILE="$PROJECT_ROOT/logs/vm_creation.log"

# Default VM storage locations
VM_STORAGE_DIR="${VM_STORAGE_DIR:-/var/lib/libvirt/images}"
ISO_STORAGE_DIR="${ISO_STORAGE_DIR:-/opt/shikra/isos}"
LIBVIRT_ISO_DIR="/var/lib/libvirt/isos"

# --- Command Line Arguments ---
VM_NAME=""
PROFILE_NAME=""
OS_ISO_PATH=""
MEMORY_MB=""
DISK_SIZE_GB=""
VCPUS=""
OS_TYPE=""
NETWORK=""
ENABLE_STEALTH=false
STEALTH_LEVEL="2"  # Default to standard stealth
HARDWARE_PROFILE="dell_optiplex"  # Default hardware profile
FORCE_RECREATE=false
DRY_RUN=false
AUTO_SNAPSHOT=true

# --- Color Codes ---
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

# --- Utility Functions ---

log() {
    mkdir -p "$(dirname "$LOG_FILE")"
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

show_usage() {
    echo "Usage: $0 --name <vm_name> --profile <profile_name> [options]"
    echo ""
    echo "Required Arguments:"
    echo "  --name <name>            Name for the new VM."
    echo "  --profile <profile>      VM profile to use (from $VM_PROFILES_DIR/)."
    echo ""
    echo "Optional Arguments:"
    echo "  --os-iso <path>          Path to OS installation ISO."
    echo "  --memory <mb>            Memory in MB (overrides profile setting)."
    echo "  --disk <gb>              Disk size in GB (overrides profile setting)."
    echo "  --stealth                Enable stealth/anti-detection features."
    echo "  --stealth-level <0-4>    Stealth level (0=disabled, 4=paranoid) [default: 2]."
    echo "  --hardware-profile <p>   Hardware profile for stealth [default: dell_optiplex]."
    echo "  --no-snapshot            Skip automatic clean baseline snapshot creation."
    echo "  --force                  Force recreate if VM already exists."
    echo "  --dry-run                Show what would be done without executing."
    echo "  -h, --help               Show this help message."
    echo ""
    echo "ISO Storage:"
    echo "  Place your ISO files in: $ISO_STORAGE_DIR"
    echo "  They will be copied to: $LIBVIRT_ISO_DIR"
    echo ""
    echo "Available VM Profiles:"
    if [[ -d "$VM_PROFILES_DIR" ]]; then
        ls -1 "$VM_PROFILES_DIR"/*.json 2>/dev/null | sed 's/.*\///;s/\.json$//' | sed 's/^/  - /' || echo "  No profiles found"
    fi
    echo ""
    echo "Available Stealth Hardware Profiles:"
    if [[ -d "$STEALTH_CONFIG_DIR/hardware_profiles" ]]; then
        ls -1 "$STEALTH_CONFIG_DIR/hardware_profiles"/*.json 2>/dev/null | sed 's/.*\///;s/\.json$//' | sed 's/^/  - /' || echo "  No hardware profiles found"
    fi
}

parse_arguments() {
    log "${BLUE}Parsing command line arguments...${NC}"
    if [[ $# -eq 0 ]]; then show_usage; exit 1; fi

    while [[ $# -gt 0 ]]; do
        case $1 in
            --name) VM_NAME="$2"; shift 2 ;;
            --profile) PROFILE_NAME="$2"; shift 2 ;;
            --os-iso) OS_ISO_PATH="$2"; shift 2 ;;
            --memory) MEMORY_MB="$2"; shift 2 ;;
            --disk) DISK_SIZE_GB="$2"; shift 2 ;;
            --stealth) ENABLE_STEALTH=true; shift ;;
            --stealth-level) STEALTH_LEVEL="$2"; shift 2 ;;
            --hardware-profile) HARDWARE_PROFILE="$2"; shift 2 ;;
            --no-snapshot) AUTO_SNAPSHOT=false; shift ;;
            --force) FORCE_RECREATE=true; shift ;;
            --dry-run) DRY_RUN=true; shift ;;
            -h|--help) show_usage; exit 0 ;;
            *) log "${RED}Unknown parameter: $1${NC}"; show_usage; exit 1 ;;
        esac
    done

    if [[ -z "$VM_NAME" ]] || [[ -z "$PROFILE_NAME" ]]; then
        log "${RED}Error: --name and --profile are required arguments.${NC}"; show_usage; exit 1;
    fi

    # Validate stealth level
    if [[ ! "$STEALTH_LEVEL" =~ ^[0-4]$ ]]; then
        log "${RED}Error: Stealth level must be 0-4${NC}"; exit 1;
    fi
}

setup_iso_directories() {
    log "${BLUE}Setting up ISO storage directories...${NC}"
    
    # Create directories with proper permissions
    mkdir -p "$ISO_STORAGE_DIR" "$LIBVIRT_ISO_DIR"
    
    # Set proper ownership and permissions for libvirt
    chown libvirt-qemu:libvirt-qemu "$LIBVIRT_ISO_DIR" 2>/dev/null || true
    chmod 755 "$LIBVIRT_ISO_DIR"
    
    # Ensure ISO storage is accessible
    chmod 755 "$ISO_STORAGE_DIR"
    
    log "${GREEN}ISO directories configured with proper permissions${NC}"
}

load_vm_profile() {
    log "${BLUE}Loading VM profile: $PROFILE_NAME${NC}"
    local profile_file="$VM_PROFILES_DIR/${PROFILE_NAME}.json"

    if [[ ! -f "$profile_file" ]]; then
        log "${RED}Error: VM profile not found: $profile_file${NC}"; exit 1;
    fi

    # Load profile values with enhanced defaults for Windows
    MEMORY_MB=${MEMORY_MB:-$(jq -r '.vm_config.memory_mb // 8192' "$profile_file")}
    DISK_SIZE_GB=${DISK_SIZE_GB:-$(jq -r '.vm_config.disk_size_gb // 80' "$profile_file")}
    VCPUS=$(jq -r '.vm_config.vcpus // 4' "$profile_file")
    OS_TYPE=$(jq -r '.vm_config.os_type // "windows"' "$profile_file")
    NETWORK=$(jq -r '.vm_config.network // "shikra-isolated"' "$profile_file")

    log "Configuration loaded:"
    log "  - Memory: ${MEMORY_MB}MB, Disk: ${DISK_SIZE_GB}GB, vCPUs: ${VCPUS}"
    log "  - OS Type: ${OS_TYPE}, Network: ${NETWORK}"
    
    if [[ "$ENABLE_STEALTH" == "true" ]]; then
        log "  - Stealth: Level $STEALTH_LEVEL, Hardware: $HARDWARE_PROFILE"
    fi
}

load_stealth_configuration() {
    if [[ "$ENABLE_STEALTH" != "true" ]]; then
        return 0
    fi

    log "${BLUE}Loading stealth configuration...${NC}"
    
    local stealth_level_file="$STEALTH_CONFIG_DIR/levels/${STEALTH_LEVEL}_*.json"
    local hardware_profile_file="$STEALTH_CONFIG_DIR/hardware_profiles/${HARDWARE_PROFILE}.json"
    
    # Check if files exist
    if ! ls $stealth_level_file 1> /dev/null 2>&1; then
        log "${RED}Error: Stealth level configuration not found for level $STEALTH_LEVEL${NC}"
        exit 1
    fi
    
    if [[ ! -f "$hardware_profile_file" ]]; then
        log "${RED}Error: Hardware profile not found: $hardware_profile_file${NC}"
        exit 1
    fi
    
    # Get the actual stealth level file
    local stealth_config_file=$(ls $stealth_level_file | head -1)
    
    log "${GREEN}Stealth configuration loaded:${NC}"
    log "  - Level: $(basename "$stealth_config_file" .json)"
    log "  - Hardware Profile: $HARDWARE_PROFILE"
}

cleanup_existing_vm() {
    log "${BLUE}Cleaning up existing VM: $VM_NAME${NC}"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "Dry run: would cleanup existing VM"
        return 0
    fi

    # Stop VM if running
    if [[ "$(virsh domstate "$VM_NAME" 2>/dev/null)" == "running" ]]; then
        log "Stopping running VM..."
        virsh destroy "$VM_NAME" 2>/dev/null || true
        sleep 2
    fi

    # Delete all snapshots first
    log "Removing snapshots..."
    local snapshots
    snapshots=$(virsh snapshot-list "$VM_NAME" --name 2>/dev/null || true)
    
    if [[ -n "$snapshots" ]]; then
        while IFS= read -r snapshot; do
            if [[ -n "$snapshot" && "$snapshot" != " " ]]; then
                log "Deleting snapshot: $snapshot"
                virsh snapshot-delete "$VM_NAME" "$snapshot" 2>/dev/null || true
            fi
        done <<< "$snapshots"
    fi

    # Undefine the domain and remove storage
    log "Undefining VM domain and removing storage..."
    virsh undefine "$VM_NAME" --remove-all-storage 2>/dev/null || virsh undefine "$VM_NAME" 2>/dev/null || true

    # Ensure disk file is removed
    local disk_path="$VM_STORAGE_DIR/${VM_NAME}.qcow2"
    if [[ -f "$disk_path" ]]; then
        log "Removing remaining disk file: $disk_path"
        rm -f "$disk_path"
    fi

    log "${GREEN}Existing VM cleaned up successfully${NC}"
}

copy_iso_to_libvirt() {
    if [[ -z "$OS_ISO_PATH" ]]; then
        return 0
    fi

    log "${BLUE}Copying ISO to libvirt storage...${NC}"
    
    # Get just the filename from the path
    local iso_filename=$(basename "$OS_ISO_PATH")
    local dest_iso_path="$LIBVIRT_ISO_DIR/$iso_filename"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "Dry run: would copy $OS_ISO_PATH to $dest_iso_path"
        return 0
    fi

    # Check if source ISO exists
    if [[ ! -f "$OS_ISO_PATH" ]]; then
        # Try to find it in ISO storage directory
        local alt_iso_path="$ISO_STORAGE_DIR/$OS_ISO_PATH"
        if [[ -f "$alt_iso_path" ]]; then
            OS_ISO_PATH="$alt_iso_path"
        else
            log "${RED}Error: OS ISO not found at: $OS_ISO_PATH${NC}"
            log "${YELLOW}Please place your ISO file in $ISO_STORAGE_DIR/${NC}"
            exit 1
        fi
    fi

    # Copy ISO if it doesn't already exist or is different
    if [[ ! -f "$dest_iso_path" ]] || ! cmp -s "$OS_ISO_PATH" "$dest_iso_path"; then
        log "Copying ISO: $OS_ISO_PATH -> $dest_iso_path"
        if ! cp "$OS_ISO_PATH" "$dest_iso_path"; then
            log "${RED}Failed to copy ISO file${NC}"
            exit 1
        fi
        
        # Set proper permissions
        chown libvirt-qemu:libvirt-qemu "$dest_iso_path" 2>/dev/null || true
        chmod 644 "$dest_iso_path"
        
        log "${GREEN}ISO copied successfully with proper permissions${NC}"
    else
        log "ISO already exists in libvirt storage: $dest_iso_path"
    fi
    
    # Update OS_ISO_PATH to point to the copied file
    OS_ISO_PATH="$dest_iso_path"
}

check_prerequisites() {
    log "${BLUE}Checking prerequisites...${NC}"
    if [[ $EUID -ne 0 ]]; then log "${RED}This script must be run as root.${NC}"; exit 1; fi
    
    local commands=("virsh" "virt-install" "qemu-img" "jq")
    for cmd in "${commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then log "${RED}Required command not found: $cmd${NC}"; exit 1; fi
    done
    
    if ! systemctl is-active --quiet libvirtd; then log "${RED}libvirtd service is not running.${NC}"; exit 1; fi
    
    # Check if VM exists and handle accordingly
    if virsh dominfo "$VM_NAME" &>/dev/null; then
        if [[ "$FORCE_RECREATE" == "true" ]]; then
            cleanup_existing_vm
        else
            log "${RED}VM '$VM_NAME' already exists. Use --force to recreate.${NC}"; exit 1;
        fi
    fi
    
    mkdir -p "$VM_STORAGE_DIR"
    setup_iso_directories
    
    # Check stealth scripts if stealth is enabled
    if [[ "$ENABLE_STEALTH" == "true" ]]; then
        if [[ ! -d "$STEALTH_SCRIPTS_DIR" ]]; then
            log "${RED}Stealth scripts directory not found: $STEALTH_SCRIPTS_DIR${NC}"; exit 1;
        fi
        
        local stealth_scripts=("apply_stealth.sh" "hardware_stealth.sh" "software_stealth.sh")
        for script in "${stealth_scripts[@]}"; do
            if [[ ! -f "$STEALTH_SCRIPTS_DIR/$script" ]]; then
                log "${RED}Required stealth script not found: $script${NC}"; exit 1;
            fi
        done
    fi
    
    log "${GREEN}Prerequisites check passed.${NC}"
}

create_disk_image() {
    log "${BLUE}Creating optimized qcow2 disk image for $VM_NAME...${NC}"
    local disk_path="$VM_STORAGE_DIR/${VM_NAME}.qcow2"
    local final_disk_size="${DISK_SIZE_GB}G"

    if [[ "$DRY_RUN" == "true" ]]; then
        log "Dry run: would create qcow2 disk image at $disk_path with size $final_disk_size"
        return
    fi

    log "Creating optimized qcow2 disk: $disk_path ($final_disk_size)"
    
    # Create qcow2 with optimization for Windows and malware analysis
    if ! qemu-img create -f qcow2 \
        -o lazy_refcounts=on,cluster_size=64k,preallocation=metadata \
        "$disk_path" "$final_disk_size"; then
        log "${RED}Failed to create disk image.${NC}"; exit 1;
    fi
    
    # Set proper permissions
    chown libvirt-qemu:libvirt-qemu "$disk_path"
    chmod 644 "$disk_path"
    
    log "${GREEN}Optimized qcow2 disk image created successfully${NC}"
}

apply_stealth_modifications() {
    if [[ "$ENABLE_STEALTH" != "true" ]]; then
        return 0
    fi

    log "${BLUE}Applying stealth modifications to VM definition...${NC}"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "Dry run: would apply stealth modifications"
        return 0
    fi

    # Apply hardware stealth
    if [[ -f "$STEALTH_SCRIPTS_DIR/hardware_stealth.sh" ]]; then
        log "Applying hardware stealth profile: $HARDWARE_PROFILE"
        bash "$STEALTH_SCRIPTS_DIR/hardware_stealth.sh" "$VM_NAME" "$HARDWARE_PROFILE" "$STEALTH_LEVEL"
    fi

    # Apply software stealth
    if [[ -f "$STEALTH_SCRIPTS_DIR/software_stealth.sh" ]]; then
        log "Applying software stealth modifications"
        bash "$STEALTH_SCRIPTS_DIR/software_stealth.sh" "$VM_NAME" "$STEALTH_LEVEL"
    fi

    # Validate stealth configuration
    if [[ -f "$STEALTH_SCRIPTS_DIR/validate_stealth.sh" ]]; then
        log "Validating stealth configuration"
        if ! bash "$STEALTH_SCRIPTS_DIR/validate_stealth.sh" "$VM_NAME"; then
            log "${YELLOW}Warning: Stealth validation issues detected${NC}"
        fi
    fi

    log "${GREEN}Stealth modifications applied successfully${NC}"
}

install_os() {
    log "${BLUE}Starting optimized OS installation for $VM_NAME...${NC}"
    if [[ -z "$OS_ISO_PATH" ]]; then
        log "${YELLOW}No --os-iso specified. VM will be created without an OS.${NC}"; return;
    fi

    local disk_path="$VM_STORAGE_DIR/${VM_NAME}.qcow2"
    local os_variant="generic"
    local disk_bus="sata"  # Default for Windows compatibility
    local nic_model="e1000"  # Better Windows compatibility
    
    # Enhanced OS detection and optimization
    case "${OS_TYPE,,}" in
        windows*|win*)
            os_variant="win10"
            disk_bus="sata"
            nic_model="e1000"
            log "Optimizing for Windows installation"
            ;;
        ubuntu*|debian*|linux*)
            os_variant="ubuntu22.04"
            disk_bus="virtio"
            nic_model="virtio"
            log "Optimizing for Linux installation"
            ;;
    esac

    local virt_install_cmd=(
        "virt-install"
        "--name" "$VM_NAME"
        "--memory" "$MEMORY_MB"
        "--vcpus" "$VCPUS"
        "--cpu" "host-passthrough"  # Better performance and compatibility
        "--disk" "path=$disk_path,format=qcow2,bus=$disk_bus,cache=writeback"
        "--cdrom" "$OS_ISO_PATH"
        "--network" "network=$NETWORK,model=$nic_model"
        "--os-variant" "$os_variant"
        "--graphics" "vnc,listen=127.0.0.1,port=-1"
        "--video" "vga"
        "--sound" "ich6"  # Audio support for malware analysis
        "--boot" "menu=on,useserial=on"
        "--features" "acpi=on,apic=on,pae=on"
        "--clock" "offset=localtime"
        "--noautoconsole"
        "--wait" "-1"  # Don't wait for installation to complete
    )

    # Add Windows-specific optimizations
    if [[ "${OS_TYPE,,}" =~ windows|win ]]; then
        virt_install_cmd+=(
            "--controller" "type=ide,index=0"
            "--controller" "type=ide,index=1"
        )
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        log "Dry run: would run virt-install with the following command:"
        log "  ${virt_install_cmd[*]}"
        return
    fi

    log "Starting optimized virt-install for ${OS_TYPE}..."
    log "Using $disk_bus disk bus and $nic_model network model for optimal compatibility"
    
    if ! "${virt_install_cmd[@]}"; then
        log "${RED}virt-install command failed.${NC}"; exit 1;
    fi
    
    log "${GREEN}VM '$VM_NAME' created successfully with optimized settings${NC}"
    
    # Apply stealth modifications after VM creation
    apply_stealth_modifications
    
    log "${YELLOW}To complete installation, connect with: virt-viewer $VM_NAME${NC}"
    log "${CYAN}Or access via VNC at: $(virsh vncdisplay $VM_NAME 2>/dev/null || echo 'VNC info not available')${NC}"
}

create_snapshot() {
    if [[ "$AUTO_SNAPSHOT" != "true" ]]; then
        log "${YELLOW}Automatic snapshot creation skipped${NC}"
        return 0
    fi

    log "${BLUE}Monitoring VM for shutdown to create 'clean_baseline' snapshot...${NC}"
    if [[ "$DRY_RUN" == "true" ]]; then
        log "Dry run: would monitor for shutdown and create 'clean_baseline' snapshot"
        return
    fi
    
    log "${YELLOW}Please complete the OS installation and shut down the VM${NC}"
    log "${YELLOW}The script will automatically create a snapshot when the VM shuts down${NC}"
    
    # Monitor VM state in background
    (
        while true; do
            if [[ "$(virsh domstate "$VM_NAME" 2>/dev/null)" == "shut off" ]]; then
                sleep 5  # Wait a bit to ensure shutdown is complete
                
                local snapshot_name="clean_baseline"
                local snapshot_desc="Clean state after initial OS installation and stealth setup on $(date)"

                log "VM has shut down. Creating snapshot '$snapshot_name'..."
                
                if virsh snapshot-create-as --domain "$VM_NAME" --name "$snapshot_name" --description "$snapshot_desc" --atomic; then
                    log "${GREEN}Snapshot '$snapshot_name' created successfully${NC}"
                else
                    log "${RED}Failed to create snapshot '$snapshot_name'${NC}"
                fi
                break
            fi
            sleep 30
        done
    ) &
    
    local monitor_pid=$!
    echo $monitor_pid > "/tmp/shikra_snapshot_monitor_${VM_NAME}.pid"
    log "${GREEN}Background snapshot monitor started (PID: $monitor_pid)${NC}"
}

cleanup_on_error() {
    log "${YELLOW}An error occurred. Cleaning up resources for '$VM_NAME'...${NC}"
    
    # Kill snapshot monitor if running
    local monitor_pid_file="/tmp/shikra_snapshot_monitor_${VM_NAME}.pid"
    if [[ -f "$monitor_pid_file" ]]; then
        local monitor_pid=$(cat "$monitor_pid_file")
        kill "$monitor_pid" 2>/dev/null || true
        rm -f "$monitor_pid_file"
    fi
    
    # Try to undefine the domain first
    if virsh dominfo "$VM_NAME" &>/dev/null; then
        log "Undefining VM domain: $VM_NAME..."
        virsh undefine "$VM_NAME" --remove-all-storage &>/dev/null || virsh undefine "$VM_NAME" &>/dev/null
    fi
    
    # Explicitly remove the disk image if it still exists
    local disk_path="$VM_STORAGE_DIR/${VM_NAME}.qcow2"
    if [[ -f "$disk_path" ]]; then
        log "Removing disk image: $disk_path..."
        rm -f "$disk_path"
    fi
    log "Cleanup finished."
}

# --- Main Execution ---
main() {
    trap cleanup_on_error ERR SIGINT SIGTERM
    
    log "${GREEN}=== Shikra Enhanced VM Creation Script Started ===${NC}"
    
    parse_arguments "$@"
    load_vm_profile
    
    if [[ "$ENABLE_STEALTH" == "true" ]]; then
        load_stealth_configuration
    fi
    
    check_prerequisites
    copy_iso_to_libvirt
    create_disk_image
    install_os
    create_snapshot
    
    log "${GREEN}=== VM Creation Process Completed for '$VM_NAME' ===${NC}"
    log ""
    log "Next Steps:"
    log "1. Complete OS installation via VNC/virt-viewer"
    log "2. Install guest additions/tools"
    log "3. Configure for malware analysis"
    log "4. Shutdown VM to trigger automatic snapshot creation"
    log ""
    log "VM Management Commands:"
    log "  Start VM:    virsh start $VM_NAME"
    log "  Connect:     virt-viewer $VM_NAME"
    log "  Stop VM:     virsh shutdown $VM_NAME"
    log "  Destroy VM:  virsh destroy $VM_NAME"
    log ""
    
    if [[ "$ENABLE_STEALTH" == "true" ]]; then
        log "${GREEN}Stealth features enabled with level $STEALTH_LEVEL${NC}"
        log "Hardware profile: $HARDWARE_PROFILE"
    fi

    trap - ERR SIGINT SIGTERM
}

main "$@"