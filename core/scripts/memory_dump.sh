#!/bin/bash
# Shikra Memory Dump Collection Script
#
# Purpose:
# This script handles memory dump collection from running VMs during malware analysis.
# It supports multiple hypervisors and dump formats, with options for live dumping
# or snapshot-based collection.
#
# Key Functions:
# - collect_memory_dump(): Main memory collection function
# - detect_hypervisor(): Auto-detect VM hypervisor type
# - validate_vm_state(): Ensure VM is in correct state for dumping
# - compress_dump(): Compress large memory dumps for storage
# - verify_dump(): Verify dump integrity and completeness
#
# Usage:
#   ./memory_dump.sh --vm <vm_name> [options]
#
# Examples:
#   ./memory_dump.sh --vm win10-analysis --output /analysis/dumps/
#   ./memory_dump.sh --vm malware-vm --format lime --compress

# --- Script Configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
LOG_FILE="$PROJECT_ROOT/logs/memory_dump.log"
DUMPS_DIR="$PROJECT_ROOT/data/memory_dumps"

# Default settings
DEFAULT_OUTPUT_DIR="$DUMPS_DIR"
DEFAULT_FORMAT="raw"
DEFAULT_COMPRESS=true

# --- Color Codes ---
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

# --- Configuration Variables ---
VM_NAME=""
OUTPUT_DIR="$DEFAULT_OUTPUT_DIR"
DUMP_FORMAT="$DEFAULT_FORMAT"
COMPRESS_DUMP=$DEFAULT_COMPRESS
LIVE_DUMP=false
SNAPSHOT_DUMP=false
FORCE_DUMP=false
DRY_RUN=false
HYPERVISOR_TYPE=""

# --- Logging Function ---
log() {
    mkdir -p "$(dirname "$LOG_FILE")"
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# --- Function Definitions ---
show_usage() {
    echo "Usage: $0 --vm <vm_name> [options]"
    echo ""
    echo "Required Arguments:"
    echo "  --vm <vm_name>           Name of the VM to dump memory from"
    echo ""
    echo "Optional Arguments:"
    echo "  --output <dir>           Output directory for dumps (default: $DEFAULT_OUTPUT_DIR)"
    echo "  --format <format>        Dump format: raw, lime, rekall (default: $DEFAULT_FORMAT)"
    echo "  --live                   Perform live memory dump (VM keeps running)"
    echo "  --snapshot               Create snapshot before dumping"
    echo "  --compress               Compress the memory dump (default: enabled)"
    echo "  --no-compress            Don't compress the memory dump"
    echo "  --force                  Force dump even if VM state is not ideal"
    echo "  --dry-run                Show what would be done without executing"
    echo "  -h, --help               Show this help message"
    echo ""
    echo "Supported Dump Formats:"
    echo "  raw                      Raw physical memory dump"
    echo "  lime                     Linux Memory Extractor format"
    echo "  rekall                   Rekall-compatible format"
    echo ""
    echo "Examples:"
    echo "  $0 --vm win10-analysis --output /tmp/dumps/"
    echo "  $0 --vm malware-vm --format lime --live --compress"
    echo "  $0 --vm test-vm --snapshot --no-compress"
}

parse_arguments() {
    log "${BLUE}Parsing command line arguments...${NC}"
    
    if [[ $# -eq 0 ]]; then
        show_usage
        exit 1
    fi

    while [[ $# -gt 0 ]]; do
        case $1 in
            --vm)
                if [[ -z "$2" ]]; then log "${RED}--vm requires a value${NC}"; exit 1; fi
                VM_NAME="$2"; shift 2 ;;
            --output)
                OUTPUT_DIR="$2"; shift 2 ;;
            --format)
                DUMP_FORMAT="$2"; shift 2 ;;
            --live)
                LIVE_DUMP=true; shift ;;
            --snapshot)
                SNAPSHOT_DUMP=true; shift ;;
            --compress)
                COMPRESS_DUMP=true; shift ;;
            --no-compress)
                COMPRESS_DUMP=false; shift ;;
            --force)
                FORCE_DUMP=true; shift ;;
            --dry-run)
                DRY_RUN=true; shift ;;
            -h|--help)
                show_usage; exit 0 ;;
            *)
                log "${RED}Unknown parameter: $1${NC}"; show_usage; exit 1 ;;
        esac
    done

    # Validate required arguments
    if [[ -z "$VM_NAME" ]]; then
        log "${RED}VM name is required (--vm)${NC}"
        exit 1
    fi

    # Validate dump format
    case "$DUMP_FORMAT" in
        raw|lime|rekall) ;;
        *) log "${RED}Invalid dump format: $DUMP_FORMAT${NC}"; show_usage; exit 1 ;;
    esac

    log "Memory Dump Configuration:"
    log "  VM Name: $VM_NAME"
    log "  Output Directory: $OUTPUT_DIR"
    log "  Dump Format: $DUMP_FORMAT"
    log "  Live Dump: $LIVE_DUMP"
    log "  Snapshot First: $SNAPSHOT_DUMP"
    log "  Compress: $COMPRESS_DUMP"
    log "  Force: $FORCE_DUMP"
    log "  Dry Run: $DRY_RUN"
}

check_prerequisites() {
    log "${BLUE}Checking prerequisites...${NC}"
    
    # Check if running as root or with appropriate permissions
    if [[ $EUID -ne 0 ]] && ! groups | grep -q libvirt; then
        log "${RED}This script requires root privileges or libvirt group membership${NC}"
        exit 1
    fi
    
    # Check required commands based on hypervisor
    local required_commands=("virsh")
    
    # Add format-specific tools
    case "$DUMP_FORMAT" in
        lime)
            required_commands+=("lime-forensics")
            ;;
        rekall)
            required_commands+=("rekall")
            ;;
    esac
    
    # Add compression tools if needed
    if [[ "$COMPRESS_DUMP" == "true" ]]; then
        required_commands+=("gzip")
    fi
    
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            if [[ "$cmd" == "lime-forensics" || "$cmd" == "rekall" ]]; then
                log "${YELLOW}Optional tool not found: $cmd (continuing with raw format)${NC}"
                DUMP_FORMAT="raw"
            else
                log "${RED}Required command not found: $cmd${NC}"
                exit 1
            fi
        fi
    done
    
    # Create output directory
    if [[ ! -d "$OUTPUT_DIR" ]]; then
        log "Creating output directory: $OUTPUT_DIR"
        mkdir -p "$OUTPUT_DIR" || {
            log "${RED}Failed to create output directory: $OUTPUT_DIR${NC}"
            exit 1
        }
    fi
    
    log "${GREEN}Prerequisites check passed${NC}"
}

detect_hypervisor() {
    log "${BLUE}Detecting hypervisor type for VM: $VM_NAME${NC}"
    
    # Check if VM exists in libvirt
    if virsh dominfo "$VM_NAME" &>/dev/null; then
        HYPERVISOR_TYPE="libvirt"
        local vm_hypervisor=$(virsh dominfo "$VM_NAME" | grep "Hypervisor:" | awk '{print $2}')
        log "Detected hypervisor: libvirt ($vm_hypervisor)"
        return 0
    fi
    
    # Check VirtualBox
    if command -v VBoxManage &>/dev/null; then
        if VBoxManage showvminfo "$VM_NAME" &>/dev/null; then
            HYPERVISOR_TYPE="virtualbox"
            log "Detected hypervisor: VirtualBox"
            return 0
        fi
    fi
    
    # Check VMware
    if command -v vmrun &>/dev/null; then
        if vmrun list | grep -q "$VM_NAME"; then
            HYPERVISOR_TYPE="vmware"
            log "Detected hypervisor: VMware"
            return 0
        fi
    fi
    
    log "${RED}Could not detect hypervisor for VM: $VM_NAME${NC}"
    exit 1
}

validate_vm_state() {
    log "${BLUE}Validating VM state...${NC}"
    
    case "$HYPERVISOR_TYPE" in
        libvirt)
            local vm_state=$(virsh domstate "$VM_NAME" 2>/dev/null)
            case "$vm_state" in
                "running")
                    log "VM is running - suitable for memory dump"
                    return 0
                    ;;
                "paused")
                    log "VM is paused - suitable for memory dump"
                    return 0
                    ;;
                "shut off")
                    if [[ "$FORCE_DUMP" == "true" ]]; then
                        log "${YELLOW}VM is shut off but force flag is set${NC}"
                        return 0
                    else
                        log "${RED}VM is shut off - cannot dump memory${NC}"
                        log "Use --force to attempt dump from disk image"
                        exit 1
                    fi
                    ;;
                *)
                    log "${RED}VM is in unknown state: $vm_state${NC}"
                    if [[ "$FORCE_DUMP" == "true" ]]; then
                        log "${YELLOW}Continuing due to force flag${NC}"
                        return 0
                    else
                        exit 1
                    fi
                    ;;
            esac
            ;;
        virtualbox)
            local vm_state=$(VBoxManage showvminfo "$VM_NAME" | grep "State:" | awk '{print $2}')
            if [[ "$vm_state" != "running" && "$FORCE_DUMP" != "true" ]]; then
                log "${RED}VirtualBox VM is not running: $vm_state${NC}"
                exit 1
            fi
            ;;
        vmware)
            if ! vmrun list | grep -q "$VM_NAME" && [[ "$FORCE_DUMP" != "true" ]]; then
                log "${RED}VMware VM is not running${NC}"
                exit 1
            fi
            ;;
    esac
    
    log "${GREEN}VM state validation passed${NC}"
}

create_snapshot_if_requested() {
    if [[ "$SNAPSHOT_DUMP" != "true" ]]; then
        return 0
    fi
    
    log "${BLUE}Creating snapshot before memory dump...${NC}"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "Dry run: would create snapshot for $VM_NAME"
        return 0
    fi
    
    local snapshot_name="memdump_$(date +%Y%m%d_%H%M%S)"
    local snapshot_desc="Snapshot created before memory dump - $(date)"
    
    case "$HYPERVISOR_TYPE" in
        libvirt)
            if ! virsh snapshot-create-as \
                --domain "$VM_NAME" \
                --name "$snapshot_name" \
                --description "$snapshot_desc" \
                --atomic; then
                log "${RED}Failed to create snapshot${NC}"
                if [[ "$FORCE_DUMP" != "true" ]]; then
                    exit 1
                fi
            else
                log "${GREEN}Snapshot created: $snapshot_name${NC}"
            fi
            ;;
        virtualbox)
            if ! VBoxManage snapshot "$VM_NAME" take "$snapshot_name" --description "$snapshot_desc"; then
                log "${RED}Failed to create VirtualBox snapshot${NC}"
                if [[ "$FORCE_DUMP" != "true" ]]; then
                    exit 1
                fi
            fi
            ;;
        vmware)
            if ! vmrun snapshot "$VM_NAME" "$snapshot_name"; then
                log "${RED}Failed to create VMware snapshot${NC}"
                if [[ "$FORCE_DUMP" != "true" ]]; then
                    exit 1
                fi
            fi
            ;;
    esac
}

collect_memory_dump() {
    log "${BLUE}Collecting memory dump from $VM_NAME...${NC}"
    
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local dump_filename="${VM_NAME}_memory_${timestamp}.${DUMP_FORMAT}"
    local dump_path="$OUTPUT_DIR/$dump_filename"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "Dry run: would collect memory dump to $dump_path"
        return 0
    fi
    
    log "Starting memory dump collection..."
    log "  VM: $VM_NAME"
    log "  Format: $DUMP_FORMAT"
    log "  Output: $dump_path"
    log "  Live dump: $LIVE_DUMP"
    
    case "$HYPERVISOR_TYPE" in
        libvirt)
            collect_libvirt_memory_dump "$dump_path"
            ;;
        virtualbox)
            collect_virtualbox_memory_dump "$dump_path"
            ;;
        vmware)
            collect_vmware_memory_dump "$dump_path"
            ;;
        *)
            log "${RED}Unsupported hypervisor: $HYPERVISOR_TYPE${NC}"
            exit 1
            ;;
    esac
    
    # Verify dump was created
    if [[ ! -f "$dump_path" ]]; then
        log "${RED}Memory dump was not created: $dump_path${NC}"
        exit 1
    fi
    
    local dump_size=$(du -h "$dump_path" | cut -f1)
    log "${GREEN}Memory dump completed: $dump_path ($dump_size)${NC}"
    
    # Compress if requested
    if [[ "$COMPRESS_DUMP" == "true" ]]; then
        compress_memory_dump "$dump_path"
    fi
    
    # Verify dump integrity
    verify_memory_dump "$dump_path"
}

collect_libvirt_memory_dump() {
    local dump_path="$1"
    
    case "$DUMP_FORMAT" in
        raw)
            log "Using virsh dump-memory for raw format"
            if ! virsh dump-memory "$VM_NAME" "$dump_path" --format raw; then
                log "${RED}Failed to dump memory using virsh${NC}"
                exit 1
            fi
            ;;
        lime)
            log "${YELLOW}LIME format requires guest agent or manual collection${NC}"
            log "Falling back to raw format"
            collect_libvirt_memory_dump "${dump_path%.lime}.raw"
            ;;
        rekall)
            log "Using virsh dump-memory with Rekall-compatible format"
            if ! virsh dump-memory "$VM_NAME" "$dump_path" --format elf; then
                log "${RED}Failed to dump memory for Rekall${NC}"
                exit 1
            fi
            ;;
    esac
}

collect_virtualbox_memory_dump() {
    local dump_path="$1"
    
    log "Collecting memory dump from VirtualBox VM"
    
    # VirtualBox doesn't have a direct memory dump command
    # We need to use the debugger interface
    log "${YELLOW}VirtualBox memory dumping requires VM to be paused${NC}"
    
    # Pause VM if it's running and not live dump
    if [[ "$LIVE_DUMP" != "true" ]]; then
        VBoxManage controlvm "$VM_NAME" pause
    fi
    
    # Use VBoxManage debugvm to dump memory
    if ! VBoxManage debugvm "$VM_NAME" dumpguestmem --filename "$dump_path"; then
        log "${RED}Failed to dump VirtualBox memory${NC}"
        if [[ "$LIVE_DUMP" != "true" ]]; then
            VBoxManage controlvm "$VM_NAME" resume
        fi
        exit 1
    fi
    
    # Resume VM if we paused it
    if [[ "$LIVE_DUMP" != "true" ]]; then
        VBoxManage controlvm "$VM_NAME" resume
    fi
}

collect_vmware_memory_dump() {
    local dump_path="$1"
    
    log "Collecting memory dump from VMware VM"
    
    # VMware memory dump through vmrun
    if [[ "$LIVE_DUMP" != "true" ]]; then
        vmrun pause "$VM_NAME"
    fi
    
    # Extract memory from .vmem file
    local vmx_path=$(vmrun list | grep "$VM_NAME")
    local vmem_path="${vmx_path%.*}.vmem"
    
    if [[ -f "$vmem_path" ]]; then
        cp "$vmem_path" "$dump_path"
    else
        log "${RED}VMware memory file not found: $vmem_path${NC}"
        exit 1
    fi
    
    if [[ "$LIVE_DUMP" != "true" ]]; then
        vmrun unpause "$VM_NAME"
    fi
}

compress_memory_dump() {
    local dump_path="$1"
    
    log "${BLUE}Compressing memory dump...${NC}"
    
    if [[ ! -f "$dump_path" ]]; then
        log "${RED}Dump file not found for compression: $dump_path${NC}"
        return 1
    fi
    
    local original_size=$(du -h "$dump_path" | cut -f1)
    log "Original size: $original_size"
    
    if ! gzip "$dump_path"; then
        log "${RED}Failed to compress memory dump${NC}"
        return 1
    fi
    
    local compressed_path="${dump_path}.gz"
    local compressed_size=$(du -h "$compressed_path" | cut -f1)
    log "${GREEN}Compressed to: $compressed_path ($compressed_size)${NC}"
    
    # Update dump_path for verification
    echo "$compressed_path" > /tmp/shikra_dump_path
}

verify_memory_dump() {
    local dump_path="$1"
    
    # Use compressed path if compression was done
    if [[ -f "/tmp/shikra_dump_path" ]]; then
        dump_path=$(cat /tmp/shikra_dump_path)
        rm -f /tmp/shikra_dump_path
    fi
    
    log "${BLUE}Verifying memory dump integrity...${NC}"
    
    if [[ ! -f "$dump_path" ]]; then
        log "${RED}Dump file not found for verification: $dump_path${NC}"
        return 1
    fi
    
    # Basic file integrity checks
    local file_size=$(stat -f%z "$dump_path" 2>/dev/null || stat -c%s "$dump_path" 2>/dev/null)
    
    if [[ "$file_size" -lt 1048576 ]]; then  # Less than 1MB is suspicious
        log "${YELLOW}Warning: Memory dump seems unusually small ($file_size bytes)${NC}"
    fi
    
    # Check file header for format-specific validation
    if [[ "$dump_path" == *.gz ]]; then
        if ! gzip -t "$dump_path"; then
            log "${RED}Compressed dump failed integrity check${NC}"
            return 1
        fi
    fi
    
    # Create checksum for verification
    local checksum_path="${dump_path}.sha256"
    if command -v sha256sum &>/dev/null; then
        sha256sum "$dump_path" > "$checksum_path"
        log "Checksum saved: $checksum_path"
    elif command -v shasum &>/dev/null; then
        shasum -a 256 "$dump_path" > "$checksum_path"
        log "Checksum saved: $checksum_path"
    fi
    
    log "${GREEN}Memory dump verification completed${NC}"
}

generate_dump_info() {
    local dump_path="$1"
    local info_path="${dump_path%.*}.json"
    
    log "${BLUE}Generating dump information file...${NC}"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "Dry run: would create info file at $info_path"
        return
    fi
    
    cat > "$info_path" << EOF
{
  "vm_name": "$VM_NAME",
  "dump_timestamp": "$(date -Iseconds)",
  "hypervisor": "$HYPERVISOR_TYPE",
  "dump_format": "$DUMP_FORMAT",
  "dump_file": "$(basename "$dump_path")",
  "compressed": $COMPRESS_DUMP,
  "live_dump": $LIVE_DUMP,
  "snapshot_created": $SNAPSHOT_DUMP,
  "file_size_bytes": $(stat -f%z "$dump_path" 2>/dev/null || stat -c%s "$dump_path" 2>/dev/null),
  "collection_method": "$(basename "$0")",
  "shikra_version": "1.0.0"
}
EOF
    
    log "Dump information saved: $info_path"
}

# --- Main Execution ---
main() {
    log "${GREEN}--- Shikra Memory Dump Collection Started ---${NC}"
    
    parse_arguments "$@"
    check_prerequisites
    detect_hypervisor
    validate_vm_state
    create_snapshot_if_requested
    collect_memory_dump
    
    local final_dump_path="$OUTPUT_DIR/${VM_NAME}_memory_$(date +%Y%m%d_%H%M%S).${DUMP_FORMAT}"
    if [[ "$COMPRESS_DUMP" == "true" ]]; then
        final_dump_path="${final_dump_path}.gz"
    fi
    
    generate_dump_info "$final_dump_path"
    
    log "${GREEN}--- Memory Dump Collection Completed ---${NC}"
    log "Memory dump saved to: $OUTPUT_DIR"
    log "VM: $VM_NAME"
    log "Format: $DUMP_FORMAT"
    log "Compressed: $COMPRESS_DUMP"
    log ""
    log "Next steps:"
    log "1. Analyze with: python3 $PROJECT_ROOT/analysis/modules/analysis/memory_analysis.py"
    log "2. Or use Volatility/Rekall directly on the dump file"
}

main "$@"