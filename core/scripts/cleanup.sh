#!/bin/bash
# Shikra Environment Cleanup Script
#
# Purpose:
# This script is responsible for cleaning up the Shikra analysis environment.
# This includes reverting VMs to clean snapshots, shutting down VMs, removing
# temporary network configurations, deleting old analysis data, and stopping
# any lingering processes related to Shikra.
#
# Key Functions Implemented:
# - parse_arguments(): Determine scope of cleanup (VMs, network, files, all)
# - cleanup_vms(): Shutdown and revert specified or all analysis VMs
# - cleanup_network(): Remove temporary bridges, firewall rules created by network_setup.sh
# - cleanup_data(): Delete old analysis results/logs based on retention policy
# - cleanup_processes(): Kill any lingering Shikra-related processes
#
# Usage:
#   ./cleanup.sh [--all | --vms [<vm_name>] | --network [<interface_name>] | --data [<age_days>] | --processes]
#
# Examples:
#   ./cleanup.sh --all
#   ./cleanup.sh --vms win10-analysis
#   ./cleanup.sh --network shikra-br0
#   ./cleanup.sh --data 7  (removes data older than 7 days)

# --- Script Configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")" # shikra/
RESULTS_BASE_DIR="$PROJECT_ROOT/data/results"
LOG_FILE="$PROJECT_ROOT/logs/cleanup.log" # Centralized logs

# --- Cleanup Flags (to be set by parse_arguments) ---
CLEANUP_ALL=false
CLEANUP_VMS=false
TARGET_VM=""
CLEANUP_NETWORK=false
TARGET_NETWORK_IF=""
CLEANUP_DATA=false
DATA_RETENTION_DAYS=30 # Default: delete data older than 30 days
CLEANUP_PROCESSES=false
DRY_RUN=false

# --- Color Codes ---
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

# --- Logging Function ---
log() {
    mkdir -p "$(dirname "$LOG_FILE")"
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# --- Function Definitions ---
show_usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  --all                    Perform all cleanup actions (VMs, network, data, processes)"
    echo "  --vms [vm_name]          Clean up VMs. If vm_name is provided, only that VM."
    echo "                           Otherwise, attempts to clean all known Shikra VMs."
    echo "                           Actions: shutdown, revert to 'clean_baseline' snapshot"
    echo "  --network [if_name]      Clean up network configurations. If if_name (bridge) is provided,"
    echo "                           targets that specific interface. Otherwise, attempts to find known Shikra interfaces"
    echo "  --data [days]            Clean up old analysis data from '$RESULTS_BASE_DIR'."
    echo "                           If 'days' is provided, data older than 'days' is removed."
    echo "                           Default retention: $DATA_RETENTION_DAYS days"
    echo "  --processes              Kill lingering Shikra-related processes"
    echo "  --dry-run                Show what would be done without executing"
    echo "  -h, --help               Show this help message"
    echo ""
    echo "If no options are provided, a basic cleanup (VMs and default network interfaces) will be performed."
}

parse_arguments() {
    log "${BLUE}Parsing command line arguments...${NC}"
    
    if [[ $# -eq 0 ]]; then
        log "${YELLOW}No cleanup options specified. Performing default cleanup: VMs and known network interfaces.${NC}"
        CLEANUP_VMS=true
        CLEANUP_NETWORK=true
        return
    fi

    while [[ $# -gt 0 ]]; do
        case $1 in
            --all)
                CLEANUP_ALL=true; CLEANUP_VMS=true; CLEANUP_NETWORK=true; CLEANUP_DATA=true; CLEANUP_PROCESSES=true;
                shift ;;
            --vms)
                CLEANUP_VMS=true;
                if [[ -n "$2" && ! "$2" =~ ^-- ]]; then TARGET_VM="$2"; shift; fi;
                shift ;;
            --network)
                CLEANUP_NETWORK=true;
                if [[ -n "$2" && ! "$2" =~ ^-- ]]; then TARGET_NETWORK_IF="$2"; shift; fi;
                shift ;;
            --data)
                CLEANUP_DATA=true;
                if [[ -n "$2" && "$2" =~ ^[0-9]+$ ]]; then DATA_RETENTION_DAYS="$2"; shift; fi;
                shift ;;
            --processes)
                CLEANUP_PROCESSES=true; shift ;;
            --dry-run)
                DRY_RUN=true; shift ;;
            -h|--help) show_usage; exit 0 ;;
            *) log "${RED}Unknown parameter or missing argument: $1${NC}"; show_usage; exit 1 ;;
        esac
    done

    if ! $CLEANUP_ALL && ! $CLEANUP_VMS && ! $CLEANUP_NETWORK && ! $CLEANUP_DATA && ! $CLEANUP_PROCESSES; then
         log "${YELLOW}No specific cleanup actions chosen. Defaulting to VMs and Network cleanup.${NC}"
         CLEANUP_VMS=true
         CLEANUP_NETWORK=true
    fi

    log "Cleanup Scope:"
    [[ "$CLEANUP_VMS" == "true" ]] && log "  VMs: Enabled ${TARGET_VM:+(Target: $TARGET_VM)}"
    [[ "$CLEANUP_NETWORK" == "true" ]] && log "  Network: Enabled ${TARGET_NETWORK_IF:+(Target Interface: $TARGET_NETWORK_IF)}"
    [[ "$CLEANUP_DATA" == "true" ]] && log "  Data: Enabled (Retention: $DATA_RETENTION_DAYS days)"
    [[ "$CLEANUP_PROCESSES" == "true" ]] && log "  Processes: Enabled"
    [[ "$DRY_RUN" == "true" ]] && log "  Mode: DRY RUN (no actual changes)"
}

identify_shikra_vms() {
    local vms_list=()
    
    # Get all VMs and filter for Shikra-related ones
    while IFS= read -r vm_name; do
        if [[ -z "$vm_name" ]]; then continue; fi
        
        # Check VM name patterns
        if [[ "$vm_name" =~ (shikra|analysis|sandbox|malware|test-vm) ]]; then
            vms_list+=("$vm_name")
            continue
        fi
        
        # Check VM description/metadata
        local vm_desc=$(virsh desc "$vm_name" 2>/dev/null | tr '[:upper:]' '[:lower:]')
        if [[ "$vm_desc" =~ (shikra|analysis|malware) ]]; then
            vms_list+=("$vm_name")
            continue
        fi
        
        # Check if VM uses Shikra networks
        local vm_networks=$(virsh domiflist "$vm_name" 2>/dev/null | awk 'NR>2 {print $3}')
        for network in $vm_networks; do
            if [[ "$network" =~ (shikra|analysis|isolated) ]]; then
                vms_list+=("$vm_name")
                break
            fi
        done
        
    done < <(virsh list --all --name 2>/dev/null)
    
    printf '%s\n' "${vms_list[@]}"
}

cleanup_target_vms() {
    if [[ "$CLEANUP_VMS" != "true" ]]; then return; fi
    log "${BLUE}Starting VM cleanup...${NC}"

    local vms_to_clean=()
    if [[ -n "$TARGET_VM" ]]; then
        # Verify target VM exists
        if ! virsh dominfo "$TARGET_VM" >/dev/null 2>&1; then
            log "${RED}Target VM '$TARGET_VM' not found${NC}"
            return 1
        fi
        vms_to_clean=("$TARGET_VM")
    else
        log "Identifying Shikra-managed VMs..."
        readarray -t vms_to_clean < <(identify_shikra_vms)
    fi

    if [[ ${#vms_to_clean[@]} -eq 0 ]]; then
        log "${YELLOW}No Shikra VMs identified for cleanup.${NC}"
        return 0
    fi

    log "Found ${#vms_to_clean[@]} VM(s) to clean: ${vms_to_clean[*]}"

    for vm in "${vms_to_clean[@]}"; do
        log "Processing VM: $vm"
        
        if [[ "$DRY_RUN" == "true" ]]; then
            log "Dry run: would clean VM '$vm'"
            continue
        fi
        
        cleanup_single_vm "$vm"
    done
    
    log "${GREEN}VM cleanup completed.${NC}"
}

cleanup_single_vm() {
    local vm_name="$1"
    
    # Get current VM state
    local vm_state=$(virsh domstate "$vm_name" 2>/dev/null || echo "undefined")
    log "VM '$vm_name' current state: $vm_state"
    
    # Shutdown VM if running
    case "$vm_state" in
        "running")
            log "Shutting down VM '$vm_name'..."
            if virsh shutdown "$vm_name" >/dev/null 2>&1; then
                # Wait for graceful shutdown
                local shutdown_timeout=30
                local elapsed=0
                while [[ $elapsed -lt $shutdown_timeout ]]; do
                    vm_state=$(virsh domstate "$vm_name" 2>/dev/null)
                    if [[ "$vm_state" != "running" ]]; then
                        break
                    fi
                    sleep 2
                    elapsed=$((elapsed + 2))
                done
                
                # Force shutdown if still running
                if [[ "$(virsh domstate "$vm_name" 2>/dev/null)" == "running" ]]; then
                    log "${YELLOW}VM '$vm_name' did not shutdown gracefully. Forcing power-off...${NC}"
                    virsh destroy "$vm_name" >/dev/null 2>&1
                fi
            else
                log "${YELLOW}Graceful shutdown failed, forcing power-off...${NC}"
                virsh destroy "$vm_name" >/dev/null 2>&1
            fi
            ;;
        "paused")
            log "Resuming paused VM '$vm_name' before shutdown..."
            virsh resume "$vm_name" >/dev/null 2>&1
            virsh shutdown "$vm_name" >/dev/null 2>&1
            sleep 5
            virsh destroy "$vm_name" >/dev/null 2>&1
            ;;
        "shut off")
            log "VM '$vm_name' is already shut off"
            ;;
    esac

    # Revert to clean_baseline snapshot if it exists
    if virsh snapshot-list "$vm_name" 2>/dev/null | grep -q "clean_baseline"; then
        log "Reverting VM '$vm_name' to 'clean_baseline' snapshot..."
        if virsh snapshot-revert "$vm_name" clean_baseline --force >/dev/null 2>&1; then
            log "VM '$vm_name' reverted to clean state"
        else
            log "${RED}Error reverting VM '$vm_name' to snapshot${NC}"
        fi
    else
        log "${YELLOW}No 'clean_baseline' snapshot found for VM '$vm_name'${NC}"
    fi
    
    # Clean up analysis snapshots
    cleanup_analysis_snapshots "$vm_name"
    
    # Clean up any temporary disk files
    cleanup_vm_temp_files "$vm_name"
}

cleanup_analysis_snapshots() {
    local vm_name="$1"
    
    # Remove analysis snapshots (but keep baseline snapshots)
    local analysis_snapshots=$(virsh snapshot-list "$vm_name" --name 2>/dev/null | grep -E "(analysis|temp|test)" || true)
    
    if [[ -n "$analysis_snapshots" ]]; then
        log "Cleaning up analysis snapshots for VM '$vm_name'..."
        echo "$analysis_snapshots" | while read -r snapshot; do
            if [[ -n "$snapshot" ]]; then
                log "  Deleting snapshot: $snapshot"
                virsh snapshot-delete "$vm_name" "$snapshot" >/dev/null 2>&1 || true
            fi
        done
    fi
}

cleanup_vm_temp_files() {
    local vm_name="$1"
    
    # Clean up temporary files in common locations
    local temp_locations=(
        "/tmp"
        "/var/tmp"
        "$PROJECT_ROOT/data/tmp"
        "$PROJECT_ROOT/data/vm_temp"
    )
    
    for temp_dir in "${temp_locations[@]}"; do
        if [[ -d "$temp_dir" ]]; then
            find "$temp_dir" -name "*${vm_name}*" -type f -mtime +1 -delete 2>/dev/null || true
        fi
    done
}

identify_shikra_networks() {
    local networks_list=()
    
    # Get libvirt networks
    while IFS= read -r network_name; do
        if [[ -z "$network_name" ]]; then continue; fi
        
        if [[ "$network_name" =~ (shikra|analysis|isolated|sandbox) ]]; then
            networks_list+=("$network_name")
        fi
    done < <(virsh net-list --all --name 2>/dev/null)
    
    # Get bridge interfaces
    while IFS= read -r bridge_line; do
        local bridge_name=$(echo "$bridge_line" | awk '{print $2}')
        if [[ "$bridge_name" =~ ^(br-|virbr-).*?(shikra|analysis|isolated) ]]; then
            networks_list+=("$bridge_name")
        fi
    done < <(ip link show type bridge 2>/dev/null)
    
    printf '%s\n' "${networks_list[@]}" | sort -u
}

cleanup_target_network() {
    if [[ "$CLEANUP_NETWORK" != "true" ]]; then return; fi
    log "${BLUE}Starting network cleanup...${NC}"

    local interfaces_to_clean=()
    if [[ -n "$TARGET_NETWORK_IF" ]]; then
        interfaces_to_clean=("$TARGET_NETWORK_IF")
    else
        log "Identifying Shikra-managed network interfaces..."
        readarray -t interfaces_to_clean < <(identify_shikra_networks)
    fi

    if [[ ${#interfaces_to_clean[@]} -eq 0 ]]; then
        log "${YELLOW}No Shikra network interfaces identified for cleanup.${NC}"
        return 0
    fi

    log "Found ${#interfaces_to_clean[@]} network(s) to clean: ${interfaces_to_clean[*]}"

    for if_name in "${interfaces_to_clean[@]}"; do
        log "Cleaning up network interface/configuration: $if_name"
        
        if [[ "$DRY_RUN" == "true" ]]; then
            log "Dry run: would clean network '$if_name'"
            continue
        fi
        
        cleanup_single_network "$if_name"
    done
    
    log "${GREEN}Network cleanup completed.${NC}"
}

cleanup_single_network() {
    local network_name="$1"
    
    # Check if it's a libvirt network
    if virsh net-info "$network_name" &>/dev/null; then
        log "Cleaning up libvirt network: $network_name"
        
        # Stop network services first
        cleanup_network_services "$network_name"
        
        # Destroy and undefine network
        virsh net-destroy "$network_name" 2>/dev/null || true
        virsh net-undefine "$network_name" 2>/dev/null || true
        
    elif ip link show "$network_name" &>/dev/null; then
        log "Cleaning up bridge interface: $network_name"
        
        # Stop network services
        cleanup_network_services "$network_name"
        
        # Remove bridge interface
        ip link set "$network_name" down 2>/dev/null || true
        ip link delete "$network_name" 2>/dev/null || true
    fi
    
    # Clean up firewall rules
    cleanup_network_firewall_rules "$network_name"
}

cleanup_network_services() {
    local network_name="$1"
    
    # Stop dnsmasq instances for this network
    local dnsmasq_pids=$(pgrep -f "dnsmasq.*$network_name" 2>/dev/null || true)
    if [[ -n "$dnsmasq_pids" ]]; then
        log "Stopping dnsmasq processes for network '$network_name'"
        echo "$dnsmasq_pids" | xargs kill 2>/dev/null || true
    fi
    
    # Stop tcpdump processes
    local tcpdump_pids=$(pgrep -f "tcpdump.*$network_name" 2>/dev/null || true)
    if [[ -n "$tcpdump_pids" ]]; then
        log "Stopping tcpdump processes for network '$network_name'"
        echo "$tcpdump_pids" | xargs kill 2>/dev/null || true
    fi
    
    # Stop fake services
    local fake_service_pids=$(pgrep -f "fake.*$network_name" 2>/dev/null || true)
    if [[ -n "$fake_service_pids" ]]; then
        log "Stopping fake services for network '$network_name'"
        echo "$fake_service_pids" | xargs kill 2>/dev/null || true
    fi
    
    # Clean up PID files
    find /tmp -name "*${network_name}*.pid" -delete 2>/dev/null || true
    
    # Clean up configuration files
    find /tmp -name "*${network_name}*.conf" -delete 2>/dev/null || true
    find /tmp -name "*${network_name}*.hosts" -delete 2>/dev/null || true
    find /tmp -name "*${network_name}*.log" -delete 2>/dev/null || true
}

cleanup_network_firewall_rules() {
    local network_name="$1"
    
    log "Cleaning up firewall rules for network '$network_name'"
    
    # Remove iptables rules containing the network name
    # This is a conservative approach - only remove rules that clearly reference our network
    local rules_to_remove=$(iptables-save | grep -n "$network_name" | cut -d: -f1 | tac)
    
    if [[ -n "$rules_to_remove" ]]; then
        log "Found firewall rules to remove for '$network_name'"
        # Note: This is a simplified approach. In production, you might want more precise rule removal
        iptables-save | grep -v "$network_name" | iptables-restore 2>/dev/null || {
            log "${YELLOW}Could not automatically remove all firewall rules for '$network_name'${NC}"
            log "Manual cleanup may be required"
        }
    fi
}

cleanup_analysis_data() {
    if [[ "$CLEANUP_DATA" != "true" ]]; then return; fi
    log "${BLUE}Cleaning up old analysis data (older than $DATA_RETENTION_DAYS days) from '$RESULTS_BASE_DIR'...${NC}"
    
    if [[ ! -d "$RESULTS_BASE_DIR" ]]; then
        log "${YELLOW}Results directory '$RESULTS_BASE_DIR' not found. Nothing to clean.${NC}"
        return 0
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        log "Dry run: would remove old analysis data"
        local old_dirs=$(find "$RESULTS_BASE_DIR" -mindepth 1 -maxdepth 1 -type d -mtime +"$DATA_RETENTION_DAYS" 2>/dev/null)
        if [[ -n "$old_dirs" ]]; then
            log "Would remove the following directories:"
            echo "$old_dirs" | while read -r dir; do
                log "  - $dir"
            done
        else
            log "No old directories found to remove"
        fi
        return 0
    fi

    # Find and remove old analysis directories
    local removed_count=0
    while IFS= read -r -d '' old_dir; do
        log "Removing old analysis directory: $old_dir"
        if rm -rf "$old_dir"; then
            removed_count=$((removed_count + 1))
        else
            log "${YELLOW}Failed to remove: $old_dir${NC}"
        fi
    done < <(find "$RESULTS_BASE_DIR" -mindepth 1 -maxdepth 1 -type d -mtime +"$DATA_RETENTION_DAYS" -print0 2>/dev/null)

    # Clean up old log files
    local log_dirs=("$PROJECT_ROOT/logs")
    for log_dir in "${log_dirs[@]}"; do
        if [[ -d "$log_dir" ]]; then
            find "$log_dir" -name "*.log" -mtime +"$DATA_RETENTION_DAYS" -delete 2>/dev/null || true
            find "$log_dir" -name "*.log.*" -mtime +"$DATA_RETENTION_DAYS" -delete 2>/dev/null || true
        fi
    done

    # Clean up old PCAP files
    local pcap_dir="$PROJECT_ROOT/data/pcap"
    if [[ -d "$pcap_dir" ]]; then
        find "$pcap_dir" -name "*.pcap*" -mtime +"$DATA_RETENTION_DAYS" -delete 2>/dev/null || true
        # Remove empty directories
        find "$pcap_dir" -type d -empty -delete 2>/dev/null || true
    fi

    log "${GREEN}Old analysis data cleanup completed. Removed $removed_count directories.${NC}"
}

cleanup_stray_processes() {
    if [[ "$CLEANUP_PROCESSES" != "true" ]]; then return; fi
    log "${BLUE}Cleaning up lingering Shikra-related processes...${NC}"

    if [[ "$DRY_RUN" == "true" ]]; then
        log "Dry run: would clean up processes"
        show_shikra_processes
        return 0
    fi

    local killed_count=0

    # Patterns for Shikra processes
    local process_patterns=(
        "tcpdump.*shikra"
        "tcpdump.*analysis"
        "tcpdump.*isolated"
        "dnsmasq.*shikra"
        "dnsmasq.*analysis"
        "python3.*shikra"
        "python.*shikra"
        "fake.*shikra"
        "behavioral_monitor"
        "packet_analyzer"
        "procmon_processor"
    )

    for pattern in "${process_patterns[@]}"; do
        local pids=$(pgrep -f "$pattern" 2>/dev/null || true)
        if [[ -n "$pids" ]]; then
            log "Killing processes matching pattern '$pattern': $pids"
            echo "$pids" | xargs kill -TERM 2>/dev/null || true
            sleep 2
            # Force kill if still running
            local remaining_pids=$(pgrep -f "$pattern" 2>/dev/null || true)
            if [[ -n "$remaining_pids" ]]; then
                echo "$remaining_pids" | xargs kill -KILL 2>/dev/null || true
            fi
            killed_count=$((killed_count + $(echo "$pids" | wc -w)))
        fi
    done

    # Clean up orphaned PID files
    find /tmp -name "*shikra*.pid" -delete 2>/dev/null || true
    find /tmp -name "*analysis*.pid" -delete 2>/dev/null || true
    find "$PROJECT_ROOT" -name "*.pid" -delete 2>/dev/null || true

    log "${GREEN}Lingering process cleanup completed. Killed $killed_count processes.${NC}"
}

show_shikra_processes() {
    log "Current Shikra-related processes:"
    
    local process_patterns=(
        "tcpdump.*shikra"
        "tcpdump.*analysis"
        "dnsmasq.*shikra"
        "python3.*shikra"
        "fake.*shikra"
    )

    local found_processes=false
    for pattern in "${process_patterns[@]}"; do
        local processes=$(pgrep -f "$pattern" -l 2>/dev/null || true)
        if [[ -n "$processes" ]]; then
            found_processes=true
            echo "$processes" | while read -r pid cmd; do
                log "  PID $pid: $cmd"
            done
        fi
    done

    if [[ "$found_processes" == "false" ]]; then
        log "  No Shikra-related processes found"
    fi
}

# --- Main Execution ---
main() {
    log "${GREEN}--- Shikra Environment Cleanup Script Started ---${NC}"
    
    # Check if running as root for certain operations
    if [[ $EUID -ne 0 ]] && [[ "$CLEANUP_VMS" == "true" || "$CLEANUP_NETWORK" == "true" ]]; then
        log "${YELLOW}Warning: Not running as root. Some cleanup operations may fail.${NC}"
        log "Consider running with sudo for complete cleanup."
    fi
    
    parse_arguments "$@"

    if $CLEANUP_VMS; then cleanup_target_vms; fi
    if $CLEANUP_NETWORK; then cleanup_target_network; fi
    if $CLEANUP_DATA; then cleanup_analysis_data; fi
    if $CLEANUP_PROCESSES; then cleanup_stray_processes; fi

    log "${GREEN}--- Shikra Cleanup Process Finished ---${NC}"
    
    if ! $CLEANUP_VMS && ! $CLEANUP_NETWORK && ! $CLEANUP_DATA && ! $CLEANUP_PROCESSES; then
        log "${YELLOW}No cleanup actions were performed.${NC}"
        show_usage
    else
        log "Cleanup summary:"
        [[ "$CLEANUP_VMS" == "true" ]] && log "  ✓ VM cleanup completed"
        [[ "$CLEANUP_NETWORK" == "true" ]] && log "  ✓ Network cleanup completed"
        [[ "$CLEANUP_DATA" == "true" ]] && log "  ✓ Data cleanup completed"
        [[ "$CLEANUP_PROCESSES" == "true" ]] && log "  ✓ Process cleanup completed"
    fi
}

main "$@"