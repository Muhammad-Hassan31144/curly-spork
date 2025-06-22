#!/bin/bash
# Shikra Analysis Orchestration Script - Enhanced
#
# Purpose:
# This script orchestrates complete malware analysis workflows by coordinating
# VM management, stealth techniques, network simulation, monitoring setup, 
# sample execution, and comprehensive results collection.
#
# Key Functions:
# - setup_analysis_environment(): Prepares VM, stealth, and monitoring
# - execute_sample(): Runs malware sample in controlled environment
# - collect_artifacts(): Gathers logs, dumps, and analysis data
# - generate_reports(): Creates comprehensive analysis reports
# - cleanup_analysis(): Restores environment to clean state
#
# Usage:
#   ./run_analysis.sh --sample <path> --vm <vm_name> [options]

# --- Script Configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
CONFIG_DIR="$PROJECT_ROOT/config"
LOG_FILE="$PROJECT_ROOT/logs/analysis_orchestration.log"
RESULTS_BASE_DIR="$PROJECT_ROOT/data/results"
SAMPLES_DIR="$PROJECT_ROOT/data/samples"

# Module paths
VM_CONTROLLER_MODULE="$PROJECT_ROOT/core/modules/vm_controller"
MONITORING_MODULE="$PROJECT_ROOT/core/modules/monitoring"
NETWORK_MODULE="$PROJECT_ROOT/core/modules/network"

# Analysis configuration defaults
DEFAULT_TIMEOUT=300
DEFAULT_VM_PROFILE="default"
DEFAULT_ANALYSIS_PROFILE="comprehensive"
DEFAULT_NETWORK="shikra-isolated"

# Color codes
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

# Configuration variables
SAMPLE_PATH=""
VM_NAME=""
VM_PROFILE="$DEFAULT_VM_PROFILE"
ANALYSIS_PROFILE="$DEFAULT_ANALYSIS_PROFILE"
NETWORK_NAME="$DEFAULT_NETWORK"
ANALYSIS_TIMEOUT="$DEFAULT_TIMEOUT"
OUTPUT_DIR=""
RUN_ID=""
SKIP_SETUP=false
SKIP_CLEANUP=false
MEMORY_DUMP=true
NETWORK_CAPTURE=true
BEHAVIORAL_MONITORING=true
STEALTH_MODE=true
FAKE_SERVICES=true
DRY_RUN=false
VERBOSE=false

# Internal state tracking
ANALYSIS_START_TIME=""
VM_SNAPSHOT_CREATED=false
MONITORING_STARTED=false
NETWORK_SERVICES_STARTED=false
STEALTH_APPLIED=false
SAMPLE_EXECUTED=false
ARTIFACTS_COLLECTED=false

# Module availability tracking
VM_CONTROLLER_AVAILABLE=false
MONITORING_AVAILABLE=false
NETWORK_AVAILABLE=false
STEALTH_AVAILABLE=false

# --- Logging Function ---
log() {
    mkdir -p "$(dirname "$LOG_FILE")"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "$timestamp - $1" | tee -a "$LOG_FILE"
    
    if [[ "$VERBOSE" == "true" ]]; then
        echo -e "$timestamp - $1" >&2
    fi
}

# --- Module Availability Check ---
check_module_availability() {
    log "${BLUE}Checking module availability...${NC}"
    
    # Check vm_controller module
    if [[ -f "$VM_CONTROLLER_MODULE/__init__.py" ]]; then
        VM_CONTROLLER_AVAILABLE=true
        log "✓ VM Controller module available"
    else
        log "${YELLOW}✗ VM Controller module not found${NC}"
    fi
    
    # Check monitoring module
    if [[ -f "$MONITORING_MODULE/behavioral_monitor.py" ]]; then
        MONITORING_AVAILABLE=true
        log "✓ Monitoring module available"
    else
        log "${YELLOW}✗ Monitoring module not found${NC}"
    fi
    
    # Check network module
    if [[ -f "$NETWORK_MODULE/capture.py" ]] && [[ -f "$NETWORK_MODULE/fake_services.py" ]]; then
        NETWORK_AVAILABLE=true
        log "✓ Network module available"
    else
        log "${YELLOW}✗ Network module not found${NC}"
    fi
    
    # Check stealth capability
    if [[ -f "$VM_CONTROLLER_MODULE/stealth.py" ]]; then
        STEALTH_AVAILABLE=true
        log "✓ Stealth module available"
    else
        log "${YELLOW}✗ Stealth module not found${NC}"
    fi
}

# --- Function Definitions ---
show_usage() {
    echo "Usage: $0 --sample <path> --vm <vm_name> [options]"
    echo ""
    echo "Required Arguments:"
    echo "  --sample <path>          Path to malware sample to analyze"
    echo "  --vm <vm_name>           Name of VM to use for analysis"
    echo ""
    echo "Optional Arguments:"
    echo "  --vm-profile <profile>   VM profile to use (default: $DEFAULT_VM_PROFILE)"
    echo "  --analysis-profile <p>   Analysis profile (default: $DEFAULT_ANALYSIS_PROFILE)"
    echo "  --network <network>      Network to use (default: $DEFAULT_NETWORK)"
    echo "  --timeout <seconds>      Analysis timeout (default: $DEFAULT_TIMEOUT)"
    echo "  --output <dir>           Output directory for results"
    echo "  --run-id <id>            Custom run identifier"
    echo "  --skip-setup             Skip environment setup"
    echo "  --skip-cleanup           Skip post-analysis cleanup"
    echo "  --no-memory-dump         Skip memory dump collection"
    echo "  --no-network-capture     Skip network traffic capture"
    echo "  --no-behavioral          Skip behavioral monitoring"
    echo "  --no-stealth             Skip stealth techniques"
    echo "  --no-fake-services       Skip fake service deployment"
    echo "  --dry-run                Show what would be done"
    echo "  --verbose                Enable verbose output"
    echo "  -h, --help               Show this help message"
    echo ""
    echo "Analysis Profiles:"
    echo "  basic                    Basic dynamic analysis"
    echo "  comprehensive            Full analysis suite (default)"
    echo "  stealth                  Anti-evasion focused analysis"
    echo "  network-focused          Network behavior analysis with fake services"
    echo "  memory-focused           Memory analysis emphasis"
    echo "  behavioral-focused       Deep behavioral monitoring"
    echo ""
    echo "Examples:"
    echo "  $0 --sample /tmp/malware.exe --vm win10-analysis"
    echo "  $0 --sample sample.bin --vm linux-vm --timeout 600 --analysis-profile stealth"
    echo "  $0 --sample trojan.exe --vm win10-analysis --analysis-profile network-focused"
}

parse_arguments() {
    log "${BLUE}Parsing command line arguments...${NC}"
    
    if [[ $# -eq 0 ]]; then
        show_usage
        exit 1
    fi

    while [[ $# -gt 0 ]]; do
        case $1 in
            --sample)
                if [[ -z "$2" ]]; then log "${RED}--sample requires a path${NC}"; exit 1; fi
                SAMPLE_PATH="$2"; shift 2 ;;
            --vm)
                if [[ -z "$2" ]]; then log "${RED}--vm requires a name${NC}"; exit 1; fi
                VM_NAME="$2"; shift 2 ;;
            --vm-profile)
                VM_PROFILE="$2"; shift 2 ;;
            --analysis-profile)
                ANALYSIS_PROFILE="$2"; shift 2 ;;
            --network)
                NETWORK_NAME="$2"; shift 2 ;;
            --timeout)
                ANALYSIS_TIMEOUT="$2"; shift 2 ;;
            --output)
                OUTPUT_DIR="$2"; shift 2 ;;
            --run-id)
                RUN_ID="$2"; shift 2 ;;
            --skip-setup)
                SKIP_SETUP=true; shift ;;
            --skip-cleanup)
                SKIP_CLEANUP=true; shift ;;
            --no-memory-dump)
                MEMORY_DUMP=false; shift ;;
            --no-network-capture)
                NETWORK_CAPTURE=false; shift ;;
            --no-behavioral)
                BEHAVIORAL_MONITORING=false; shift ;;
            --no-stealth)
                STEALTH_MODE=false; shift ;;
            --no-fake-services)
                FAKE_SERVICES=false; shift ;;
            --dry-run)
                DRY_RUN=true; shift ;;
            --verbose)
                VERBOSE=true; shift ;;
            -h|--help)
                show_usage; exit 0 ;;
            *)
                log "${RED}Unknown parameter: $1${NC}"; show_usage; exit 1 ;;
        esac
    done

    # Validate required arguments
    if [[ -z "$SAMPLE_PATH" ]]; then
        log "${RED}Sample path is required (--sample)${NC}"
        exit 1
    fi
    
    if [[ -z "$VM_NAME" ]]; then
        log "${RED}VM name is required (--vm)${NC}"
        exit 1
    fi

    # Generate run ID if not provided
    if [[ -z "$RUN_ID" ]]; then
        RUN_ID="analysis_$(date +%Y%m%d_%H%M%S)_$(basename "$SAMPLE_PATH" | tr '.' '_')"
    fi

    # Set output directory if not provided
    if [[ -z "$OUTPUT_DIR" ]]; then
        OUTPUT_DIR="$RESULTS_BASE_DIR/$RUN_ID"
    fi

    # Adjust settings based on analysis profile
    configure_analysis_profile

    log "Analysis Configuration:"
    log "  Sample: $SAMPLE_PATH"
    log "  VM: $VM_NAME"
    log "  VM Profile: $VM_PROFILE"
    log "  Analysis Profile: $ANALYSIS_PROFILE"
    log "  Network: $NETWORK_NAME"
    log "  Timeout: ${ANALYSIS_TIMEOUT}s"
    log "  Output Directory: $OUTPUT_DIR"
    log "  Run ID: $RUN_ID"
    log "  Memory Dump: $MEMORY_DUMP"
    log "  Network Capture: $NETWORK_CAPTURE"
    log "  Behavioral Monitoring: $BEHAVIORAL_MONITORING"
    log "  Stealth Mode: $STEALTH_MODE"
    log "  Fake Services: $FAKE_SERVICES"
}

configure_analysis_profile() {
    case "$ANALYSIS_PROFILE" in
        "stealth")
            STEALTH_MODE=true
            BEHAVIORAL_MONITORING=true
            NETWORK_CAPTURE=true
            FAKE_SERVICES=false  # Don't create obvious fake services in stealth mode
            ;;
        "network-focused")
            NETWORK_CAPTURE=true
            FAKE_SERVICES=true
            BEHAVIORAL_MONITORING=true
            MEMORY_DUMP=false  # Focus on network, skip memory
            ;;
        "memory-focused")
            MEMORY_DUMP=true
            BEHAVIORAL_MONITORING=true
            NETWORK_CAPTURE=false
            FAKE_SERVICES=false
            ;;
        "behavioral-focused")
            BEHAVIORAL_MONITORING=true
            MEMORY_DUMP=true
            NETWORK_CAPTURE=true
            FAKE_SERVICES=false
            ;;
        "basic")
            BEHAVIORAL_MONITORING=true
            MEMORY_DUMP=false
            NETWORK_CAPTURE=false
            FAKE_SERVICES=false
            STEALTH_MODE=false
            ;;
        "comprehensive")
            # Keep all defaults (everything enabled)
            ;;
    esac
}

check_prerequisites() {
    log "${BLUE}Checking prerequisites...${NC}"
    
    # Check module availability first
    check_module_availability
    
    # Check if sample file exists
    if [[ ! -f "$SAMPLE_PATH" ]]; then
        log "${RED}Sample file not found: $SAMPLE_PATH${NC}"
        exit 1
    fi
    
    # Check if VM exists
    if ! virsh dominfo "$VM_NAME" &>/dev/null; then
        log "${RED}VM not found: $VM_NAME${NC}"
        log "Use './create_vm.sh' to create the VM first"
        exit 1
    fi
    
    # Check Python environment
    if ! python3 -c "import sys; print(f'Python {sys.version}')" &>/dev/null; then
        log "${RED}Python 3 not available${NC}"
        exit 1
    fi
    
    # Create output directory
    mkdir -p "$OUTPUT_DIR"
    
    log "${GREEN}Prerequisites check passed${NC}"
}

setup_analysis_environment() {
    if [[ "$SKIP_SETUP" == "true" ]]; then
        log "${YELLOW}Skipping environment setup${NC}"
        return 0
    fi
    
    log "${BLUE}Setting up analysis environment...${NC}"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "Dry run: would setup analysis environment"
        return 0
    fi
    
    # Setup network first (required for VM)
    setup_analysis_network
    
    # Setup fake services if enabled
    if [[ "$FAKE_SERVICES" == "true" ]]; then
        setup_fake_services
    fi
    
    # Prepare VM
    prepare_analysis_vm
    
    # Apply stealth techniques if enabled
    if [[ "$STEALTH_MODE" == "true" ]]; then
        apply_stealth_techniques
    fi
    
    # Setup monitoring
    setup_monitoring_tools
    
    log "${GREEN}Analysis environment setup completed${NC}"
}

setup_analysis_network() {
    log "Setting up analysis network: $NETWORK_NAME"
    
    # Check if network exists, create if needed
    if ! virsh net-info "$NETWORK_NAME" &>/dev/null; then
        log "Creating isolated network: $NETWORK_NAME"
        
        local network_args="--create-isolated --name $NETWORK_NAME"
        
        if [[ "$NETWORK_CAPTURE" == "true" ]]; then
            network_args="$network_args --enable-capture"
        fi
        
        if [[ "$ANALYSIS_PROFILE" == "network-focused" ]]; then
            network_args="$network_args --enable-sinkhole --enable-fake-services"
        fi
        
        if ! "$SCRIPT_DIR/network_setup.sh" $network_args; then
            log "${RED}Failed to setup network${NC}"
            exit 1
        fi
    else
        log "Using existing network: $NETWORK_NAME"
    fi
    
    # Start network capture if enabled and module available
    if [[ "$NETWORK_CAPTURE" == "true" ]] && [[ "$NETWORK_AVAILABLE" == "true" ]]; then
        start_network_capture
    fi
}

start_network_capture() {
    log "Starting network capture..."
    
    local capture_dir="$OUTPUT_DIR/network"
    mkdir -p "$capture_dir"
    
    # Use network capture module
    if [[ -f "$NETWORK_MODULE/capture.py" ]]; then
        log "Starting network capture module..."
        nohup python3 -m shikra.core.modules.network.capture \
            --interface "br-$(echo "$NETWORK_NAME" | tr '[:upper:]' '[:lower:]' | tr '_' '-')" \
            --output-dir "$capture_dir" \
            --run-id "$RUN_ID" \
            > "$capture_dir/network_capture.log" 2>&1 &
        
        local capture_pid=$!
        echo "$capture_pid" > "$capture_dir/network_capture.pid"
        log "Network capture started (PID: $capture_pid)"
    else
        log "${YELLOW}Network capture module not available${NC}"
    fi
}

setup_fake_services() {
    if [[ "$NETWORK_AVAILABLE" != "true" ]]; then
        log "${YELLOW}Network module not available, skipping fake services${NC}"
        return 0
    fi
    
    log "Setting up fake network services..."
    
    local services_dir="$OUTPUT_DIR/fake_services"
    mkdir -p "$services_dir"
    
    # Start fake services using network module
    if [[ -f "$NETWORK_MODULE/fake_services.py" ]]; then
        log "Starting fake services module..."
        nohup python3 -m shikra.core.modules.network.fake_services \
            --network "$NETWORK_NAME" \
            --output-dir "$services_dir" \
            --run-id "$RUN_ID" \
            --services "http,ftp,smtp,dns,irc" \
            > "$services_dir/fake_services.log" 2>&1 &
        
        local services_pid=$!
        echo "$services_pid" > "$services_dir/fake_services.pid"
        NETWORK_SERVICES_STARTED=true
        log "Fake services started (PID: $services_pid)"
    else
        log "${YELLOW}Fake services module not available${NC}"
    fi
}

prepare_analysis_vm() {
    log "Preparing analysis VM: $VM_NAME"
    
    if [[ "$VM_CONTROLLER_AVAILABLE" != "true" ]]; then
        log "${RED}VM Controller module not available${NC}"
        exit 1
    fi
    
    # Get current VM state
    local vm_state=$(virsh domstate "$VM_NAME" 2>/dev/null)
    
    # If VM is running, shut it down for snapshot revert
    if [[ "$vm_state" == "running" ]]; then
        log "Shutting down VM for clean state preparation..."
        python3 -m shikra.core.modules.vm_controller --snapshot "$VM_NAME" --restore clean_baseline
    fi
    
    # Create analysis snapshot using vm_controller
    local analysis_snapshot="analysis_start_${RUN_ID}"
    log "Creating analysis start snapshot: $analysis_snapshot"
    
    if python3 -m shikra.core.modules.vm_controller --snapshot "$VM_NAME" --create "$analysis_snapshot"; then
        VM_SNAPSHOT_CREATED=true
        log "Analysis snapshot created successfully"
    else
        log "${YELLOW}Failed to create analysis snapshot - continuing${NC}"
    fi
    
    # Start VM
    log "Starting analysis VM..."
    if ! virsh start "$VM_NAME"; then
        log "${RED}Failed to start VM${NC}"
        exit 1
    fi
    
    # Wait for VM to be ready
    wait_for_vm_ready
}

apply_stealth_techniques() {
    if [[ "$STEALTH_AVAILABLE" != "true" ]]; then
        log "${YELLOW}Stealth module not available, skipping stealth techniques${NC}"
        return 0
    fi
    
    log "Applying stealth techniques to VM..."
    
    # Apply stealth using vm_controller stealth module
    if python3 -m shikra.core.modules.vm_controller --apply-stealth "$VM_NAME" --level full; then
        STEALTH_APPLIED=true
        log "${GREEN}Stealth techniques applied successfully${NC}"
    else
        log "${YELLOW}Failed to apply stealth techniques${NC}"
    fi
}

wait_for_vm_ready() {
    log "Waiting for VM to be ready for analysis..."
    
    local ready_timeout=120
    local elapsed=0
    local check_interval=5
    
    while [[ $elapsed -lt $ready_timeout ]]; do
        local vm_state=$(virsh domstate "$VM_NAME" 2>/dev/null)
        
        if [[ "$vm_state" == "running" ]]; then
            # Try to ping the VM to check network connectivity
            local vm_ip=$(get_vm_ip "$VM_NAME")
            if [[ -n "$vm_ip" ]] && ping -c 1 -W 2 "$vm_ip" &>/dev/null; then
                log "${GREEN}VM is ready and network accessible${NC}"
                return 0
            fi
        fi
        
        log "VM not ready yet, waiting... (${elapsed}s elapsed)"
        sleep $check_interval
        elapsed=$((elapsed + check_interval))
    done
    
    log "${YELLOW}VM readiness timeout reached, continuing anyway${NC}"
    return 0
}

get_vm_ip() {
    local vm_name="$1"
    
    # Try to get IP from DHCP leases
    local lease_file="/var/lib/libvirt/dnsmasq/${NETWORK_NAME}.leases"
    if [[ -f "$lease_file" ]]; then
        local vm_mac=$(virsh domiflist "$vm_name" | grep "$NETWORK_NAME" | awk '{print $5}')
        if [[ -n "$vm_mac" ]]; then
            local vm_ip=$(grep "$vm_mac" "$lease_file" | awk '{print $3}' | head -1)
            echo "$vm_ip"
            return
        fi
    fi
    
    # Fallback: try arp table
    local vm_mac=$(virsh domiflist "$vm_name" | grep "$NETWORK_NAME" | awk '{print $5}')
    if [[ -n "$vm_mac" ]]; then
        local vm_ip=$(arp -a | grep "$vm_mac" | awk '{print $2}' | tr -d '()')
        echo "$vm_ip"
    fi
}

setup_monitoring_tools() {
    log "Setting up monitoring tools..."
    
    # Start behavioral monitoring
    if [[ "$BEHAVIORAL_MONITORING" == "true" ]]; then
        setup_behavioral_monitoring
    fi
    
    MONITORING_STARTED=true
    log "${GREEN}Monitoring tools setup completed${NC}"
}

setup_behavioral_monitoring() {
    if [[ "$MONITORING_AVAILABLE" != "true" ]]; then
        log "${YELLOW}Monitoring module not available, skipping behavioral monitoring${NC}"
        return 0
    fi
    
    log "Setting up behavioral monitoring..."
    
    # Create monitoring output directory
    local monitoring_dir="$OUTPUT_DIR/monitoring"
    mkdir -p "$monitoring_dir"
    
    # Start behavioral monitor using monitoring module
    if [[ -f "$MONITORING_MODULE/behavioral_monitor.py" ]]; then
        log "Starting behavioral monitor..."
        nohup python3 -m shikra.core.modules.monitoring.behavioral_monitor \
            --vm "$VM_NAME" \
            --output-dir "$monitoring_dir" \
            --run-id "$RUN_ID" \
            --enable-procmon \
            --enable-filter-engine \
            > "$monitoring_dir/behavioral_monitor.log" 2>&1 &
        
        local monitor_pid=$!
        echo "$monitor_pid" > "$monitoring_dir/behavioral_monitor.pid"
        log "Behavioral monitor started (PID: $monitor_pid)"
        
        # Also start procmon handler if available
        start_procmon_handler "$monitoring_dir"
    else
        log "${YELLOW}Behavioral monitor script not found${NC}"
    fi
}

start_procmon_handler() {
    local monitoring_dir="$1"
    
    if [[ -f "$MONITORING_MODULE/procmon_handler.py" ]]; then
        log "Starting ProcMon handler..."
        nohup python3 -m shikra.core.modules.monitoring.procmon_handler \
            --vm "$VM_NAME" \
            --output-dir "$monitoring_dir" \
            --run-id "$RUN_ID" \
            > "$monitoring_dir/procmon_handler.log" 2>&1 &
        
        local handler_pid=$!
        echo "$handler_pid" > "$monitoring_dir/procmon_handler.pid"
        log "ProcMon handler started (PID: $handler_pid)"
    fi
}

execute_sample() {
    log "${BLUE}Executing malware sample...${NC}"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "Dry run: would execute sample $SAMPLE_PATH"
        return 0
    fi
    
    ANALYSIS_START_TIME=$(date +%s)
    
    # Copy sample to VM
    copy_sample_to_vm
    
    # Execute sample in VM
    execute_sample_in_vm
    
    # Wait for analysis completion
    wait_for_analysis_completion
    
    SAMPLE_EXECUTED=true
    log "${GREEN}Sample execution completed${NC}"
}

copy_sample_to_vm() {
    log "Copying sample to VM..."
    
    if [[ "$VM_CONTROLLER_AVAILABLE" != "true" ]]; then
        log "${RED}VM Controller module not available${NC}"
        exit 1
    fi
    
    # Stage the sample file first
    if python3 -m shikra.core.modules.vm_controller --stage "$SAMPLE_PATH"; then
        log "Sample staged for transfer"
    else
        log "${RED}Failed to stage sample${NC}"
        exit 1
    fi
    
    # Copy to VM using vm_controller
    if python3 -m shikra.core.modules.vm_controller --copy-to "$VM_NAME" --method smb; then
        log "Sample copied to VM successfully"
    else
        log "${RED}Failed to copy sample to VM${NC}"
        exit 1
    fi
}

execute_sample_in_vm() {
    log "Executing sample in VM..."
    
    local sample_name=$(basename "$SAMPLE_PATH")
    local vm_os=$(get_vm_os_type "$VM_NAME")
    local execution_command=""
    
    # Prepare execution command based on OS
    case "$vm_os" in
        windows)
            execution_command="cd C:\\Temp && \\\\192.168.100.1\\tools\\$sample_name"
            ;;
        linux)
            execution_command="chmod +x /tmp/$sample_name && /tmp/$sample_name"
            ;;
    esac
    
    # Execute using vm_controller
    log "Executing command in VM: $execution_command"
    
    # Run in background to allow monitoring
    nohup python3 -m shikra.core.modules.vm_controller \
        --run-in "$VM_NAME" \
        --command "$execution_command" \
        --timeout "$ANALYSIS_TIMEOUT" \
        > "$OUTPUT_DIR/sample_execution.log" 2>&1 &
    
    local exec_pid=$!
    echo "$exec_pid" > "$OUTPUT_DIR/sample_execution.pid"
    log "Sample execution started (PID: $exec_pid)"
}

get_vm_os_type() {
    local vm_name="$1"
    
    # Try to determine OS from VM metadata or configuration
    local vm_xml=$(virsh dumpxml "$vm_name" 2>/dev/null)
    
    if echo "$vm_xml" | grep -qi "windows"; then
        echo "windows"
    elif echo "$vm_xml" | grep -qi "linux\|ubuntu\|centos\|debian"; then
        echo "linux"
    else
        # Default assumption
        echo "windows"
    fi
}

wait_for_analysis_completion() {
    log "Waiting for analysis completion (timeout: ${ANALYSIS_TIMEOUT}s)..."
    
    local start_time=$(date +%s)
    local check_interval=10
    
    while true; do
        local current_time=$(date +%s)
        local elapsed=$((current_time - start_time))
        
        # Check if timeout reached
        if [[ $elapsed -ge $ANALYSIS_TIMEOUT ]]; then
            log "${YELLOW}Analysis timeout reached${NC}"
            break
        fi
        
        # Check if sample execution finished
        local exec_pid_file="$OUTPUT_DIR/sample_execution.pid"
        if [[ -f "$exec_pid_file" ]]; then
            local exec_pid=$(cat "$exec_pid_file")
            if ! kill -0 "$exec_pid" 2>/dev/null; then
                log "Sample execution process finished"
                break
            fi
        fi
        
        log "Analysis in progress... (${elapsed}s elapsed)"
        sleep $check_interval
    done
    
    # Kill sample execution if still running
    local exec_pid_file="$OUTPUT_DIR/sample_execution.pid"
    if [[ -f "$exec_pid_file" ]]; then
        local exec_pid=$(cat "$exec_pid_file")
        if kill -0 "$exec_pid" 2>/dev/null; then
            log "Terminating sample execution process..."
            kill "$exec_pid" 2>/dev/null || true
        fi
    fi
}

collect_analysis_artifacts() {
    log "${BLUE}Collecting analysis artifacts...${NC}"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "Dry run: would collect analysis artifacts"
        return 0
    fi
    
    # Stop monitoring
    stop_monitoring_tools
    
    # Stop network services
    stop_network_services
    
    # Collect memory dump
    if [[ "$MEMORY_DUMP" == "true" ]]; then
        collect_memory_dump
    fi
    
    # Collect network artifacts
    collect_network_artifacts
    
    # Collect behavioral artifacts
    collect_behavioral_artifacts
    
    # Collect VM artifacts
    collect_vm_artifacts
    
    ARTIFACTS_COLLECTED=true
    log "${GREEN}Analysis artifacts collection completed${NC}"
}

stop_monitoring_tools() {
    log "Stopping monitoring tools..."
    
    # Stop behavioral monitor
    local behavioral_pid_file="$OUTPUT_DIR/monitoring/behavioral_monitor.pid"
    if [[ -f "$behavioral_pid_file" ]]; then
        local pid=$(cat "$behavioral_pid_file")
        if kill "$pid" 2>/dev/null; then
            log "Stopped behavioral monitor (PID: $pid)"
        fi
        rm -f "$behavioral_pid_file"
    fi
    
    # Stop procmon handler
    local procmon_pid_file="$OUTPUT_DIR/monitoring/procmon_handler.pid"
    if [[ -f "$procmon_pid_file" ]]; then
        local pid=$(cat "$procmon_pid_file")
        if kill "$pid" 2>/dev/null; then
            log "Stopped ProcMon handler (PID: $pid)"
        fi
        rm -f "$procmon_pid_file"
    fi
}

stop_network_services() {
    log "Stopping network services..."
    
    # Stop network capture
    local capture_pid_file="$OUTPUT_DIR/network/network_capture.pid"
    if [[ -f "$capture_pid_file" ]]; then
        local pid=$(cat "$capture_pid_file")
        if kill "$pid" 2>/dev/null; then
            log "Stopped network capture (PID: $pid)"
        fi
        rm -f "$capture_pid_file"
    fi
    
    # Stop fake services
    local services_pid_file="$OUTPUT_DIR/fake_services/fake_services.pid"
    if [[ -f "$services_pid_file" ]]; then
        local pid=$(cat "$services_pid_file")
        if kill "$pid" 2>/dev/null; then
            log "Stopped fake services (PID: $pid)"
        fi
        rm -f "$services_pid_file"
    fi
}

collect_memory_dump() {
    log "Collecting memory dump..."
    
    local memory_dir="$OUTPUT_DIR/memory"
    mkdir -p "$memory_dir"
    
    if "$SCRIPT_DIR/memory_dump.sh" \
        --vm "$VM_NAME" \
        --output "$memory_dir" \
        --format raw \
        --compress; then
        log "${GREEN}Memory dump collected successfully${NC}"
    else
        log "${YELLOW}Memory dump collection failed${NC}"
    fi
}

collect_network_artifacts() {
    log "Collecting network artifacts..."
    
    local network_dir="$OUTPUT_DIR/network"
    mkdir -p "$network_dir"
    
    # Network capture files should already be in the network directory
    # Add any additional network artifact collection here
    
    log "Network artifacts collected in: $network_dir"
}

collect_behavioral_artifacts() {
    log "Collecting behavioral artifacts..."
    
    local behavioral_dir="$OUTPUT_DIR/behavioral"
    mkdir -p "$behavioral_dir"
    
    # Copy monitoring data
    if [[ -d "$OUTPUT_DIR/monitoring" ]]; then
        cp -r "$OUTPUT_DIR/monitoring"/* "$behavioral_dir/" 2>/dev/null || true
    fi
    
    # Process collected data using monitoring modules
    if [[ "$MONITORING_AVAILABLE" == "true" ]]; then
        process_behavioral_data "$behavioral_dir"
    fi
    
    # Collect additional behavioral data from VM
    collect_vm_behavioral_data
}

process_behavioral_data() {
    local behavioral_dir="$1"
    
    # Use procmon_processor if available
    if [[ -f "$MONITORING_MODULE/procmon_processor.py" ]]; then
        log "Processing behavioral data with procmon_processor..."
        python3 -m shikra.core.modules.monitoring.procmon_processor \
            --input-dir "$behavioral_dir" \
            --output-dir "$behavioral_dir/processed" \
            --run-id "$RUN_ID" \
            > "$behavioral_dir/processing.log" 2>&1 || true
    fi
    
    # Use filter_engine if available
    if [[ -f "$MONITORING_MODULE/filter_engine.py" ]]; then
        log "Applying filter engine to behavioral data..."
        python3 -m shikra.core.modules.monitoring.filter_engine \
            --input-dir "$behavioral_dir" \
            --output-dir "$behavioral_dir/filtered" \
            --run-id "$RUN_ID" \
            > "$behavioral_dir/filtering.log" 2>&1 || true
    fi
}

collect_vm_behavioral_data() {
    log "Collecting behavioral data from VM..."
    
    local vm_os=$(get_vm_os_type "$VM_NAME")
    local behavioral_dir="$OUTPUT_DIR/behavioral"
    
    case "$vm_os" in
        windows)
            collect_windows_behavioral_data "$behavioral_dir"
            ;;
        linux)
            collect_linux_behavioral_data "$behavioral_dir"
            ;;
    esac
}

collect_windows_behavioral_data() {
    local output_dir="$1"
    
    if [[ "$VM_CONTROLLER_AVAILABLE" == "true" ]]; then
        # Collect process list
        python3 -m shikra.core.modules.vm_controller --run-in "$VM_NAME" --command "tasklist /v" \
            > "$output_dir/process_list.txt" 2>/dev/null || true
        
        # Collect network connections
        python3 -m shikra.core.modules.vm_controller --run-in "$VM_NAME" --command "netstat -an" \
            > "$output_dir/network_connections.txt" 2>/dev/null || true
        
        # Collect registry changes
        python3 -m shikra.core.modules.vm_controller --run-in "$VM_NAME" --command "reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" \
            > "$output_dir/registry_run_keys.txt" 2>/dev/null || true
    fi
}

collect_linux_behavioral_data() {
    local output_dir="$1"
    
    if [[ "$VM_CONTROLLER_AVAILABLE" == "true" ]]; then
        # Collect process list
        python3 -m shikra.core.modules.vm_controller --run-in "$VM_NAME" --command "ps aux" \
            > "$output_dir/process_list.txt" 2>/dev/null || true
        
        # Collect network connections
        python3 -m shikra.core.modules.vm_controller --run-in "$VM_NAME" --command "netstat -tuln" \
            > "$output_dir/network_connections.txt" 2>/dev/null || true
        
        # Collect file system changes
        python3 -m shikra.core.modules.vm_controller --run-in "$VM_NAME" --command "find /tmp -newer /tmp -ls" \
            > "$output_dir/filesystem_changes.txt" 2>/dev/null || true
    fi
}

collect_vm_artifacts() {
    log "Collecting VM artifacts..."
    
    local vm_dir="$OUTPUT_DIR/vm_artifacts"
    mkdir -p "$vm_dir"
    
    # Copy execution logs
    if [[ -f "$OUTPUT_DIR/sample_execution.log" ]]; then
        cp "$OUTPUT_DIR/sample_execution.log" "$vm_dir/"
    fi
    
    # Collect VM console output if available
    virsh console "$VM_NAME" --force < /dev/null > "$vm_dir/console_output.txt" 2>&1 || true
}

analyze_collected_data() {
    log "${BLUE}Analyzing collected data...${NC}"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "Dry run: would analyze collected data"
        return 0
    fi
    
    local analysis_dir="$OUTPUT_DIR/analysis_results"
    mkdir -p "$analysis_dir"
    
    # Run behavioral analysis
    run_behavioral_analysis
    
    # Run network analysis
    run_network_analysis
    
    # Run memory analysis
    run_memory_analysis
    
    log "${GREEN}Data analysis completed${NC}"
}

run_behavioral_analysis() {
    log "Running behavioral analysis..."
    
    local behavioral_module="$PROJECT_ROOT/analysis/modules/analysis/behavioral.py"
    local behavioral_data="$OUTPUT_DIR/behavioral"
    local analysis_output="$OUTPUT_DIR/analysis_results/behavioral_analysis.json"
    
    if [[ -f "$behavioral_module" && -d "$behavioral_data" ]]; then
        python3 "$behavioral_module" \
            --input-dir "$behavioral_data" \
            --output "$analysis_output" \
            --sample-id "$RUN_ID" \
            > "$OUTPUT_DIR/analysis_results/behavioral_analysis.log" 2>&1 || true
        
        if [[ -f "$analysis_output" ]]; then
            log "Behavioral analysis completed: $analysis_output"
        else
            log "${YELLOW}Behavioral analysis did not produce expected output${NC}"
        fi
    else
        log "${YELLOW}Behavioral analysis module or data not available${NC}"
    fi
}

run_network_analysis() {
    log "Running network analysis..."
    
    local network_module="$PROJECT_ROOT/analysis/modules/analysis/network_analysis.py"
    local network_data="$OUTPUT_DIR/network"
    local analysis_output="$OUTPUT_DIR/analysis_results/network_analysis.json"
    
    # Find PCAP files for analysis
    local pcap_files=$(find "$network_data" -name "*.pcap" 2>/dev/null | head -1)
    
    if [[ -f "$network_module" && -n "$pcap_files" ]]; then
        python3 "$network_module" \
            --pcap "$pcap_files" \
            --output "$analysis_output" \
            --sample-id "$RUN_ID" \
            > "$OUTPUT_DIR/analysis_results/network_analysis.log" 2>&1 || true
        
        if [[ -f "$analysis_output" ]]; then
            log "Network analysis completed: $analysis_output"
        else
            log "${YELLOW}Network analysis did not produce expected output${NC}"
        fi
    else
        log "${YELLOW}Network analysis module or PCAP data not available${NC}"
    fi
}

run_memory_analysis() {
    log "Running memory analysis..."
    
    local memory_module="$PROJECT_ROOT/analysis/modules/analysis/memory_analysis.py"
    local memory_data="$OUTPUT_DIR/memory"
    local analysis_output="$OUTPUT_DIR/analysis_results/memory_analysis.json"
    
    # Find memory dump files
    local memory_dumps=$(find "$memory_data" -name "*.raw*" -o -name "*.dmp*" 2>/dev/null | head -1)
    
    if [[ -f "$memory_module" && -n "$memory_dumps" ]]; then
        python3 "$memory_module" \
            --memory-dump "$memory_dumps" \
            --output "$analysis_output" \
            --sample-id "$RUN_ID" \
            > "$OUTPUT_DIR/analysis_results/memory_analysis.log" 2>&1 || true
        
        if [[ -f "$analysis_output" ]]; then
            log "Memory analysis completed: $analysis_output"
        else
            log "${YELLOW}Memory analysis did not produce expected output${NC}"
        fi
    else
        log "${YELLOW}Memory analysis module or dump data not available${NC}"
    fi
}

generate_comprehensive_report() {
    log "${BLUE}Generating comprehensive analysis report...${NC}"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "Dry run: would generate comprehensive report"
        return 0
    fi
    
    local report_generator="$PROJECT_ROOT/reporting/modules/reporting/report_generator.py"
    local reports_dir="$OUTPUT_DIR/reports"
    
    if [[ -f "$report_generator" ]]; then
        mkdir -p "$reports_dir"
        
        python3 "$report_generator" \
            --run-id "$RUN_ID" \
            --analysis-results-dir "$OUTPUT_DIR/analysis_results" \
            --output-dir "$reports_dir" \
            --sample-path "$SAMPLE_PATH" \
            > "$reports_dir/report_generation.log" 2>&1 || true
        
        log "${GREEN}Comprehensive report generated in: $reports_dir${NC}"
    else
        log "${YELLOW}Report generator not available${NC}"
    fi
}

cleanup_analysis_environment() {
    if [[ "$SKIP_CLEANUP" == "true" ]]; then
        log "${YELLOW}Skipping environment cleanup${NC}"
        return 0
    fi
    
    log "${BLUE}Cleaning up analysis environment...${NC}"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "Dry run: would cleanup analysis environment"
        return 0
    fi
    
    # Stop VM
    cleanup_vm
    
    # Clean up temporary files
    cleanup_temporary_files
    
    log "${GREEN}Analysis environment cleanup completed${NC}"
}

cleanup_vm() {
    log "Cleaning up VM state..."
    
    if [[ "$VM_CONTROLLER_AVAILABLE" != "true" ]]; then
        log "${YELLOW}VM Controller not available for cleanup${NC}"
        return 0
    fi
    
    # Shutdown VM
    local vm_state=$(virsh domstate "$VM_NAME" 2>/dev/null)
    if [[ "$vm_state" == "running" ]]; then
        log "Shutting down VM..."
        virsh shutdown "$VM_NAME"
        sleep 10
        
        # Force shutdown if needed
        vm_state=$(virsh domstate "$VM_NAME" 2>/dev/null)
        if [[ "$vm_state" == "running" ]]; then
            virsh destroy "$VM_NAME"
        fi
    fi
    
    # Revert to clean baseline using vm_controller
    if [[ "$VM_SNAPSHOT_CREATED" == "true" ]]; then
        log "Reverting VM to clean baseline..."
        python3 -m shikra.core.modules.vm_controller --snapshot "$VM_NAME" --restore clean_baseline || true
        
        # Delete analysis snapshot
        local analysis_snapshot="analysis_start_${RUN_ID}"
        python3 -m shikra.core.modules.vm_controller --snapshot "$VM_NAME" --delete "$analysis_snapshot" || true
    fi
}

cleanup_temporary_files() {
    log "Cleaning up temporary files..."
    
    # Remove PID files
    find "$OUTPUT_DIR" -name "*.pid" -delete 2>/dev/null || true
    
    # Clear staging directory
    if [[ "$VM_CONTROLLER_AVAILABLE" == "true" ]]; then
        python3 -m shikra.core.modules.vm_controller --clear-staging || true
    fi
}

generate_analysis_summary() {
    log "${BLUE}Generating analysis summary...${NC}"
    
    local summary_file="$OUTPUT_DIR/analysis_summary.txt"
    local end_time=$(date +%s)
    local total_duration=$((end_time - ANALYSIS_START_TIME))
    
    cat > "$summary_file" << EOF
# Shikra Malware Analysis Summary

## Analysis Information
- Run ID: $RUN_ID
- Sample: $(basename "$SAMPLE_PATH")
- VM: $VM_NAME
- Analysis Profile: $ANALYSIS_PROFILE
- Network: $NETWORK_NAME
- Start Time: $(date -d "@$ANALYSIS_START_TIME" 2>/dev/null || date)
- End Time: $(date)
- Duration: ${total_duration}s

## Module Availability
- VM Controller: $VM_CONTROLLER_AVAILABLE
- Monitoring: $MONITORING_AVAILABLE
- Network: $NETWORK_AVAILABLE
- Stealth: $STEALTH_AVAILABLE

## Analysis Components
- Behavioral Monitoring: $BEHAVIORAL_MONITORING
- Network Capture: $NETWORK_CAPTURE
- Memory Dump: $MEMORY_DUMP
- Stealth Mode: $STEALTH_MODE
- Fake Services: $FAKE_SERVICES
- VM Snapshot Created: $VM_SNAPSHOT_CREATED
- Monitoring Started: $MONITORING_STARTED
- Network Services Started: $NETWORK_SERVICES_STARTED
- Stealth Applied: $STEALTH_APPLIED
- Sample Executed: $SAMPLE_EXECUTED
- Artifacts Collected: $ARTIFACTS_COLLECTED

## Output Directories
- Main Output: $OUTPUT_DIR
- Behavioral Data: $OUTPUT_DIR/behavioral
- Network Data: $OUTPUT_DIR/network
- Memory Data: $OUTPUT_DIR/memory
- Fake Services: $OUTPUT_DIR/fake_services
- Analysis Results: $OUTPUT_DIR/analysis_results
- Reports: $OUTPUT_DIR/reports

## Next Steps
1. Review analysis results in: $OUTPUT_DIR/analysis_results/
2. Check comprehensive reports in: $OUTPUT_DIR/reports/
3. Examine raw artifacts in respective subdirectories
4. Use web interface for detailed analysis review

EOF
    
    log "Analysis summary saved to: $summary_file"
}

# --- Error Handling ---
handle_error() {
    local exit_code=$?
    log "${RED}An error occurred during analysis (exit code: $exit_code)${NC}"
    
    # Attempt cleanup on error
    if [[ "$MONITORING_STARTED" == "true" ]]; then
        stop_monitoring_tools
    fi
    
    if [[ "$NETWORK_SERVICES_STARTED" == "true" ]]; then
        stop_network_services
    fi
    
    if [[ "$SKIP_CLEANUP" != "true" ]]; then
        cleanup_vm
    fi
    
    generate_analysis_summary
    
    exit $exit_code
}

# --- Main Execution ---
main() {
    log "${GREEN}=== Shikra Malware Analysis Started ===${NC}"
    log "Enhanced orchestration with full module integration"
    
    # Set up error handling
    trap handle_error ERR
    
    parse_arguments "$@"
    check_prerequisites
    setup_analysis_environment
    execute_sample
    collect_analysis_artifacts
    analyze_collected_data
    generate_comprehensive_report
    cleanup_analysis_environment
    generate_analysis_summary
    
    log "${GREEN}=== Shikra Malware Analysis Completed ===${NC}"
    log "Results available in: $OUTPUT_DIR"
    log "Summary: $OUTPUT_DIR/analysis_summary.txt"
    log "Reports: $OUTPUT_DIR/reports/"
    
    # Display key findings if available
    display_key_findings
}

display_key_findings() {
    local behavioral_results="$OUTPUT_DIR/analysis_results/behavioral_analysis.json"
    local network_results="$OUTPUT_DIR/analysis_results/network_analysis.json"
    local memory_results="$OUTPUT_DIR/analysis_results/memory_analysis.json"
    
    echo ""
    echo "${BLUE}=== Key Analysis Findings ===${NC}"
    
    # Extract key findings from analysis results
    if [[ -f "$behavioral_results" ]] && command -v jq &>/dev/null; then
        local behavioral_classification=$(jq -r '.classification // "Unknown"' "$behavioral_results" 2>/dev/null)
        local behavioral_score=$(jq -r '.score // "Unknown"' "$behavioral_results" 2>/dev/null)
        echo "Behavioral Analysis: $behavioral_classification (Score: $behavioral_score)"
    fi
    
    if [[ -f "$network_results" ]] && command -v jq &>/dev/null; then
        local network_classification=$(jq -r '.classification // "Unknown"' "$network_results" 2>/dev/null)
        local network_score=$(jq -r '.score // "Unknown"' "$network_results" 2>/dev/null)
        echo "Network Analysis: $network_classification (Score: $network_score)"
    fi
    
    if [[ -f "$memory_results" ]] && command -v jq &>/dev/null; then
        local memory_classification=$(jq -r '.classification // "Unknown"' "$memory_results" 2>/dev/null)
        local memory_score=$(jq -r '.score // "Unknown"' "$memory_results" 2>/dev/null)
        echo "Memory Analysis: $memory_classification (Score: $memory_score)"
    fi
    
    echo ""
    echo "For detailed analysis, check: $OUTPUT_DIR/reports/"
}

main "$@"