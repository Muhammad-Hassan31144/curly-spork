#!/bin/bash
# Shikra Environment Setup Script
#
# Purpose:
# This script performs the initial one-time setup of the Shikra analysis environment.
# It prepares the host system with all necessary dependencies, virtualization software,
# and security configurations required for safe malware analysis.
#
# Usage:
#     sudo ./setup_environment.sh [options]
#
# Options:
#     --skip-virtualization    Skip virtualization setup
#     --skip-network          Skip network configuration
#     --minimal               Install core components + VM/network tools (no heavy analysis tools)
#     --force                 Force reinstallation of components
#     --dry-run               Show what would be done without executing
#     --help                  Show this help message

# --- Script Configuration and Global Variables ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")" 
LOG_FILE="$PROJECT_ROOT/logs/setup.log"
SETUP_CONFIG_FILE="$PROJECT_ROOT/.setup_state"

# System requirements
REQUIRED_RAM_KB=8388608   # 8GB minimum (16GB recommended)
REQUIRED_DISK_GB=50       # 50GB minimum free space
PYTHON_MIN_VERSION="3.8"

# Setup flags
SKIP_VIRTUALIZATION=false
SKIP_NETWORK=false
MINIMAL_INSTALL=false
DRY_RUN=false
FORCE_REINSTALL=false

# Color codes for enhanced output formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# --- Logging and Utility Functions ---

setup_logging() {
    mkdir -p "$(dirname "$LOG_FILE")"
    if [[ -n "$SUDO_USER" ]]; then
        chown -R "$SUDO_USER:$SUDO_USER" "$(dirname "$LOG_FILE")"
    fi
}

log() {
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

show_usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  --skip-virtualization    Skip QEMU/KVM installation"
    echo "  --skip-network           Skip network configuration"
    echo "  --minimal                Install core components + VM/network tools (recommended)"
    echo "  --force                  Force reinstallation of components"
    echo "  --dry-run                Show what would be done without executing"
    echo "  --help                   Show this help message"
    echo ""
    echo "Installation Types:"
    echo "  --minimal                Core + VM setup + network tools + web libraries"
    echo "  (full install)           Everything + heavy analysis tools (Wireshark, Volatility, etc.)"
    echo ""
    echo "Examples:"
    echo "  sudo $0 --minimal            # Recommended: Core + VM/network setup"
    echo "  sudo $0                      # Full: Adds heavy analysis tools"
    echo "  sudo $0 --skip-virtualization  # Skip VM setup"
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --skip-virtualization) SKIP_VIRTUALIZATION=true; shift ;;
            --skip-network) SKIP_NETWORK=true; shift ;;
            --minimal) MINIMAL_INSTALL=true; shift ;;
            --force) FORCE_REINSTALL=true; shift ;;
            --dry-run) DRY_RUN=true; shift ;;
            --help|-h) show_usage; exit 0 ;;
            *)
                log "${RED}Unknown parameter: $1${NC}"
                show_usage; exit 1 ;;
        esac
    done
    
    log "Setup Configuration:"
    log "  - Skip Virtualization: $SKIP_VIRTUALIZATION"
    log "  - Skip Network: $SKIP_NETWORK"
    log "  - Minimal Install: $MINIMAL_INSTALL"
    log "  - Force Reinstall: $FORCE_REINSTALL"
    log "  - Dry Run: $DRY_RUN"
}

save_setup_state() {
    local component="$1"
    local status="$2"
    
    mkdir -p "$(dirname "$SETUP_CONFIG_FILE")"
    sed -i "/^${component}=/d" "$SETUP_CONFIG_FILE" 2>/dev/null || true
    echo "${component}=${status}" >> "$SETUP_CONFIG_FILE"
}

check_setup_state() {
    local component="$1"
    
    if [[ -f "$SETUP_CONFIG_FILE" ]]; then
        grep -q "^${component}=completed" "$SETUP_CONFIG_FILE"
        return $?
    fi
    return 1
}

# --- System Requirements and Pre-flight Checks ---
check_requirements() {
    log "${BLUE}Phase 1: Checking system requirements...${NC}"
    local all_ok=true
    local warnings=0

    # Check for root privileges
    if [[ $EUID -ne 0 ]]; then
        log "${RED}Error: This script must be run as root (use sudo).${NC}"
        all_ok=false
    fi

    # Check OS
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        log "Operating System: $PRETTY_NAME"
        if [[ "$ID" != "ubuntu" && "$ID" != "debian" ]]; then
            log "${YELLOW}Warning: Untested OS ($ID). Ubuntu/Debian is recommended.${NC}"
            warnings=$((warnings + 1))
        fi
    else
        log "${RED}Error: Cannot determine operating system.${NC}"
        all_ok=false
    fi

    # Check CPU virtualization
    if ! grep -q -E "vmx|svm" /proc/cpuinfo; then
        if [[ "$SKIP_VIRTUALIZATION" != "true" ]]; then
            log "${RED}Error: CPU virtualization (VT-x/AMD-V) not detected or not enabled in BIOS/UEFI.${NC}"
            all_ok=false
        else
            log "${YELLOW}Warning: No CPU virtualization detected, but skipping related setup.${NC}"
        fi
    else
        log "${GREEN}CPU virtualization support detected.${NC}"
    fi

    # Check RAM and Disk
    local total_mem_gb=$(( $(grep MemTotal /proc/meminfo | awk '{print $2}') / 1024 / 1024 ))
    if (( total_mem_gb < (REQUIRED_RAM_KB / 1024 / 1024) )); then
        log "${YELLOW}Warning: Only ${total_mem_gb}GB RAM detected. 8GB is the minimum, 16GB is recommended.${NC}"
        warnings=$((warnings + 1))
    else
        log "${GREEN}Sufficient RAM available: ${total_mem_gb}GB.${NC}"
    fi

    local available_space_gb=$(df -BG "$PROJECT_ROOT" | awk 'NR==2 {print int($4)}')
    if (( available_space_gb < REQUIRED_DISK_GB )); then
        log "${RED}Error: Insufficient disk space. Need ${REQUIRED_DISK_GB}GB, but only ${available_space_gb}GB is available.${NC}"
        all_ok=false
    else
        log "${GREEN}Sufficient disk space available: ${available_space_gb}GB.${NC}"
    fi
    
    if [[ "$all_ok" == "true" ]]; then
        log "${GREEN}System requirements check passed.${NC}"
        return 0
    else
        log "${RED}System requirements check failed. Please resolve the errors above.${NC}"
        return 1
    fi
}

# --- Installation & Setup Functions ---

create_data_directories() {
    if check_setup_state "data_directories" && [[ "$FORCE_REINSTALL" != "true" ]]; then
        log "${GREEN}Data directories already exist, skipping.${NC}"
        return 0
    fi
    log "${BLUE}Creating data directory structure...${NC}"
    
    local directories=(
        "data/samples/quarantine"
        "data/vm_images"
        "data/memory_dumps"
        "data/pcap"
        "data/results/behavioral"
        "data/results/network"
        "data/results/memory"
        "data/results/reports"
        "data/yara_rules"
        "logs/analysis"
        "tools/sysinternals"
        "tools/procmon"
        "config/vm_profiles"
        "config/inetsim"
        "config/procmon"
    )
    
    for dir in "${directories[@]}"; do
        mkdir -p "$PROJECT_ROOT/$dir"
    done
    
    log "${GREEN}Data directories created.${NC}"
    save_setup_state "data_directories" "completed"
}

install_system_packages() {
    if check_setup_state "system_packages" && [[ "$FORCE_REINSTALL" != "true" ]]; then
        log "${GREEN}System packages already installed, skipping.${NC}"
        return 0
    fi

    log "${BLUE}Installing system packages...${NC}"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "Dry run: would install system packages"
        return 0
    fi

    # Update package lists
    log "Updating package lists..."
    apt-get update

    # CORE PACKAGES - Always installed (minimal and full)
    local core_packages=(
        "python3"
        "python3-pip"
        "python3-venv"
        "python3-dev"
        "git"
        "curl"
        "wget"
        "unzip"
        "build-essential"
        "jq"
        "ca-certificates"
        "gnupg"
        "lsb-release"
    )

    # VM AND NETWORK PACKAGES - Installed with minimal (core infrastructure)
    local vm_network_packages=(
        "qemu-kvm"
        "libvirt-daemon-system"
        "libvirt-clients"
        "bridge-utils"
        "virt-manager"
        "ovmf"
        "qemu-utils"
        "iptables"
        "iptables-persistent"
        "net-tools"
        "iproute2"
        "dnsutils"
        "netcat-openbsd"
        "nmap"
        "tcpdump"
        "dnsmasq"
        "nginx"
    )

    # HEAVY ANALYSIS PACKAGES - Only installed with full installation
    local analysis_packages=(
        "wireshark"
        "tshark"
        "volatility3"
        "binwalk"
        "hexdump"
        "file"
        "strace"
        "ltrace"
        "gdb"
        "radare2"
        "yara"
        "clamav"
        "clamav-daemon"
    )

    # Install core packages (always)
    log "Installing core packages..."
    for package in "${core_packages[@]}"; do
        log "Installing: $package"
        apt-get install -y "$package" || log "${YELLOW}Warning: Failed to install $package${NC}"
    done

    # Install VM/network packages (minimal and full)
    log "Installing VM and network packages..."
    for package in "${vm_network_packages[@]}"; do
        log "Installing: $package"
        apt-get install -y "$package" || log "${YELLOW}Warning: Failed to install $package${NC}"
    done

    # Install heavy analysis packages (full only)
    if [[ "$MINIMAL_INSTALL" != "true" ]]; then
        log "Installing heavy analysis packages (full installation)..."
        for package in "${analysis_packages[@]}"; do
            log "Installing: $package"
            apt-get install -y "$package" || log "${YELLOW}Warning: Failed to install $package${NC}"
        done
    else
        log "${YELLOW}Skipping heavy analysis packages (minimal installation)${NC}"
    fi

    log "${GREEN}System packages installation completed.${NC}"
    save_setup_state "system_packages" "completed"
}

create_virtual_environment() {
    if check_setup_state "virtual_environment" && [[ "$FORCE_REINSTALL" != "true" ]]; then
        log "${GREEN}Virtual environment already exists, skipping.${NC}"
        return 0
    fi

    log "${BLUE}Setting up Python virtual environment...${NC}"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "Dry run: would create virtual environment"
        return 0
    fi
    
    cd "$PROJECT_ROOT" || {
        log "${RED}Error: Cannot navigate to project root: $PROJECT_ROOT${NC}"
        return 1
    }
    
    # Remove existing venv if force reinstall
    if [[ "$FORCE_REINSTALL" == "true" && -d "venv" ]]; then
        log "Removing existing virtual environment..."
        rm -rf venv
    fi
    
    # Create virtual environment
    python3 -m venv venv
    
    # Upgrade pip
    "$PROJECT_ROOT/venv/bin/pip" install --upgrade pip wheel

    # CORE PYTHON PACKAGES - Always installed (minimal and full)
    local core_python_packages=(
        "requests"
        "urllib3"
        "psutil"
        "jinja2"
        "pyyaml"
        "click"
        "paramiko"
        "pywinrm"
        "flask"
        "fastapi"
        "uvicorn"
        "websockets"
        "aiohttp"
        "httpx"
    )

    # WEB AND NETWORK PYTHON PACKAGES - Installed with minimal
    local web_network_python_packages=(
        "scapy"
        "dpkt"
        "netaddr"
        "dnspython"
        "netifaces"
        "python-nmap"
    )

    # ANALYSIS PYTHON PACKAGES - Only installed with full installation
    local analysis_python_packages=(
        "volatility3"
        "yara-python"
        "pefile"
        "python-magic"
        "pyshark"
        "pandas"
        "numpy"
        "matplotlib"
        "seaborn"
        "networkx"
        "plotly"
        "jupyter"
        "capstone"
        "keystone-engine"
        "unicorn"
    )

    # Install core Python packages (always)
    log "Installing core Python packages..."
    for package in "${core_python_packages[@]}"; do
        log "Installing: $package"
        "$PROJECT_ROOT/venv/bin/pip" install "$package" || log "${YELLOW}Warning: Failed to install $package${NC}"
    done

    # Install web/network Python packages (minimal and full)
    log "Installing web and network Python packages..."
    for package in "${web_network_python_packages[@]}"; do
        log "Installing: $package"
        "$PROJECT_ROOT/venv/bin/pip" install "$package" || log "${YELLOW}Warning: Failed to install $package${NC}"
    done

    # Install analysis Python packages (full only)
    if [[ "$MINIMAL_INSTALL" != "true" ]]; then
        log "Installing analysis Python packages (full installation)..."
        for package in "${analysis_python_packages[@]}"; do
            log "Installing: $package"
            "$PROJECT_ROOT/venv/bin/pip" install "$package" || log "${YELLOW}Warning: Failed to install $package${NC}"
        done
    else
        log "${YELLOW}Skipping heavy analysis Python packages (minimal installation)${NC}"
    fi
    
    # Set proper ownership
    if [[ -n "$SUDO_USER" ]]; then
        chown -R "$SUDO_USER:$SUDO_USER" "$PROJECT_ROOT/venv/"
        log "Set ownership of virtual environment to $SUDO_USER"
    fi
    
    log "${GREEN}Virtual environment created successfully.${NC}"
    save_setup_state "virtual_environment" "completed"
}

setup_virtualization() {
    if [[ "$SKIP_VIRTUALIZATION" == "true" ]]; then
        log "${YELLOW}Skipping virtualization setup as requested.${NC}"
        return 0
    fi
    if check_setup_state "virtualization" && [[ "$FORCE_REINSTALL" != "true" ]]; then
        log "${GREEN}Virtualization seems to be already set up, skipping.${NC}"
        return 0
    fi
    log "${BLUE}Setting up QEMU/KVM and Libvirt...${NC}"

    if [[ "$DRY_RUN" == "true" ]]; then
        log "Dry run: Would configure QEMU/KVM and libvirt."
        return 0
    fi

    # Start and enable the service
    systemctl enable --now libvirtd
    
    # Add user to relevant groups for passwordless management
    if [[ -n "$SUDO_USER" ]]; then
        usermod -aG libvirt "$SUDO_USER"
        usermod -aG kvm "$SUDO_USER"
        log "Added user '$SUDO_USER' to 'libvirt' and 'kvm' groups. A re-login is required for this to take effect."
    fi
    
    log "${GREEN}Virtualization setup complete.${NC}"
    save_setup_state "virtualization" "completed"
}

configure_network() {
    if [[ "$SKIP_NETWORK" == "true" ]]; then
        log "${YELLOW}Skipping network configuration as requested.${NC}"
        return 0
    fi
    if check_setup_state "network" && [[ "$FORCE_REINSTALL" != "true" ]]; then
        log "${GREEN}Network already configured, skipping.${NC}"
        return 0
    fi
    log "${BLUE}Configuring default libvirt network...${NC}"

    if [[ "$DRY_RUN" == "true" ]]; then
        log "Dry run: Would ensure the default libvirt network is active."
        return 0
    fi
    
    # Check if default network exists
    if ! virsh net-list --all | grep -q "default"; then
        log "Default network not found. Trying to create it."
        if [[ -f /usr/share/libvirt/networks/default.xml ]]; then
             virsh net-define /usr/share/libvirt/networks/default.xml
        else
            log "${RED}Could not find a default network definition file.${NC}"
            return 1
        fi
    fi
    
    # Ensure it's active and set to autostart
    if ! virsh net-info default >/dev/null 2>&1; then
        log "${RED}The 'default' libvirt network does not exist or is not defined.${NC}"
        return 1
    fi

    virsh net-autostart default
    if ! virsh net-list --inactive | grep -q "default"; then
        log "Default network is already active."
    else
        virsh net-start default
    fi
    
    log "${GREEN}Default libvirt network is active.${NC}"
    save_setup_state "network" "completed"
}

install_analysis_tools() {
    if [[ "$MINIMAL_INSTALL" == "true" ]]; then
        log "${YELLOW}Skipping external analysis tools installation (minimal mode).${NC}"
        return 0
    fi
    if check_setup_state "analysis_tools" && [[ "$FORCE_REINSTALL" != "true" ]]; then
        log "${GREEN}Analysis tools already installed, skipping.${NC}"
        return 0
    fi
    log "${BLUE}Installing external analysis tools (full installation only)...${NC}"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "Dry run: Would download Sysinternals tools, ProcMon, and YARA rules."
        return 0
    fi

    install_sysinternals_tools
    install_procmon_tools
    install_yara_rules
    
    log "${GREEN}Analysis tools installed.${NC}"
    save_setup_state "analysis_tools" "completed"
}

install_sysinternals_tools() {
    log "Downloading Sysinternals tools..."
    local sysinternals_dir="$PROJECT_ROOT/tools/sysinternals"
    
    local tools=(
        "https://live.sysinternals.com/procexp.exe"
        "https://live.sysinternals.com/autoruns.exe"
        "https://live.sysinternals.com/tcpview.exe"
        "https://live.sysinternals.com/strings.exe"
        "https://live.sysinternals.com/handle.exe"
    )
    
    for tool_url in "${tools[@]}"; do
        local tool_name=$(basename "$tool_url")
        if ! wget -q "$tool_url" -O "$sysinternals_dir/$tool_name"; then
            log "${YELLOW}Warning: Failed to download $tool_name${NC}"
        fi
    done
}

install_procmon_tools() {
    log "Downloading ProcMon..."
    local procmon_dir="$PROJECT_ROOT/tools/procmon"
    
    local tools=(
        "https://live.sysinternals.com/procmon.exe"
        "https://live.sysinternals.com/procmon64.exe"
    )
    
    for tool_url in "${tools[@]}"; do
        local tool_name=$(basename "$tool_url")
        if ! wget -q "$tool_url" -O "$procmon_dir/$tool_name"; then
            log "${YELLOW}Warning: Failed to download $tool_name${NC}"
        fi
    done
}

install_yara_rules() {
    log "Cloning common YARA rules..."
    local yara_dir="$PROJECT_ROOT/data/yara_rules"
    
    git clone --depth 1 https://github.com/Yara-Rules/rules.git "$yara_dir/Yara-Rules-rules" || log "${YELLOW}Warning: Failed to clone YARA rules${NC}"
    git clone --depth 1 https://github.com/reversinglabs/reversinglabs-yara-rules.git "$yara_dir/reversinglabs-yara-rules" || log "${YELLOW}Warning: Failed to clone ReversingLabs YARA rules${NC}"
}

create_default_configs() {
    if check_setup_state "default_configs" && [[ "$FORCE_REINSTALL" != "true" ]]; then
        log "${GREEN}Default configs already exist, skipping.${NC}"
        return 0
    fi
    log "${BLUE}Creating default configuration files...${NC}"
    
    # Create a default VM profile
    cat > "$PROJECT_ROOT/config/vm_profiles/win10_default.json" << EOF
{
  "name": "win10_default",
  "description": "Default Windows 10 analysis environment",
  "vm_config": {
    "os_type": "windows",
    "memory_mb": 4096,
    "vcpus": 2,
    "disk_size_gb": 60,
    "network": "default"
  },
  "analysis_tools": ["procmon", "procexp", "autoruns"]
}
EOF

    # Create basic INetSim config
    cat > "$PROJECT_ROOT/config/inetsim/inetsim.conf" << EOF
# Basic INetSim configuration for Shikra
service_bind_address    192.168.122.1
dns_bind_port           53
dns_default_ip          192.168.122.1
http_bind_port          80
https_bind_port         443
EOF

    log "Created default configuration files"
    save_setup_state "default_configs" "completed"
}

configure_permissions() {
    log "${BLUE}Finalizing directory permissions and ownership...${NC}"

    if [[ "$DRY_RUN" == "true" ]]; then
        log "Dry run: Would set final permissions and ownership."
        return 0
    fi
    
    # Set restrictive permissions on samples directory
    chmod 700 "$PROJECT_ROOT/data/samples"
    
    # Make core scripts executable (if they exist)
    if [[ -d "$PROJECT_ROOT/core/scripts" ]]; then
        find "$PROJECT_ROOT/core/scripts" -name "*.sh" -exec chmod +x {} \;
    fi
    
    # Set ownership for the entire project to the user who ran sudo
    if [[ -n "$SUDO_USER" ]]; then
        chown -R "$SUDO_USER:$SUDO_USER" "$PROJECT_ROOT"
        log "Set ownership of project root to '$SUDO_USER'."
    fi
    
    log "${GREEN}Permissions configured successfully.${NC}"
    save_setup_state "permissions" "completed"
}

# --- Main Execution ---
main() {
    setup_logging
    log "${GREEN}======================================${NC}"
    log "${GREEN}  Starting Shikra Environment Setup   ${NC}"
    log "${GREEN}======================================${NC}"
    log "Project Root: $PROJECT_ROOT"
    log "Log File:     $LOG_FILE"
    
    parse_arguments "$@"
    
    # Execute setup steps
    check_requirements
    create_data_directories
    install_system_packages
    create_virtual_environment
    setup_virtualization
    configure_network
    install_analysis_tools
    create_default_configs
    configure_permissions

    log "${GREEN}========================================${NC}"
    log "${GREEN}  Shikra Environment Setup Completed!   ${NC}"
    log "${GREEN}========================================${NC}"
    
    echo -e "\n${CYAN}🎉 Shikra Malware Analysis Framework is ready!${NC}\n"
    
    if [[ "$MINIMAL_INSTALL" == "true" ]]; then
        echo -e "${BLUE}Minimal Installation Complete:${NC}"
        echo -e "✅ Core system + Python environment"
        echo -e "✅ VM setup (QEMU/KVM + libvirt)"
        echo -e "✅ Network tools and web libraries"
        echo -e "✅ Basic analysis infrastructure"
        echo -e ""
        echo -e "${YELLOW}For heavy analysis tools, run: sudo $0 (without --minimal)${NC}"
    else
        echo -e "${BLUE}Full Installation Complete:${NC}"
        echo -e "✅ Everything from minimal install"
        echo -e "✅ Heavy analysis tools (Wireshark, Volatility, etc.)"
        echo -e "✅ External tools (Sysinternals, YARA rules)"
        echo -e "✅ Advanced Python analysis libraries"
    fi
    
    echo -e "\n${BLUE}Next Steps:${NC}"
    echo -e "1. ${YELLOW}IMPORTANT: Log out and log back in${NC} for group changes (libvirt, kvm) to take effect."
    echo -e "2. Activate the environment: ${GREEN}source venv/bin/activate${NC}"
    echo -e "3. Create an analysis VM using virt-manager or scripts."
    echo -e "4. Run your analysis."
    echo -e "\nFor details, check the log: ${GREEN}$LOG_FILE${NC}\n"
}

# --- Script Entry Point ---
trap 'log "${RED}An error occurred. Setup failed. Check log for details.${NC}"; exit 1' ERR
main "$@"