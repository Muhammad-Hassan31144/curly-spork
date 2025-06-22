#!/bin/bash
# Shikra Network Setup Script
#
# Purpose:
# This script configures and manages isolated network environments for malware analysis.
# It handles the creation of virtual bridges, configuration of firewall rules for isolation
# and NAT, DNS sinkholing, and starting of network traffic capture.
#
# Version: 1.1
# Last Updated: 2024-05-20

# --- Script Configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# This assumes the script is in a subdirectory like 'scripts/' within the project root.
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
LOG_FILE="$PROJECT_ROOT/logs/network_setup.log"
PCAP_DIR="$PROJECT_ROOT/data/pcap"

# --- Network Defaults ---
DEFAULT_NETWORK_NAME="shikra-isolated"
DEFAULT_SUBNET="192.168.100.0/24"
DEFAULT_GATEWAY="192.168.100.1"
DEFAULT_DNS_SERVER="192.168.100.1"
DEFAULT_DHCP_RANGE="192.168.100.10,192.168.100.100"

# --- Color Codes ---
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

# --- Global Variables ---
NETWORK_NAME="$DEFAULT_NETWORK_NAME"
SUBNET="$DEFAULT_SUBNET"
GATEWAY="$DEFAULT_GATEWAY"
DNS_SERVER="$DEFAULT_DNS_SERVER"
DHCP_RANGE="$DEFAULT_DHCP_RANGE"
CREATE_ISOLATED=false
CLEANUP_NETWORK=false
ENABLE_CAPTURE=false
ENABLE_SINKHOLE=false
ENABLE_FAKE_SERVICES=false
DRY_RUN=false
BRIDGE_NAME=""

# --- Utility Functions ---

log() {
    # Ensures the log directory exists before writing.
    mkdir -p "$(dirname "$LOG_FILE")"
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

show_usage() {
    echo "Usage: $0 [action] [options]"
    echo ""
    echo "Actions:"
    echo "  --create-isolated        Create an isolated analysis network."
    echo "  --cleanup                Remove the network configuration and all related resources."
    echo "  --status                 Show the status of libvirt networks and related processes."
    echo ""
    echo "Options:"
    echo "  --name <name>            Network name (default: $DEFAULT_NETWORK_NAME)."
    echo "  --enable-capture         Enable packet capture on the network bridge."
    echo "  --enable-sinkhole        Enable a DNS sinkhole with a local DHCP/DNS server (dnsmasq)."
    echo "  --enable-fake-services   Start fake HTTP, FTP, and SMTP services on the gateway."
    echo "  --dry-run                Show what would be done without making changes."
    echo "  -h, --help               Show this help message."
}

parse_arguments() {
    if [[ $# -eq 0 ]]; then show_usage; exit 1; fi

    while [[ $# -gt 0 ]]; do
        case $1 in
            --create-isolated) CREATE_ISOLATED=true; shift ;;
            --cleanup) CLEANUP_NETWORK=true; shift ;;
            --status) show_network_status; exit 0 ;;
            --name) NETWORK_NAME="$2"; shift 2 ;;
            --enable-capture) ENABLE_CAPTURE=true; shift ;;
            --enable-sinkhole) ENABLE_SINKHOLE=true; shift ;;
            --enable-fake-services) ENABLE_FAKE_SERVICES=true; shift ;;
            --dry-run) DRY_RUN=true; shift ;;
            -h|--help) show_usage; exit 0 ;;
            *) log "${RED}Unknown parameter: $1${NC}"; show_usage; exit 1 ;;
        esac
    done

    if [[ "$CREATE_ISOLATED" != "true" && "$CLEANUP_NETWORK" != "true" ]]; then
        log "${RED}An action is required (--create-isolated or --cleanup).${NC}"; show_usage; exit 1;
    fi

    # Sanitize network name to create a valid bridge name.
    BRIDGE_NAME="br-$(echo "$NETWORK_NAME" | tr '[:upper:]' '[:lower:]' | tr -d ' ' | cut -c 1-12)"
}

check_prerequisites() {
    log "${BLUE}Checking prerequisites...${NC}"
    if [[ $EUID -ne 0 ]]; then log "${RED}Error: This script must be run as root.${NC}"; exit 1; fi

    local commands=("ip" "iptables" "virsh")
    [[ "$ENABLE_SINKHOLE" == "true" ]] && commands+=("dnsmasq")
    [[ "$ENABLE_CAPTURE" == "true" ]] && commands+=("tcpdump")
    [[ "$ENABLE_FAKE_SERVICES" == "true" ]] && commands+=("nc")

    for cmd in "${commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            log "${RED}Required command not found: '$cmd'. Please install it.${NC}"; exit 1;
        fi
    done
    
    # Specifically check for netcat version that supports persistence.
    if [[ "$ENABLE_FAKE_SERVICES" == "true" ]] && ! nc -h 2>&1 | grep -q -- '-k'; then
        log "${RED}The version of 'nc' (netcat) installed does not support the '-k' (keep-open) flag.${NC}"
        log "${RED}Please install a compatible version, like 'netcat-openbsd'.${NC}"; exit 1;
    fi
    log "${GREEN}Prerequisites check passed.${NC}"
}

# --- Core Network Functions ---

create_isolated_network() {
    log "${BLUE}Creating isolated network: $NETWORK_NAME${NC}"
    if [[ "$DRY_RUN" == "true" ]]; then log "Dry run: would create libvirt network '$NETWORK_NAME'"; return 0; fi

    if virsh net-info "$NETWORK_NAME" &>/dev/null; then
        log "${YELLOW}Network '$NETWORK_NAME' already exists. Skipping creation.${NC}"; return 0;
    fi

    local network_xml="/tmp/${NETWORK_NAME}-network.xml"
    
    # [CRITICAL FIX] Conditionally create DHCP section. If enabling our own sinkhole/DHCP server
    # with dnsmasq, we MUST disable the one in libvirt to avoid conflicts.
    local dhcp_section=""
    if [[ "$ENABLE_SINKHOLE" != "true" ]]; then
        log "Info: Using libvirt's built-in DHCP server."
        dhcp_section="
    <dhcp>
      <range start='$(echo "$DHCP_RANGE" | cut -d, -f1)' end='$(echo "$DHCP_RANGE" | cut -d, -f2)'/>
    </dhcp>"
    else
        log "${YELLOW}DNS Sinkhole enabled. Disabling libvirt's DHCP to avoid conflicts.${NC}"
    fi

    # Use <forward mode='none'/> and manage firewall rules manually for greater control and safety.
    cat > "$network_xml" << EOF
<network>
  <name>$NETWORK_NAME</name>
  <bridge name='$BRIDGE_NAME' stp='on' delay='0'/>
  <forward mode='none'/>
  <ip address='$GATEWAY' netmask='255.255.255.0'>
    $dhcp_section
  </ip>
</network>
EOF
    
    virsh net-define "$network_xml" || { log "${RED}Failed to define network${NC}"; exit 1; }
    virsh net-start "$NETWORK_NAME" || { log "${RED}Failed to start network${NC}"; exit 1; }
    virsh net-autostart "$NETWORK_NAME" || { log "${RED}Failed to set network autostart${NC}"; exit 1; }
    
    rm -f "$network_xml"
    log "${GREEN}Isolated network '$NETWORK_NAME' created on bridge '$BRIDGE_NAME'.${NC}"
}

configure_firewall_rules() {
    log "${BLUE}Configuring firewall rules for $BRIDGE_NAME...${NC}"
    if [[ "$DRY_RUN" == "true" ]]; then log "Dry run: would configure iptables rules."; return 0; fi

    local ext_iface
    ext_iface=$(ip route | grep default | awk '{print $5}')
    if [[ -z "$ext_iface" ]]; then log "${RED}Could not determine external interface. Cannot set up NAT.${NC}"; exit 1; fi
    log "Info: External interface detected as '$ext_iface'. Setting up NAT."

    # Enable NAT for internet access from the guest.
    iptables -A FORWARD -i "$BRIDGE_NAME" -o "$ext_iface" -j ACCEPT
    iptables -A FORWARD -i "$ext_iface" -o "$BRIDGE_NAME" -m state --state RELATED,ESTABLISHED -j ACCEPT
    iptables -t nat -A POSTROUTING -s "$SUBNET" -o "$ext_iface" -j MASQUERADE
    
    # Isolate from other private networks (e.g., your main LAN).
    log "Info: Blocking VM from accessing other local networks (e.g., 192.168.1.0/24)."
    iptables -I FORWARD -i "$BRIDGE_NAME" -d 192.168.0.0/16 ! -d "$SUBNET" -j DROP
    iptables -I FORWARD -i "$BRIDGE_NAME" -d 10.0.0.0/8 -j DROP
    iptables -I FORWARD -i "$BRIDGE_NAME" -d 172.16.0.0/12 -j DROP
    
    log "${GREEN}Firewall rules configured.${NC}"
}

setup_traffic_capture() {
    if [[ "$ENABLE_CAPTURE" != "true" ]]; then return 0; fi
    log "${BLUE}Setting up traffic capture on '$BRIDGE_NAME'...${NC}"
    if [[ "$DRY_RUN" == "true" ]]; then log "Dry run: would start tcpdump."; return 0; fi

    local pcap_file="$PCAP_DIR/$(date +%Y%m%d_%H%M%S)_${NETWORK_NAME}.pcap"
    mkdir -p "$(dirname "$pcap_file")"
    
    nohup tcpdump -i "$BRIDGE_NAME" -w "$pcap_file" -s 0 > /dev/null 2>&1 &
    echo $! > "/tmp/tcpdump_${NETWORK_NAME}.pid"
    log "${GREEN}Traffic capture started. Saving to: $pcap_file${NC}"
}

configure_dns_sinkhole() {
    if [[ "$ENABLE_SINKHOLE" != "true" ]]; then return 0; fi
    log "${BLUE}Configuring DNS sinkhole with dnsmasq...${NC}"
    if [[ "$DRY_RUN" == "true" ]]; then log "Dry run: would start dnsmasq."; return 0; fi

    local dnsmasq_conf="/tmp/dnsmasq-${NETWORK_NAME}.conf"
    cat > "$dnsmasq_conf" << EOF
# Shikra DNS Sinkhole for $NETWORK_NAME
interface=$BRIDGE_NAME
bind-interfaces
listen-address=$GATEWAY
# Provide DHCP leases.
dhcp-range=$(echo "$DHCP_RANGE" | tr ',' ' ')
# Set the gateway and DNS server for DHCP clients.
dhcp-option=option:router,$GATEWAY
dhcp-option=option:dns-server,$GATEWAY
# Redirect ALL other DNS queries to the gateway address.
address=/#/$GATEWAY
log-queries
log-facility=/tmp/dnsmasq-${NETWORK_NAME}.log
EOF
    
    dnsmasq --conf-file="$dnsmasq_conf" --pid-file="/tmp/dnsmasq_${NETWORK_NAME}.pid" || { log "${RED}Failed to start DNS sinkhole${NC}"; exit 1; }
    log "${GREEN}DNS sinkhole/DHCP server started. Queries logged to /tmp/dnsmasq-${NETWORK_NAME}.log${NC}"
}

start_fake_services() {
    if [[ "$ENABLE_FAKE_SERVICES" != "true" ]]; then return 0; fi
    log "${BLUE}Starting fake network services...${NC}"
    if [[ "$DRY_RUN" == "true" ]]; then log "Dry run: would start fake services."; return 0; fi

    # [STABILITY FIX] Use -k flag for persistent netcat listeners.
    log "Starting fake HTTP service on $GATEWAY:80"
    nohup bash -c "while true; do echo -e 'HTTP/1.1 200 OK\r\n\r\nHello Malware' | nc -kl -p 80 -s $GATEWAY; done" &> /dev/null &
    echo $! > "/tmp/fake_http_${NETWORK_NAME}.pid"

    log "Starting fake FTP service on $GATEWAY:21"
    nohup bash -c "while true; do echo '220 Fake FTP Server Ready' | nc -kl -p 21 -s $GATEWAY; done" &> /dev/null &
    echo $! > "/tmp/fake_ftp_${NETWORK_NAME}.pid"

    log "Starting fake SMTP service on $GATEWAY:25"
    nohup bash -c "while true; do echo '220 fake-mail.local ESMTP Service' | nc -kl -p 25 -s $GATEWAY; done" &> /dev/null &
    echo $! > "/tmp/fake_smtp_${NETWORK_NAME}.pid"

    log "${GREEN}Fake services started.${NC}"
}

# --- Cleanup Functions ---

cleanup_network() {
    log "${YELLOW}--- Cleaning up network environment for $NETWORK_NAME ---${NC}"
    if [[ "$DRY_RUN" == "true" ]]; then log "Dry run: would run all cleanup steps."; return 0; fi

    # Order of cleanup is important: processes, firewall, then interfaces.
    cleanup_fake_services
    cleanup_traffic_capture
    cleanup_dns_sinkhole
    cleanup_firewall_rules
    
    if virsh net-info "$NETWORK_NAME" &>/dev/null; then
        log "Destroying and undefining libvirt network '$NETWORK_NAME'..."
        virsh net-destroy "$NETWORK_NAME" 2>/dev/null
        virsh net-undefine "$NETWORK_NAME" 2>/dev/null
        log "Libvirt network '$NETWORK_NAME' removed."
    fi
    log "${GREEN}Network cleanup completed.${NC}"
}

cleanup_firewall_rules() {
    log "Removing firewall rules for $BRIDGE_NAME..."
    # [SAFETY FIX] Safely remove the exact rules we added. Errors are ignored in case a rule was already removed.
    local ext_iface
    ext_iface=$(ip route | grep default | awk '{print $5}')
    if [[ -z "$ext_iface" ]]; then ext_iface="any"; fi # Fallback if external iface is already gone

    iptables -D FORWARD -i "$BRIDGE_NAME" -d 172.16.0.0/12 -j DROP 2>/dev/null
    iptables -D FORWARD -i "$BRIDGE_NAME" -d 10.0.0.0/8 -j DROP 2>/dev/null
    iptables -D FORWARD -i "$BRIDGE_NAME" -d 192.168.0.0/16 ! -d "$SUBNET" -j DROP 2>/dev/null
    iptables -t nat -D POSTROUTING -s "$SUBNET" -o "$ext_iface" -j MASQUERADE 2>/dev/null
    iptables -D FORWARD -i "$ext_iface" -o "$BRIDGE_NAME" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
    iptables -D FORWARD -i "$BRIDGE_NAME" -o "$ext_iface" -j ACCEPT 2>/dev/null
    log "Specific firewall rules removed."
}

cleanup_process_by_pidfile() {
    local process_name=$1
    local pid_file=$2
    if [[ -f "$pid_file" ]]; then
        local pid
        pid=$(cat "$pid_file")
        if kill "$pid" 2>/dev/null; then
            log "Stopped $process_name (PID: $pid)."
        fi
        rm -f "$pid_file"
    fi
}

cleanup_fake_services() {
    log "Stopping fake services..."
    cleanup_process_by_pidfile "Fake HTTP" "/tmp/fake_http_${NETWORK_NAME}.pid"
    cleanup_process_by_pidfile "Fake FTP" "/tmp/fake_ftp_${NETWORK_NAME}.pid"
    cleanup_process_by_pidfile "Fake SMTP" "/tmp/fake_smtp_${NETWORK_NAME}.pid"
}

cleanup_traffic_capture() {
    log "Stopping traffic capture..."
    cleanup_process_by_pidfile "tcpdump" "/tmp/tcpdump_${NETWORK_NAME}.pid"
}

cleanup_dns_sinkhole() {
    log "Stopping DNS sinkhole..."
    cleanup_process_by_pidfile "dnsmasq" "/tmp/dnsmasq_${NETWORK_NAME}.pid"
    rm -f "/tmp/dnsmasq-${NETWORK_NAME}".{conf,log} 2>/dev/null
}

# --- Main Execution ---

main() {
    # [SAFETY FIX] Trap interrupts and errors to ensure cleanup is always attempted.
    trap 'log "${RED}\nScript interrupted. Running cleanup...${NC}"; cleanup_network; exit 1' SIGINT SIGTERM ERR

    parse_arguments "$@"
    
    if [[ "$CREATE_ISOLATED" == "true" ]]; then
        log "${GREEN}--- Starting Network Setup for '$NETWORK_NAME' ---${NC}"
        check_prerequisites
        create_isolated_network
        configure_firewall_rules
        setup_traffic_capture
        configure_dns_sinkhole
        start_fake_services
        log "${GREEN}--- Network Setup Completed Successfully ---${NC}"
        echo -e "\n${CYAN}Network '$NETWORK_NAME' is active on bridge '$BRIDGE_NAME'.${NC}"
        echo "VMs can now be attached to this network (e.g., using '--network network=$NETWORK_NAME' in virt-install)."
        
    elif [[ "$CLEANUP_NETWORK" == "true" ]]; then
        cleanup_network
    fi
    
    # Remove the trap on a normal, successful exit.
    trap - SIGINT SIGTERM ERR
}

main "$@"
