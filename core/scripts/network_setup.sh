#!/usr/bin/env bash
# -----------------------------------------------------------------------------
#  Shikra Network Setup Script (merged, feature‑complete)
# -----------------------------------------------------------------------------
#  Purpose : Build, run, tweak and tear‑down **isolated** libvirt networks for
#            malware analysis labs ­— with optional DNS sinkhole, INetSim fake
#            Internet, packet capture, NAT on‑demand, IPv6 kill‑switch and
#            persistent firewall rules.
#  Version : 2.0
#  Author  : Muhammad Hassan (@31144)
#  Updated : 2025‑06‑23
# -----------------------------------------------------------------------------
#  Quick usage
#     sudo ./shikra_network_setup.sh --create-isolated \
#          --enable-sinkhole --enable-inetsim --enable-capture --block-ipv6
#
#     # allow the VM to fetch Windows updates *temporarily*
#     sudo ./shikra_network_setup.sh --enable-nat
#
#     # cleanup everything
#     sudo ./shikra_network_setup.sh --cleanup
# -----------------------------------------------------------------------------

set -euo pipefail

# --- Path scaffolding ---------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
LOG_FILE="$PROJECT_ROOT/logs/network_setup.log"
PCAP_DIR="$PROJECT_ROOT/data/pcap"
mkdir -p "$(dirname "$LOG_FILE")" "$PCAP_DIR"

# --- Network defaults ---------------------------------------------------------
DEFAULT_NETWORK_NAME="shikra-isolated"
DEFAULT_SUBNET="192.168.100.0/24"
DEFAULT_GATEWAY="192.168.100.1"
DEFAULT_DNS_SERVER="192.168.100.1"
DEFAULT_DHCP_RANGE="192.168.100.10,192.168.100.100"

# --- Colour escape codes ------------------------------------------------------
RED='\033[0;31m' ; GREEN='\033[0;32m' ; YELLOW='\033[1;33m' ; \
BLUE='\033[0;34m' ; CYAN='\033[0;36m' ; NC='\033[0m'

# --- Global option flags ------------------------------------------------------
NETWORK_NAME="$DEFAULT_NETWORK_NAME"
SUBNET="$DEFAULT_SUBNET"
GATEWAY="$DEFAULT_GATEWAY"
DNS_SERVER="$DEFAULT_DNS_SERVER"
DHCP_RANGE="$DEFAULT_DHCP_RANGE"

CREATE_ISOLATED=false   # --create-isolated
CLEANUP_NETWORK=false   # --cleanup
ENABLE_CAPTURE=false    # --enable-capture
ENABLE_SINKHOLE=false   # --enable-sinkhole (dnsmasq)
ENABLE_FAKE_SERVICES=false # --enable-fake-services (netcat stubs)
ENABLE_INETSIM=false    # --enable-inetsim (supersedes fake services)
ENABLE_NAT=false        # --enable-nat (insert/remove NAT rules)
BLOCK_IPV6=false        # --block-ipv6 (add ip6tables kills)
PERSIST_RULES=false     # --persist (save iptables to /etc)
ACTION_STATUS=false     # --status
DISABLE_NAT=false       # --disable-nat
DRY_RUN=false           # --dry-run
BRIDGE_NAME=""          # computed from network name

# --- Logging helpers ----------------------------------------------------------
log() {
  local ts msg
  ts="$(date '+%Y-%m-%d %H:%M:%S')"
  msg="$1"
  echo -e "${ts} - ${msg}" | tee -a "$LOG_FILE"
}

fatal() { log "${RED}ERROR:${NC} $1" ; exit 1 ; }

# --- Usage --------------------------------------------------------------------
show_usage() {
  cat << EOF
Usage: $0 [ACTION] [OPTIONS]

 Actions
   --create-isolated        Build & start a new isolated libvirt network
   --cleanup                Tear down the network & all helpers
   --status                 Show status of networks / helpers
   --enable-nat             Toggle NAT *on* (if already created)
   --disable-nat            Toggle NAT *off*

 Options (can be mixed with --create-isolated)
   --name <name>            Network name            (default: $DEFAULT_NETWORK_NAME)
   --enable-capture         Start tcpdump on bridge and save .pcap
   --enable-sinkhole        Start dnsmasq DHCP+DNS sinkhole (binds on gateway)
   --enable-fake-services   Start basic HTTP/FTP/SMTP stubs with netcat
   --enable-inetsim         Start INetSim full fake Internet (implies sinkhole)
   --block-ipv6             Add ip6tables drops + disable bridge IPv6
   --persist                iptables-save / ip6tables-save to /etc (on create)
   --dry-run                Print steps without executing
   -h | --help              Show this help
EOF
}

# --- CLI ----------------------------------------------------------------------
parse_arguments() {
  [[ $# -eq 0 ]] && { show_usage ; exit 1 ; }

  while [[ $# -gt 0 ]]; do
    case $1 in
      --create-isolated) CREATE_ISOLATED=true ;;
      --cleanup)         CLEANUP_NETWORK=true  ;;
      --status)          ACTION_STATUS=true    ;;
      --enable-nat)      ENABLE_NAT=true       ;;
      --disable-nat)     DISABLE_NAT=true      ;;
      --name)            NETWORK_NAME="$2" ; shift ;;
      --enable-capture)  ENABLE_CAPTURE=true   ;;
      --enable-sinkhole) ENABLE_SINKHOLE=true  ;;
      --enable-fake-services) ENABLE_FAKE_SERVICES=true ;;
      --enable-inetsim) ENABLE_INETSIM=true ; ENABLE_SINKHOLE=true ;;
      --block-ipv6)      BLOCK_IPV6=true       ;;
      --persist)         PERSIST_RULES=true    ;;
      --dry-run)         DRY_RUN=true          ;;
      -h|--help)         show_usage ; exit 0   ;;
      *) fatal "Unknown parameter: $1" ;;
    esac
    shift
  done

  # derive bridge name (≤15 chars for Linux)
  BRIDGE_NAME="br-$(echo "$NETWORK_NAME" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9' | cut -c 1-12)"

  # guard: choose one main action
  local main_flags=0
  [[ $CREATE_ISOLATED == true ]] && ((main_flags++))
  [[ $CLEANUP_NETWORK  == true ]] && ((main_flags++))
  [[ $ACTION_STATUS    == true ]] && ((main_flags++))
  [[ $ENABLE_NAT       == true ]] && ((main_flags++))
  [[ $DISABLE_NAT      == true ]] && ((main_flags++))
  (( main_flags == 0 )) && fatal "You must specify an action (e.g. --create-isolated)"
  (( main_flags > 1 ))  && fatal "Choose *one* primary action at a time"
}

# --- Prerequisites ------------------------------------------------------------
check_prerequisites() {
  log "${BLUE}Checking prerequisites...${NC}"
  [[ $EUID -ne 0 ]] && fatal "Script must be run as root"

  local cmds=(ip iptables virsh)
  [[ $ENABLE_SINKHOLE == true ]] && cmds+=(dnsmasq)
  [[ $ENABLE_CAPTURE == true ]] && cmds+=(tcpdump)
  [[ $ENABLE_FAKE_SERVICES == true ]] && cmds+=(nc)
  [[ $ENABLE_INETSIM == true ]] && cmds+=(inetsim)

  for c in "${cmds[@]}"; do command -v "$c" &>/dev/null || fatal "Required command '$c' not found"; done

  if [[ $ENABLE_FAKE_SERVICES == true ]] && ! nc -h 2>&1 | grep -q -- '-k'; then
    fatal "'nc' build lacks -k (persistent) flag. Install netcat‑openbsd"
  fi
  log "${GREEN}Prerequisites OK${NC}"
}

# --- Libvirt network management ----------------------------------------------
create_isolated_network() {
  log "${BLUE}Creating libvirt network '$NETWORK_NAME'...${NC}"
  $DRY_RUN && { log "[dry‑run] Would define network"; return; }

  if virsh net-info "$NETWORK_NAME" &>/dev/null; then
    log "${YELLOW}Network exists, skipping define${NC}"
    return
  fi

  local xml="/tmp/${NETWORK_NAME}.xml"
  local dhcp=""
  if [[ $ENABLE_SINKHOLE == false ]]; then
    dhcp="\n    <dhcp>\n      <range start='${DHCP_RANGE%%,*}' end='${DHCP_RANGE##*,}'/>\n    </dhcp>"
  fi

  cat > "$xml" <<-XML
<network>
  <name>$NETWORK_NAME</name>
  <bridge name='$BRIDGE_NAME' stp='on' delay='0'/>
  <forward mode='none'/>
  <ip address='$GATEWAY' netmask='255.255.255.0'>$dhcp
  </ip>
</network>
XML

  virsh net-define "$xml" && virsh net-start "$NETWORK_NAME" && virsh net-autostart "$NETWORK_NAME"
  rm -f "$xml"
  log "${GREEN}Libvirt network up on bridge '$BRIDGE_NAME'${NC}"
}

# --- Firewall rules -----------------------------------------------------------
EXT_IFACE() { ip route | awk '/default/ {print $5; exit}'; }

configure_firewall_rules() {
  log "${BLUE}Applying firewall rules (bridge $BRIDGE_NAME)...${NC}"
  $DRY_RUN && { log "[dry‑run] Would install iptables"; return; }

  local ext="$(EXT_IFACE)"; [[ -z $ext ]] && fatal "Cannot detect outbound interface"

  # cleanliness: remove stale rules first
  cleanup_firewall_rules silent

  # Intra‑subnet allow
  iptables -I FORWARD 1 -i "$BRIDGE_NAME" -d "$SUBNET"      -j ACCEPT
  iptables -I FORWARD 1 -o "$BRIDGE_NAME" -s "$SUBNET"      -j ACCEPT
  iptables -I FORWARD 1 -i "$BRIDGE_NAME" -j LOG --log-prefix "SHIKRA-BLOCKED: "

  if [[ $ENABLE_NAT == true ]]; then
    log " NAT enabled — guests can reach Internet via $ext"
    iptables -A FORWARD -i "$BRIDGE_NAME" -o "$ext" -j ACCEPT
    iptables -A FORWARD -i "$ext" -o "$BRIDGE_NAME" -m state --state RELATED,ESTABLISHED -j ACCEPT
    iptables -t nat -A POSTROUTING -s "$SUBNET" -o "$ext" -j MASQUERADE
  else
    log " NAT disabled — guests blocked from Internet"
    iptables -I FORWARD 1 -i "$BRIDGE_NAME" -o "$ext" -j REJECT --reject-with icmp-net-prohibited
  fi

  # Block access to other RFC1918 nets
  iptables -I FORWARD 1 -i "$BRIDGE_NAME" -d 10.0.0.0/8         -j DROP
  iptables -I FORWARD 1 -i "$BRIDGE_NAME" -d 172.16.0.0/12      -j DROP
  iptables -I FORWARD 1 -i "$BRIDGE_NAME" -d 192.168.0.0/16 ! -d "$SUBNET" -j DROP

  if [[ $BLOCK_IPV6 == true ]]; then
    log " Blocking IPv6 on bridge"
    sysctl -qw net.ipv6.conf."$BRIDGE_NAME".disable_ipv6=1
    ip6tables -I FORWARD 1 -i "$BRIDGE_NAME" -j DROP
    ip6tables -t nat -I POSTROUTING 1 -s ::/0 -o "$ext" -j DROP
  fi

  if [[ $PERSIST_RULES == true ]]; then
    iptables-save > /etc/iptables/rules.v4
    [[ $BLOCK_IPV6 == true ]] && ip6tables-save > /etc/iptables/rules.v6 || true
    log "Firewall rules persisted to /etc/iptables"
  fi

  log "${GREEN}Firewall configured${NC}"
}

cleanup_firewall_rules() {
  local silent=${1:-no}
  $silent || log "Removing firewall rules for $BRIDGE_NAME ..."

  local ext="$(EXT_IFACE)" || true

  # reverse of configure_firewall_rules (ignore failures)
  iptables -D FORWARD -i "$BRIDGE_NAME" -j LOG --log-prefix "SHIKRA-BLOCKED: "     2>/dev/null || true
  iptables -D FORWARD -i "$BRIDGE_NAME" -d "$SUBNET" -j ACCEPT                     2>/dev/null || true
  iptables -D FORWARD -o "$BRIDGE_NAME" -s "$SUBNET" -j ACCEPT                     2>/dev/null || true

  iptables -D FORWARD -i "$BRIDGE_NAME" -d 10.0.0.0/8 -j DROP             2>/dev/null || true
  iptables -D FORWARD -i "$BRIDGE_NAME" -d 172.16.0.0/12 -j DROP          2>/dev/null || true
  iptables -D FORWARD -i "$BRIDGE_NAME" -d 192.168.0.0/16 ! -d "$SUBNET" -j DROP 2>/dev/null || true

  if [[ -n $ext ]]; then
    iptables -t nat -D POSTROUTING -s "$SUBNET" -o "$ext" -j MASQUERADE         2>/dev/null || true
    iptables -D FORWARD -i "$ext" -o "$BRIDGE_NAME" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i "$BRIDGE_NAME" -o "$ext" -j ACCEPT                  2>/dev/null || true
    iptables -D FORWARD -i "$BRIDGE_NAME" -o "$ext" -j REJECT --reject-with icmp-net-prohibited 2>/dev/null || true
  fi

  if [[ $BLOCK_IPV6 == true ]]; then
    ip6tables -D FORWARD -i "$BRIDGE_NAME" -j DROP 2>/dev/null || true
    ip6tables -t nat -D POSTROUTING -s ::/0 -o "$ext" -j DROP 2>/dev/null || true
  fi

  $silent || log "Firewall rules removed"
}

# --- Packet capture ----------------------------------------------------------
setup_traffic_capture() {
  [[ $ENABLE_CAPTURE == true ]] || return 0
  log "${BLUE}Starting tcpdump on $BRIDGE_NAME...${NC}"
  $DRY_RUN && { log "[dry‑run] Would start tcpdump"; return; }

  local pcap="$PCAP_DIR/$(date +%Y%m%d_%H%M%S)_${NETWORK_NAME}.pcap"
  nohup tcpdump -i "$BRIDGE_NAME" -w "$pcap" -s 0 > /dev/null 2>&1 &
  echo $! > "/tmp/tcpdump_${NETWORK_NAME}.pid"
  log "${GREEN}tcpdump PID $(cat /tmp/tcpdump_${NETWORK_NAME}.pid) capturing to $pcap${NC}"
}

cleanup_process_by_pidfile() {
  local name="$1" pidf="$2"
  [[ -f $pidf ]] || return 0
  local pid; pid=$(cat "$pidf")
  if kill "$pid" 2>/dev/null; then log "Stopped $name (PID $pid)"; fi
  rm -f "$pidf"
}

cleanup_traffic_capture() { cleanup_process_by_pidfile "tcpdump" "/tmp/tcpdump_${NETWORK_NAME}.pid"; }

# --- DNS sinkhole -------------------------------------------------------------
configure_dns_sinkhole() {
  [[ $ENABLE_SINKHOLE == true ]] || return 0
  log "${BLUE}Starting dnsmasq sinkhole...${NC}"
  $DRY_RUN && { log "[dry‑run] Would start dnsmasq"; return; }

  local cfg="/tmp/dnsmasq-${NETWORK_NAME}.conf"
  cat > "$cfg" << EOF
# sinkhole for $NETWORK_NAME
authoritative
interface=$BRIDGE_NAME
bind-interfaces
listen-address=$GATEWAY
 # DHCP
 dhcp-range=${DHCP_RANGE//,/ }
 dhcp-option=option:router,$GATEWAY
 dhcp-option=option:dns-server,$GATEWAY
 # wildcard redirect
 address=/#/$GATEWAY
 log-queries
 log-facility=/tmp/dnsmasq-${NETWORK_NAME}.log
EOF

  dnsmasq --conf-file="$cfg" --pid-file="/tmp/dnsmasq_${NETWORK_NAME}.pid"
  log "${GREEN}dnsmasq sinkhole running (PID $(cat /tmp/dnsmasq_${NETWORK_NAME}.pid))${NC}"
}

cleanup_dns_sinkhole() {
  cleanup_process_by_pidfile "dnsmasq" "/tmp/dnsmasq_${NETWORK_NAME}.pid"
  rm -f /tmp/dnsmasq-${NETWORK_NAME}.{conf,log} 2>/dev/null || true
}

# --- Fake services / INetSim --------------------------------------------------
start_fake_services() {
  [[ $ENABLE_FAKE_SERVICES == true ]] || return 0
  log "${BLUE}Starting netcat fake services...${NC}"
  $DRY_RUN && { log "[dry‑run] Would start netcat listeners"; return; }

  local svc=( [80]="HTTP/1.1 200 OK\r\n\r\nHello Malware" \
              [21]="220 Fake FTP Ready" \
              [25]="220 fake‑mail.local ESMTP Service" )
  for port in "${!svc[@]}"; do
    local msg="${svc[$port]}"
    nohup bash -c "while true; do echo -e '$msg' | nc -kl -s $GATEWAY -p $port; done" &>/dev/null &
    echo $! > "/tmp/fake_${port}_${NETWORK_NAME}.pid"
    log " fake service on $GATEWAY:$port (PID $(cat /tmp/fake_${port}_${NETWORK_NAME}.pid))"
  done
}

cleanup_fake_services() {
  for p in 80 21 25; do cleanup_process_by_pidfile "fake service $p" "/tmp/fake_${p}_${NETWORK_NAME}.pid"; done
}

start_inetsim() {
  [[ $ENABLE_INETSIM == true ]] || return 0
  log "${BLUE}Starting INetSim...${NC}"
  $DRY_RUN && { log "[dry‑run] Would run inetsim"; return; }

  inetsim --bind-address "$GATEWAY" --pidfile "/tmp/inetsim_${NETWORK_NAME}.pid" &> /tmp/inetsim-${NETWORK_NAME}.log &
  log "${GREEN}INetSim running (PID $(cat /tmp/inetsim_${NETWORK_NAME}.pid))${NC}"
}

cleanup_inetsim() { cleanup_process_by_pidfile "INetSim" "/tmp/inetsim_${NETWORK_NAME}.pid"; }

# --- Status -------------------------------------------------------------------
show_network_status() {
  echo -e "\n${CYAN}Libvirt networks:${NC}"
  virsh net-list --all
  echo -e "\n${CYAN}Bridges:${NC}"
  brctl show | grep "$BRIDGE_NAME" || true
  echo -e "\n${CYAN}iptables (${BRIDGE_NAME} rules):${NC}"
  iptables -S | grep "$BRIDGE_NAME" || true
  echo -e "\n${CYAN}Active helper PIDs:${NC}"
  for pidf in /tmp/{tcpdump,dnsmasq,inetsim,fake_*}_${NETWORK_NAME}.pid; do
    [[ -f $pidf ]] && printf " %-45s -> %s\n" "$(basename "$pidf")" "$(cat "$pidf")";
  done
}

# --- Cleanup ------------------------------------------------------------------
cleanup_network() {
  log "${YELLOW}Cleaning up $NETWORK_NAME...${NC}"
  $DRY_RUN && { log "[dry‑run] Would cleanup"; return; }

  cleanup_inetsim
  cleanup_fake_services
  cleanup_dns_sinkhole
  cleanup_traffic_capture
  cleanup_firewall_rules

  if virsh net-info "$NETWORK_NAME" &>/dev/null; then
    virsh net-destroy "$NETWORK_NAME" 2>/dev/null || true
    virsh net-undefine "$NETWORK_NAME" 2>/dev/null || true
    log "Libvirt network removed"
  fi

  log "${GREEN}Cleanup done${NC}"
}

# --- NAT toggles (without touching other bits) --------------------------------
add_nat_rules()   { ENABLE_NAT=true  ; configure_firewall_rules; }
remove_nat_rules() { ENABLE_NAT=false ; configure_firewall_rules; }

# --- Main ---------------------------------------------------------------------
main() {
  parse_arguments "$@"

  trap 'log "${RED}\nInterrupted – running cleanup ...${NC}" ; cleanup_network ; exit 1' INT TERM

  if [[ $CREATE_ISOLATED == true ]]; then
    check_prerequisites
    create_isolated_network
    configure_firewall_rules
    setup_traffic_capture
    configure_dns_sinkhole
    start_fake_services
    start_inetsim
    log "${GREEN}--- Network setup complete ---${NC}"
    echo -e "\n${CYAN}Attach VMs with: --network network=$NETWORK_NAME${NC}"
  elif [[ $ENABLE_NAT == true ]]; then
    add_nat_rules
  elif [[ $DISABLE_NAT == true ]]; then
    remove_nat_rules
  elif [[ $CLEANUP_NETWORK == true ]]; then
    cleanup_network
  elif [[ $ACTION_STATUS == true ]]; then
    show_network_status
  fi

  trap - INT TERM
}

main "$@"
