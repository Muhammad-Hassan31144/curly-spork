#!/bin/bash

VM_NAME="shikra-windows-analysis"
VM_IP="192.168.100.10"
SSH_KEY="$HOME/.ssh/shikra_vm_key"
LOG_DIR="$HOME/shikra/logs"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a $LOG_DIR/shikra.log
}

start_environment() {
    log "Starting Shikra analysis environment..."
    
    # Start required services
    sudo systemctl start libvirtd
    sudo systemctl start inetsim
    
    # Apply network isolation
    sudo $HOME/shikra/core/scripts/network_isolation.sh
    
    # Start VM
    virsh start $VM_NAME
    
    # Start web VNC
    pkill websockify 2>/dev/null || true
    websockify --web /usr/share/novnc 6080 localhost:5900 &
    
    # Wait for VM to boot
    log "Waiting for VM to boot..."
    sleep 30
    
    log "Environment started successfully"
    log "VM accessible at: $VM_IP"
    log "Web VNC: http://localhost:6080/vnc.html"
}

stop_environment() {
    log "Stopping Shikra analysis environment..."
    
    # Stop web VNC
    pkill websockify 2>/dev/null || true
    
    # Shutdown VM gracefully
    virsh shutdown $VM_NAME
    
    # Wait for shutdown
    timeout 30 bash -c 'while virsh domstate '$VM_NAME' | grep -q running; do sleep 2; done'
    
    # Force shutdown if needed
    if virsh domstate $VM_NAME | grep -q running; then
        log "Force stopping VM..."
        virsh destroy $VM_NAME
    fi
    
    log "Environment stopped"
}

reset_environment() {
    log "Resetting analysis environment..."
    stop_environment
    
    # Create fresh analysis snapshot
    rm -f /var/lib/libvirt/images/shikra-analysis/windows-analysis.qcow2
    qemu-img create -f qcow2 -b /var/lib/libvirt/images/shikra-analysis/windows-base.qcow2 /var/lib/libvirt/images/shikra-analysis/windows-analysis.qcow2
    
    start_environment
}

status() {
    echo "=== Shikra Environment Status ==="
    echo "VM State: $(virsh domstate $VM_NAME 2>/dev/null || echo 'Not defined')"
    echo "LibVirtD: $(systemctl is-active libvirtd)"
    echo "InetSim: $(systemctl is-active inetsim)"
    echo "Network: $(virsh net-list | grep shikra-isolated | awk '{print $2}')"
    
    if virsh domstate $VM_NAME | grep -q running; then
        echo "VM IP: $VM_IP"
        echo "Web VNC: http://localhost:6080/vnc.html"
    fi
}

case "$1" in
    start) start_environment ;;
    stop) stop_environment ;;
    reset) reset_environment ;;
    status) status ;;
    *)
        echo "Shikra Analysis Environment Manager"
        echo "Usage: $0 {start|stop|reset|status}"
        echo ""
        echo "Commands:"
        echo "  start  - Start complete environment"
        echo "  stop   - Stop environment"
        echo "  reset  - Reset to clean analysis state"
        echo "  status - Show environment status"
        ;;
esac
