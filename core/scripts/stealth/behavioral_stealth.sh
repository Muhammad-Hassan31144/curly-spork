# ================================================================
# behavioral_stealth.sh - Behavioral stealth measures
#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHIKRA_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
CONFIG_DIR="${SHIKRA_ROOT}/config/stealth"

log_info() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] BH-STEALTH: $1"
}

log_error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] BH-ERROR: $1" >&2
}

# Parse behavioral stealth arguments
parse_bh_args() {
    VM_NAME=""
    GUEST_OS=""
    CONFIG_FILE=""
    DRY_RUN=false
    VERBOSE=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            --vm-name)
                VM_NAME="$2"
                shift 2
                ;;
            --guest-os)
                GUEST_OS="$2"
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
                log_error "Unknown behavioral stealth option: $1"
                exit 1
                ;;
        esac
    done
}

# Execute command in VM (simplified version)
vm_exec() {
    local cmd="$1"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "DRY RUN - Would execute: $cmd"
        return 0
    fi
    
    # Placeholder for VM command execution
    # In real implementation, this would use virsh, VBoxManage, etc.
    log_info "Executing in VM: $cmd"
}

# Create user artifacts
create_user_artifacts() {
    log_info "Creating user artifacts"
    
    if [[ "$GUEST_OS" == "windows" ]]; then
        # Create common user documents
        vm_exec "mkdir \"C:\\Users\\Public\\Documents\" 2>nul"
        vm_exec "echo Sample document content > \"C:\\Users\\Public\\Documents\\Report.docx\""
        vm_exec "echo ID,Value\n1,100\n2,200 > \"C:\\Users\\Public\\Documents\\Data.csv\""
        
        # Create desktop shortcuts
        vm_exec "mkdir \"C:\\Users\\Public\\Desktop\" 2>nul"
        vm_exec "echo [InternetShortcut]\nURL=file:///C:/Users/Public/Documents > \"C:\\Users\\Public\\Desktop\\MyProject.url\""
        
    else
        # Create Linux user artifacts
        vm_exec "mkdir -p /home/user/Documents /home/user/Desktop 2>/dev/null"
        vm_exec "echo 'Meeting notes from today...' > /home/user/Documents/notes.txt"
        vm_exec "echo '[Desktop Entry]\nName=My App\nExec=/usr/bin/gedit\nType=Application' > /home/user/Desktop/run_app.desktop"
    fi
    
    log_info "User artifacts created"
}

# Simulate usage patterns  
simulate_usage_patterns() {
    log_info "Simulating usage patterns"
    
    if [[ "$GUEST_OS" == "windows" ]]; then
        # Create recent file entries
        vm_exec "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs\" /v \"Document1\" /t REG_SZ /d \"Report.docx\" /f >nul 2>&1"
        vm_exec "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs\" /v \"Document2\" /t REG_SZ /d \"Data.csv\" /f >nul 2>&1"
        
        # Create temp files to simulate usage
        for i in {1..3}; do
            vm_exec "echo temp data $RANDOM > \"C:\\Windows\\Temp\\tmp$i.tmp\""
        done
        
        # Create prefetch entries
        vm_exec "echo. > \"C:\\Windows\\Prefetch\\NOTEPAD.EXE-ABC123.pf\""
        vm_exec "echo. > \"C:\\Windows\\Prefetch\\CALC.EXE-DEF456.pf\""
        
    else
        # Create bash history
        vm_exec "echo 'ls -la' >> ~/.bash_history"
        vm_exec "echo 'cd /tmp' >> ~/.bash_history"
        vm_exec "echo 'cat /proc/cpuinfo' >> ~/.bash_history"
        vm_exec "echo 'df -h' >> ~/.bash_history"
        
        # Create some log entries
        vm_exec "logger 'User session started' 2>/dev/null"
        vm_exec "logger 'Application launched successfully' 2>/dev/null"
    fi
    
    log_info "Usage patterns simulated"
}

# Generate browsing history
generate_browsing_history() {
    log_info "Generating browsing history"
    
    if [[ "$GUEST_OS" == "windows" ]]; then
        # IE TypedURLs
        vm_exec "reg add \"HKCU\\Software\\Microsoft\\Internet Explorer\\TypedURLs\" /v \"url1\" /t REG_SZ /d \"http://www.google.com\" /f >nul 2>&1"
        vm_exec "reg add \"HKCU\\Software\\Microsoft\\Internet Explorer\\TypedURLs\" /v \"url2\" /t REG_SZ /d \"http://www.wikipedia.org\" /f >nul 2>&1"
        vm_exec "reg add \"HKCU\\Software\\Microsoft\\Internet Explorer\\TypedURLs\" /v \"url3\" /t REG_SZ /d \"http://www.github.com\" /f >nul 2>&1"
        
        # Create fake Chrome history directory and file
        vm_exec "mkdir \"C:\\Users\\Public\\AppData\\Local\\Google\\Chrome\\User Data\\Default\" 2>nul"
        vm_exec "echo Fake Chrome History Data > \"C:\\Users\\Public\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History\""
        
    else
        # Create Firefox profile directory
        vm_exec "mkdir -p /home/user/.mozilla/firefox/randomprofile.default 2>/dev/null"
        vm_exec "echo 'SQLite format 3' > /home/user/.mozilla/firefox/randomprofile.default/places.sqlite"
        
        # Create some wget history
        vm_exec "echo 'wget http://www.google.com' >> ~/.bash_history"
        vm_exec "echo 'curl -o page.html http://www.wikipedia.org' >> ~/.bash_history"
    fi
    
    log_info "Browsing history generated"
}

# Create system activity
create_system_activity() {
    log_info "Creating system activity traces"
    
    if [[ "$GUEST_OS" == "windows" ]]; then
        # Create Windows event log entries
        vm_exec "eventcreate /T INFORMATION /ID 1001 /L APPLICATION /SO \"UserApp\" /D \"Application started successfully\" >nul 2>&1"
        vm_exec "eventcreate /T INFORMATION /ID 1002 /L APPLICATION /SO \"UserApp\" /D \"User completed task\" >nul 2>&1"
        
        # Create additional prefetch files
        vm_exec "echo. > \"C:\\Windows\\Prefetch\\EXPLORER.EXE-GHI789.pf\""
        vm_exec "echo. > \"C:\\Windows\\Prefetch\\WINWORD.EXE-JKL012.pf\""
        
    else
        # Create syslog entries
        vm_exec "logger -p user.info 'User application started' 2>/dev/null"
        vm_exec "logger -p user.info 'System maintenance completed' 2>/dev/null"
        
        # Create some command history that shows normal usage
        vm_exec "echo 'ps aux' >> ~/.bash_history"
        vm_exec "echo 'top' >> ~/.bash_history" 
        vm_exec "echo 'netstat -an' >> ~/.bash_history"
    fi
    
    log_info "System activity traces created"
}

# Populate network artifacts
populate_network_artifacts() {
    log_info "Populating network artifacts"
    
    # Perform some DNS lookups to populate cache
    local domains=("google.com" "microsoft.com" "wikipedia.org")
    
    for domain in "${domains[@]}"; do
        if [[ "$GUEST_OS" == "windows" ]]; then
            vm_exec "nslookup $domain >nul 2>&1"
        else
            vm_exec "getent hosts $domain >/dev/null 2>&1 || dig +short $domain >/dev/null 2>&1"
        fi
    done
    
    # Add some fake ARP entries (may need admin privileges)
    if [[ "$GUEST_OS" == "windows" ]]; then
        vm_exec "arp -s 192.168.1.1 00-1A-2B-3C-4D-01 2>nul"
        vm_exec "arp -s 192.168.1.254 00-1A-2B-3C-4D-FE 2>nul"
    else
        vm_exec "arp -s 192.168.1.1 00:1a:2b:3c:4d:01 2>/dev/null || true"
        vm_exec "arp -s 192.168.1.254 00:1a:2b:3c:4d:fe 2>/dev/null || true"
    fi
    
    log_info "Network artifacts populated"
}

# Main behavioral stealth function
main_behavioral() {
    parse_bh_args "$@"
    
    if [[ -z "$VM_NAME" || -z "$GUEST_OS" || -z "$CONFIG_FILE" ]]; then
        log_error "Missing required arguments for behavioral stealth"
        exit 1
    fi
    
    log_info "Applying behavioral stealth for VM: $VM_NAME ($GUEST_OS)"
    
    # Check what behavioral measures are enabled
    local create_artifacts=$(jq -r '.behavioral_stealth.create_user_artifacts' "$CONFIG_FILE")
    local simulate_usage=$(jq -r '.behavioral_stealth.simulate_usage_patterns' "$CONFIG_FILE")
    local generate_browsing=$(jq -r '.behavioral_stealth.generate_browsing_history' "$CONFIG_FILE")
    local create_activity=$(jq -r '.behavioral_stealth.create_system_activity' "$CONFIG_FILE")
    local network_stealth=$(jq -r '.network_stealth.enabled // false' "$CONFIG_FILE")
    
    # Apply enabled measures
    if [[ "$create_artifacts" == "true" ]]; then
        create_user_artifacts
    fi
    
    if [[ "$simulate_usage" == "true" ]]; then
        simulate_usage_patterns
    fi
    
    if [[ "$generate_browsing" == "true" ]]; then
        generate_browsing_history
    fi
    
    if [[ "$create_activity" == "true" ]]; then
        create_system_activity
    fi
    
    if [[ "$network_stealth" == "true" ]]; then
        populate_network_artifacts
    fi
    
    log_info "Behavioral stealth application completed"
}

# Run behavioral stealth if called directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main_behavioral "$@"
fi