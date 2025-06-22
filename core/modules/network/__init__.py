#!/usr/bin/env python3
"""
shikra/core/modules/network/__init__.py
Network Module - Unified interface for network monitoring and simulation

Purpose:
This module provides functionalities related to network monitoring, traffic capture,
and network service simulation for the Shikra malware analysis platform. It aims
to create controlled network environments where malware's network behavior can be
observed and logged safely.

Key Components:
- NetworkCapture: Manages packet capture using tools like tcpdump or tshark
- FakeServices: Implements network service simulation (HTTP, DNS, FTP, SMTP, IRC, etc.)
- TrafficAnalyzer: Provides utilities to analyze captured PCAP files
- NetworkIsolationManager: Manages network isolation and controlled access

Usage:
    python -m core.modules.network --capture --interface br-shikra --output /tmp/capture.pcap
    python -m core.modules.network --fake-services --network shikra-isolated --services http,dns,ftp
    python -m core.modules.network --analyze --pcap /tmp/capture.pcap --output /tmp/analysis.json
"""

import sys
import os
import argparse
import time
import json
from pathlib import Path

# Add current module to path for imports
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

# Module metadata
__version__ = "1.0.0"
__author__ = "Shikra Development Team"
__description__ = "Network monitoring and simulation for malware analysis"

# Default configurations
DEFAULT_CAPTURE_INTERFACE = "any"
DEFAULT_ANALYSIS_SUBNET_PROFILE = {
    "name": "shikra_isolated_net",
    "bridge_name": "shikra-br0",
    "ip_cidr": "192.168.100.1/24",
    "dhcp_range_start": "192.168.100.10", 
    "dhcp_range_end": "192.168.100.50",
    "dns_server": "192.168.100.1",
    "isolation_mode": "full_drop_external"
}

# Standard directories
PCAP_DIR = Path.home() / ".shikra" / "pcap"
LOGS_DIR = Path.home() / ".shikra" / "network_logs"

# Create directories
PCAP_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)

# Import network modules with graceful fallbacks
NetworkCapture = None
FakeServices = None
CAPTURE_AVAILABLE = False
FAKE_SERVICES_AVAILABLE = False

try:
    from .capture import NetworkCapture
    CAPTURE_AVAILABLE = True
    print("✓ Network capture module available")
except ImportError as e:
    print(f"Warning: capture.py not available: {e}")
    
    # Create minimal fallback
    class NetworkCapture:
        def __init__(self, interface="any", output_dir=None):
            self.interface = interface
            self.output_dir = output_dir or str(PCAP_DIR)
            self.capture_pid = None
            
        def start_capture(self, output_file=None, filter_expression=None, timeout=None):
            print(f"[!] NetworkCapture not fully available. Would start capture on {self.interface}")
            print(f"[!] Install dependencies: sudo apt install tcpdump tshark")
            return False
            
        def stop_capture(self):
            print("[!] NetworkCapture not fully available")
            return False
            
        def get_capture_stats(self):
            return {"packets_captured": 0, "status": "unavailable"}

try:
    from .fake_services import FakeServices
    FAKE_SERVICES_AVAILABLE = True
    print("✓ Fake services module available")
except ImportError as e:
    print(f"Warning: fake_services.py not available: {e}")
    
    # Create minimal fallback
    class FakeServices:
        def __init__(self, network="shikra-isolated", output_dir=None):
            self.network = network
            self.output_dir = output_dir or str(LOGS_DIR)
            self.services = {}
            
        def start_services(self, services=None):
            services = services or ["http", "dns"]
            print(f"[!] FakeServices not fully available. Would start: {', '.join(services)}")
            print(f"[!] Install dependencies or implement fake_services.py")
            return False
            
        def stop_services(self):
            print("[!] FakeServices not fully available")
            return False
            
        def get_service_logs(self):
            return {"services": [], "interactions": 0}

# Traffic analyzer (placeholder for future implementation)
class TrafficAnalyzer:
    def __init__(self, pcap_file=None):
        self.pcap_file = pcap_file
        
    def analyze_pcap(self, output_file=None):
        if not self.pcap_file or not os.path.exists(self.pcap_file):
            print("[!] No valid PCAP file for analysis")
            return False
            
        # Basic analysis using tshark if available
        try:
            import subprocess
            result = subprocess.run(['tshark', '-r', self.pcap_file, '-T', 'json'], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                analysis = {
                    "pcap_file": self.pcap_file,
                    "timestamp": time.time(),
                    "packets": len(result.stdout.strip().split('\n')) if result.stdout.strip() else 0,
                    "analysis_tool": "tshark"
                }
                
                if output_file:
                    with open(output_file, 'w') as f:
                        json.dump(analysis, f, indent=2)
                
                return analysis
        except Exception as e:
            print(f"[!] Traffic analysis failed: {e}")
            
        return False

# Expose main classes and functions
__all__ = [
    'NetworkCapture',
    'FakeServices', 
    'TrafficAnalyzer',
    'start_network_capture',
    'start_fake_services',
    'analyze_traffic',
    'get_default_network_profile',
    'main'
]

# =====  UNIFIED INTERFACE FUNCTIONS =====

def get_default_network_profile():
    """Returns a copy of the default network profile settings."""
    return DEFAULT_ANALYSIS_SUBNET_PROFILE.copy()

def start_network_capture(interface="any", output_file=None, filter_expression=None, 
                         timeout=None, background=True):
    """Start network packet capture"""
    if not CAPTURE_AVAILABLE:
        print("[!] Network capture not available. Install dependencies.")
        return False
        
    capture = NetworkCapture(interface=interface, output_dir=str(PCAP_DIR))
    
    if not output_file:
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        output_file = PCAP_DIR / f"capture_{timestamp}.pcap"
    
    print(f"[+] Starting network capture on {interface}")
    print(f"[+] Output: {output_file}")
    if filter_expression:
        print(f"[+] Filter: {filter_expression}")
    
    return capture.start_capture(
        output_file=str(output_file),
        filter_expression=filter_expression,
        timeout=timeout
    )

def start_fake_services(network="shikra-isolated", services=None, output_dir=None):
    """Start fake network services"""
    if not FAKE_SERVICES_AVAILABLE:
        print("[!] Fake services not available. Implement fake_services.py")
        return False
        
    services = services or ["http", "dns", "ftp"]
    output_dir = output_dir or str(LOGS_DIR)
    
    fake_services = FakeServices(network=network, output_dir=output_dir)
    
    print(f"[+] Starting fake services on {network}")
    print(f"[+] Services: {', '.join(services)}")
    print(f"[+] Logs: {output_dir}")
    
    return fake_services.start_services(services=services)

def analyze_traffic(pcap_file, output_file=None):
    """Analyze network traffic from PCAP file"""
    if not os.path.exists(pcap_file):
        print(f"[!] PCAP file not found: {pcap_file}")
        return False
        
    analyzer = TrafficAnalyzer(pcap_file=pcap_file)
    
    if not output_file:
        pcap_name = Path(pcap_file).stem
        output_file = LOGS_DIR / f"{pcap_name}_analysis.json"
    
    print(f"[+] Analyzing traffic: {pcap_file}")
    print(f"[+] Output: {output_file}")
    
    return analyzer.analyze_pcap(output_file=str(output_file))

def stop_network_capture(interface="any"):
    """Stop network capture on specified interface"""
    if not CAPTURE_AVAILABLE:
        print("[!] Network capture not available")
        return False
        
    capture = NetworkCapture(interface=interface)
    return capture.stop_capture()

def stop_fake_services(network="shikra-isolated"):
    """Stop fake services on specified network"""
    if not FAKE_SERVICES_AVAILABLE:
        print("[!] Fake services not available")
        return False
        
    fake_services = FakeServices(network=network)
    return fake_services.stop_services()

def list_network_interfaces():
    """List available network interfaces"""
    try:
        import subprocess
        result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
        if result.returncode == 0:
            print("[+] Available network interfaces:")
            for line in result.stdout.split('\n'):
                if ': ' in line and 'state' in line.lower():
                    parts = line.split(': ')
                    if len(parts) > 1:
                        iface_info = parts[1].split()[0]
                        print(f"  - {iface_info}")
        else:
            print("[!] Could not list network interfaces")
    except Exception as e:
        print(f"[!] Error listing interfaces: {e}")

def show_network_status():
    """Show current network monitoring status"""
    print(f"""
Network Module Status:
  Capture Available:     {'✓' if CAPTURE_AVAILABLE else '✗'}
  Fake Services Available: {'✓' if FAKE_SERVICES_AVAILABLE else '✗'}
  
Directories:
  PCAP Files:  {PCAP_DIR}
  Network Logs: {LOGS_DIR}
  
Default Network Profile:
  Name: {DEFAULT_ANALYSIS_SUBNET_PROFILE['name']}
  Bridge: {DEFAULT_ANALYSIS_SUBNET_PROFILE['bridge_name']}
  Subnet: {DEFAULT_ANALYSIS_SUBNET_PROFILE['ip_cidr']}
""")

# =====  CLI INTERFACE =====

def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description=f"{__description__} v{__version__}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Network capture
  network --capture --interface br-shikra --output /tmp/capture.pcap
  network --capture --interface any --filter "not port 22" --timeout 300
  
  # Fake services  
  network --fake-services --network shikra-isolated --services http,dns,ftp
  network --fake-services --services all --output /tmp/service_logs
  
  # Traffic analysis
  network --analyze --pcap /tmp/capture.pcap --output /tmp/analysis.json
  network --analyze --pcap /tmp/capture.pcap
  
  # Utilities
  network --list-interfaces
  network --status
  network --stop-capture --interface br-shikra
  network --stop-services --network shikra-isolated
"""
    )
    
    # ==== NETWORK CAPTURE ====
    capture_group = parser.add_argument_group("Network Capture")
    capture_group.add_argument("--capture", action="store_true", help="Start network capture")
    capture_group.add_argument("--interface", default="any", help="Interface to capture on")
    capture_group.add_argument("--output", help="Output PCAP file")
    capture_group.add_argument("--filter", help="BPF filter expression")
    capture_group.add_argument("--timeout", type=int, help="Capture timeout in seconds")
    
    # ==== FAKE SERVICES ====
    services_group = parser.add_argument_group("Fake Services")
    services_group.add_argument("--fake-services", action="store_true", help="Start fake services")
    services_group.add_argument("--network", default="shikra-isolated", help="Network to bind services")
    services_group.add_argument("--services", help="Comma-separated services (http,dns,ftp,smtp,irc)")
    services_group.add_argument("--service-output", help="Service logs output directory")
    
    # ==== TRAFFIC ANALYSIS ====
    analysis_group = parser.add_argument_group("Traffic Analysis")
    analysis_group.add_argument("--analyze", action="store_true", help="Analyze PCAP file")
    analysis_group.add_argument("--pcap", help="PCAP file to analyze")
    analysis_group.add_argument("--analysis-output", help="Analysis output file")
    
    # ==== CONTROL OPERATIONS ====
    control_group = parser.add_argument_group("Control Operations")
    control_group.add_argument("--stop-capture", action="store_true", help="Stop network capture")
    control_group.add_argument("--stop-services", action="store_true", help="Stop fake services")
    
    # ==== UTILITIES ====
    util_group = parser.add_argument_group("Utilities")
    util_group.add_argument("--list-interfaces", action="store_true", help="List network interfaces")
    util_group.add_argument("--status", action="store_true", help="Show network module status")
    util_group.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Handle case where no arguments provided
    if len(sys.argv) == 1:
        print(f"""
{__description__} v{__version__}

PCAP Directory: {PCAP_DIR}
Logs Directory: {LOGS_DIR}

Module Status:
  Network Capture:  {'✓' if CAPTURE_AVAILABLE else '✗ (install tcpdump/tshark)'}
  Fake Services:    {'✓' if FAKE_SERVICES_AVAILABLE else '✗ (implement fake_services.py)'}

Quick Commands:
  network --capture --interface br-shikra          # Start packet capture
  network --fake-services --services http,dns      # Start fake services
  network --analyze --pcap capture.pcap            # Analyze traffic
  network --list-interfaces                        # List interfaces
  network --status                                  # Show status

Use --help for full command reference.
""")
        return
    
    success = True
    
    # ==== HANDLE COMMANDS ====
    
    # Network capture operations
    if args.capture:
        services_list = None
        if args.services:
            services_list = [s.strip() for s in args.services.split(',')]
            if 'all' in services_list:
                services_list = ['http', 'https', 'dns', 'ftp', 'smtp', 'irc', 'pop3', 'ssh']
        
        success = start_network_capture(
            interface=args.interface,
            output_file=args.output,
            filter_expression=args.filter,
            timeout=args.timeout
        )
        
        if success and args.timeout:
            print(f"[+] Capture will run for {args.timeout} seconds...")
            time.sleep(args.timeout)
            stop_network_capture(args.interface)
    
    # Fake services operations
    elif args.fake_services:
        services_list = None
        if args.services:
            services_list = [s.strip() for s in args.services.split(',')]
            if 'all' in services_list:
                services_list = ['http', 'https', 'dns', 'ftp', 'smtp', 'irc']
        
        success = start_fake_services(
            network=args.network,
            services=services_list,
            output_dir=args.service_output
        )
        
        if success:
            print("[+] Fake services started. Press Ctrl+C to stop...")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n[+] Stopping fake services...")
                stop_fake_services(args.network)
    
    # Traffic analysis operations
    elif args.analyze:
        if not args.pcap:
            print("[!] PCAP file required for analysis (--pcap)")
            success = False
        else:
            success = analyze_traffic(
                pcap_file=args.pcap,
                output_file=args.analysis_output
            )
    
    # Control operations
    elif args.stop_capture:
        success = stop_network_capture(args.interface)
    elif args.stop_services:
        success = stop_fake_services(args.network)
    
    # Utility operations
    elif args.list_interfaces:
        list_network_interfaces()
    elif args.status:
        show_network_status()
    
    else:
        parser.print_help()
    
    return 0 if success else 1

# Make module executable
if __name__ == "__main__":
    sys.exit(main())