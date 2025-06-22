#!/usr/bin/env python3
"""
shikra/core/modules/vm_controller/__init__.py
VM Controller Module - Unified interface for all VM operations

Usage:
    python -m core.modules.vm_controller --copy-to <vm> --files <files>
    python -m core.modules.vm_controller --stage <files>
    python -m core.modules.vm_controller --snapshot <vm> --create

CLI Commands:
    vm_controller --copy-to win10-analysis --files script.ps1 malware.exe
    vm_controller --copy-from win10-analysis --files C:\\logs\\*.txt
    vm_controller --run-in win10-analysis --command "ipconfig"
    vm_controller --snapshot win10-analysis --create baseline
    vm_controller --stage /path/to/files/* 
"""

import sys
import os
import argparse
import time
from pathlib import Path

# Add current module to path for imports
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

# Import all VM controller modules with graceful fallbacks
VMFileTransfer = None
create_vm_evasion_script = None

try:
    # File transfer operations
    # from .copy_to_vm import VMFileTransfer, create_vm_evasion_script
    from ..vm_controller.vm_manager import VMManager
    COPY_TO_VM_AVAILABLE = True
except ImportError as e:
    print(f"Warning: copy_to_vm not fully available: {e}")
    COPY_TO_VM_AVAILABLE = False
    
    # Create minimal fallback
    class VMFileTransfer:
        def __init__(self, config=None):
            self.config = config or {}
            self.staging_dir = STAGING_DIR
            
        def stage_files(self, file_paths):
            print(f"[+] Staging files in: {self.staging_dir}")
            staged_files = []
            for file_path in file_paths:
                if os.path.exists(file_path):
                    filename = os.path.basename(file_path)
                    staged_path = self.staging_dir / filename
                    import shutil
                    shutil.copy2(file_path, staged_path)
                    staged_files.append(str(staged_path))
                    print(f"  [+] Staged: {filename}")
                else:
                    print(f"  [-] File not found: {file_path}")
            return staged_files
            
        def list_staged_files(self):
            if not self.staging_dir.exists():
                print("No staging directory found.")
                return []
            files = list(self.staging_dir.glob("*"))
            if files:
                print(f"[+] Staged files in {self.staging_dir}:")
                for f in files:
                    if f.is_file():
                        print(f"  - {f.name}")
            else:
                print("No files in staging directory.")
            return [str(f) for f in files if f.is_file()]
            
        def clear_staging(self):
            if self.staging_dir.exists():
                import shutil
                shutil.rmtree(self.staging_dir)
                self.staging_dir.mkdir(parents=True, exist_ok=True)
                print("[+] Staging directory cleared.")
                
        def setup_smb_server(self, files, vm_network="shikra-isolated"):
            print("[!] SMB server requires full installation. Install: pip3 install pywinrm paramiko")
            print("[!] For now, files are staged in:", self.staging_dir)
            return False
            
        def setup_http_server(self, files, vm_network="shikra-isolated", stealth=False):
            print("[!] HTTP server requires full installation. Install: pip3 install pywinrm paramiko") 
            print("[!] For now, files are staged in:", self.staging_dir)
            return False

try:
    # from .copy_from_vm import *
    from ..vm_controller.vm_manager import VMManager
    COPY_FROM_VM_AVAILABLE = True
except ImportError as e:
    print(f"Warning: copy_from_vm not available: {e}")
    COPY_FROM_VM_AVAILABLE = False
    
try:
    # VM execution and control
    # from .run_in_vm import *
    from ..vm_controller.vm_manager import VMManager

    RUN_IN_VM_AVAILABLE = True
except ImportError as e:
    print(f"Warning: run_in_vm not available: {e}")
    RUN_IN_VM_AVAILABLE = False
    
try:
    # VM snapshot management
    from .snapshot import *
    SNAPSHOT_AVAILABLE = True
except ImportError as e:
    print(f"Warning: snapshot not available: {e}")
    SNAPSHOT_AVAILABLE = False
    
try:
    # VM stealth and evasion
    from .stealth import *
    STEALTH_AVAILABLE = True
except ImportError as e:
    print(f"Warning: stealth not available: {e}")
    STEALTH_AVAILABLE = False

# Fallback for create_vm_evasion_script if not imported
if create_vm_evasion_script is None:
    def create_vm_evasion_script():
        """Fallback evasion script creator"""
        script_content = '''# VM Evasion Script (Basic)
Write-Host "=== VM Evasion Script ===" -ForegroundColor Cyan
Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
netsh advfirewall set allprofiles state off
Write-Host "[+] Basic security disabled" -ForegroundColor Green
'''
        script_path = STAGING_DIR / "vm_evasion.ps1"
        with open(script_path, 'w', encoding='utf-8') as f:
            f.write(script_content)
        print(f"[+] Basic VM evasion script created: {script_path}")
        return str(script_path)

# Module metadata
__version__ = "1.0.0"
__author__ = "Shikra Team"
__description__ = "Comprehensive VM Controller for malware analysis operations"

# Standard directories
STAGING_DIR = Path.home() / ".shikra" / "staging"
OUTPUT_DIR = Path.home() / ".shikra" / "output"

# Create directories
STAGING_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Expose main classes and functions from all modules
__all__ = [
    # File transfer (copy_to_vm.py)
    'VMFileTransfer',
    'create_vm_evasion_script', 
    'stage_files',
    'copy_to_vm',
    'list_staged',
    'clear_staging',
    
    # File retrieval (copy_from_vm.py) 
    'copy_from_vm',
    'retrieve_files',
    
    # VM execution (run_in_vm.py)
    'run_in_vm',
    'execute_command',
    'execute_script',
    
    # VM snapshots (snapshot.py)
    'create_snapshot',
    'restore_snapshot', 
    'list_snapshots',
    'delete_snapshot',
    
    # VM stealth (stealth.py)
    'apply_stealth',
    'hide_vm_artifacts',
    'disable_security',
    
    # Main CLI
    'main'
]

# =====  UNIFIED INTERFACE FUNCTIONS =====

def stage_files(*file_paths):
    """Stage files for transfer to VMs"""
    transfer = VMFileTransfer()
    return transfer.stage_files(file_paths)

def copy_to_vm(vm_identifier, files=None, method="smb", vm_network="shikra-isolated", guest_path=None):
    """Copy files to VM using specified method"""
    if not COPY_TO_VM_AVAILABLE and method == "direct":
        print("[!] Direct copy requires: pip3 install pywinrm paramiko")
        return False
        
    transfer = VMFileTransfer()
    files = files or transfer.list_staged_files()
    
    if not files:
        print("No files to transfer. Use --stage first or specify --files")
        return False
    
    if method == "direct":
        if not COPY_TO_VM_AVAILABLE:
            print("[!] Direct method not available. Try 'smb' method or install dependencies.")
            return False
        # Use direct push method
        success_count = 0
        for file_path in files:
            dest_path = guest_path or f"/tmp/{os.path.basename(file_path)}"
            if transfer.copy_to_guest_direct(vm_identifier, file_path, dest_path):
                success_count += 1
        return success_count == len(files)
    else:
        # Use network server methods
        if method == "smb":
            return transfer.setup_smb_server(files, vm_network)
        elif method == "http":
            return transfer.setup_http_server(files, vm_network, stealth=False)  
        elif method == "stealth-http":
            return transfer.setup_http_server(files, vm_network, stealth=True)
        return True

def copy_from_vm(vm_identifier, remote_files, local_dir=None, method="direct"):
    """Copy files from VM to local system"""
    if not COPY_FROM_VM_AVAILABLE:
        print("[!] copy_from_vm requires: pip3 install pywinrm paramiko")
        return False
        
    local_dir = local_dir or str(OUTPUT_DIR)
    
    if method == "direct":
        # Use direct pull method (if available)
        print(f"Copying files from {vm_identifier} to {local_dir}")
        # Implementation depends on copy_from_vm.py
        return True
    else:
        print(f"Method {method} not implemented for copy_from_vm")
        return False

def run_in_vm(vm_identifier, command=None, script=None, timeout=300):
    """Execute command or script in VM"""
    if not RUN_IN_VM_AVAILABLE:
        print("[!] run_in_vm requires: pip3 install pywinrm paramiko")
        return False
        
    if script:
        # Execute script file
        return execute_script(vm_identifier, script, timeout)
    elif command:
        # Execute single command
        return execute_command(vm_identifier, command, timeout)
    else:
        print("Must specify either --command or --script")
        return False

def list_staged():
    """List files in staging directory"""
    transfer = VMFileTransfer()
    return transfer.list_staged_files()

def clear_staging():
    """Clear staging directory"""
    transfer = VMFileTransfer()
    transfer.clear_staging()

def vm_snapshot(vm_identifier, action, snapshot_name=None):
    """Manage VM snapshots"""
    if not SNAPSHOT_AVAILABLE:
        print("[!] Snapshot functionality not available. Check if snapshot.py exists.")
        return False
        
    if action == "create":
        name = snapshot_name or f"snapshot_{int(time.time())}"
        return create_snapshot(vm_identifier, name)
    elif action == "restore":
        if not snapshot_name:
            print("Snapshot name required for restore")
            return False
        return restore_snapshot(vm_identifier, snapshot_name)
    elif action == "list":
        return list_snapshots(vm_identifier)
    elif action == "delete":
        if not snapshot_name:
            print("Snapshot name required for delete")
            return False
        return delete_snapshot(vm_identifier, snapshot_name)
    else:
        print(f"Unknown snapshot action: {action}")
        return False

def apply_vm_stealth(vm_identifier, stealth_level="full"):
    """Apply stealth techniques to VM"""
    if not STEALTH_AVAILABLE:
        print("[!] Stealth functionality not available. Check if stealth.py exists.")
        return False
        
    try:
        if stealth_level == "full":
            return apply_stealth(vm_identifier, all_techniques=True)
        elif stealth_level == "basic":
            return hide_vm_artifacts(vm_identifier)
        elif stealth_level == "security":
            return disable_security(vm_identifier)
        else:
            print(f"Unknown stealth level: {stealth_level}")
            return False
    except NameError:
        print("Stealth module functions not available")
        return False

# =====  CLI INTERFACE =====

def main():
    """Main CLI entry point with comprehensive argument parsing"""
    parser = argparse.ArgumentParser(
        description=f"{__description__} v{__version__}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # File staging and transfer
  vm_controller --stage /path/to/script.ps1 /path/to/malware.exe
  vm_controller --copy-to win10-analysis --method smb
  vm_controller --copy-from win10-analysis --files "C:\\logs\\*.txt"
  
  # VM execution
  vm_controller --run-in win10-analysis --command "ipconfig /all"
  vm_controller --run-in win10-analysis --script setup.ps1
  
  # VM snapshots
  vm_controller --snapshot win10-analysis --create baseline
  vm_controller --snapshot win10-analysis --restore baseline
  vm_controller --snapshot win10-analysis --list
  
  # VM stealth
  vm_controller --apply-stealth win10-analysis --level full
  
  # Utilities
  vm_controller --list-staged
  vm_controller --create-evasion-script
"""
    )
    
    # VM identifier (used by most commands)
    parser.add_argument("vm", nargs="?", help="VM identifier (name or IP)")
    
    # ==== FILE TRANSFER ====
    transfer_group = parser.add_argument_group("File Transfer")
    transfer_group.add_argument("--copy-to", metavar="VM", help="Copy files to VM")
    transfer_group.add_argument("--copy-from", metavar="VM", help="Copy files from VM")
    transfer_group.add_argument("--files", nargs="*", help="Files to transfer")
    transfer_group.add_argument("--method", choices=["direct", "smb", "http", "stealth-http"], 
                               default="smb", help="Transfer method")
    transfer_group.add_argument("--guest-path", help="Destination path on VM")
    transfer_group.add_argument("--local-dir", help="Local directory for copied files")
    
    # ==== FILE STAGING ====
    staging_group = parser.add_argument_group("File Staging")
    staging_group.add_argument("--stage", nargs="*", help="Stage files for transfer")
    staging_group.add_argument("--list-staged", action="store_true", help="List staged files")
    staging_group.add_argument("--clear-staging", action="store_true", help="Clear staging directory")
    
    # ==== VM EXECUTION ====
    exec_group = parser.add_argument_group("VM Execution")
    exec_group.add_argument("--run-in", metavar="VM", help="Execute command/script in VM")
    exec_group.add_argument("--command", help="Command to execute")
    exec_group.add_argument("--script", help="Script file to execute")
    exec_group.add_argument("--timeout", type=int, default=300, help="Execution timeout")
    
    # ==== VM SNAPSHOTS ====
    snapshot_group = parser.add_argument_group("VM Snapshots")
    snapshot_group.add_argument("--snapshot", metavar="VM", help="VM for snapshot operations")
    snapshot_group.add_argument("--create", metavar="NAME", help="Create snapshot with name")
    snapshot_group.add_argument("--restore", metavar="NAME", help="Restore snapshot by name")
    snapshot_group.add_argument("--list", action="store_true", help="List snapshots")
    snapshot_group.add_argument("--delete", metavar="NAME", help="Delete snapshot by name")
    
    # ==== VM STEALTH ====
    stealth_group = parser.add_argument_group("VM Stealth")
    stealth_group.add_argument("--apply-stealth", metavar="VM", help="Apply stealth to VM")
    stealth_group.add_argument("--level", choices=["basic", "security", "full"], 
                              default="full", help="Stealth level")
    
    # ==== UTILITIES ====
    util_group = parser.add_argument_group("Utilities")
    util_group.add_argument("--create-evasion-script", action="store_true", 
                           help="Create VM evasion PowerShell script")
    util_group.add_argument("--vm-network", default="shikra-isolated", 
                           help="VM network (shikra-isolated or default)")
    util_group.add_argument("--config", help="Path to config file")
    util_group.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Handle case where no arguments provided
    if len(sys.argv) == 1:
        print(f"""
{__description__} v{__version__}

Staging Directory: {STAGING_DIR}
Output Directory:  {OUTPUT_DIR}

Quick Commands:
  vm_controller --stage <files>                    # Stage files
  vm_controller --copy-to <vm> --method smb        # Transfer via SMB
  vm_controller --run-in <vm> --command <cmd>      # Execute command
  vm_controller --snapshot <vm> --create <name>    # Create snapshot

Use --help for full command reference.
""")
        return
    
    # Set up logging
    if args.verbose:
        import logging
        logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')
    
    # Load config if provided
    config = {}
    if args.config and os.path.exists(args.config):
        import json
        with open(args.config, 'r') as f:
            config = json.load(f)
    
    success = True
    
    # ==== HANDLE COMMANDS ====
    
    # File staging operations
    if args.stage:
        stage_files(*args.stage)
    elif args.list_staged:
        list_staged()
    elif args.clear_staging:
        clear_staging()
    
    # Create evasion script
    elif args.create_evasion_script:
        script_path = create_vm_evasion_script()
        if args.copy_to:
            # Also transfer the script
            copy_to_vm(args.copy_to, [script_path], args.method, args.vm_network)
    
    # File transfer operations
    elif args.copy_to:
        success = copy_to_vm(args.copy_to, args.files, args.method, args.vm_network, args.guest_path)
    elif args.copy_from:
        success = copy_from_vm(args.copy_from, args.files, args.local_dir)
    
    # VM execution
    elif args.run_in:
        success = run_in_vm(args.run_in, args.command, args.script, args.timeout)
    
    # VM snapshots
    elif args.snapshot:
        if args.create:
            success = vm_snapshot(args.snapshot, "create", args.create)
        elif args.restore:
            success = vm_snapshot(args.snapshot, "restore", args.restore)
        elif args.list:
            success = vm_snapshot(args.snapshot, "list")
        elif args.delete:
            success = vm_snapshot(args.snapshot, "delete", args.delete)
        else:
            print("Snapshot operation requires --create, --restore, --list, or --delete")
            success = False
    
    # VM stealth
    elif args.apply_stealth:
        success = apply_vm_stealth(args.apply_stealth, args.level)
    
    # Handle positional VM argument for backward compatibility
    elif args.vm:
        print(f"VM specified: {args.vm}")
        print("Use specific action flags like --copy-to, --run-in, --snapshot, etc.")
        parser.print_help()
    
    else:
        parser.print_help()
    
    return 0 if success else 1

# Make module executable
if __name__ == "__main__":
    sys.exit(main())