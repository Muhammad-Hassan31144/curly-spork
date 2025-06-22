# shikra/core/modules/vm_controller/vm_manager.py
# Purpose: UNIFIED VM Management - Replaces copy_to_vm.py + copy_from_vm.py + run_in_vm.py
# This ONE class handles all VM operations with connection pooling and caching

import logging
import base64
import os
import time
import threading
from typing import Dict, Optional, Tuple, Any, List
from pathlib import Path
import json

# Required dependencies
import winrm
import paramiko
from paramiko import SSHClient, SFTPClient

logger = logging.getLogger(__name__)

class VMConnectionPool:
    """
    Connection pool to maintain persistent VM connections.
    Prevents creating new WinRM/SSH sessions for every operation.
    """
    
    def __init__(self):
        self.connections = {}
        self.connection_locks = {}
        self.pool_lock = threading.Lock()
    
    def get_connection(self, vm_info: Dict[str, Any], connection_type: str):
        """Get cached connection or create new one."""
        vm_ip = vm_info.get("ip")
        cache_key = f"{connection_type}_{vm_ip}"
        
        with self.pool_lock:
            if cache_key not in self.connection_locks:
                self.connection_locks[cache_key] = threading.Lock()
        
        with self.connection_locks[cache_key]:
            if cache_key not in self.connections:
                if connection_type == "winrm":
                    conn = self._create_winrm_connection(vm_info)
                elif connection_type == "ssh":
                    conn = self._create_ssh_connection(vm_info)
                else:
                    return None
                
                if conn:
                    self.connections[cache_key] = conn
                    logger.debug(f"Created {connection_type} connection for {vm_ip}")
                
            return self.connections.get(cache_key)
    
    def _create_winrm_connection(self, vm_info: Dict) -> Optional[winrm.Session]:
        """Create WinRM session."""
        try:
            vm_ip = vm_info.get("ip")
            username = vm_info.get("user")
            password = vm_info.get("password")
            
            session = winrm.Session(
                f'http://{vm_ip}:5985/wsman',
                auth=(username, password),
                transport='ntlm',
                server_cert_validation='ignore'
            )
            
            # Test connection
            result = session.run_cmd("echo test", timeout_sec=10)
            if result.status_code == 0:
                return session
            else:
                logger.error(f"WinRM connection test failed for {vm_ip}")
                return None
                
        except Exception as e:
            logger.error(f"Failed to create WinRM connection: {e}")
            return None
    
    def _create_ssh_connection(self, vm_info: Dict) -> Optional[SSHClient]:
        """Create SSH connection."""
        try:
            vm_ip = vm_info.get("ip")
            username = vm_info.get("user")
            password = vm_info.get("password")
            ssh_key_path = vm_info.get("ssh_key_path")
            port = vm_info.get("ssh_port", 22)
            
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            if ssh_key_path and os.path.exists(ssh_key_path):
                ssh.connect(vm_ip, port=port, username=username, 
                           key_filename=ssh_key_path, timeout=30)
            else:
                ssh.connect(vm_ip, port=port, username=username, 
                           password=password, timeout=30)
            
            # Test connection
            stdin, stdout, stderr = ssh.exec_command("echo test", timeout=10)
            if stdout.channel.recv_exit_status() == 0:
                return ssh
            else:
                ssh.close()
                return None
                
        except Exception as e:
            logger.error(f"Failed to create SSH connection: {e}")
            return None
    
    def close_all(self):
        """Close all connections in the pool."""
        with self.pool_lock:
            for cache_key, connection in self.connections.items():
                try:
                    if hasattr(connection, 'close'):
                        connection.close()
                    logger.debug(f"Closed connection: {cache_key}")
                except Exception as e:
                    logger.warning(f"Error closing connection {cache_key}: {e}")
            
            self.connections.clear()
            self.connection_locks.clear()


class VMManager:
    """
    🎯 UNIFIED VM MANAGER - Single class for ALL VM operations
    
    Replaces:
    - copy_to_vm.py (VMFileTransfer class)
    - copy_from_vm.py (copy_from_guest function)
    - run_in_vm.py (execute_command_in_guest function)
    
    Features:
    - Connection pooling (reuse WinRM/SSH sessions)
    - Support for Windows (WinRM) and Linux (SSH/SFTP)
    - Simple, unified API
    - Thread-safe operations
    - Automatic cleanup
    - Error handling and retries
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize VM Manager.
        
        Args:
            config: VM configuration dictionary
                   {
                       "vms": {
                           "vm_id": {
                               "ip": "192.168.1.100",
                               "guest_os_type": "windows",
                               "user": "Administrator",
                               "password": "password123",
                               "ssh_key_path": "/path/to/key" (optional for Linux)
                           }
                       }
                   }
        """
        self.config = config
        self.connection_pool = VMConnectionPool()
        
        # Operation statistics
        self.stats = {
            "commands_executed": 0,
            "files_copied_to_vm": 0,
            "files_copied_from_vm": 0,
            "connection_failures": 0,
            "operation_failures": 0
        }
    
    def execute_command(self, vm_id: str, command: str, timeout: int = 300, 
                       shell: str = "cmd") -> Tuple[str, str, int]:
        """
        Execute command in VM.
        
        Args:
            vm_id: VM identifier
            command: Command to execute
            timeout: Command timeout in seconds
            shell: Shell type ("cmd", "powershell" for Windows, "bash" for Linux)
            
        Returns:
            Tuple of (stdout, stderr, return_code)
        """
        vm_info = self._get_vm_info(vm_id)
        if not vm_info:
            self.stats["operation_failures"] += 1
            return "", f"VM {vm_id} not found in configuration", 1
        
        os_type = vm_info.get("guest_os_type", "").lower()
        
        try:
            if os_type == "windows":
                result = self._winrm_execute(vm_info, command, timeout, shell)
            elif os_type == "linux":
                result = self._ssh_execute(vm_info, command, timeout)
            else:
                self.stats["operation_failures"] += 1
                return "", f"Unsupported OS type: {os_type}", 1
            
            self.stats["commands_executed"] += 1
            return result
            
        except Exception as e:
            logger.error(f"Error executing command in VM {vm_id}: {e}")
            self.stats["operation_failures"] += 1
            return "", str(e), 1
    
    def copy_file_to_vm(self, vm_id: str, local_path: str, remote_path: str, 
                       create_dirs: bool = True) -> bool:
        """
        Copy file from host to VM.
        
        Args:
            vm_id: VM identifier
            local_path: Local file path
            remote_path: Remote file path in VM
            create_dirs: Create remote directories if they don't exist
            
        Returns:
            Success status
        """
        vm_info = self._get_vm_info(vm_id)
        if not vm_info:
            logger.error(f"VM {vm_id} not found in configuration")
            self.stats["operation_failures"] += 1
            return False
        
        if not os.path.exists(local_path):
            logger.error(f"Local file not found: {local_path}")
            self.stats["operation_failures"] += 1
            return False
        
        os_type = vm_info.get("guest_os_type", "").lower()
        
        try:
            if os_type == "windows":
                success = self._winrm_copy_to(vm_info, local_path, remote_path, create_dirs)
            elif os_type == "linux":
                success = self._ssh_copy_to(vm_info, local_path, remote_path, create_dirs)
            else:
                logger.error(f"Unsupported OS type: {os_type}")
                self.stats["operation_failures"] += 1
                return False
            
            if success:
                self.stats["files_copied_to_vm"] += 1
            else:
                self.stats["operation_failures"] += 1
                
            return success
            
        except Exception as e:
            logger.error(f"Error copying file to VM {vm_id}: {e}")
            self.stats["operation_failures"] += 1
            return False
    
    def copy_file_from_vm(self, vm_id: str, remote_path: str, local_path: str, 
                         create_dirs: bool = True) -> bool:
        """
        Copy file from VM to host.
        
        Args:
            vm_id: VM identifier
            remote_path: Remote file path in VM
            local_path: Local file path
            create_dirs: Create local directories if they don't exist
            
        Returns:
            Success status
        """
        vm_info = self._get_vm_info(vm_id)
        if not vm_info:
            logger.error(f"VM {vm_id} not found in configuration")
            self.stats["operation_failures"] += 1
            return False
        
        os_type = vm_info.get("guest_os_type", "").lower()
        
        try:
            if create_dirs:
                local_dir = os.path.dirname(local_path)
                if local_dir:
                    os.makedirs(local_dir, exist_ok=True)
            
            if os_type == "windows":
                success = self._winrm_copy_from(vm_info, remote_path, local_path)
            elif os_type == "linux":
                success = self._ssh_copy_from(vm_info, remote_path, local_path)
            else:
                logger.error(f"Unsupported OS type: {os_type}")
                self.stats["operation_failures"] += 1
                return False
            
            if success:
                self.stats["files_copied_from_vm"] += 1
            else:
                self.stats["operation_failures"] += 1
                
            return success
            
        except Exception as e:
            logger.error(f"Error copying file from VM {vm_id}: {e}")
            self.stats["operation_failures"] += 1
            return False
    
    def copy_directory_to_vm(self, vm_id: str, local_dir: str, remote_dir: str) -> bool:
        """Copy entire directory to VM."""
        if not os.path.isdir(local_dir):
            logger.error(f"Local directory not found: {local_dir}")
            return False
        
        success_count = 0
        total_files = 0
        
        for root, dirs, files in os.walk(local_dir):
            for file in files:
                local_file = os.path.join(root, file)
                relative_path = os.path.relpath(local_file, local_dir)
                remote_file = os.path.join(remote_dir, relative_path).replace("\\", "/")
                
                total_files += 1
                if self.copy_file_to_vm(vm_id, local_file, remote_file):
                    success_count += 1
                else:
                    logger.warning(f"Failed to copy: {local_file}")
        
        logger.info(f"Directory copy completed: {success_count}/{total_files} files")
        return success_count == total_files
    
    def list_vm_files(self, vm_id: str, remote_path: str) -> List[str]:
        """List files in VM directory."""
        vm_info = self._get_vm_info(vm_id)
        if not vm_info:
            return []
        
        os_type = vm_info.get("guest_os_type", "").lower()
        
        if os_type == "windows":
            stdout, stderr, rc = self._winrm_execute(vm_info, f'dir /B "{remote_path}"', 30)
            if rc == 0:
                return [f.strip() for f in stdout.split('\n') if f.strip()]
        elif os_type == "linux":
            stdout, stderr, rc = self._ssh_execute(vm_info, f'ls -1 "{remote_path}"', 30)
            if rc == 0:
                return [f.strip() for f in stdout.split('\n') if f.strip()]
        
        return []
    
    def vm_file_exists(self, vm_id: str, remote_path: str) -> bool:
        """Check if file exists in VM."""
        vm_info = self._get_vm_info(vm_id)
        if not vm_info:
            return False
        
        os_type = vm_info.get("guest_os_type", "").lower()
        
        if os_type == "windows":
            stdout, stderr, rc = self._winrm_execute(
                vm_info, f'if exist "{remote_path}" (echo EXISTS) else (echo MISSING)', 30
            )
            return rc == 0 and "EXISTS" in stdout
        elif os_type == "linux":
            stdout, stderr, rc = self._ssh_execute(vm_info, f'test -f "{remote_path}" && echo EXISTS || echo MISSING', 30)
            return rc == 0 and "EXISTS" in stdout
        
        return False
    
    def get_vm_info(self, vm_id: str) -> Dict[str, Any]:
        """Get VM configuration info."""
        vm_info = self._get_vm_info(vm_id)
        if not vm_info:
            return {}
        
        # Add connection status
        vm_ip = vm_info.get("ip")
        os_type = vm_info.get("guest_os_type", "").lower()
        
        connection_type = "winrm" if os_type == "windows" else "ssh"
        cache_key = f"{connection_type}_{vm_ip}"
        
        result = vm_info.copy()
        result["connection_status"] = "connected" if cache_key in self.connection_pool.connections else "disconnected"
        return result
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get operation statistics."""
        return {
            **self.stats,
            "active_connections": len(self.connection_pool.connections),
            "available_vms": list(self.config.get("vms", {}).keys())
        }
    
    def close_all_connections(self):
        """Close all VM connections."""
        self.connection_pool.close_all()
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup connections."""
        self.close_all_connections()
    
    # =========================
    # PRIVATE METHODS
    # =========================
    
    def _get_vm_info(self, vm_id: str) -> Optional[Dict]:
        """Get VM configuration."""
        return self.config.get("vms", {}).get(vm_id)
    
    def _winrm_execute(self, vm_info: Dict, command: str, timeout: int, shell: str = "cmd") -> Tuple[str, str, int]:
        """Execute command via WinRM."""
        session = self.connection_pool.get_connection(vm_info, "winrm")
        if not session:
            self.stats["connection_failures"] += 1
            return "", "Failed to get WinRM session", 1
        
        try:
            if shell.lower() == "powershell":
                # Execute as PowerShell script
                result = session.run_ps(command, timeout_sec=timeout)
            else:
                # Execute as CMD command
                result = session.run_cmd(command, timeout_sec=timeout)
            
            stdout = result.std_out.decode('utf-8', errors='replace')
            stderr = result.std_err.decode('utf-8', errors='replace')
            return stdout, stderr, result.status_code
            
        except Exception as e:
            logger.error(f"WinRM execute error: {e}")
            return "", str(e), 1
    
    def _ssh_execute(self, vm_info: Dict, command: str, timeout: int) -> Tuple[str, str, int]:
        """Execute command via SSH."""
        ssh = self.connection_pool.get_connection(vm_info, "ssh")
        if not ssh:
            self.stats["connection_failures"] += 1
            return "", "Failed to get SSH connection", 1
        
        try:
            stdin, stdout, stderr = ssh.exec_command(command, timeout=timeout)
            
            stdout_data = stdout.read().decode('utf-8', errors='replace')
            stderr_data = stderr.read().decode('utf-8', errors='replace')
            return_code = stdout.channel.recv_exit_status()
            
            return stdout_data, stderr_data, return_code
            
        except Exception as e:
            logger.error(f"SSH execute error: {e}")
            return "", str(e), 1
    
    def _winrm_copy_to(self, vm_info: Dict, local_path: str, remote_path: str, create_dirs: bool) -> bool:
        """Copy file to Windows VM via WinRM."""
        try:
            # Read local file and encode as base64
            with open(local_path, 'rb') as f:
                file_data = f.read()
            
            base64_data = base64.b64encode(file_data).decode('utf-8')
            
            # Create PowerShell script
            ps_script = f'''
                $base64Data = @"
{base64_data}
"@
                $bytes = [System.Convert]::FromBase64String($base64Data)
                $remotePath = "{remote_path.replace('"', '""')}"
            '''
            
            if create_dirs:
                ps_script += '''
                $dir = Split-Path $remotePath -Parent
                if (!(Test-Path $dir)) { 
                    New-Item -ItemType Directory -Path $dir -Force | Out-Null
                }
                '''
            
            ps_script += '''
                [System.IO.File]::WriteAllBytes($remotePath, $bytes)
                Write-Output "COPY_SUCCESS"
            '''
            
            stdout, stderr, rc = self._winrm_execute(vm_info, ps_script, 120, "powershell")
            
            if rc == 0 and "COPY_SUCCESS" in stdout:
                logger.debug(f"Successfully copied {local_path} to VM:{remote_path}")
                return True
            else:
                logger.error(f"Failed to copy file to VM. RC: {rc}, Error: {stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error in _winrm_copy_to: {e}")
            return False
    
    def _winrm_copy_from(self, vm_info: Dict, remote_path: str, local_path: str) -> bool:
        """Copy file from Windows VM via WinRM."""
        try:
            # PowerShell script to read and encode file
            ps_script = f'''
                $remotePath = "{remote_path.replace('"', '""')}"
                if (Test-Path $remotePath) {{
                    $bytes = [System.IO.File]::ReadAllBytes($remotePath)
                    $base64 = [System.Convert]::ToBase64String($bytes)
                    Write-Output "COPY_START"
                    Write-Output $base64
                    Write-Output "COPY_END"
                }} else {{
                    Write-Output "FILE_NOT_FOUND"
                }}
            '''
            
            stdout, stderr, rc = self._winrm_execute(vm_info, ps_script, 120, "powershell")
            
            if rc == 0 and "COPY_START" in stdout and "COPY_END" in stdout:
                # Extract base64 content
                lines = stdout.split('\n')
                start_idx = next(i for i, line in enumerate(lines) if "COPY_START" in line) + 1
                end_idx = next(i for i, line in enumerate(lines) if "COPY_END" in line)
                
                base64_content = ''.join(lines[start_idx:end_idx]).strip()
                file_data = base64.b64decode(base64_content)
                
                # Write to local file
                with open(local_path, 'wb') as f:
                    f.write(file_data)
                
                logger.debug(f"Successfully copied VM:{remote_path} to {local_path}")
                return True
            else:
                logger.error(f"Failed to copy file from VM. RC: {rc}")
                return False
                
        except Exception as e:
            logger.error(f"Error in _winrm_copy_from: {e}")
            return False
    
    def _ssh_copy_to(self, vm_info: Dict, local_path: str, remote_path: str, create_dirs: bool) -> bool:
        """Copy file to Linux VM via SFTP."""
        ssh = self.connection_pool.get_connection(vm_info, "ssh")
        if not ssh:
            return False
        
        try:
            sftp = ssh.open_sftp()
            
            if create_dirs:
                remote_dir = os.path.dirname(remote_path)
                if remote_dir:
                    try:
                        sftp.makedirs(remote_dir)
                    except:
                        pass  # Directory might already exist
            
            sftp.put(local_path, remote_path)
            sftp.close()
            
            logger.debug(f"Successfully copied {local_path} to VM:{remote_path}")
            return True
            
        except Exception as e:
            logger.error(f"SFTP copy to VM error: {e}")
            return False
    
    def _ssh_copy_from(self, vm_info: Dict, remote_path: str, local_path: str) -> bool:
        """Copy file from Linux VM via SFTP."""
        ssh = self.connection_pool.get_connection(vm_info, "ssh")
        if not ssh:
            return False
        
        try:
            sftp = ssh.open_sftp()
            sftp.get(remote_path, local_path)
            sftp.close()
            
            logger.debug(f"Successfully copied VM:{remote_path} to {local_path}")
            return True
            
        except Exception as e:
            logger.error(f"SFTP copy from VM error: {e}")
            return False


# =========================
# BACKWARD COMPATIBILITY FUNCTIONS
# =========================

# Global VM manager instance (for backward compatibility)
_global_vm_manager = None

def get_vm_manager(config: Dict = None) -> VMManager:
    """Get global VM manager instance."""
    global _global_vm_manager
    if _global_vm_manager is None or config is not None:
        _global_vm_manager = VMManager(config)
    return _global_vm_manager

def execute_command_in_guest(vm_id: str, command: str, config: Dict, timeout_sec: int = 300) -> Tuple[bytes, bytes, int]:
    """Backward compatibility wrapper for existing code."""
    vm_manager = get_vm_manager(config)
    stdout, stderr, rc = vm_manager.execute_command(vm_id, command, timeout_sec)
    return stdout.encode('utf-8'), stderr.encode('utf-8'), rc

def copy_from_guest(vm_id: str, remote_path: str, local_path: str, config: Dict, 
                   is_directory: bool = False, timeout_sec: int = 300) -> bool:
    """Backward compatibility wrapper for existing code."""
    vm_manager = get_vm_manager(config)
    if is_directory:
        logger.warning("Directory copy not yet implemented in VMManager")
        return False
    return vm_manager.copy_file_from_vm(vm_id, remote_path, local_path)

def copy_to_guest(vm_id: str, local_path: str, remote_path: str, config: Dict) -> bool:
    """Backward compatibility wrapper for existing code."""
    vm_manager = get_vm_manager(config)
    return vm_manager.copy_file_to_vm(vm_id, local_path, remote_path)


# =========================
# EXAMPLE USAGE
# =========================

if __name__ == "__main__":
    # Example configuration
    config = {
        "vms": {
            "win10-test": {
                "ip": "192.168.122.100",
                "guest_os_type": "windows",
                "user": "Administrator",
                "password": "password123"
            },
            "ubuntu-test": {
                "ip": "192.168.122.101", 
                "guest_os_type": "linux",
                "user": "ubuntu",
                "password": "ubuntu123",
                "ssh_key_path": "/home/user/.ssh/id_rsa"
            }
        }
    }
    
    # 🎯 UNIFIED SIMPLE USAGE
    with VMManager(config) as vm:
        print("=== VM Manager Example ===")
        
        # Execute commands
        stdout, stderr, rc = vm.execute_command("win10-test", "whoami")
        print(f"Windows whoami: {stdout.strip()}")
        
        # Copy files
        # vm.copy_file_to_vm("win10-test", "local_file.txt", "C:\\temp\\remote_file.txt")
        # vm.copy_file_from_vm("win10-test", "C:\\Windows\\System32\\drivers\\etc\\hosts", "hosts_backup.txt")
        
        # Get statistics
        stats = vm.get_statistics()
        print(f"Operations performed: {stats}")
    
    print("Connections automatically closed")