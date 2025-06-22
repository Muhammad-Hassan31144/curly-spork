#!/usr/bin/env python3
"""
VM Snapshot Management Module for Shikra

This module provides comprehensive VM snapshot management capabilities
supporting multiple hypervisors including QEMU/KVM, VirtualBox, and VMware.

Usage:
    from shikra.core.modules.vm_controller.snapshot import SnapshotManager
    
    manager = SnapshotManager('vm_name', config)
    manager.create_snapshot('baseline', 'Clean VM state')
    manager.restore_snapshot('baseline')
"""

import json
import logging
import os
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

logger = logging.getLogger(__name__)

class SnapshotError(Exception):
    """Custom exception for snapshot operations."""
    pass

class HypervisorInterface:
    """Base interface for hypervisor-specific operations."""
    
    def __init__(self, vm_identifier: str, vm_config: Dict[str, Any]):
        self.vm_identifier = vm_identifier
        self.vm_config = vm_config
        self.vm_name = vm_config.get('name', vm_identifier)
    
    def create_snapshot(self, snapshot_name: str, description: str = "") -> bool:
        """Create a snapshot. To be implemented by specific hypervisor classes."""
        raise NotImplementedError("Subclasses must implement create_snapshot")
    
    def restore_snapshot(self, snapshot_name: str) -> bool:
        """Restore a snapshot. To be implemented by specific hypervisor classes."""
        raise NotImplementedError("Subclasses must implement restore_snapshot")
    
    def delete_snapshot(self, snapshot_name: str) -> bool:
        """Delete a snapshot. To be implemented by specific hypervisor classes."""
        raise NotImplementedError("Subclasses must implement delete_snapshot")
    
    def list_snapshots(self) -> List[Dict[str, Any]]:
        """List snapshots. To be implemented by specific hypervisor classes."""
        raise NotImplementedError("Subclasses must implement list_snapshots")
    
    def _run_command(self, command: List[str], timeout: int = 60) -> Tuple[str, str, int]:
        """Run a command and return stdout, stderr, return_code."""
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out: {' '.join(command)}")
            return "", "Command timed out", -1
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            return "", str(e), -1

class QEMUInterface(HypervisorInterface):
    """QEMU/KVM hypervisor interface using virsh."""
    
    def create_snapshot(self, snapshot_name: str, description: str = "") -> bool:
        """Create a QEMU snapshot using virsh."""
        try:
            # Check if VM exists
            stdout, stderr, rc = self._run_command(['virsh', 'dominfo', self.vm_name])
            if rc != 0:
                logger.error(f"VM '{self.vm_name}' not found in virsh")
                return False
            
            # Create snapshot
            cmd = ['virsh', 'snapshot-create-as', self.vm_name, snapshot_name]
            if description:
                cmd.extend(['--description', description])
            
            stdout, stderr, rc = self._run_command(cmd)
            
            if rc == 0:
                logger.info(f"QEMU snapshot '{snapshot_name}' created for VM '{self.vm_name}'")
                return True
            else:
                logger.error(f"Failed to create QEMU snapshot: {stderr}")
                return False
                
        except Exception as e:
            logger.error(f"QEMU snapshot creation failed: {e}")
            return False
    
    def restore_snapshot(self, snapshot_name: str) -> bool:
        """Restore a QEMU snapshot using virsh."""
        try:
            cmd = ['virsh', 'snapshot-revert', self.vm_name, snapshot_name]
            stdout, stderr, rc = self._run_command(cmd, timeout=120)
            
            if rc == 0:
                logger.info(f"QEMU snapshot '{snapshot_name}' restored for VM '{self.vm_name}'")
                return True
            else:
                logger.error(f"Failed to restore QEMU snapshot: {stderr}")
                return False
                
        except Exception as e:
            logger.error(f"QEMU snapshot restoration failed: {e}")
            return False
    
    def delete_snapshot(self, snapshot_name: str) -> bool:
        """Delete a QEMU snapshot using virsh."""
        try:
            cmd = ['virsh', 'snapshot-delete', self.vm_name, snapshot_name]
            stdout, stderr, rc = self._run_command(cmd)
            
            if rc == 0:
                logger.info(f"QEMU snapshot '{snapshot_name}' deleted for VM '{self.vm_name}'")
                return True
            else:
                logger.error(f"Failed to delete QEMU snapshot: {stderr}")
                return False
                
        except Exception as e:
            logger.error(f"QEMU snapshot deletion failed: {e}")
            return False
    
    def list_snapshots(self) -> List[Dict[str, Any]]:
        """List QEMU snapshots using virsh."""
        try:
            cmd = ['virsh', 'snapshot-list', self.vm_name, '--metadata']
            stdout, stderr, rc = self._run_command(cmd)
            
            if rc != 0:
                logger.error(f"Failed to list QEMU snapshots: {stderr}")
                return []
            
            snapshots = []
            lines = stdout.strip().split('\n')
            
            # Skip header lines
            for line in lines[2:]:  # First two lines are headers
                if line.strip() and not line.startswith('-'):
                    parts = line.split()
                    if len(parts) >= 3:
                        snapshot_info = {
                            'name': parts[0],
                            'creation_time': ' '.join(parts[1:3]),
                            'state': parts[3] if len(parts) > 3 else 'unknown',
                            'hypervisor': 'qemu'
                        }
                        
                        # Get detailed info for this snapshot
                        detail_cmd = ['virsh', 'snapshot-info', self.vm_name, parts[0]]
                        detail_stdout, _, detail_rc = self._run_command(detail_cmd)
                        
                        if detail_rc == 0:
                            for detail_line in detail_stdout.split('\n'):
                                if 'Description:' in detail_line:
                                    snapshot_info['description'] = detail_line.split(':', 1)[1].strip()
                                    break
                        
                        snapshots.append(snapshot_info)
            
            return snapshots
            
        except Exception as e:
            logger.error(f"QEMU snapshot listing failed: {e}")
            return []

class VirtualBoxInterface(HypervisorInterface):
    """VirtualBox hypervisor interface using VBoxManage."""
    
    def create_snapshot(self, snapshot_name: str, description: str = "") -> bool:
        """Create a VirtualBox snapshot using VBoxManage."""
        try:
            cmd = ['VBoxManage', 'snapshot', self.vm_name, 'take', snapshot_name]
            if description:
                cmd.extend(['--description', description])
            
            stdout, stderr, rc = self._run_command(cmd, timeout=120)
            
            if rc == 0:
                logger.info(f"VirtualBox snapshot '{snapshot_name}' created for VM '{self.vm_name}'")
                return True
            else:
                logger.error(f"Failed to create VirtualBox snapshot: {stderr}")
                return False
                
        except Exception as e:
            logger.error(f"VirtualBox snapshot creation failed: {e}")
            return False
    
    def restore_snapshot(self, snapshot_name: str) -> bool:
        """Restore a VirtualBox snapshot using VBoxManage."""
        try:
            cmd = ['VBoxManage', 'snapshot', self.vm_name, 'restore', snapshot_name]
            stdout, stderr, rc = self._run_command(cmd, timeout=120)
            
            if rc == 0:
                logger.info(f"VirtualBox snapshot '{snapshot_name}' restored for VM '{self.vm_name}'")
                return True
            else:
                logger.error(f"Failed to restore VirtualBox snapshot: {stderr}")
                return False
                
        except Exception as e:
            logger.error(f"VirtualBox snapshot restoration failed: {e}")
            return False
    
    def delete_snapshot(self, snapshot_name: str) -> bool:
        """Delete a VirtualBox snapshot using VBoxManage."""
        try:
            cmd = ['VBoxManage', 'snapshot', self.vm_name, 'delete', snapshot_name]
            stdout, stderr, rc = self._run_command(cmd)
            
            if rc == 0:
                logger.info(f"VirtualBox snapshot '{snapshot_name}' deleted for VM '{self.vm_name}'")
                return True
            else:
                logger.error(f"Failed to delete VirtualBox snapshot: {stderr}")
                return False
                
        except Exception as e:
            logger.error(f"VirtualBox snapshot deletion failed: {e}")
            return False
    
    def list_snapshots(self) -> List[Dict[str, Any]]:
        """List VirtualBox snapshots using VBoxManage."""
        try:
            cmd = ['VBoxManage', 'snapshot', self.vm_name, 'list', '--machinereadable']
            stdout, stderr, rc = self._run_command(cmd)
            
            if rc != 0:
                logger.error(f"Failed to list VirtualBox snapshots: {stderr}")
                return []
            
            snapshots = []
            current_snapshot = {}
            
            for line in stdout.split('\n'):
                line = line.strip()
                if '=' in line:
                    key, value = line.split('=', 1)
                    value = value.strip('"')
                    
                    if key.startswith('SnapshotName'):
                        if current_snapshot:
                            snapshots.append(current_snapshot)
                        current_snapshot = {
                            'name': value,
                            'hypervisor': 'virtualbox'
                        }
                    elif key.startswith('SnapshotDescription') and current_snapshot:
                        current_snapshot['description'] = value
                    elif key.startswith('SnapshotTimeStamp') and current_snapshot:
                        current_snapshot['creation_time'] = value
            
            if current_snapshot:
                snapshots.append(current_snapshot)
            
            return snapshots
            
        except Exception as e:
            logger.error(f"VirtualBox snapshot listing failed: {e}")
            return []

class VMwareInterface(HypervisorInterface):
    """VMware hypervisor interface using vmrun."""
    
    def __init__(self, vm_identifier: str, vm_config: Dict[str, Any]):
        super().__init__(vm_identifier, vm_config)
        self.vmx_path = vm_config.get('vmx_path', f'/path/to/{vm_identifier}.vmx')
    
    def create_snapshot(self, snapshot_name: str, description: str = "") -> bool:
        """Create a VMware snapshot using vmrun."""
        try:
            cmd = ['vmrun', 'snapshot', self.vmx_path, snapshot_name]
            stdout, stderr, rc = self._run_command(cmd, timeout=120)
            
            if rc == 0:
                logger.info(f"VMware snapshot '{snapshot_name}' created for VM '{self.vm_name}'")
                return True
            else:
                logger.error(f"Failed to create VMware snapshot: {stderr}")
                return False
                
        except Exception as e:
            logger.error(f"VMware snapshot creation failed: {e}")
            return False
    
    def restore_snapshot(self, snapshot_name: str) -> bool:
        """Restore a VMware snapshot using vmrun."""
        try:
            cmd = ['vmrun', 'revertToSnapshot', self.vmx_path, snapshot_name]
            stdout, stderr, rc = self._run_command(cmd, timeout=120)
            
            if rc == 0:
                logger.info(f"VMware snapshot '{snapshot_name}' restored for VM '{self.vm_name}'")
                return True
            else:
                logger.error(f"Failed to restore VMware snapshot: {stderr}")
                return False
                
        except Exception as e:
            logger.error(f"VMware snapshot restoration failed: {e}")
            return False
    
    def delete_snapshot(self, snapshot_name: str) -> bool:
        """Delete a VMware snapshot using vmrun."""
        try:
            cmd = ['vmrun', 'deleteSnapshot', self.vmx_path, snapshot_name]
            stdout, stderr, rc = self._run_command(cmd)
            
            if rc == 0:
                logger.info(f"VMware snapshot '{snapshot_name}' deleted for VM '{self.vm_name}'")
                return True
            else:
                logger.error(f"Failed to delete VMware snapshot: {stderr}")
                return False
                
        except Exception as e:
            logger.error(f"VMware snapshot deletion failed: {e}")
            return False
    
    def list_snapshots(self) -> List[Dict[str, Any]]:
        """List VMware snapshots using vmrun."""
        try:
            cmd = ['vmrun', 'listSnapshots', self.vmx_path]
            stdout, stderr, rc = self._run_command(cmd)
            
            if rc != 0:
                logger.error(f"Failed to list VMware snapshots: {stderr}")
                return []
            
            snapshots = []
            lines = stdout.strip().split('\n')
            
            for line in lines[1:]:  # Skip first line (total count)
                line = line.strip()
                if line:
                    snapshots.append({
                        'name': line,
                        'hypervisor': 'vmware',
                        'creation_time': 'unknown',  # vmrun doesn't provide timestamps
                        'description': ''
                    })
            
            return snapshots
            
        except Exception as e:
            logger.error(f"VMware snapshot listing failed: {e}")
            return []

class SnapshotManager:
    """
    High-level snapshot manager that automatically detects and uses
    the appropriate hypervisor interface.
    """
    
    def __init__(self, vm_identifier: str, config: Dict[str, Any]):
        """
        Initialize snapshot manager.
        
        Args:
            vm_identifier: VM name or identifier
            config: Configuration dictionary containing VM details
        """
        self.vm_identifier = vm_identifier
        self.config = config
        
        # Get VM configuration
        if vm_identifier not in config.get('vms', {}):
            raise ValueError(f"VM '{vm_identifier}' not found in configuration")
        
        self.vm_config = config['vms'][vm_identifier]
        
        # Initialize hypervisor interface
        self.hypervisor = self._detect_hypervisor()
        
        # Setup metadata storage
        self.metadata_dir = Path(config.get('snapshot_metadata_dir', '/tmp/shikra_snapshots'))
        self.metadata_dir.mkdir(parents=True, exist_ok=True)
        self.metadata_file = self.metadata_dir / f"{vm_identifier}_snapshots.json"
        
        logger.info(f"Snapshot manager initialized for VM '{vm_identifier}' using {self.hypervisor.__class__.__name__}")
    
    def _detect_hypervisor(self) -> HypervisorInterface:
        """Auto-detect hypervisor type and return appropriate interface."""
        # Check for explicit hypervisor type in config
        hypervisor_type = self.vm_config.get('hypervisor_type', '').lower()
        
        if hypervisor_type == 'qemu' or hypervisor_type == 'kvm':
            return QEMUInterface(self.vm_identifier, self.vm_config)
        elif hypervisor_type == 'virtualbox' or hypervisor_type == 'vbox':
            return VirtualBoxInterface(self.vm_identifier, self.vm_config)
        elif hypervisor_type == 'vmware':
            return VMwareInterface(self.vm_identifier, self.vm_config)
        
        # Auto-detection based on available tools
        detection_commands = [
            (['virsh', '--version'], QEMUInterface),
            (['VBoxManage', '--version'], VirtualBoxInterface),
            (['vmrun'], VMwareInterface)
        ]
        
        for cmd, interface_class in detection_commands:
            try:
                result = subprocess.run(cmd, capture_output=True, timeout=5, check=False)
                if result.returncode == 0:
                    logger.info(f"Auto-detected hypervisor: {interface_class.__name__}")
                    return interface_class(self.vm_identifier, self.vm_config)
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        
        # Default to QEMU if nothing else is detected
        logger.warning("Could not detect hypervisor, defaulting to QEMU")
        return QEMUInterface(self.vm_identifier, self.vm_config)
    
    def _load_metadata(self) -> Dict[str, Any]:
        """Load snapshot metadata from file."""
        try:
            if self.metadata_file.exists():
                with open(self.metadata_file, 'r') as f:
                    return json.load(f)
            return {}
        except Exception as e:
            logger.warning(f"Failed to load snapshot metadata: {e}")
            return {}
    
    def _save_metadata(self, metadata: Dict[str, Any]):
        """Save snapshot metadata to file."""
        try:
            with open(self.metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Failed to save snapshot metadata: {e}")
    
    def create_snapshot(self, snapshot_name: str, description: str = "") -> bool:
        """
        Create a VM snapshot.
        
        Args:
            snapshot_name: Name for the snapshot
            description: Optional description
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Validate snapshot name
            if not snapshot_name or not snapshot_name.replace('_', '').replace('-', '').isalnum():
                raise ValueError("Snapshot name must contain only alphanumeric characters, hyphens, and underscores")
            
            # Check if snapshot already exists
            existing_snapshots = self.list_snapshots(detailed=False)
            if any(s['name'] == snapshot_name for s in existing_snapshots):
                logger.error(f"Snapshot '{snapshot_name}' already exists")
                return False
            
            # Create snapshot using hypervisor interface
            success = self.hypervisor.create_snapshot(snapshot_name, description)
            
            if success:
                # Update metadata
                metadata = self._load_metadata()
                metadata[snapshot_name] = {
                    'name': snapshot_name,
                    'description': description,
                    'creation_time': datetime.now().isoformat(),
                    'hypervisor': self.hypervisor.__class__.__name__.replace('Interface', '').lower(),
                    'vm_identifier': self.vm_identifier
                }
                self._save_metadata(metadata)
                
                logger.info(f"Snapshot '{snapshot_name}' created successfully")
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to create snapshot '{snapshot_name}': {e}")
            return False
    
    def restore_snapshot(self, snapshot_name: str) -> bool:
        """
        Restore VM to a specific snapshot.
        
        Args:
            snapshot_name: Name of the snapshot to restore
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Verify snapshot exists
            existing_snapshots = self.list_snapshots(detailed=False)
            if not any(s['name'] == snapshot_name for s in existing_snapshots):
                logger.error(f"Snapshot '{snapshot_name}' not found")
                return False
            
            # Restore snapshot using hypervisor interface
            success = self.hypervisor.restore_snapshot(snapshot_name)
            
            if success:
                logger.info(f"Snapshot '{snapshot_name}' restored successfully")
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to restore snapshot '{snapshot_name}': {e}")
            return False
    
    def delete_snapshot(self, snapshot_name: str) -> bool:
        """
        Delete a specific snapshot.
        
        Args:
            snapshot_name: Name of the snapshot to delete
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Delete snapshot using hypervisor interface
            success = self.hypervisor.delete_snapshot(snapshot_name)
            
            if success:
                # Update metadata
                metadata = self._load_metadata()
                if snapshot_name in metadata:
                    del metadata[snapshot_name]
                    self._save_metadata(metadata)
                
                logger.info(f"Snapshot '{snapshot_name}' deleted successfully")
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to delete snapshot '{snapshot_name}': {e}")
            return False
    
    def list_snapshots(self, detailed: bool = True) -> List[Dict[str, Any]]:
        """
        List all snapshots for the VM.
        
        Args:
            detailed: If True, include metadata from local storage
            
        Returns:
            List of snapshot information dictionaries
        """
        try:
            # Get snapshots from hypervisor
            snapshots = self.hypervisor.list_snapshots()
            
            if detailed:
                # Enhance with metadata
                metadata = self._load_metadata()
                for snapshot in snapshots:
                    snapshot_name = snapshot['name']
                    if snapshot_name in metadata:
                        snapshot.update(metadata[snapshot_name])
            
            return snapshots
            
        except Exception as e:
            logger.error(f"Failed to list snapshots: {e}")
            return []
    
    def get_snapshot_info(self, snapshot_name: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about a specific snapshot.
        
        Args:
            snapshot_name: Name of the snapshot
            
        Returns:
            Snapshot information dictionary or None if not found
        """
        snapshots = self.list_snapshots(detailed=True)
        for snapshot in snapshots:
            if snapshot['name'] == snapshot_name:
                return snapshot
        return None
    
    def cleanup_old_snapshots(self, keep_count: int = 10, 
                            keep_days: int = 30) -> Dict[str, Any]:
        """
        Clean up old snapshots based on count and age criteria.
        
        Args:
            keep_count: Maximum number of snapshots to keep
            keep_days: Maximum age in days for snapshots to keep
            
        Returns:
            Dictionary with cleanup results
        """
        try:
            snapshots = self.list_snapshots(detailed=True)
            
            # Sort by creation time (newest first)
            snapshots.sort(key=lambda x: x.get('creation_time', ''), reverse=True)
            
            deleted_count = 0
            errors = []
            
            # Keep only the most recent snapshots
            snapshots_to_delete = snapshots[keep_count:]
            
            # Also check age-based deletion
            cutoff_time = datetime.now().timestamp() - (keep_days * 24 * 60 * 60)
            
            for snapshot in snapshots_to_delete:
                try:
                    creation_time_str = snapshot.get('creation_time', '')
                    if creation_time_str:
                        creation_time = datetime.fromisoformat(creation_time_str).timestamp()
                        if creation_time < cutoff_time:
                            if self.delete_snapshot(snapshot['name']):
                                deleted_count += 1
                            else:
                                errors.append(f"Failed to delete {snapshot['name']}")
                except Exception as e:
                    errors.append(f"Error processing {snapshot['name']}: {e}")
            
            return {
                'success': len(errors) == 0,
                'deleted_count': deleted_count,
                'errors': errors
            }
            
        except Exception as e:
            logger.error(f"Snapshot cleanup failed: {e}")
            return {
                'success': False,
                'deleted_count': 0,
                'errors': [str(e)]
            }


# Export main class
__all__ = ['SnapshotManager', 'SnapshotError']