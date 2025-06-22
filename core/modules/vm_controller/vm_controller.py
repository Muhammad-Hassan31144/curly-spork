#!/usr/bin/env python3
"""
Comprehensive VM Controller Integration for Shikra

This module provides the main VMController class that integrates all VM operations
including snapshots, file transfers, command execution, and stealth configuration.

Usage:
    from shikra.core.modules.vm_controller import VMController, execute_complete_analysis
    
    with VMController('vm_name', config) as vm:
        vm.create_snapshot('baseline')
        vm.execute_command('echo test')
        vm.copy_file_to_vm('local.txt', 'remote.txt')
"""

import json
import logging
import time
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from contextlib import contextmanager

# Import individual VM controller components
from .snapshot import SnapshotManager
from .copy_to_vm import copy_to_guest
from .copy_from_vm import copy_from_guest
from .run_in_vm import execute_command_in_guest
from .stealth import (
    AdvancedStealthManager, 
    apply_stealth_to_vm, 
    validate_vm_stealth,
    generate_random_mac_address,
    get_stealth_qemu_args
)

logger = logging.getLogger(__name__)

class VMState(Enum):
    """VM states for tracking VM status."""
    UNKNOWN = "unknown"
    RUNNING = "running"
    STOPPED = "stopped"
    PAUSED = "paused"
    STARTING = "starting"
    STOPPING = "stopping"
    ERROR = "error"

class VMController:
    """
    Comprehensive VM Controller that integrates all VM operations.
    
    This class provides a unified interface for:
    - VM snapshot management
    - File operations (copy to/from VM)
    - Command execution in VMs
    - Stealth configuration and anti-detection
    - Complete malware analysis workflows
    """
    
    def __init__(self, vm_identifier: str, config: Dict[str, Any]):
        """
        Initialize VM Controller.
        
        Args:
            vm_identifier: Name/ID of the VM
            config: Configuration dictionary containing VM details
        """
        self.vm_identifier = vm_identifier
        self.config = config
        
        # Validate VM exists in config
        if vm_identifier not in config.get('vms', {}):
            raise ValueError(f"VM '{vm_identifier}' not found in configuration")
        
        self.vm_config = config['vms'][vm_identifier]
        self.guest_os_type = self.vm_config.get('guest_os_type', 'windows').lower()
        
        # Initialize managers
        self.snapshot_manager = SnapshotManager(vm_identifier, config)
        self.stealth_manager = None  # Initialized on demand
        
        # Operation tracking
        self.operation_history: List[Dict[str, Any]] = []
        
        logger.info(f"VM Controller initialized for '{vm_identifier}' ({self.guest_os_type})")
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with cleanup."""
        try:
            if self.stealth_manager:
                # Cleanup any stealth artifacts if manager was used
                self.stealth_manager.cleanup_stealth_artifacts()
        except Exception as e:
            logger.warning(f"Error during cleanup: {e}")
        
        if exc_type:
            logger.error(f"VM Controller exiting with exception: {exc_val}")
        return False
    
    def _record_operation(self, operation_type: str, success: bool, 
                         duration: float, details: Dict[str, Any] = None):
        """Record operation in history for tracking."""
        operation = {
            'timestamp': datetime.now().isoformat(),
            'operation_type': operation_type,
            'success': success,
            'duration': duration,
            'details': details or {}
        }
        self.operation_history.append(operation)
        
        # Keep only last 100 operations
        if len(self.operation_history) > 100:
            self.operation_history = self.operation_history[-100:]
    
    # ===== VM STATUS AND INFO =====
    
    def get_vm_status(self) -> Dict[str, Any]:
        """Get comprehensive VM status information."""
        start_time = time.time()
        
        try:
            # Get snapshot information
            snapshots = self.snapshot_manager.list_snapshots(detailed=False)
            
            # Determine VM state (this would need to be implemented based on hypervisor)
            current_state = self._detect_vm_state()
            
            status = {
                'vm_identifier': self.vm_identifier,
                'vm_name': self.vm_config.get('name', self.vm_identifier),
                'guest_os_type': self.guest_os_type,
                'current_state': current_state,
                'ip_address': self.vm_config.get('ip'),
                'total_snapshots': len(snapshots),
                'recent_snapshots': [s['name'] for s in snapshots[-3:]],
                'total_operations': len(self.operation_history),
                'last_operation': self.operation_history[-1] if self.operation_history else None
            }
            
            self._record_operation('get_vm_status', True, time.time() - start_time)
            return status
            
        except Exception as e:
            self._record_operation('get_vm_status', False, time.time() - start_time, {'error': str(e)})
            logger.error(f"Failed to get VM status: {e}")
            return {
                'vm_identifier': self.vm_identifier,
                'current_state': VMState.ERROR.value,
                'error': str(e)
            }
    
    def _detect_vm_state(self) -> str:
        """
        Detect current VM state. This is a placeholder that should be 
        implemented based on the hypervisor being used.
        """
        try:
            # Try to execute a simple command to check if VM is responsive
            stdout, stderr, rc = execute_command_in_guest(
                self.vm_identifier, 'echo "status_check"', self.config, timeout_sec=10
            )
            
            if rc == 0 and 'status_check' in stdout:
                return VMState.RUNNING.value
            else:
                return VMState.STOPPED.value
                
        except Exception:
            return VMState.UNKNOWN.value
    
    # ===== SNAPSHOT OPERATIONS =====
    
    def create_snapshot(self, snapshot_name: str, description: str = "") -> bool:
        """Create a VM snapshot."""
        start_time = time.time()
        
        try:
            success = self.snapshot_manager.create_snapshot(snapshot_name, description)
            self._record_operation('create_snapshot', success, time.time() - start_time, 
                                 {'snapshot_name': snapshot_name})
            return success
            
        except Exception as e:
            self._record_operation('create_snapshot', False, time.time() - start_time, 
                                 {'snapshot_name': snapshot_name, 'error': str(e)})
            logger.error(f"Failed to create snapshot '{snapshot_name}': {e}")
            return False
    
    def restore_snapshot(self, snapshot_name: str) -> bool:
        """Restore VM to a specific snapshot."""
        start_time = time.time()
        
        try:
            success = self.snapshot_manager.restore_snapshot(snapshot_name)
            self._record_operation('restore_snapshot', success, time.time() - start_time,
                                 {'snapshot_name': snapshot_name})
            return success
            
        except Exception as e:
            self._record_operation('restore_snapshot', False, time.time() - start_time,
                                 {'snapshot_name': snapshot_name, 'error': str(e)})
            logger.error(f"Failed to restore snapshot '{snapshot_name}': {e}")
            return False
    
    def delete_snapshot(self, snapshot_name: str) -> bool:
        """Delete a specific snapshot."""
        start_time = time.time()
        
        try:
            success = self.snapshot_manager.delete_snapshot(snapshot_name)
            self._record_operation('delete_snapshot', success, time.time() - start_time,
                                 {'snapshot_name': snapshot_name})
            return success
            
        except Exception as e:
            self._record_operation('delete_snapshot', False, time.time() - start_time,
                                 {'snapshot_name': snapshot_name, 'error': str(e)})
            logger.error(f"Failed to delete snapshot '{snapshot_name}': {e}")
            return False
    
    def list_snapshots(self, detailed: bool = True) -> List[Dict[str, Any]]:
        """List all snapshots for the VM."""
        start_time = time.time()
        
        try:
            snapshots = self.snapshot_manager.list_snapshots(detailed=detailed)
            self._record_operation('list_snapshots', True, time.time() - start_time)
            return snapshots
            
        except Exception as e:
            self._record_operation('list_snapshots', False, time.time() - start_time, {'error': str(e)})
            logger.error(f"Failed to list snapshots: {e}")
            return []
    
    # ===== COMMAND EXECUTION =====
    
    def execute_command(self, command: str, timeout_sec: int = 60) -> Tuple[str, str, int]:
        """Execute a command in the VM."""
        start_time = time.time()
        
        try:
            stdout, stderr, rc = execute_command_in_guest(
                self.vm_identifier, command, self.config, timeout_sec=timeout_sec
            )
            
            self._record_operation('execute_command', rc == 0, time.time() - start_time,
                                 {'command': command[:100], 'return_code': rc})
            return stdout, stderr, rc
            
        except Exception as e:
            self._record_operation('execute_command', False, time.time() - start_time,
                                 {'command': command[:100], 'error': str(e)})
            logger.error(f"Failed to execute command '{command}': {e}")
            return "", str(e), -1
    
    # ===== FILE OPERATIONS =====
    
    def copy_file_to_vm(self, local_path: str, remote_path: str) -> bool:
        """Copy a file from host to VM."""
        start_time = time.time()
        
        try:
            success = copy_to_guest(self.vm_identifier, local_path, remote_path, self.config)
            self._record_operation('copy_file_to_vm', success, time.time() - start_time,
                                 {'local_path': local_path, 'remote_path': remote_path})
            return success
            
        except Exception as e:
            self._record_operation('copy_file_to_vm', False, time.time() - start_time,
                                 {'local_path': local_path, 'remote_path': remote_path, 'error': str(e)})
            logger.error(f"Failed to copy file to VM: {e}")
            return False
    
    def copy_file_from_vm(self, remote_path: str, local_path: str) -> bool:
        """Copy a file from VM to host."""
        start_time = time.time()
        
        try:
            success = copy_from_guest(self.vm_identifier, remote_path, local_path, self.config)
            self._record_operation('copy_file_from_vm', success, time.time() - start_time,
                                 {'remote_path': remote_path, 'local_path': local_path})
            return success
            
        except Exception as e:
            self._record_operation('copy_file_from_vm', False, time.time() - start_time,
                                 {'remote_path': remote_path, 'local_path': local_path, 'error': str(e)})
            logger.error(f"Failed to copy file from VM: {e}")
            return False
    
    # ===== STEALTH OPERATIONS =====
    
    def get_stealth_configuration(self) -> Dict[str, Any]:
        """Get stealth configuration for the VM."""
        try:
            # Generate stealth configuration
            stealth_profile = self.vm_config.get('stealth_profile', {})
            
            # Generate random MAC
            random_mac = generate_random_mac_address()
            
            # Generate QEMU args if applicable
            qemu_args = get_stealth_qemu_args({'stealth_options': stealth_profile})
            
            return {
                'vm_identifier': self.vm_identifier,
                'stealth_profile': stealth_profile,
                'random_mac': random_mac,
                'qemu_args': qemu_args
            }
            
        except Exception as e:
            logger.error(f"Failed to get stealth configuration: {e}")
            return {'error': str(e)}
    
    def apply_stealth_measures(self, stealth_level: str = "advanced") -> Dict[str, Any]:
        """Apply stealth measures to the VM."""
        start_time = time.time()
        
        try:
            if not self.stealth_manager:
                self.stealth_manager = AdvancedStealthManager(self.vm_identifier, self.config)
            
            # Apply stealth measures
            results = apply_stealth_to_vm(self.vm_identifier, self.config, stealth_level)
            
            self._record_operation('apply_stealth_measures', results.get('success', False), 
                                 time.time() - start_time, {'stealth_level': stealth_level})
            return results
            
        except Exception as e:
            self._record_operation('apply_stealth_measures', False, time.time() - start_time,
                                 {'stealth_level': stealth_level, 'error': str(e)})
            logger.error(f"Failed to apply stealth measures: {e}")
            return {'success': False, 'error': str(e)}
    
    def validate_stealth_effectiveness(self) -> Dict[str, Any]:
        """Validate the effectiveness of applied stealth measures."""
        start_time = time.time()
        
        try:
            results = validate_vm_stealth(self.vm_identifier, self.config)
            self._record_operation('validate_stealth_effectiveness', True, time.time() - start_time)
            return results
            
        except Exception as e:
            self._record_operation('validate_stealth_effectiveness', False, time.time() - start_time,
                                 {'error': str(e)})
            logger.error(f"Failed to validate stealth effectiveness: {e}")
            return {'success': False, 'error': str(e)}
    
    # ===== HIGH-LEVEL ANALYSIS WORKFLOWS =====
    
    def prepare_analysis_environment(self, setup_commands: List[str] = None,
                                   tools_to_copy: List[Dict[str, str]] = None,
                                   create_baseline: bool = True) -> Dict[str, Any]:
        """Prepare VM environment for malware analysis."""
        start_time = time.time()
        results = {
            'success': True,
            'commands_executed': [],
            'tools_copied': [],
            'baseline_snapshot': None,
            'errors': []
        }
        
        try:
            # Execute setup commands
            if setup_commands:
                for cmd in setup_commands:
                    stdout, stderr, rc = self.execute_command(cmd, timeout_sec=60)
                    results['commands_executed'].append({
                        'command': cmd,
                        'success': rc == 0,
                        'output': stdout if rc == 0 else stderr
                    })
                    if rc != 0:
                        results['errors'].append(f"Setup command failed: {cmd}")
                        results['success'] = False
            
            # Copy analysis tools
            if tools_to_copy:
                for tool in tools_to_copy:
                    local_path = tool.get('local_path')
                    remote_path = tool.get('remote_path')
                    
                    if local_path and remote_path and Path(local_path).exists():
                        if self.copy_file_to_vm(local_path, remote_path):
                            results['tools_copied'].append(tool['name'])
                        else:
                            results['errors'].append(f"Failed to copy tool: {tool['name']}")
                            results['success'] = False
            
            # Create baseline snapshot
            if create_baseline:
                snapshot_name = f"baseline_{int(time.time())}"
                if self.create_snapshot(snapshot_name, "Analysis environment baseline"):
                    results['baseline_snapshot'] = snapshot_name
                else:
                    results['errors'].append("Failed to create baseline snapshot")
                    results['success'] = False
            
            self._record_operation('prepare_analysis_environment', results['success'], 
                                 time.time() - start_time)
            
        except Exception as e:
            results['success'] = False
            results['errors'].append(str(e))
            self._record_operation('prepare_analysis_environment', False, time.time() - start_time,
                                 {'error': str(e)})
            logger.error(f"Failed to prepare analysis environment: {e}")
        
        return results
    
    def execute_malware_analysis(self, malware_sample_path: str, analysis_duration: int = 300,
                                collect_artifacts: List[str] = None,
                                pre_execution_snapshot: bool = True,
                                post_execution_snapshot: bool = True) -> Dict[str, Any]:
        """Execute malware analysis workflow."""
        start_time = time.time()
        results = {
            'success': True,
            'malware_sample': malware_sample_path,
            'pre_execution_snapshot': None,
            'post_execution_snapshot': None,
            'execution_output': None,
            'artifacts_collected': [],
            'errors': []
        }
        
        try:
            # Create pre-execution snapshot
            if pre_execution_snapshot:
                pre_snapshot = f"pre_execution_{int(time.time())}"
                if self.create_snapshot(pre_snapshot, "Pre-malware execution snapshot"):
                    results['pre_execution_snapshot'] = pre_snapshot
                else:
                    results['errors'].append("Failed to create pre-execution snapshot")
            
            # Copy malware sample to VM
            sample_name = Path(malware_sample_path).name
            if self.guest_os_type == 'windows':
                remote_sample_path = f"C:\\Temp\\{sample_name}"
            else:
                remote_sample_path = f"/tmp/{sample_name}"
            
            if not self.copy_file_to_vm(malware_sample_path, remote_sample_path):
                results['errors'].append("Failed to copy malware sample to VM")
                results['success'] = False
                return results
            
            # Execute malware sample
            if self.guest_os_type == 'windows':
                exec_cmd = f'"{remote_sample_path}"'
            else:
                exec_cmd = f'chmod +x "{remote_sample_path}" && "{remote_sample_path}"'
            
            stdout, stderr, rc = self.execute_command(exec_cmd, timeout_sec=analysis_duration)
            results['execution_output'] = {
                'command': exec_cmd,
                'stdout': stdout,
                'stderr': stderr,
                'return_code': rc
            }
            
            # Wait for analysis duration
            if analysis_duration > 30:  # If we have time, let it run
                time.sleep(min(30, analysis_duration - 30))  # Wait additional time
            
            # Collect artifacts
            if collect_artifacts:
                for artifact_path in collect_artifacts:
                    local_artifact = f"/tmp/artifact_{int(time.time())}_{Path(artifact_path).name}"
                    if self.copy_file_from_vm(artifact_path, local_artifact):
                        results['artifacts_collected'].append(local_artifact)
            
            # Create post-execution snapshot
            if post_execution_snapshot:
                post_snapshot = f"post_execution_{int(time.time())}"
                if self.create_snapshot(post_snapshot, "Post-malware execution snapshot"):
                    results['post_execution_snapshot'] = post_snapshot
                else:
                    results['errors'].append("Failed to create post-execution snapshot")
            
            self._record_operation('execute_malware_analysis', results['success'], 
                                 time.time() - start_time)
            
        except Exception as e:
            results['success'] = False
            results['errors'].append(str(e))
            self._record_operation('execute_malware_analysis', False, time.time() - start_time,
                                 {'error': str(e)})
            logger.error(f"Failed to execute malware analysis: {e}")
        
        return results
    
    def cleanup_analysis_session(self, keep_recent_snapshots: int = 5) -> Dict[str, Any]:
        """Clean up analysis session artifacts."""
        start_time = time.time()
        results = {
            'success': True,
            'snapshots_pruned': False,
            'errors': []
        }
        
        try:
            # Clean up old snapshots (keep only recent ones)
            snapshots = self.list_snapshots(detailed=False)
            if len(snapshots) > keep_recent_snapshots:
                snapshots_to_delete = snapshots[:-keep_recent_snapshots]
                
                for snapshot in snapshots_to_delete:
                    if not self.delete_snapshot(snapshot['name']):
                        results['errors'].append(f"Failed to delete snapshot: {snapshot['name']}")
                        results['success'] = False
                
                results['snapshots_pruned'] = True
            
            # Clean up stealth artifacts if stealth manager was used
            if self.stealth_manager:
                cleanup_results = self.stealth_manager.cleanup_stealth_artifacts()
                if not cleanup_results.get('success', True):
                    results['errors'].extend(cleanup_results.get('cleanup_errors', []))
                    results['success'] = False
            
            self._record_operation('cleanup_analysis_session', results['success'], 
                                 time.time() - start_time)
            
        except Exception as e:
            results['success'] = False
            results['errors'].append(str(e))
            self._record_operation('cleanup_analysis_session', False, time.time() - start_time,
                                 {'error': str(e)})
            logger.error(f"Failed to cleanup analysis session: {e}")
        
        return results
    
    def get_operation_history(self, last_n: int = 10) -> List[Dict[str, Any]]:
        """Get recent operation history."""
        return self.operation_history[-last_n:] if last_n else self.operation_history


# ===== HIGH-LEVEL CONVENIENCE FUNCTIONS =====

def execute_complete_analysis(vm_identifier: str, config: Dict[str, Any],
                             malware_sample_path: str, analysis_duration: int = 300,
                             setup_commands: List[str] = None,
                             analysis_tools: List[Dict[str, str]] = None,
                             collect_artifacts: List[str] = None) -> Dict[str, Any]:
    """
    Execute a complete malware analysis workflow.
    
    This high-level function orchestrates the entire analysis process:
    1. Prepare analysis environment
    2. Execute malware analysis
    3. Collect artifacts
    4. Clean up
    
    Args:
        vm_identifier: VM to use for analysis
        config: VM configuration
        malware_sample_path: Path to malware sample
        analysis_duration: How long to run analysis (seconds)
        setup_commands: Commands to prepare environment
        analysis_tools: Tools to copy to VM
        collect_artifacts: Paths of artifacts to collect
    
    Returns:
        Dictionary with complete analysis results
    """
    overall_start_time = time.time()
    
    with VMController(vm_identifier, config) as controller:
        # Environment preparation
        env_results = controller.prepare_analysis_environment(
            setup_commands=setup_commands,
            tools_to_copy=analysis_tools,
            create_baseline=True
        )
        
        # Malware analysis
        analysis_results = controller.execute_malware_analysis(
            malware_sample_path=malware_sample_path,
            analysis_duration=analysis_duration,
            collect_artifacts=collect_artifacts,
            pre_execution_snapshot=True,
            post_execution_snapshot=True
        )
        
        # Cleanup
        cleanup_results = controller.cleanup_analysis_session()
        
        # Final VM status
        vm_status = controller.get_vm_status()
        
        return {
            'overall_success': (env_results['success'] and 
                              analysis_results['success'] and 
                              cleanup_results['success']),
            'execution_time': time.time() - overall_start_time,
            'vm_identifier': vm_identifier,
            'malware_sample': malware_sample_path,
            'environment_preparation': env_results,
            'malware_analysis': analysis_results,
            'cleanup': cleanup_results,
            'vm_status': vm_status
        }


def create_vm_controller(vm_identifier: str, config: Dict[str, Any]) -> VMController:
    """
    Factory function to create a VM controller instance.
    
    Args:
        vm_identifier: VM name/ID
        config: Configuration dictionary
        
    Returns:
        VMController instance
    """
    return VMController(vm_identifier, config)


# Export main classes and functions
__all__ = [
    'VMController',
    'VMState', 
    'execute_complete_analysis',
    'create_vm_controller'
]