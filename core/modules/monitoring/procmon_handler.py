# shikra/core/modules/monitoring/procmon_handler.py
# Purpose: ProcMon handler using UNIFIED VMManager
# SIMPLIFIED: All VM operations through one clean interface

import os
import json
import logging
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta

# ✅ UNIFIED: Single import for ALL VM operations
from ..vm_controller.vm_manager import VMManager

logger = logging.getLogger(__name__)

class ProcMonHandler:
    """
    🎯 SIMPLIFIED ProcMon Handler using Unified VMManager
    
    - Clean, simple VM operations
    - Connection pooling for performance  
    - No more import confusion
    - One interface for everything
    """
    
    def __init__(self, config_settings: dict = None):
        """Initialize ProcMon handler."""
        self.config = config_settings or {}
        self.monitoring_sessions = {}
        
        # Initialize VM manager with VM configuration
        vm_config = self.config.get("vm_config", {})
        self.vm_manager = VMManager(vm_config)
        
        # Tool paths
        self.procmon_tools_path = Path(self.config.get(
            "procmon_tools_path", 
            Path(__file__).parent.parent.parent.parent / "tools" / "procmon"
        ))
        
    def deploy_procmon_to_vm(self, vm_id: str) -> bool:
        """
        Deploy ProcMon executable to target VM.
        
        ✅ SIMPLIFIED: Just 3 clean method calls
        """
        logger.info(f"Deploying ProcMon to VM: {vm_id}")
        
        try:
            # 1. Select and copy ProcMon binary
            procmon_binary = self._select_procmon_binary(vm_id)
            if not procmon_binary:
                return False
            
            vm_procmon_path = "C:\\Windows\\Temp\\procmon.exe"
            if not self.vm_manager.copy_file_to_vm(vm_id, procmon_binary, vm_procmon_path):
                logger.error(f"Failed to copy ProcMon to VM: {vm_id}")
                return False
            
            # 2. Copy PMC config if available
            pmc_config = self._get_pmc_config()
            if pmc_config:
                vm_pmc_path = "C:\\Windows\\Temp\\procmon_config.pmc"
                self.vm_manager.copy_file_to_vm(vm_id, pmc_config, vm_pmc_path)
            
            # 3. Verify deployment
            if not self.vm_manager.vm_file_exists(vm_id, vm_procmon_path):
                logger.error(f"ProcMon deployment verification failed: {vm_id}")
                return False
            
            logger.info(f"✅ ProcMon deployed successfully to VM: {vm_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error deploying ProcMon to VM {vm_id}: {e}")
            return False
    
    def start_monitoring(self, vm_id: str, session_name: str = None, duration_seconds: int = None) -> str:
        """
        Start ProcMon monitoring in VM.
        
        ✅ SIMPLIFIED: Clean command execution
        """
        session_id = session_name or f"procmon_{vm_id}_{int(time.time())}"
        
        logger.info(f"Starting ProcMon monitoring session: {session_id}")
        
        try:
            # Generate VM paths
            vm_log_path = f"C:\\Windows\\Temp\\procmon_log_{session_id}.pml"
            vm_csv_path = f"C:\\Windows\\Temp\\procmon_log_{session_id}.csv"
            
            # Build ProcMon command
            procmon_cmd = self._build_procmon_command(vm_log_path, duration_seconds)
            
            # ✅ SIMPLIFIED: Single method call for command execution
            stdout, stderr, rc = self.vm_manager.execute_command(vm_id, procmon_cmd, timeout=10)
            
            if rc != 0:
                logger.error(f"Failed to start ProcMon. RC: {rc}, Error: {stderr}")
                return None
            
            # Track session
            self.monitoring_sessions[session_id] = {
                "vm_id": vm_id,
                "start_time": datetime.now(),
                "duration_seconds": duration_seconds,
                "vm_log_path": vm_log_path,
                "vm_csv_path": vm_csv_path,
                "status": "running"
            }
            
            logger.info(f"✅ ProcMon monitoring started: {session_id}")
            return session_id
            
        except Exception as e:
            logger.error(f"Error starting ProcMon monitoring: {e}")
            return None
    
    def stop_monitoring(self, session_id: str) -> bool:
        """
        Stop ProcMon monitoring session.
        
        ✅ SIMPLIFIED: Clean stop command
        """
        if session_id not in self.monitoring_sessions:
            logger.error(f"Session not found: {session_id}")
            return False
        
        session = self.monitoring_sessions[session_id]
        logger.info(f"Stopping ProcMon session: {session_id}")
        
        try:
            # ✅ SIMPLIFIED: Single method call to stop ProcMon
            stdout, stderr, rc = self.vm_manager.execute_command(
                session["vm_id"], "taskkill /F /IM procmon.exe", timeout=30
            )
            
            session["status"] = "stopped"
            session["stop_time"] = datetime.now()
            
            logger.info(f"✅ ProcMon monitoring stopped: {session_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error stopping ProcMon: {e}")
            return False
    
    def export_and_collect_logs(self, session_id: str, host_output_dir: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Export logs and collect from VM.
        
        ✅ SIMPLIFIED: Clean file operations
        """
        if session_id not in self.monitoring_sessions:
            logger.error(f"Session not found: {session_id}")
            return None, None
        
        session = self.monitoring_sessions[session_id]
        logger.info(f"Collecting logs for session: {session_id}")
        
        try:
            # Ensure monitoring is stopped
            if session.get("status") == "running":
                self.stop_monitoring(session_id)
                time.sleep(2)
            
            # Export PML to CSV in VM
            export_cmd = (
                f'cd /d C:\\Windows\\Temp && '
                f'procmon.exe /OpenLog "{session["vm_log_path"]}" '
                f'/SaveAs "{session["vm_csv_path"]}" /SaveFormat CSV'
            )
            
            stdout, stderr, rc = self.vm_manager.execute_command(
                session["vm_id"], export_cmd, timeout=120
            )
            
            # Create output directory
            os.makedirs(host_output_dir, exist_ok=True)
            
            # ✅ SIMPLIFIED: Clean file copy operations
            host_pml_path = os.path.join(host_output_dir, f"procmon_log_{session_id}.pml")
            host_csv_path = os.path.join(host_output_dir, f"procmon_log_{session_id}.csv")
            
            # Copy files from VM
            pml_success = self.vm_manager.copy_file_from_vm(
                session["vm_id"], session["vm_log_path"], host_pml_path
            )
            
            csv_success = self.vm_manager.copy_file_from_vm(
                session["vm_id"], session["vm_csv_path"], host_csv_path
            )
            
            # Cleanup VM files
            self._cleanup_vm_files(session)
            
            # Update session
            session["host_pml_path"] = host_pml_path if pml_success else None
            session["host_csv_path"] = host_csv_path if csv_success else None
            session["collection_time"] = datetime.now()
            
            if csv_success:
                logger.info(f"✅ Logs collected successfully: {host_csv_path}")
                return (host_pml_path if pml_success else None, host_csv_path)
            else:
                logger.error("❌ Failed to collect CSV log")
                return None, None
                
        except Exception as e:
            logger.error(f"Error collecting logs: {e}")
            return None, None
    
    def get_session_status(self, session_id: str) -> Dict:
        """Get session status with VM info."""
        if session_id not in self.monitoring_sessions:
            return {"error": "Session not found"}
        
        session = self.monitoring_sessions[session_id].copy()
        
        # Add duration info
        if session.get("start_time"):
            if session.get("stop_time"):
                session["duration"] = (session["stop_time"] - session["start_time"]).total_seconds()
            else:
                session["running_duration"] = (datetime.now() - session["start_time"]).total_seconds()
        
        # Add VM info
        vm_id = session.get("vm_id")
        if vm_id:
            session["vm_info"] = self.vm_manager.get_vm_info(vm_id)
        
        return session
    
    def list_active_sessions(self) -> List[str]:
        """List active monitoring sessions."""
        return [sid for sid, session in self.monitoring_sessions.items() 
                if session.get("status") == "running"]
    
    def cleanup_session(self, session_id: str) -> bool:
        """Clean up session and VM files."""
        if session_id not in self.monitoring_sessions:
            return False
        
        session = self.monitoring_sessions[session_id]
        
        try:
            # Stop if running
            if session.get("status") == "running":
                self.stop_monitoring(session_id)
            
            # Cleanup VM files
            self._cleanup_vm_files(session)
            
            # Remove session
            del self.monitoring_sessions[session_id]
            
            logger.info(f"✅ Session cleaned up: {session_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error cleaning up session {session_id}: {e}")
            return False
    
    def close(self):
        """Close VM connections."""
        self.vm_manager.close_all_connections()
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
    
    # =========================
    # PRIVATE HELPER METHODS
    # =========================
    
    def _select_procmon_binary(self, vm_id: str) -> Optional[str]:
        """Select appropriate ProcMon binary."""
        # Detect VM architecture
        stdout, stderr, rc = self.vm_manager.execute_command(
            vm_id, "wmic computersystem get systemtype", timeout=30
        )
        
        if rc == 0 and stdout:
            arch_info = stdout.lower()
            if "arm64" in arch_info:
                binary_name = "procmon64a.exe"
            elif "x64" in arch_info or "amd64" in arch_info:
                binary_name = "procmon64.exe"
            else:
                binary_name = "procmon.exe"
        else:
            binary_name = "procmon64.exe"  # Default
            logger.warning("Could not detect architecture, using default")
        
        binary_path = self.procmon_tools_path / binary_name
        
        if binary_path.exists():
            logger.info(f"Selected ProcMon binary: {binary_name}")
            return str(binary_path)
        else:
            logger.error(f"ProcMon binary not found: {binary_path}")
            return None
    
    def _get_pmc_config(self) -> Optional[str]:
        """Get PMC configuration file path."""
        config_path = self.procmon_tools_path.parent.parent / "config" / "procmon" / "procmon_config.pmc"
        return str(config_path) if config_path.exists() else None
    
    def _build_procmon_command(self, vm_log_path: str, duration_seconds: int = None) -> str:
        """Build ProcMon execution command."""
        cmd_parts = [
            "cd /d C:\\Windows\\Temp &&",
            "procmon.exe",
            "/AcceptEula",
            "/Quiet",
            "/Minimized", 
            f'/BackingFile "{vm_log_path}"'
        ]
        
        # Add config if available
        if self.vm_manager.vm_file_exists(self.monitoring_sessions.get("vm_id", ""), "C:\\Windows\\Temp\\procmon_config.pmc"):
            cmd_parts.append("/LoadConfig procmon_config.pmc")
        
        # Add duration
        if duration_seconds:
            cmd_parts.append(f"/Runtime {duration_seconds}")
        
        return " ".join(cmd_parts)
    
    def _cleanup_vm_files(self, session: Dict):
        """Clean up temporary files in VM."""
        vm_id = session.get("vm_id")
        if not vm_id:
            return
        
        cleanup_files = [
            session.get("vm_log_path"),
            session.get("vm_csv_path"),
            "C:\\Windows\\Temp\\procmon.exe",
            "C:\\Windows\\Temp\\procmon_config.pmc"
        ]
        
        for file_path in cleanup_files:
            if file_path:
                try:
                    self.vm_manager.execute_command(
                        vm_id, f'del /F /Q "{file_path}" 2>nul', timeout=10
                    )
                except:
                    pass  # Ignore cleanup errors


# ✅ SIMPLIFIED INTEGRATION FUNCTION
def monitor_vm_behavior(vm_id: str, vm_config: dict, duration_seconds: int = 300,
                       output_dir: str = "logs/monitoring") -> Tuple[bool, Optional[str]]:
    """
    Complete monitoring workflow using unified VMManager.
    
    ✅ CLEAN: No more complex VM management
    """
    config = {"vm_config": {"vms": vm_config.get("vms", {})}}
    
    with ProcMonHandler(config) as handler:
        try:
            # Deploy -> Monitor -> Collect
            if not handler.deploy_procmon_to_vm(vm_id):
                return False, None
            
            session_id = handler.start_monitoring(vm_id, duration_seconds=duration_seconds)
            if not session_id:
                return False, None
            
            logger.info(f"Monitoring for {duration_seconds} seconds...")
            time.sleep(duration_seconds + 5)
            
            pml_path, csv_path = handler.export_and_collect_logs(session_id, output_dir)
            handler.cleanup_session(session_id)
            
            if csv_path and os.path.exists(csv_path):
                logger.info(f"✅ Monitoring completed: {csv_path}")
                return True, csv_path
            else:
                return False, None
                
        except Exception as e:
            logger.error(f"Monitoring workflow error: {e}")
            return False, None


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Example config
    config = {
        "vm_config": {
            "vms": {
                "win10-test": {
                    "ip": "192.168.122.100",
                    "guest_os_type": "windows",
                    "user": "Administrator",
                    "password": "password123"
                }
            }
        }
    }
    
    # ✅ SIMPLE USAGE
    with ProcMonHandler(config) as handler:
        print("✅ ProcMon Handler using Unified VMManager")
        print("   - Single VM interface: ✅")
        print("   - Connection pooling: ✅")
        print("   - Clean error handling: ✅")
        print("   - Simple operations: ✅")