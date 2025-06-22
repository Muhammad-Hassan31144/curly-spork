

#!/usr/bin/env python3
# Purpose: Advanced filtering engine for noise reduction and intelligent event filtering.
# This version is specifically designed to parse and apply complex, hierarchical JSON configurations.

import re
import json
import logging
import os
from typing import Dict, List, Optional
from pathlib import Path
from collections import defaultdict

logger = logging.getLogger(__name__)

# --- Configuration Discovery Logic ---

def find_config_path(filename: str) -> Optional[Path]:
    """
    Finds a configuration file by searching in standard project locations.
    """
    # List of common root directories for the 'config/procmon' structure
    base_paths = [
        Path.cwd(),
        Path.cwd().parent,
        Path.cwd().parent.parent,
        Path.home() / ".shikra",
        Path("/etc/shikra"),
    ]
    
    for base in base_paths:
        config_path = base / "config" / "procmon" / filename
        if config_path.is_file():
            logger.info(f"Discovered configuration file: {config_path}")
            return config_path
            
    logger.warning(f"Could not find '{filename}' in any standard directory.")
    return None

# --- Filter Classes ---

class NoiseFilter:
    """Handles loading and application of noise-reduction filter rules."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initializes the noise filter, automatically finding the config if no path is provided."""
        self.rules = defaultdict(list)
        self.compiled_patterns = defaultdict(list)
        
        # [FIX] Use the find_config_path helper for robust discovery.
        actual_path = config_path or find_config_path("noise_filters.json")
        
        if actual_path:
            config = self._load_json(str(actual_path))
            if config:
                self._parse_config(config)
                self._compile_patterns()
        else:
            logger.error("No noise filter configuration file provided or found.")

    def _load_json(self, path: str) -> Dict:
        try:
            with open(path, 'r') as f:
                logger.info(f"Loading noise configuration from {path}")
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.error(f"Error loading or parsing noise config {path}: {e}")
        return {}

    def _parse_config(self, config: Dict):
        """Recursively parses the noise filter config to extract all rule lists."""
        def recurse_extract(node):
            if isinstance(node, dict):
                for key, value in node.items():
                    if isinstance(value, list):
                        if "process" in key or "filter" in key:
                            self.rules["process_patterns"].extend(value)
                        elif "path" in key or "operations" in key or "files" in key:
                            self.rules["path_patterns"].extend(value)
                        elif "operation" in key:
                             self.rules["operation_exclusions"].extend(value)
                        elif "result" in key:
                            self.rules["result_exclusions"].extend(value)
                    elif isinstance(value, dict):
                        recurse_extract(value)
        
        recurse_extract(config)

    def _compile_patterns(self):
        """Compiles regex patterns from the parsed rule lists."""
        for key in ["process_patterns", "path_patterns"]:
            for pattern in self.rules.get(key, []):
                try:
                    self.compiled_patterns[key].append(re.compile(pattern, re.IGNORECASE))
                except re.error as e:
                    logger.warning(f"Invalid regex for noise rule '{key}': {pattern} - {e}")

    def check_event(self, process_name: str, operation: str, path: str, result: str) -> Optional[str]:
        """Checks if an event matches any noise exclusion criteria."""
        for pattern in self.compiled_patterns["process_patterns"]:
            if pattern.fullmatch(process_name):
                return "noise_process"
        
        if operation in self.rules["operation_exclusions"]:
            return "noise_operation"
        
        if result in self.rules["result_exclusions"]:
            return "noise_result"
        
        for pattern in self.compiled_patterns["path_patterns"]:
            if pattern.search(path):
                return "noise_path"
        
        return None

class BehavioralFilter:
    """Handles loading and application of high-interest and malware pattern rules."""

    def __init__(self, behavioral_path: Optional[str] = None, malware_path: Optional[str] = None):
        """Initializes the behavioral filter, automatically finding configs if no paths are provided."""
        self.rules = defaultdict(list)
        self.compiled_patterns = defaultdict(list)
        
        # [FIX] Use the find_config_path helper for robust discovery.
        actual_behavioral_path = behavioral_path or find_config_path("behavioral_filters.json")
        actual_malware_path = malware_path or find_config_path("malware_patterns.json")
        
        self._parse_configs(actual_behavioral_path, actual_malware_path)
        self._compile_patterns()

    def _load_json(self, path: Optional[str]) -> Dict:
        if not path: return {}
        try:
            with open(path, 'r') as f:
                logger.info(f"Loading behavioral/malware configuration from {path}")
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.error(f"Error loading or parsing config {path}: {e}")
        return {}

    def _parse_configs(self, behavioral_path: Optional[str], malware_path: Optional[str]):
        """Parses behavioral and malware pattern JSON files into rule lists."""
        behavioral_config = self._load_json(behavioral_path)
        malware_config = self._load_json(malware_path)

        self.rules['high_value_operations'].extend(behavioral_config.get("high_value_operations", []))
        self.rules['process_whitelist'].extend(behavioral_config.get("process_whitelist", []))
        self.rules['path_patterns'].extend(behavioral_config.get("high_value_paths", []))
        self.rules['path_patterns'].extend(malware_config.get("suspicious_file_patterns", []))
        self.rules['registry_patterns'].extend(malware_config.get("registry_whitelist_patterns", []))

    def _compile_patterns(self):
        """Compiles regex patterns from the parsed rule lists."""
        for key in ["path_patterns", "registry_patterns"]:
             for pattern in self.rules.get(key, []):
                try:
                    self.compiled_patterns[key].append(re.compile(pattern, re.IGNORECASE))
                except re.error as e:
                    logger.warning(f"Invalid regex for behavioral rule '{key}': {pattern} - {e}")

    def check_event(self, process_name: str, operation: str, path: str) -> Optional[str]:
        """Checks if an event matches any high-interest criteria."""
        if operation in self.rules["high_value_operations"]:
            return "high_value_operation"
        
        # Use exact match for whitelisted processes
        if process_name.lower() in [p.lower() for p in self.rules["process_whitelist"]]:
            return "process_whitelist"

        for pattern in self.compiled_patterns["path_patterns"]:
            if pattern.search(path):
                return "behavioral_path"

        for pattern in self.compiled_patterns["registry_patterns"]:
            if pattern.search(path):
                return "behavioral_registry"

        return None

class FilterEngine:
    """Orchestrates noise and behavioral filters to make a final decision on processing an event."""
    
    def __init__(self, noise_filter: Optional[NoiseFilter] = None, behavioral_filter: Optional[BehavioralFilter] = None):
        self.stats = defaultdict(lambda: defaultdict(int))
        self.noise_filter = noise_filter
        self.behavioral_filter = behavioral_filter
        logger.info("FilterEngine orchestrator initialized.")

    def should_process_event(self, event: Dict) -> bool:
        """Determines if an event should be processed or filtered out."""
        self.stats["tally"]["total_events"] += 1
        
        process_name = event.get("Process Name", "")
        operation = event.get("Operation", "")
        path = event.get("Path", "")
        result = event.get("Result", "")
        
        # 1. Check for high-interest events to explicitly include.
        if self.behavioral_filter:
            behavioral_match = self.behavioral_filter.check_event(process_name, operation, path)
            if behavioral_match:
                self.stats["tally"]["filtered_in"] += 1
                self.stats["matches"][behavioral_match] += 1
                return True
            
        # 2. Check for noise events to explicitly exclude.
        if self.noise_filter:
            noise_match = self.noise_filter.check_event(process_name, operation, path, result)
            if noise_match:
                self.stats["tally"]["filtered_out"] += 1
                self.stats["matches"][noise_match] += 1
                return False
        
        # 3. Default action: keep events that don't match any specific rule.
        self.stats["tally"]["filtered_in"] += 1
        self.stats["matches"]["default_include"] += 1
        return True

    def get_statistics(self) -> Dict:
        """Returns a dictionary of filtering statistics."""
        total = self.stats["tally"]["total_events"]
        if total == 0:
            return {"message": "No events processed."}
        
        return {
            "total_events_processed": total,
            "events_included": self.stats["tally"]["filtered_in"],
            "events_excluded": self.stats["tally"]["filtered_out"],
            "filter_efficiency_percent": (self.stats["tally"]["filtered_out"] / total) * 100,
            "filter_match_breakdown": dict(self.stats["matches"])
        }

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(name)s - %(levelname)s - %(message)s')

    # Example demonstrates usage with the new, more robust path discovery.
    # No need to specify paths if they are in standard locations.
    
    # 1. Create instances of the individual filter classes. They will find their own configs.
    noise_filter_instance = NoiseFilter()
    behavioral_filter_instance = BehavioralFilter()

    # 2. Initialize the main FilterEngine with these instances
    filter_engine = FilterEngine(
        noise_filter=noise_filter_instance,
        behavioral_filter=behavioral_filter_instance
    )

    # --- Test Events ---
    test_events = [
        {"Process Name": "svchost.exe", "Operation": "QueryNameInformationFile", "Path": "C:\\Windows\\System32\\kernel32.dll", "Result": "SUCCESS"},
        {"Process Name": "malware.exe", "Operation": "RegSetValue", "Path": "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater", "Result": "SUCCESS"},
        {"Process Name": "powershell.exe", "Operation": "Process Create", "Path": "C:\\Windows\\System32\\whoami.exe", "Result": "SUCCESS"},
        {"Process Name": "legit.exe", "Operation": "WriteFile", "Path": "C:\\Users\\Admin\\Documents\\report.docx", "Result": "SUCCESS"},
    ]

    print("\n--- Testing Refactored Filter Engine ---")
    for i, event in enumerate(test_events):
        should_process = filter_engine.should_process_event(event)
        result_text = 'PROCESS' if should_process else 'FILTER OUT'
        print(f"Event {i+1}: {event['Process Name']:<15} | {event['Operation']:<25} -> {result_text}")

    print("\n--- Final Statistics ---")
    stats = filter_engine.get_statistics()
    print(json.dumps(stats, indent=2))
