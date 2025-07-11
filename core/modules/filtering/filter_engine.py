"""
Runtime Filter Engine (filter_engine.py)

Purpose:
High-performance runtime filtering engine that applies pre-generated filters
to analysis events in real-time. Provides fast filtering decisions for
behavioral monitoring, network analysis, and other analysis components.

Context in Shikra:
- Input: Real-time analysis events (ProcMon, network, etc.)
- Processing: Fast pattern matching against loaded filter sets
- Output: Boolean decisions (filter/keep) + optional metadata

Integration Points:
- Used by: behavioral_processor.py, network_analyzer.py, procmon_handler.py
- Loads filters from: config/filters/ (generated by generator.py)
- Managed by: filter_manager.py (CRUD operations)
- Validated by: filter_validator.py (effectiveness testing)
"""

import logging
import json
import re
import threading
from pathlib import Path
from typing import Dict, List, Set, Any, Optional, Tuple, Union
from collections import defaultdict, Counter
from datetime import datetime
import time

logger = logging.getLogger(__name__)

class FilterEngine:
    """
    High-performance runtime filtering engine for real-time analysis events.
    
    Provides fast filtering decisions using pre-compiled filter patterns
    for behavioral monitoring, network analysis, and other components.
    Thread-safe and optimized for high-throughput analysis scenarios.
    """
    
    def __init__(self, config_dir: Optional[Path] = None):
        """
        Initialize the filter engine.
        
        Args:
            config_dir (Optional[Path]): Directory containing filter configuration files
        """
        self.config_dir = Path(config_dir) if config_dir else Path("config/filters")
        self.filters = {
            'whitelist': defaultdict(list),
            'blacklist': defaultdict(list),
            'custom': defaultdict(list)
        }
        self.compiled_patterns = {
            'whitelist': defaultdict(list),
            'blacklist': defaultdict(list), 
            'custom': defaultdict(list)
        }
        self.filter_stats = {
            'total_checks': 0,
            'filtered_events': 0,
            'whitelist_hits': 0,
            'blacklist_hits': 0,
            'custom_hits': 0,
            'last_reload': None
        }
        self.performance_metrics = {
            'avg_filter_time_ms': 0.0,
            'total_filter_time': 0.0,
            'peak_filter_time_ms': 0.0
        }
        self._lock = threading.RLock()
        self._hot_reload_enabled = True
        self._last_config_check = 0
        
        logger.info("FilterEngine initialized")
    
    def load_filters(self, config_dir: Optional[Path] = None) -> bool:
        """
        Load all filter configurations from directory.
        
        Loads whitelist, blacklist, and custom filters from JSON files
        and compiles them into efficient pattern matching structures.
        
        Args:
            config_dir (Optional[Path]): Directory containing filter files
            
        Returns:
            bool: True if filters loaded successfully, False otherwise
        """
        if config_dir:
            self.config_dir = Path(config_dir)
        
        if not self.config_dir.exists():
            logger.warning(f"Filter config directory does not exist: {self.config_dir}")
            return False
        
        with self._lock:
            try:
                # Reset filters
                self.filters = {
                    'whitelist': defaultdict(list),
                    'blacklist': defaultdict(list),
                    'custom': defaultdict(list)
                }
                
                # Load whitelist filters
                whitelist_file = self.config_dir / "behavioral_baseline.json"
                if whitelist_file.exists():
                    self._load_filter_file(whitelist_file, 'whitelist')
                
                # Load blacklist filters  
                blacklist_file = self.config_dir / "malware_indicators.json"
                if blacklist_file.exists():
                    self._load_filter_file(blacklist_file, 'blacklist')
                
                # Load custom filters
                custom_file = self.config_dir / "custom_rules.json"
                if custom_file.exists():
                    self._load_filter_file(custom_file, 'custom')
                
                # Compile patterns for performance
                self._compile_patterns()
                
                self.filter_stats['last_reload'] = datetime.now()
                
                total_filters = sum(
                    len(patterns) for filter_type in self.filters.values() 
                    for patterns in filter_type.values()
                )
                
                logger.info(f"Loaded {total_filters} total filter patterns")
                return True
                
            except Exception as e:
                logger.error(f"Failed to load filters: {e}")
                return False
    
    def should_filter_event(self, event: Dict[str, Any], event_type: str = "behavioral") -> Tuple[bool, str]:
        """
        Determine if an event should be filtered out.
        
        Primary filtering decision method. Returns whether to filter the event
        and the reason for the decision.
        
        Args:
            event (Dict[str, Any]): Event data to evaluate
            event_type (str): Type of event (behavioral, network, registry, etc.)
            
        Returns:
            Tuple[bool, str]: (should_filter, reason)
                - True = filter out (don't process)
                - False = keep (continue processing)
        """
        start_time = time.perf_counter()
        
        try:
            with self._lock:
                self.filter_stats['total_checks'] += 1
                
                # Check for hot reload if enabled
                if self._hot_reload_enabled:
                    self._check_hot_reload()
                
                # Extract relevant data from event
                extracted_data = self._extract_filterable_data(event, event_type)
                
                # Check whitelist first (allow known good)
                is_whitelisted, whitelist_reason = self._check_whitelist(extracted_data, event_type)
                if is_whitelisted:
                    self.filter_stats['whitelist_hits'] += 1
                    return True, f"Whitelisted: {whitelist_reason}"
                
                # Check blacklist (block known bad)
                is_blacklisted, blacklist_reason = self._check_blacklist(extracted_data, event_type)
                if is_blacklisted:
                    self.filter_stats['blacklist_hits'] += 1
                    self.filter_stats['filtered_events'] += 1
                    return False, f"Keep (Blacklisted): {blacklist_reason}"
                
                # Check custom rules
                custom_result, custom_reason = self._check_custom_rules(extracted_data, event_type)
                if custom_result is not None:
                    self.filter_stats['custom_hits'] += 1
                    if custom_result:
                        self.filter_stats['filtered_events'] += 1
                    action = "Filter" if custom_result else "Keep"
                    return custom_result, f"{action} (Custom): {custom_reason}"
                
                # Default: keep if no rules match
                return False, "Keep (No matching rules)"
                
        except Exception as e:
            logger.error(f"Error in filter evaluation: {e}")
            return False, f"Keep (Filter error: {e})"
        
        finally:
            # Update performance metrics
            filter_time = (time.perf_counter() - start_time) * 1000  # Convert to ms
            self._update_performance_metrics(filter_time)
    
    def should_filter_process(self, process_info: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Filter process creation events.
        
        Args:
            process_info (Dict[str, Any]): Process information
                Expected keys: command, process_name, parent_process, etc.
        
        Returns:
            Tuple[bool, str]: (should_filter, reason)
        """
        return self.should_filter_event(process_info, "processes")
    
    def should_filter_file_operation(self, file_op: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Filter file system operation events.
        
        Args:
            file_op (Dict[str, Any]): File operation information
                Expected keys: path, operation, process_name, etc.
        
        Returns:
            Tuple[bool, str]: (should_filter, reason)
        """
        return self.should_filter_event(file_op, "files")
    
    def should_filter_registry_operation(self, reg_op: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Filter registry operation events.
        
        Args:
            reg_op (Dict[str, Any]): Registry operation information
                Expected keys: key, value, operation, process_name, etc.
        
        Returns:
            Tuple[bool, str]: (should_filter, reason)
        """
        return self.should_filter_event(reg_op, "registry")
    
    def should_filter_network_event(self, net_event: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Filter network communication events.
        
        Args:
            net_event (Dict[str, Any]): Network event information
                Expected keys: destination, protocol, port, domain, etc.
        
        Returns:
            Tuple[bool, str]: (should_filter, reason)
        """
        return self.should_filter_event(net_event, "network")
    
    def is_suspicious_domain(self, domain: str) -> bool:
        """
        Quick check if a domain is suspicious.
        
        Args:
            domain (str): Domain name to check
            
        Returns:
            bool: True if domain is suspicious (keep for analysis)
        """
        if not domain:
            return False
        
        # Check against network blacklist patterns
        for pattern in self.compiled_patterns['blacklist'].get('network', []):
            if pattern.search(domain.lower()):
                return True
        
        # Check if domain is whitelisted (known good)
        for pattern in self.compiled_patterns['whitelist'].get('network', []):
            if pattern.search(domain.lower()):
                return False
        
        # Additional heuristics for suspicious domains
        return self._is_domain_suspicious_heuristic(domain)
    
    def get_filter_statistics(self) -> Dict[str, Any]:
        """
        Get current filter performance statistics.
        
        Returns:
            Dict[str, Any]: Statistics including hit rates, performance metrics
        """
        with self._lock:
            total_checks = self.filter_stats['total_checks']
            
            stats = {
                'total_checks': total_checks,
                'filtered_events': self.filter_stats['filtered_events'],
                'filter_rate': self.filter_stats['filtered_events'] / total_checks if total_checks > 0 else 0,
                'whitelist_hits': self.filter_stats['whitelist_hits'],
                'blacklist_hits': self.filter_stats['blacklist_hits'],
                'custom_hits': self.filter_stats['custom_hits'],
                'last_reload': self.filter_stats['last_reload'],
                'performance': self.performance_metrics.copy(),
                'loaded_filters': {
                    filter_type: {
                        category: len(patterns) 
                        for category, patterns in filters.items()
                    }
                    for filter_type, filters in self.filters.items()
                }
            }
            
            return stats
    
    def add_runtime_filter(self, filter_type: str, category: str, pattern: str) -> bool:
        """
        Add a filter pattern at runtime without reloading.
        
        Args:
            filter_type (str): Filter type (whitelist, blacklist, custom)
            category (str): Filter category (processes, files, etc.)
            pattern (str): Filter pattern
            
        Returns:
            bool: True if filter added successfully
        """
        try:
            with self._lock:
                if filter_type not in self.filters:
                    logger.error(f"Invalid filter type: {filter_type}")
                    return False
                
                self.filters[filter_type][category].append(pattern)
                
                # Compile the new pattern
                compiled_pattern = self._compile_single_pattern(pattern)
                if compiled_pattern:
                    self.compiled_patterns[filter_type][category].append(compiled_pattern)
                
                logger.info(f"Added runtime filter: {filter_type}/{category} - {pattern}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to add runtime filter: {e}")
            return False
    
    def remove_runtime_filter(self, filter_type: str, category: str, pattern: str) -> bool:
        """
        Remove a filter pattern at runtime.
        
        Args:
            filter_type (str): Filter type (whitelist, blacklist, custom)
            category (str): Filter category (processes, files, etc.)
            pattern (str): Filter pattern to remove
            
        Returns:
            bool: True if filter removed successfully
        """
        try:
            with self._lock:
                if filter_type not in self.filters:
                    return False
                
                if pattern in self.filters[filter_type][category]:
                    self.filters[filter_type][category].remove(pattern)
                    
                    # Recompile patterns for this category
                    self._compile_category_patterns(filter_type, category)
                    
                    logger.info(f"Removed runtime filter: {filter_type}/{category} - {pattern}")
                    return True
                
                return False
                
        except Exception as e:
            logger.error(f"Failed to remove runtime filter: {e}")
            return False
    
    def reload_filters(self) -> bool:
        """
        Manually reload all filters from configuration files.
        
        Returns:
            bool: True if reload successful
        """
        logger.info("Manually reloading filters")
        return self.load_filters()
    
    def enable_hot_reload(self, enabled: bool = True):
        """
        Enable or disable automatic hot reload of filter configurations.
        
        Args:
            enabled (bool): Whether to enable hot reload
        """
        self._hot_reload_enabled = enabled
        logger.info(f"Hot reload {'enabled' if enabled else 'disabled'}")
    
    def _load_filter_file(self, file_path: Path, filter_type: str):
        """Load filters from a JSON file."""
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            if isinstance(data, dict):
                for category, patterns in data.items():
                    if isinstance(patterns, list):
                        self.filters[filter_type][category].extend(patterns)
                    else:
                        logger.warning(f"Invalid pattern format in {file_path}: {category}")
            else:
                logger.warning(f"Invalid file format: {file_path}")
                
        except Exception as e:
            logger.error(f"Failed to load filter file {file_path}: {e}")
    
    def _compile_patterns(self):
        """Compile all filter patterns into regex objects for performance."""
        self.compiled_patterns = {
            'whitelist': defaultdict(list),
            'blacklist': defaultdict(list),
            'custom': defaultdict(list)
        }
        
        for filter_type, categories in self.filters.items():
            for category, patterns in categories.items():
                self._compile_category_patterns(filter_type, category)
    
    def _compile_category_patterns(self, filter_type: str, category: str):
        """Compile patterns for a specific filter type and category."""
        patterns = self.filters[filter_type][category]
        self.compiled_patterns[filter_type][category] = []
        
        for pattern in patterns:
            compiled_pattern = self._compile_single_pattern(pattern)
            if compiled_pattern:
                self.compiled_patterns[filter_type][category].append(compiled_pattern)
    
    def _compile_single_pattern(self, pattern: str) -> Optional[re.Pattern]:
        """Compile a single pattern into a regex object."""
        try:
            # Convert glob-like wildcards to regex
            regex_pattern = pattern.replace('*', '.*').replace('?', '.')
            regex_pattern = re.escape(regex_pattern).replace(r'\.\*', '.*').replace(r'\.', '.')
            return re.compile(f"^{regex_pattern}$", re.IGNORECASE)
        except re.error as e:
            logger.warning(f"Failed to compile pattern '{pattern}': {e}")
            return None
    
    def _extract_filterable_data(self, event: Dict[str, Any], event_type: str) -> Dict[str, List[str]]:
        """Extract filterable data from an event based on its type."""
        data = defaultdict(list)
        
        try:
            if event_type == "processes":
                if 'command' in event:
                    data['command'].append(event['command'].lower())
                if 'process_name' in event:
                    data['process'].append(event['process_name'].lower())
                if 'parent_process' in event:
                    data['parent'].append(event['parent_process'].lower())
                    
            elif event_type == "files":
                if 'path' in event:
                    data['path'].append(event['path'].lower())
                if 'operation' in event:
                    data['operation'].append(event['operation'].lower())
                    
            elif event_type == "registry":
                if 'key' in event:
                    data['key'].append(event['key'].lower())
                if 'value' in event:
                    data['value'].append(str(event['value']).lower())
                    
            elif event_type == "network":
                if 'destination' in event:
                    data['destination'].append(event['destination'].lower())
                if 'domain' in event:
                    data['domain'].append(event['domain'].lower())
                if 'protocol' in event:
                    data['protocol'].append(event['protocol'].lower())
                    
        except Exception as e:
            logger.warning(f"Error extracting filterable data: {e}")
        
        return data
    
    def _check_whitelist(self, data: Dict[str, List[str]], event_type: str) -> Tuple[bool, str]:
        """Check if event matches whitelist patterns."""
        category_map = {
            "processes": ["command", "process", "parent"],
            "files": ["path", "operation"],
            "registry": ["key", "value"],
            "network": ["destination", "domain", "protocol"]
        }
        
        categories_to_check = category_map.get(event_type, [])
        
        for category in categories_to_check:
            if category in data:
                for value in data[category]:
                    for pattern in self.compiled_patterns['whitelist'].get(event_type, []):
                        if pattern.search(value):
                            return True, f"{category}:{value}"
        
        return False, ""
    
    def _check_blacklist(self, data: Dict[str, List[str]], event_type: str) -> Tuple[bool, str]:
        """Check if event matches blacklist patterns."""
        category_map = {
            "processes": ["command", "process", "parent"],
            "files": ["path", "operation"],
            "registry": ["key", "value"],
            "network": ["destination", "domain", "protocol"]
        }
        
        categories_to_check = category_map.get(event_type, [])
        
        for category in categories_to_check:
            if category in data:
                for value in data[category]:
                    for pattern in self.compiled_patterns['blacklist'].get(event_type, []):
                        if pattern.search(value):
                            return True, f"{category}:{value}"
        
        return False, ""
    
    def _check_custom_rules(self, data: Dict[str, List[str]], event_type: str) -> Tuple[Optional[bool], str]:
        """Check custom filtering rules."""
        # Custom rules can implement more complex logic
        # For now, treating them similar to blacklist
        category_map = {
            "processes": ["command", "process", "parent"],
            "files": ["path", "operation"],
            "registry": ["key", "value"],
            "network": ["destination", "domain", "protocol"]
        }
        
        categories_to_check = category_map.get(event_type, [])
        
        for category in categories_to_check:
            if category in data:
                for value in data[category]:
                    for pattern in self.compiled_patterns['custom'].get(event_type, []):
                        if pattern.search(value):
                            return False, f"{category}:{value}"  # Keep suspicious custom matches
        
        return None, ""
    
    def _is_domain_suspicious_heuristic(self, domain: str) -> bool:
        """Apply heuristic checks for suspicious domains."""
        # Length-based heuristics
        if len(domain) > 50:
            return True
        
        # Character composition heuristics
        if domain.count('.') > 4:  # Too many subdomains
            return True
            
        # DGA-like patterns
        if len(domain.split('.')[0]) > 15:  # Very long subdomain
            consonants = sum(1 for c in domain if c.lower() in 'bcdfghjklmnpqrstvwxyz')
            if consonants / len(domain) > 0.7:  # High consonant ratio
                return True
        
        return False
    
    def _check_hot_reload(self):
        """Check if configuration files have been updated and reload if necessary."""
        current_time = time.time()
        
        # Check only every 5 seconds to avoid excessive file system calls
        if current_time - self._last_config_check < 5:
            return
        
        self._last_config_check = current_time
        
        try:
            config_files = [
                self.config_dir / "behavioral_baseline.json",
                self.config_dir / "malware_indicators.json",
                self.config_dir / "custom_rules.json"
            ]
            
            latest_mtime = 0
            for config_file in config_files:
                if config_file.exists():
                    latest_mtime = max(latest_mtime, config_file.stat().st_mtime)
            
            if (self.filter_stats['last_reload'] and 
                latest_mtime > self.filter_stats['last_reload'].timestamp()):
                logger.info("Configuration files updated, reloading filters")
                self.load_filters()
                
        except Exception as e:
            logger.warning(f"Hot reload check failed: {e}")
    
    def _update_performance_metrics(self, filter_time_ms: float):
        """Update performance metrics with latest timing."""
        total_checks = self.filter_stats['total_checks']
        
        # Update total time
        self.performance_metrics['total_filter_time'] += filter_time_ms
        
        # Update average
        self.performance_metrics['avg_filter_time_ms'] = (
            self.performance_metrics['total_filter_time'] / total_checks
        )
        
        # Update peak
        if filter_time_ms > self.performance_metrics['peak_filter_time_ms']:
            self.performance_metrics['peak_filter_time_ms'] = filter_time_ms