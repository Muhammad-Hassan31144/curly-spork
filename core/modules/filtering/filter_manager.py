"""
Filter Management System (filter_manager.py)

Purpose:
Provides CRUD (Create, Read, Update, Delete) operations for filter management.
Handles filter configuration persistence, validation, and coordination with
the runtime filter engine. Primary interface for web UI and admin operations.

Context in Shikra:
- Input: Filter management requests from web UI, API, admin scripts
- Processing: Filter validation, conflict resolution, persistence
- Output: Updated filter configurations, operation status

Integration Points:
- Used by: web interface (monitoring_api.py), admin scripts, setup tools
- Coordinates with: filter_engine.py (runtime updates), generator.py (new filters)
- Manages: config/filters/ directory and all filter configuration files
- Validates with: filter_validator.py (effectiveness testing)
"""

import logging
import json
import shutil
from pathlib import Path
from typing import Dict, List, Set, Any, Optional, Union, Tuple
from collections import defaultdict
from datetime import datetime, timedelta
import threading
import hashlib

logger = logging.getLogger(__name__)

class FilterManager:
    """
    Manages filter configurations with CRUD operations and validation.
    
    Provides a centralized interface for managing all filter configurations,
    including whitelists, blacklists, and custom rules. Handles persistence,
    validation, backup/restore, and coordination with the runtime engine.
    """
    
    def __init__(self, config_dir: Optional[Path] = None, backup_dir: Optional[Path] = None):
        """
        Initialize the filter manager.
        
        Args:
            config_dir (Optional[Path]): Directory containing filter configurations
            backup_dir (Optional[Path]): Directory for filter backups
        """
        self.config_dir = Path(config_dir) if config_dir else Path("config/filters")
        self.backup_dir = Path(backup_dir) if backup_dir else self.config_dir / "backups"
        
        # Ensure directories exist
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        
        self.filter_files = {
            'whitelist': self.config_dir / "behavioral_baseline.json",
            'blacklist': self.config_dir / "malware_indicators.json", 
            'custom': self.config_dir / "custom_rules.json"
        }
        
        # Cache for loaded filters
        self._filter_cache = {}
        self._cache_timestamps = {}
        self._lock = threading.RLock()
        
        # Filter validation settings
        self.validation_config = {
            'max_pattern_length': 500,
            'max_patterns_per_category': 10000,
            'reserved_patterns': {'*', '**', '?', ''},
            'dangerous_patterns': {'.', '.*', '/', '\\'},
            'required_categories': {'processes', 'files', 'registry', 'network'}
        }
        
        logger.info("FilterManager initialized")
    
    def get_all_filters(self) -> Dict[str, Dict[str, List[str]]]:
        """
        Get all current filter configurations.
        
        Returns:
            Dict[str, Dict[str, List[str]]]: Complete filter configuration
                Format: {filter_type: {category: [patterns]}}
        """
        with self._lock:
            all_filters = {}
            
            for filter_type, file_path in self.filter_files.items():
                filters = self._load_filter_file(file_path)
                all_filters[filter_type] = filters if filters else {}
            
            return all_filters
    
    def get_filters_by_type(self, filter_type: str) -> Dict[str, List[str]]:
        """
        Get filters of a specific type.
        
        Args:
            filter_type (str): Filter type (whitelist, blacklist, custom)
            
        Returns:
            Dict[str, List[str]]: Filters by category
        """
        if filter_type not in self.filter_files:
            logger.error(f"Invalid filter type: {filter_type}")
            return {}
        
        with self._lock:
            return self._load_filter_file(self.filter_files[filter_type]) or {}
    
    def get_filters_by_category(self, category: str) -> Dict[str, List[str]]:
        """
        Get all filters for a specific category across all types.
        
        Args:
            category (str): Filter category (processes, files, registry, network)
            
        Returns:
            Dict[str, List[str]]: Filters by type for the category
        """
        with self._lock:
            category_filters = {}
            
            for filter_type in self.filter_files.keys():
                filters = self.get_filters_by_type(filter_type)
                if category in filters:
                    category_filters[filter_type] = filters[category]
                else:
                    category_filters[filter_type] = []
            
            return category_filters
    
    def add_filter(self, filter_type: str, category: str, pattern: str, 
                   validate: bool = True, notify_engine: bool = True) -> Tuple[bool, str]:
        """
        Add a new filter pattern.
        
        Args:
            filter_type (str): Filter type (whitelist, blacklist, custom)
            category (str): Filter category (processes, files, etc.)
            pattern (str): Filter pattern to add
            validate (bool): Whether to validate the pattern
            notify_engine (bool): Whether to notify the runtime engine
            
        Returns:
            Tuple[bool, str]: (success, message)
        """
        with self._lock:
            try:
                # Validate inputs
                if filter_type not in self.filter_files:
                    return False, f"Invalid filter type: {filter_type}"
                
                if validate:
                    is_valid, validation_msg = self._validate_pattern(pattern, category)
                    if not is_valid:
                        return False, f"Pattern validation failed: {validation_msg}"
                
                # Load current filters
                current_filters = self.get_filters_by_type(filter_type)
                
                # Add pattern if not already exists
                if category not in current_filters:
                    current_filters[category] = []
                
                if pattern in current_filters[category]:
                    return False, f"Pattern already exists in {filter_type}/{category}"
                
                current_filters[category].append(pattern)
                
                # Save updated filters
                success = self._save_filter_file(self.filter_files[filter_type], current_filters)
                if not success:
                    return False, "Failed to save filter configuration"
                
                # Notify runtime engine if requested
                if notify_engine:
                    self._notify_engine_update(filter_type, category, 'add', pattern)
                
                logger.info(f"Added filter: {filter_type}/{category} - {pattern}")
                return True, "Filter added successfully"
                
            except Exception as e:
                logger.error(f"Failed to add filter: {e}")
                return False, f"Error adding filter: {e}"
    
    def remove_filter(self, filter_type: str, category: str, pattern: str,
                      notify_engine: bool = True) -> Tuple[bool, str]:
        """
        Remove a filter pattern.
        
        Args:
            filter_type (str): Filter type (whitelist, blacklist, custom)
            category (str): Filter category
            pattern (str): Filter pattern to remove
            notify_engine (bool): Whether to notify the runtime engine
            
        Returns:
            Tuple[bool, str]: (success, message)
        """
        with self._lock:
            try:
                if filter_type not in self.filter_files:
                    return False, f"Invalid filter type: {filter_type}"
                
                # Load current filters
                current_filters = self.get_filters_by_type(filter_type)
                
                if category not in current_filters:
                    return False, f"Category {category} not found in {filter_type}"
                
                if pattern not in current_filters[category]:
                    return False, f"Pattern not found in {filter_type}/{category}"
                
                # Remove pattern
                current_filters[category].remove(pattern)
                
                # Clean up empty categories
                if not current_filters[category]:
                    del current_filters[category]
                
                # Save updated filters
                success = self._save_filter_file(self.filter_files[filter_type], current_filters)
                if not success:
                    return False, "Failed to save filter configuration"
                
                # Notify runtime engine if requested
                if notify_engine:
                    self._notify_engine_update(filter_type, category, 'remove', pattern)
                
                logger.info(f"Removed filter: {filter_type}/{category} - {pattern}")
                return True, "Filter removed successfully"
                
            except Exception as e:
                logger.error(f"Failed to remove filter: {e}")
                return False, f"Error removing filter: {e}"
    
    def update_filter(self, filter_type: str, category: str, old_pattern: str, 
                      new_pattern: str, validate: bool = True, 
                      notify_engine: bool = True) -> Tuple[bool, str]:
        """
        Update an existing filter pattern.
        
        Args:
            filter_type (str): Filter type
            category (str): Filter category
            old_pattern (str): Current pattern to replace
            new_pattern (str): New pattern
            validate (bool): Whether to validate the new pattern
            notify_engine (bool): Whether to notify the runtime engine
            
        Returns:
            Tuple[bool, str]: (success, message)
        """
        with self._lock:
            try:
                # Validate new pattern
                if validate:
                    is_valid, validation_msg = self._validate_pattern(new_pattern, category)
                    if not is_valid:
                        return False, f"New pattern validation failed: {validation_msg}"
                
                # Remove old pattern
                success, msg = self.remove_filter(filter_type, category, old_pattern, False)
                if not success:
                    return False, f"Failed to remove old pattern: {msg}"
                
                # Add new pattern
                success, msg = self.add_filter(filter_type, category, new_pattern, False, False)
                if not success:
                    # Rollback - add old pattern back
                    self.add_filter(filter_type, category, old_pattern, False, False)
                    return False, f"Failed to add new pattern: {msg}"
                
                # Notify runtime engine if requested
                if notify_engine:
                    self._notify_engine_update(filter_type, category, 'update', 
                                               {'old': old_pattern, 'new': new_pattern})
                
                logger.info(f"Updated filter: {filter_type}/{category} - {old_pattern} -> {new_pattern}")
                return True, "Filter updated successfully"
                
            except Exception as e:
                logger.error(f"Failed to update filter: {e}")
                return False, f"Error updating filter: {e}"
    
    def bulk_add_filters(self, filters: Dict[str, Dict[str, List[str]]], 
                         validate: bool = True, notify_engine: bool = True) -> Tuple[bool, List[str]]:
        """
        Add multiple filters in bulk operation.
        
        Args:
            filters (Dict[str, Dict[str, List[str]]]): Filters to add
                Format: {filter_type: {category: [patterns]}}
            validate (bool): Whether to validate patterns
            notify_engine (bool): Whether to notify the runtime engine
            
        Returns:
            Tuple[bool, List[str]]: (overall_success, list_of_messages)
        """
        with self._lock:
            messages = []
            overall_success = True
            
            # Create backup before bulk operation
            backup_path = self._create_backup("bulk_add_operation")
            messages.append(f"Created backup at: {backup_path}")
            
            try:
                for filter_type, categories in filters.items():
                    for category, patterns in categories.items():
                        for pattern in patterns:
                            success, msg = self.add_filter(filter_type, category, pattern, 
                                                          validate, False)
                            if success:
                                messages.append(f"Added: {filter_type}/{category} - {pattern}")
                            else:
                                messages.append(f"Failed: {filter_type}/{category} - {pattern}: {msg}")
                                overall_success = False
                
                # Notify engine once after all additions
                if notify_engine and overall_success:
                    self._notify_engine_reload()
                    messages.append("Notified runtime engine of bulk changes")
                
            except Exception as e:
                logger.error(f"Bulk add operation failed: {e}")
                messages.append(f"Bulk operation error: {e}")
                overall_success = False
            
            if not overall_success:
                messages.append("Some filters failed to add. Consider reviewing the backup.")
            
            return overall_success, messages
    
    def replace_filter_set(self, filter_type: str, new_filters: Dict[str, List[str]],
                          create_backup: bool = True) -> Tuple[bool, str]:
        """
        Replace an entire filter set with new configuration.
        
        Args:
            filter_type (str): Filter type to replace
            new_filters (Dict[str, List[str]]): New filter configuration
            create_backup (bool): Whether to create backup before replacement
            
        Returns:
            Tuple[bool, str]: (success, message)
        """
        with self._lock:
            try:
                if filter_type not in self.filter_files:
                    return False, f"Invalid filter type: {filter_type}"
                
                # Create backup if requested
                if create_backup:
                    backup_path = self._create_backup(f"replace_{filter_type}")
                    logger.info(f"Created backup before replacement: {backup_path}")
                
                # Validate new filters
                for category, patterns in new_filters.items():
                    for pattern in patterns:
                        is_valid, validation_msg = self._validate_pattern(pattern, category)
                        if not is_valid:
                            return False, f"Validation failed for {category}/{pattern}: {validation_msg}"
                
                # Save new filter set
                success = self._save_filter_file(self.filter_files[filter_type], new_filters)
                if not success:
                    return False, "Failed to save new filter configuration"
                
                # Notify runtime engine
                self._notify_engine_reload()
                
                total_patterns = sum(len(patterns) for patterns in new_filters.values())
                logger.info(f"Replaced {filter_type} filters with {total_patterns} patterns")
                return True, f"Filter set replaced successfully with {total_patterns} patterns"
                
            except Exception as e:
                logger.error(f"Failed to replace filter set: {e}")
                return False, f"Error replacing filter set: {e}"
    
    def import_filters_from_file(self, file_path: Path, filter_type: str,
                                merge: bool = True) -> Tuple[bool, str]:
        """
        Import filters from external file.
        
        Args:
            file_path (Path): Path to filter file
            filter_type (str): Target filter type
            merge (bool): Whether to merge with existing (True) or replace (False)
            
        Returns:
            Tuple[bool, str]: (success, message)
        """
        try:
            if not file_path.exists():
                return False, f"File not found: {file_path}"
            
            # Load filters from file
            imported_filters = self._load_filter_file(file_path)
            if not imported_filters:
                return False, "Failed to load filters from file or file is empty"
            
            if merge:
                # Merge with existing filters
                current_filters = self.get_filters_by_type(filter_type)
                
                for category, patterns in imported_filters.items():
                    if category not in current_filters:
                        current_filters[category] = []
                    
                    # Add patterns that don't already exist
                    new_patterns = [p for p in patterns if p not in current_filters[category]]
                    current_filters[category].extend(new_patterns)
                
                success, msg = self.replace_filter_set(filter_type, current_filters, True)
            else:
                # Replace existing filters
                success, msg = self.replace_filter_set(filter_type, imported_filters, True)
            
            if success:
                total_imported = sum(len(patterns) for patterns in imported_filters.values())
                action = "merged" if merge else "replaced"
                return True, f"Successfully {action} {total_imported} patterns from {file_path.name}"
            else:
                return False, f"Import failed: {msg}"
                
        except Exception as e:
            logger.error(f"Failed to import filters from {file_path}: {e}")
            return False, f"Import error: {e}"
    
    def export_filters_to_file(self, file_path: Path, filter_type: Optional[str] = None,
                              format_type: str = "json") -> Tuple[bool, str]:
        """
        Export filters to external file.
        
        Args:
            file_path (Path): Output file path
            filter_type (Optional[str]): Specific filter type to export (None for all)
            format_type (str): Export format (json, text)
            
        Returns:
            Tuple[bool, str]: (success, message)
        """
        try:
            if filter_type:
                filters_to_export = {filter_type: self.get_filters_by_type(filter_type)}
            else:
                filters_to_export = self.get_all_filters()
            
            # Ensure output directory exists
            file_path.parent.mkdir(parents=True, exist_ok=True)
            
            if format_type.lower() == "json":
                with open(file_path, 'w') as f:
                    json.dump(filters_to_export, f, indent=2)
            elif format_type.lower() == "text":
                with open(file_path, 'w') as f:
                    for ftype, categories in filters_to_export.items():
                        f.write(f"# {ftype.upper()} FILTERS\n")
                        for category, patterns in categories.items():
                            f.write(f"\n## {category}\n")
                            for pattern in patterns:
                                f.write(f"{pattern}\n")
                        f.write("\n" + "="*50 + "\n")
            else:
                return False, f"Unsupported export format: {format_type}"
            
            total_patterns = sum(
                len(patterns) for categories in filters_to_export.values()
                for patterns in categories.values()
            )
            
            logger.info(f"Exported {total_patterns} patterns to {file_path}")
            return True, f"Successfully exported {total_patterns} patterns to {file_path.name}"
            
        except Exception as e:
            logger.error(f"Failed to export filters to {file_path}: {e}")
            return False, f"Export error: {e}"
    
    def search_filters(self, query: str, filter_type: Optional[str] = None,
                      category: Optional[str] = None) -> Dict[str, Dict[str, List[str]]]:
        """
        Search for filters matching a query.
        
        Args:
            query (str): Search query (supports partial matching)
            filter_type (Optional[str]): Limit search to specific filter type
            category (Optional[str]): Limit search to specific category
            
        Returns:
            Dict[str, Dict[str, List[str]]]: Matching filters
        """
        results = defaultdict(lambda: defaultdict(list))
        query_lower = query.lower()
        
        filters_to_search = self.get_all_filters()
        
        for ftype, categories in filters_to_search.items():
            if filter_type and ftype != filter_type:
                continue
                
            for cat, patterns in categories.items():
                if category and cat != category:
                    continue
                
                matching_patterns = [
                    pattern for pattern in patterns
                    if query_lower in pattern.lower()
                ]
                
                if matching_patterns:
                    results[ftype][cat] = matching_patterns
        
        return dict(results)
    
    def get_filter_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about current filter configuration.
        
        Returns:
            Dict[str, Any]: Filter statistics and metrics
        """
        all_filters = self.get_all_filters()
        
        stats = {
            'total_filters': 0,
            'by_type': {},
            'by_category': defaultdict(int),
            'largest_category': {'name': '', 'count': 0},
            'duplicate_patterns': [],
            'config_files': {},
            'last_modified': {}
        }
        
        # Count filters by type and category
        all_patterns = set()
        for filter_type, categories in all_filters.items():
            type_count = 0
            for category, patterns in categories.items():
                count = len(patterns)
                type_count += count
                stats['by_category'][category] += count
                
                # Check for largest category
                if count > stats['largest_category']['count']:
                    stats['largest_category'] = {'name': f"{filter_type}/{category}", 'count': count}
                
                # Check for duplicates within this category
                if len(patterns) != len(set(patterns)):
                    duplicates = [p for p in patterns if patterns.count(p) > 1]
                    stats['duplicate_patterns'].extend(duplicates)
                
                # Add to global pattern set to check cross-category duplicates
                all_patterns.update(patterns)
            
            stats['by_type'][filter_type] = type_count
            stats['total_filters'] += type_count
        
        # Get file information
        for filter_type, file_path in self.filter_files.items():
            if file_path.exists():
                stat = file_path.stat()
                stats['config_files'][filter_type] = {
                    'path': str(file_path),
                    'size_bytes': stat.st_size,
                    'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
                }
                stats['last_modified'][filter_type] = stat.st_mtime
        
        return stats
    
    def create_backup(self, backup_name: Optional[str] = None) -> Path:
        """
        Create a backup of all current filter configurations.
        
        Args:
            backup_name (Optional[str]): Custom backup name
            
        Returns:
            Path: Path to created backup directory
        """
        return self._create_backup(backup_name)
    
    def restore_from_backup(self, backup_path: Path) -> Tuple[bool, str]:
        """
        Restore filter configurations from backup.
        
        Args:
            backup_path (Path): Path to backup directory
            
        Returns:
            Tuple[bool, str]: (success, message)
        """
        try:
            if not backup_path.exists() or not backup_path.is_dir():
                return False, f"Backup directory not found: {backup_path}"
            
            # Create current backup before restore
            current_backup = self._create_backup("pre_restore_backup")
            
            # Restore each filter file
            restored_files = []
            for filter_type, target_file in self.filter_files.items():
                backup_file = backup_path / target_file.name
                if backup_file.exists():
                    shutil.copy2(backup_file, target_file)
                    restored_files.append(filter_type)
            
            if restored_files:
                # Notify runtime engine to reload
                self._notify_engine_reload()
                
                logger.info(f"Restored filters from backup: {backup_path}")
                return True, f"Successfully restored {len(restored_files)} filter types. Current backup created at: {current_backup}"
            else:
                return False, "No valid filter files found in backup"
                
        except Exception as e:
            logger.error(f"Failed to restore from backup {backup_path}: {e}")
            return False, f"Restore error: {e}"
    
    def list_backups(self) -> List[Dict[str, Any]]:
        """
        List available filter backups.
        
        Returns:
            List[Dict[str, Any]]: List of backup information
        """
        backups = []
        
        try:
            for backup_dir in self.backup_dir.iterdir():
                if backup_dir.is_dir():
                    stat = backup_dir.stat()
                    backup_info = {
                        'name': backup_dir.name,
                        'path': str(backup_dir),
                        'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                        'size_bytes': sum(f.stat().st_size for f in backup_dir.rglob('*') if f.is_file()),
                        'files': [f.name for f in backup_dir.iterdir() if f.is_file()]
                    }
                    backups.append(backup_info)
            
            # Sort by creation time (newest first)
            backups.sort(key=lambda x: x['created'], reverse=True)
            
        except Exception as e:
            logger.error(f"Failed to list backups: {e}")
        
        return backups
    
    def cleanup_old_backups(self, keep_days: int = 30, keep_minimum: int = 5) -> Tuple[int, str]:
        """
        Clean up old backup files.
        
        Args:
            keep_days (int): Days to keep backups
            keep_minimum (int): Minimum number of backups to keep
            
        Returns:
            Tuple[int, str]: (deleted_count, message)
        """
        try:
            backups = self.list_backups()
            cutoff_date = datetime.now() - timedelta(days=keep_days)
            
            # Identify backups to delete
            to_delete = []
            for backup in backups[keep_minimum:]:  # Skip the minimum recent backups
                backup_date = datetime.fromisoformat(backup['created'])
                if backup_date < cutoff_date:
                    to_delete.append(backup)
            
            # Delete old backups
            deleted_count = 0
            for backup in to_delete:
                backup_path = Path(backup['path'])
                if backup_path.exists():
                    shutil.rmtree(backup_path)
                    deleted_count += 1
                    logger.info(f"Deleted old backup: {backup['name']}")
            
            return deleted_count, f"Deleted {deleted_count} old backups"
            
        except Exception as e:
            logger.error(f"Failed to cleanup old backups: {e}")
            return 0, f"Cleanup error: {e}"
    
    def _load_filter_file(self, file_path: Path) -> Optional[Dict[str, List[str]]]:
        """Load filters from a JSON file with caching."""
        try:
            if not file_path.exists():
                return {}
            
            # Check cache
            file_mtime = file_path.stat().st_mtime
            cache_key = str(file_path)
            
            if (cache_key in self._filter_cache and 
                cache_key in self._cache_timestamps and
                self._cache_timestamps[cache_key] >= file_mtime):
                return self._filter_cache[cache_key]
            
            # Load from file
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Update cache
            self._filter_cache[cache_key] = data
            self._cache_timestamps[cache_key] = file_mtime
            
            return data
            
        except Exception as e:
            logger.error(f"Failed to load filter file {file_path}: {e}")
            return None
    
    def _save_filter_file(self, file_path: Path, filters: Dict[str, List[str]]) -> bool:
        """Save filters to a JSON file."""
        try:
            # Create backup of current file if it exists
            if file_path.exists():
                backup_path = file_path.with_suffix(f".bak.{int(datetime.now().timestamp())}")
                shutil.copy2(file_path, backup_path)
            
            # Write new configuration
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(filters, f, indent=2, ensure_ascii=False)
            
            # Clear cache for this file
            cache_key = str(file_path)
            if cache_key in self._filter_cache:
                del self._filter_cache[cache_key]
            if cache_key in self._cache_timestamps:
                del self._cache_timestamps[cache_key]
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to save filter file {file_path}: {e}")
            return False
    
    def _validate_pattern(self, pattern: str, category: str) -> Tuple[bool, str]:
        """Validate a filter pattern."""
        # Check length
        if len(pattern) > self.validation_config['max_pattern_length']:
            return False, f"Pattern too long (max {self.validation_config['max_pattern_length']} chars)"
        
        # Check reserved patterns
        if pattern in self.validation_config['reserved_patterns']:
            return False, f"Reserved pattern: {pattern}"
        
        # Check dangerous patterns
        if pattern in self.validation_config['dangerous_patterns']:
            return False, f"Dangerous pattern: {pattern}"
        
        # Check pattern format based on category
        if category == 'processes':
            if not pattern.strip():
                return False, "Empty process pattern"
        elif category == 'files':
            if not any(char in pattern for char in ['\\', '/', '.']):
                return False, "File pattern should contain path separators or extensions"
        elif category == 'registry':
            if not any(key in pattern.lower() for key in ['hkey', 'hklm', 'hkcu', 'software', 'system']):
                return False, "Registry pattern should contain valid registry paths"
        elif category == 'network':
            if not any(char in pattern for char in ['.', ':']):
                return False, "Network pattern should contain domain or IP format"
        
        return True, "Pattern is valid"
    
    def _create_backup(self, backup_name: Optional[str] = None) -> Path:
        """Create a backup of current filter configurations."""
        if not backup_name:
            backup_name = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        backup_path = self.backup_dir / backup_name
        backup_path.mkdir(parents=True, exist_ok=True)
        
        # Copy all filter files
        for filter_type, file_path in self.filter_files.items():
            if file_path.exists():
                shutil.copy2(file_path, backup_path / file_path.name)
        
        # Create backup metadata
        metadata = {
            'created': datetime.now().isoformat(),
            'filter_files': [str(f) for f in self.filter_files.values()],
            'statistics': self.get_filter_statistics()
        }
        
        with open(backup_path / 'backup_metadata.json', 'w') as f:
            json.dump(metadata, f, indent=2)
        
        logger.info(f"Created backup: {backup_path}")
        return backup_path
    
    def _notify_engine_update(self, filter_type: str, category: str, action: str, data: Any):
        """Notify the runtime filter engine of updates."""
        try:
            # Import here to avoid circular imports
            from .filter_engine import FilterEngine
            
            # This would need to be implemented based on how the engine is instantiated
            # For now, just log the update
            logger.info(f"Filter engine notification: {action} {filter_type}/{category}")
            
        except ImportError:
            logger.warning("FilterEngine not available for runtime notification")
        except Exception as e:
            logger.warning(f"Failed to notify filter engine: {e}")
    
    def _notify_engine_reload(self):
        """Notify the runtime filter engine to reload all filters."""
        try:
            # Import here to avoid circular imports
            from .filter_engine import FilterEngine
            
            # This would need to be implemented based on how the engine is instantiated
            logger.info("Filter engine notification: reload all filters")
            
        except ImportError:
            logger.warning("FilterEngine not available for reload notification")
        except Exception as e:
            logger.warning(f"Failed to notify filter engine for reload: {e}")