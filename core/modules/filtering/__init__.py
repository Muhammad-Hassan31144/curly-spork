"""
Shikra Filtering Module

Unified filtering system for behavioral analysis noise reduction and threat detection.
Provides filter generation, runtime filtering, management, and validation capabilities.

Modules:
- generator: Generate filters from baseline and malware analysis data
- engine: High-performance runtime filtering for analysis events  
- manager: CRUD operations and filter configuration management
- validator: Filter effectiveness testing and performance validation

Usage:
    from core.modules.filtering import FilterEngine, FilterManager, FilterValidator
    from core.modules.filtering.generator import FilterGenerator
    
    # Basic usage
    engine = FilterEngine()
    engine.load_filters("config/filters/")
    
    should_filter, reason = engine.should_filter_event(event_data, "behavioral")
    
    # Management
    manager = FilterManager()
    success, msg = manager.add_filter("blacklist", "processes", "malware*.exe")
    
    # Validation
    validator = FilterValidator()
    report = validator.validate_all_filters(engine)
"""

import logging
from pathlib import Path
from typing import Optional

from .filter_engine import FilterEngine
from .filter_manager import FilterManager  
from .filter_validator import FilterValidator

# Import generator if it exists in the expected location
try:
    from .generator import FilterGenerator
except ImportError:
    try:
        # Try importing from the current location (analysis/utils)
        import sys
        sys.path.append(str(Path(__file__).parent.parent.parent / "analysis" / "utils"))
        from generate_filters import FilterGenerator
    except ImportError:
        FilterGenerator = None
        logging.warning("FilterGenerator not available. Please ensure generate_filters.py is in the correct location.")

__version__ = "1.0.0"
__author__ = "Shikra Development Team"

# Package-level logger
logger = logging.getLogger(__name__)

class FilteringSystem:
    """
    Unified interface for the complete filtering system.
    
    Provides a single entry point for all filtering operations,
    coordinating between generator, engine, manager, and validator.
    """
    
    def __init__(self, config_dir: Optional[Path] = None):
        """
        Initialize the complete filtering system.
        
        Args:
            config_dir (Optional[Path]): Directory containing filter configurations
        """
        self.config_dir = Path(config_dir) if config_dir else Path("config/filters")
        
        # Initialize components
        self.engine = FilterEngine(self.config_dir)
        self.manager = FilterManager(self.config_dir)
        self.validator = FilterValidator()
        
        if FilterGenerator:
            self.generator = FilterGenerator()
        else:
            self.generator = None
            logger.warning("FilterGenerator not available in unified system")
        
        # Load filters on initialization
        self.reload_filters()
        
        logger.info("FilteringSystem initialized")
    
    def reload_filters(self) -> bool:
        """
        Reload all filters in the system.
        
        Returns:
            bool: True if reload successful
        """
        return self.engine.load_filters(self.config_dir)
    
    def should_filter(self, event, event_type: str = "behavioral"):
        """
        Primary filtering interface - determine if event should be filtered.
        
        Args:
            event: Event data to evaluate
            event_type (str): Type of event
            
        Returns:
            Tuple[bool, str]: (should_filter, reason)
        """
        return self.engine.should_filter_event(event, event_type)
    
    def add_filter(self, filter_type: str, category: str, pattern: str) -> bool:
        """
        Add a new filter pattern.
        
        Args:
            filter_type (str): Filter type (whitelist, blacklist, custom)
            category (str): Filter category (processes, files, etc.)
            pattern (str): Filter pattern
            
        Returns:
            bool: True if added successfully
        """
        success, msg = self.manager.add_filter(filter_type, category, pattern, notify_engine=True)
        if success:
            self.reload_filters()
        return success
    
    def validate_system(self) -> dict:
        """
        Validate the entire filtering system.
        
        Returns:
            dict: Validation report
        """
        return self.validator.validate_all_filters(self.engine)
    
    def get_statistics(self) -> dict:
        """
        Get comprehensive system statistics.
        
        Returns:
            dict: System statistics including engine performance and filter counts
        """
        return {
            'engine_stats': self.engine.get_filter_statistics(),
            'filter_stats': self.manager.get_filter_statistics(),
            'validation_history': getattr(self.validator, 'validation_results', [])
        }
    
    def generate_new_filters(self, baseline_data=None, malware_data=None):
        """
        Generate new filters from analysis data.
        
        Args:
            baseline_data: Clean system baseline data
            malware_data: Malware analysis data
            
        Returns:
            dict: Generated filters or error message
        """
        if not self.generator:
            return {'error': 'FilterGenerator not available'}
        
        try:
            if baseline_data:
                whitelist = self.generator.generate_whitelist_from_baseline(baseline_data)
                self.manager.replace_filter_set('whitelist', whitelist)
            
            if malware_data:
                blacklist = self.generator.generate_blacklist_from_malware(malware_data)
                self.manager.replace_filter_set('blacklist', blacklist)
            
            self.reload_filters()
            return {'success': True, 'message': 'Filters generated and loaded successfully'}
            
        except Exception as e:
            logger.error(f"Filter generation failed: {e}")
            return {'error': f'Filter generation failed: {e}'}

# Convenience function for quick setup
def setup_filtering_system(config_dir: Optional[Path] = None) -> FilteringSystem:
    """
    Quick setup for the filtering system.
    
    Args:
        config_dir (Optional[Path]): Filter configuration directory
        
    Returns:
        FilteringSystem: Configured filtering system
    """
    return FilteringSystem(config_dir)

# Backward compatibility aliases
Filter = FilterEngine
FilterManager = FilterManager  
FilterValidator = FilterValidator

__all__ = [
    'FilterEngine',
    'FilterManager', 
    'FilterValidator',
    'FilterGenerator',
    'FilteringSystem',
    'setup_filtering_system'
]