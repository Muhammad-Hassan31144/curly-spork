"""
Stealth Reporting Module

Generates comprehensive reports on stealth effectiveness.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger(__name__)

class StealthReporter:
    """Advanced stealth reporting engine."""
    
    def __init__(self, output_dir: Optional[Path] = None):
        self.output_dir = Path(output_dir) if output_dir else Path("reports/stealth")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        logger.info("StealthReporter initialized")
    
    def generate_comprehensive_report(self, validation_report, stealth_config: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive stealth report."""
        logger.info(f"Generating report for VM: {validation_report.vm_name}")
        
        report = {
            'metadata': {
                'vm_name': validation_report.vm_name,
                'report_type': 'comprehensive_stealth_analysis',
                'generation_timestamp': datetime.now().isoformat(),
                'stealth_level': validation_report.stealth_level,
                'overall_effectiveness': validation_report.effectiveness_rating,
                'overall_score': validation_report.overall_score
            },
            'executive_summary': {
                'overall_effectiveness': validation_report.effectiveness_rating,
                'confidence_score': validation_report.overall_score,
                'tests_passed': f"{sum(1 for t in validation_report.tests if t.passed)}/{len(validation_report.tests)}",
                'stealth_level_applied': validation_report.stealth_level
            },
            'recommendations': validation_report.recommendations
        }
        
        return report
    
    def export_report(self, report_data: Dict[str, Any], format_type: str = "json", 
                     filename: Optional[str] = None) -> Path:
        """Export report to file."""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            vm_name = report_data['metadata']['vm_name']
            filename = f"stealth_report_{vm_name}_{timestamp}"
        
        if format_type.lower() == "json":
            output_file = self.output_dir / f"{filename}.json"
            with open(output_file, 'w') as f:
                json.dump(report_data, f, indent=2)
        else:
            raise ValueError(f"Unsupported format: {format_type}")
        
        logger.info(f"Report exported to: {output_file}")
        return output_file
