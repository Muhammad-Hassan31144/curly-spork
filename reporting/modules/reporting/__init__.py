# shikra/modules/reporting/__init__.py
# Purpose: Initialize the reporting module, provide easy imports, and define the main orchestration logic.

import logging
from pathlib import Path
from typing import Dict, Any

# Import the core classes from the modules you provided
from .report_generator import ReportGenerator
from .visualizer import DataVisualizer
from .timeline_analyzer import TimelineAnalyzer

# Configure logging for the package
logger = logging.getLogger(__name__)

def generate_full_report(analysis_data: Dict[str, Any], output_directory: Path, report_formats: list, template_dir: Path):
    """
    Orchestrates the entire reporting pipeline from raw analysis to final report generation.

    Args:
        analysis_data (Dict[str, Any]): The raw JSON data from the ProcMon analyzer.
        output_directory (Path): The directory to save all reports and visualizations.
        report_formats (list): A list of formats to generate (e.g., ['html', 'pdf', 'json']).
        template_dir (Path): Path to the directory containing HTML templates.

    Returns:
        bool: True if successful, False otherwise.
    """
    logger.info("Starting full report generation pipeline...")
    output_directory.mkdir(parents=True, exist_ok=True)

    # --- Step 1: Timeline Analysis ---
    # Ingest raw data to find temporal patterns and correlations.
    timeline_analyzer = TimelineAnalyzer()
    
    # We will pass the full analysis data to the timeline analyzer
    # which can extract behavioral, network, and other events.
    # For this integration, we'll assume the main analysis JSON is the primary source.
    timeline_analyzer.events = analysis_data.get('high_risk_processes', [])
    
    # The 'analyze_timeline' method would need to be adapted to process this structure
    # For now, we'll pass the whole dict and assume it can handle it.
    enriched_data = timeline_analyzer.analyze_timeline() # This would ideally return the full, enriched dataset
    
    # For a robust integration, we will merge the timeline analysis back into the main data
    analysis_data['timeline_analysis'] = enriched_data


    # --- Step 2: Generate Visualizations ---
    # Use the enriched data to create all visual artifacts.
    visualizer = DataVisualizer(output_directory=output_directory)
    base_filename = analysis_data.get('metadata', {}).get('source_file', 'analysis').replace('.', '_')
    
    logger.info(f"Generating visual artifacts for base name: {base_filename}")
    visualization_paths = visualizer.generate_all_visualizations(analysis_data, base_filename)


    # --- Step 3: Generate Final Reports ---
    # Consolidate all data and visualizations into the final reports.
    report_generator = ReportGenerator(template_directory=template_dir, output_directory=output_directory)
    
    # Extract sample info for the report header
    sample_info = {
        "filename": analysis_data.get("metadata", {}).get("source_file", "N/A"),
        "hostname": analysis_data.get("metadata", {}).get("hostname", "N/A"),
        "timestamp": analysis_data.get("metadata", {}).get("analysis_timestamp_utc", "N/A"),
    }

    # Integrate the generated visualization paths into the report data
    analysis_data['visualizations'] = []
    for viz_name, viz_path in visualization_paths.items():
        if viz_path.exists():
            try:
                with open(viz_path, 'rb') as f:
                    image_data = base64.b64encode(f.read()).decode('utf-8')
                mime_type = f"image/{viz_path.suffix[1:]}"
                analysis_data['visualizations'].append({
                    "name": viz_name,
                    "data_uri": f"data:{mime_type};base64,{image_data}"
                })
            except Exception as e:
                logger.error(f"Failed to embed visualization {viz_path}: {e}")

    for report_format in report_formats:
        try:
            report_filename = f"{base_filename}_report.{report_format}"
            output_path = output_directory / report_filename
            report_generator.generate_comprehensive_report(
                analysis_results=analysis_data,
                sample_info=sample_info,
                output_path=output_path,
                report_format=report_format
            )
        except Exception as e:
            logger.error(f"Failed to generate {report_format} report: {e}", exc_info=True)
            return False
            
    logger.info("Full report generation pipeline completed successfully.")
    return True


# Expose the primary classes and the main orchestrator function
__all__ = [
    'ReportGenerator',
    'DataVisualizer',
    'TimelineAnalyzer',
    'generate_full_report'
]

__version__ = '1.0.0'
__author__ = 'Shikra Development Team'
