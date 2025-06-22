"""
Filter Validation System (filter_validator.py)

Purpose:
Validates filter effectiveness against known datasets and provides metrics
for filter performance. Ensures filters maintain high detection rates with
low false positives through continuous testing and statistical analysis.

Context in Shikra:
- Input: Filter configurations, test datasets with known classifications
- Processing: False positive/negative analysis, performance benchmarking
- Output: Validation reports, effectiveness metrics, improvement recommendations

Integration Points:
- Used by: filter_manager.py (validation before deployment), admin reports
- Tests with: generator.py (new filter validation), engine.py (performance testing)
- Validates: All filter types (whitelist, blacklist, custom) against test data
- Reports to: Web interface, monitoring systems, admin dashboards
"""

import logging
import json
import time
import statistics
from pathlib import Path
from typing import Dict, List, Set, Any, Optional, Tuple, Union
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from dataclasses import dataclass
import threading
import concurrent.futures

logger = logging.getLogger(__name__)

@dataclass
class ValidationResult:
    """Container for validation results."""
    filter_type: str
    category: str
    precision: float
    recall: float
    f1_score: float
    accuracy: float
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    test_samples: int
    validation_time_ms: float

@dataclass
class PerformanceMetrics:
    """Container for performance metrics."""
    avg_filter_time_ms: float
    max_filter_time_ms: float
    min_filter_time_ms: float
    throughput_per_second: float
    memory_usage_mb: float
    cpu_usage_percent: float

class FilterValidator:
    """
    Validates filter effectiveness and performance against test datasets.
    
    Provides comprehensive testing of filter configurations to ensure
    they maintain high detection rates with acceptable false positive
    rates. Includes performance benchmarking and continuous monitoring.
    """
    
    def __init__(self, test_data_dir: Optional[Path] = None):
        """
        Initialize the filter validator.
        
        Args:
            test_data_dir (Optional[Path]): Directory containing test datasets
        """
        self.test_data_dir = Path(test_data_dir) if test_data_dir else Path("test_data")
        self.validation_results = []
        self.performance_history = []
        
        # Validation thresholds
        self.thresholds = {
            'min_precision': 0.85,
            'min_recall': 0.80,
            'min_f1_score': 0.82,
            'max_false_positive_rate': 0.15,
            'max_filter_time_ms': 5.0,
            'min_throughput_per_second': 1000
        }
        
        # Test data configuration
        self.test_config = {
            'baseline_samples': 1000,
            'malware_samples': 500,
            'mixed_samples': 200,
            'performance_iterations': 10000,
            'concurrent_threads': 4
        }
        
        self._lock = threading.RLock()
        
        logger.info("FilterValidator initialized")
    
    def validate_all_filters(self, filter_engine, test_datasets: Optional[Dict[str, List[Dict]]] = None) -> Dict[str, Any]:
        """
        Validate all filter configurations comprehensively.
        
        Args:
            filter_engine: FilterEngine instance to test
            test_datasets (Optional[Dict[str, List[Dict]]]): Custom test datasets
            
        Returns:
            Dict[str, Any]: Complete validation report
        """
        logger.info("Starting comprehensive filter validation")
        start_time = time.time()
        
        # Load test datasets
        if not test_datasets:
            test_datasets = self._load_test_datasets()
        
        if not test_datasets:
            logger.error("No test datasets available for validation")
            return {'error': 'No test datasets available'}
        
        validation_report = {
            'validation_timestamp': datetime.now().isoformat(),
            'filter_results': {},
            'performance_metrics': {},
            'overall_scores': {},
            'recommendations': [],
            'pass_fail_status': {},
            'test_summary': {
                'total_samples': sum(len(samples) for samples in test_datasets.values()),
                'datasets': list(test_datasets.keys())
            }
        }
        
        # Validate each filter type and category
        for filter_type in ['whitelist', 'blacklist', 'custom']:
            validation_report['filter_results'][filter_type] = {}
            
            for category in ['processes', 'files', 'registry', 'network']:
                logger.info(f"Validating {filter_type}/{category} filters")
                
                result = self._validate_filter_category(
                    filter_engine, filter_type, category, test_datasets
                )
                
                validation_report['filter_results'][filter_type][category] = result
                
                # Store individual result
                self.validation_results.append(ValidationResult(
                    filter_type=filter_type,
                    category=category,
                    precision=result['precision'],
                    recall=result['recall'],
                    f1_score=result['f1_score'],
                    accuracy=result['accuracy'],
                    true_positives=result['confusion_matrix']['true_positives'],
                    false_positives=result['confusion_matrix']['false_positives'],
                    true_negatives=result['confusion_matrix']['true_negatives'],
                    false_negatives=result['confusion_matrix']['false_negatives'],
                    test_samples=result['test_samples'],
                    validation_time_ms=result['validation_time_ms']
                ))
        
        # Performance testing
        logger.info("Conducting performance testing")
        validation_report['performance_metrics'] = self._test_performance(filter_engine, test_datasets)
        
        # Calculate overall scores
        validation_report['overall_scores'] = self._calculate_overall_scores(validation_report['filter_results'])
        
        # Generate recommendations
        validation_report['recommendations'] = self._generate_recommendations(validation_report)
        
        # Determine pass/fail status
        validation_report['pass_fail_status'] = self._evaluate_pass_fail(validation_report)
        
        # Add timing information
        validation_report['validation_time_seconds'] = time.time() - start_time
        
        logger.info(f"Filter validation completed in {validation_report['validation_time_seconds']:.2f} seconds")
        return validation_report
    
    def validate_specific_filters(self, filter_engine, filter_patterns: Dict[str, List[str]], 
                                  test_samples: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Validate specific filter patterns against test samples.
        
        Args:
            filter_engine: FilterEngine instance
            filter_patterns (Dict[str, List[str]]): Patterns to test
            test_samples (List[Dict[str, Any]]): Test data with known classifications
            
        Returns:
            Dict[str, Any]: Validation results for specific patterns
        """
        logger.info(f"Validating {len(filter_patterns)} filter patterns against {len(test_samples)} samples")
        
        results = {
            'pattern_results': {},
            'summary': {
                'total_patterns': sum(len(patterns) for patterns in filter_patterns.values()),
                'total_samples': len(test_samples),
                'validation_timestamp': datetime.now().isoformat()
            }
        }
        
        for category, patterns in filter_patterns.items():
            results['pattern_results'][category] = {}
            
            for pattern in patterns:
                pattern_result = self._test_single_pattern(pattern, category, test_samples, filter_engine)
                results['pattern_results'][category][pattern] = pattern_result
        
        # Calculate summary statistics
        all_results = [
            result for category_results in results['pattern_results'].values()
            for result in category_results.values()
        ]
        
        if all_results:
            results['summary'].update({
                'avg_precision': statistics.mean(r['precision'] for r in all_results),
                'avg_recall': statistics.mean(r['recall'] for r in all_results),
                'avg_f1_score': statistics.mean(r['f1_score'] for r in all_results),
                'total_false_positives': sum(r['false_positives'] for r in all_results),
                'total_false_negatives': sum(r['false_negatives'] for r in all_results)
            })
        
        return results
    
    def benchmark_performance(self, filter_engine, iterations: int = 10000, 
                              concurrent_threads: int = 4) -> PerformanceMetrics:
        """
        Benchmark filter engine performance under load.
        
        Args:
            filter_engine: FilterEngine instance to benchmark
            iterations (int): Number of test iterations
            concurrent_threads (int): Number of concurrent threads
            
        Returns:
            PerformanceMetrics: Performance benchmark results
        """
        logger.info(f"Benchmarking performance with {iterations} iterations, {concurrent_threads} threads")
        
        # Generate test events
        test_events = self._generate_performance_test_events(iterations)
        
        # Single-threaded benchmark
        start_time = time.perf_counter()
        single_thread_times = []
        
        for event in test_events[:1000]:  # Sample for single-thread timing
            event_start = time.perf_counter()
            filter_engine.should_filter_event(event, event.get('type', 'behavioral'))
            event_time = (time.perf_counter() - event_start) * 1000  # Convert to ms
            single_thread_times.append(event_time)
        
        single_thread_duration = time.perf_counter() - start_time
        
        # Multi-threaded benchmark
        def process_batch(events_batch):
            batch_times = []
            for event in events_batch:
                event_start = time.perf_counter()
                filter_engine.should_filter_event(event, event.get('type', 'behavioral'))
                event_time = (time.perf_counter() - event_start) * 1000
                batch_times.append(event_time)
            return batch_times
        
        # Split events into batches for concurrent processing
        batch_size = len(test_events) // concurrent_threads
        batches = [
            test_events[i:i + batch_size] 
            for i in range(0, len(test_events), batch_size)
        ]
        
        start_time = time.perf_counter()
        all_times = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrent_threads) as executor:
            futures = [executor.submit(process_batch, batch) for batch in batches]
            for future in concurrent.futures.as_completed(futures):
                all_times.extend(future.result())
        
        total_duration = time.perf_counter() - start_time
        
        # Calculate metrics
        metrics = PerformanceMetrics(
            avg_filter_time_ms=statistics.mean(all_times),
            max_filter_time_ms=max(all_times),
            min_filter_time_ms=min(all_times),
            throughput_per_second=len(test_events) / total_duration,
            memory_usage_mb=self._get_memory_usage(),
            cpu_usage_percent=self._get_cpu_usage()
        )
        
        # Store in history
        self.performance_history.append({
            'timestamp': datetime.now().isoformat(),
            'metrics': metrics,
            'test_parameters': {
                'iterations': iterations,
                'concurrent_threads': concurrent_threads
            }
        })
        
        logger.info(f"Performance benchmark completed: {metrics.throughput_per_second:.0f} events/sec, "
                   f"avg {metrics.avg_filter_time_ms:.3f}ms per event")
        
        return metrics
    
    def continuous_validation(self, filter_engine, interval_hours: int = 24,
                              alert_threshold: float = 0.1) -> Dict[str, Any]:
        """
        Set up continuous validation monitoring.
        
        Args:
            filter_engine: FilterEngine instance to monitor
            interval_hours (int): Hours between validation runs
            alert_threshold (float): Threshold for performance degradation alerts
            
        Returns:
            Dict[str, Any]: Continuous monitoring setup status
        """
        logger.info(f"Setting up continuous validation every {interval_hours} hours")
        
        monitoring_config = {
            'interval_hours': interval_hours,
            'alert_threshold': alert_threshold,
            'next_validation': datetime.now() + timedelta(hours=interval_hours),
            'monitoring_enabled': True,
            'baseline_metrics': None
        }
        
        # Establish baseline metrics
        baseline_validation = self.validate_all_filters(filter_engine)
        monitoring_config['baseline_metrics'] = baseline_validation['overall_scores']
        
        logger.info("Continuous validation monitoring configured")
        return monitoring_config
    
    def compare_filter_versions(self, current_engine, new_engine, test_datasets: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Compare performance between two filter engine versions.
        
        Args:
            current_engine: Current FilterEngine instance
            new_engine: New FilterEngine instance to compare
            test_datasets (Optional[Dict]): Test datasets for comparison
            
        Returns:
            Dict[str, Any]: Comparison results and recommendations
        """
        logger.info("Comparing filter engine versions")
        
        if not test_datasets:
            test_datasets = self._load_test_datasets()
        
        # Validate both versions
        current_results = self.validate_all_filters(current_engine, test_datasets)
        new_results = self.validate_all_filters(new_engine, test_datasets)
        
        comparison = {
            'comparison_timestamp': datetime.now().isoformat(),
            'current_version': current_results,
            'new_version': new_results,
            'improvements': {},
            'regressions': {},
            'performance_delta': {},
            'recommendation': 'analyze'
        }
        
        # Compare overall scores
        current_scores = current_results['overall_scores']
        new_scores = new_results['overall_scores']
        
        for metric in ['precision', 'recall', 'f1_score']:
            delta = new_scores[metric] - current_scores[metric]
            comparison['performance_delta'][metric] = {
                'current': current_scores[metric],
                'new': new_scores[metric],
                'delta': delta,
                'percent_change': (delta / current_scores[metric]) * 100 if current_scores[metric] > 0 else 0
            }
            
            if delta > 0.02:  # Significant improvement
                comparison['improvements'][metric] = delta
            elif delta < -0.02:  # Significant regression
                comparison['regressions'][metric] = delta
        
        # Generate recommendation
        if comparison['regressions']:
            comparison['recommendation'] = 'reject'
        elif comparison['improvements']:
            comparison['recommendation'] = 'approve'
        else:
            comparison['recommendation'] = 'neutral'
        
        logger.info(f"Version comparison complete: {comparison['recommendation']}")
        return comparison
    
    def generate_validation_report(self, validation_results: Dict[str, Any],
                                   format_type: str = 'detailed') -> str:
        """
        Generate human-readable validation report.
        
        Args:
            validation_results (Dict[str, Any]): Results from validation
            format_type (str): Report format (detailed, summary, json)
            
        Returns:
            str: Formatted validation report
        """
        if format_type == 'json':
            return json.dumps(validation_results, indent=2)
        
        report_lines = []
        
        # Header
        report_lines.append("="*80)
        report_lines.append("SHIKRA FILTER VALIDATION REPORT")
        report_lines.append("="*80)
        report_lines.append(f"Validation Date: {validation_results.get('validation_timestamp', 'Unknown')}")
        report_lines.append(f"Total Test Samples: {validation_results.get('test_summary', {}).get('total_samples', 0)}")
        report_lines.append("")
        
        # Overall Scores
        overall = validation_results.get('overall_scores', {})
        report_lines.append("OVERALL PERFORMANCE:")
        report_lines.append(f"  Precision: {overall.get('precision', 0):.3f}")
        report_lines.append(f"  Recall:    {overall.get('recall', 0):.3f}")
        report_lines.append(f"  F1 Score:  {overall.get('f1_score', 0):.3f}")
        report_lines.append(f"  Accuracy:  {overall.get('accuracy', 0):.3f}")
        report_lines.append("")
        
        # Pass/Fail Status
        status = validation_results.get('pass_fail_status', {})
        report_lines.append("VALIDATION STATUS:")
        for category, passed in status.items():
            status_text = "PASS" if passed else "FAIL"
            report_lines.append(f"  {category}: {status_text}")
        report_lines.append("")
        
        if format_type == 'detailed':
            # Detailed filter results
            filter_results = validation_results.get('filter_results', {})
            for filter_type, categories in filter_results.items():
                report_lines.append(f"{filter_type.upper()} FILTERS:")
                for category, results in categories.items():
                    report_lines.append(f"  {category}:")
                    report_lines.append(f"    Precision: {results.get('precision', 0):.3f}")
                    report_lines.append(f"    Recall:    {results.get('recall', 0):.3f}")
                    report_lines.append(f"    F1 Score:  {results.get('f1_score', 0):.3f}")
                    
                    confusion = results.get('confusion_matrix', {})
                    report_lines.append(f"    TP: {confusion.get('true_positives', 0)}, "
                                      f"FP: {confusion.get('false_positives', 0)}, "
                                      f"TN: {confusion.get('true_negatives', 0)}, "
                                      f"FN: {confusion.get('false_negatives', 0)}")
                report_lines.append("")
            
            # Performance metrics
            perf = validation_results.get('performance_metrics', {})
            if perf:
                report_lines.append("PERFORMANCE METRICS:")
                report_lines.append(f"  Avg Filter Time: {perf.get('avg_filter_time_ms', 0):.3f} ms")
                report_lines.append(f"  Max Filter Time: {perf.get('max_filter_time_ms', 0):.3f} ms")
                report_lines.append(f"  Throughput: {perf.get('throughput_per_second', 0):.0f} events/sec")
                report_lines.append("")
        
        # Recommendations
        recommendations = validation_results.get('recommendations', [])
        if recommendations:
            report_lines.append("RECOMMENDATIONS:")
            for i, rec in enumerate(recommendations, 1):
                report_lines.append(f"  {i}. {rec}")
            report_lines.append("")
        
        report_lines.append("="*80)
        
        return "\n".join(report_lines)
    
    def _load_test_datasets(self) -> Dict[str, List[Dict[str, Any]]]:
        """Load test datasets from files."""
        datasets = {}
        
        try:
            dataset_files = {
                'baseline': self.test_data_dir / 'baseline_samples.json',
                'malware': self.test_data_dir / 'malware_samples.json',
                'mixed': self.test_data_dir / 'mixed_samples.json'
            }
            
            for dataset_name, file_path in dataset_files.items():
                if file_path.exists():
                    with open(file_path, 'r') as f:
                        datasets[dataset_name] = json.load(f)
                    logger.info(f"Loaded {len(datasets[dataset_name])} samples from {dataset_name}")
                else:
                    logger.warning(f"Test dataset not found: {file_path}")
                    # Generate synthetic test data as fallback
                    datasets[dataset_name] = self._generate_synthetic_test_data(dataset_name)
            
        except Exception as e:
            logger.error(f"Failed to load test datasets: {e}")
            # Generate all synthetic data as fallback
            datasets = {
                'baseline': self._generate_synthetic_test_data('baseline'),
                'malware': self._generate_synthetic_test_data('malware'),
                'mixed': self._generate_synthetic_test_data('mixed')
            }
        
        return datasets
    
    def _generate_synthetic_test_data(self, dataset_type: str) -> List[Dict[str, Any]]:
        """Generate synthetic test data for validation."""
        logger.info(f"Generating synthetic test data for {dataset_type}")
        
        synthetic_data = []
        
        if dataset_type == 'baseline':
            # Generate benign system activity
            for i in range(self.test_config['baseline_samples']):
                synthetic_data.extend([
                    {
                        'type': 'processes',
                        'classification': 'benign',
                        'command': f'C:\\Windows\\System32\\{choice(["svchost.exe", "explorer.exe", "winlogon.exe"])}',
                        'process_name': choice(['svchost.exe', 'explorer.exe', 'winlogon.exe']),
                        'parent_process': 'services.exe'
                    },
                    {
                        'type': 'files',
                        'classification': 'benign',
                        'path': f'C:\\Users\\User\\Documents\\file_{i}.txt',
                        'operation': 'create'
                    },
                    {
                        'type': 'registry',
                        'classification': 'benign',
                        'key': f'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\{choice(["Run", "Explorer", "Policies"])}',
                        'value': f'legitimate_value_{i}'
                    },
                    {
                        'type': 'network',
                        'classification': 'benign',
                        'destination': choice(['microsoft.com', 'windows.com', 'office.com']),
                        'domain': choice(['microsoft.com', 'windows.com', 'office.com']),
                        'protocol': 'https'
                    }
                ])
        
        elif dataset_type == 'malware':
            # Generate malicious activity patterns
            for i in range(self.test_config['malware_samples']):
                synthetic_data.extend([
                    {
                        'type': 'processes',
                        'classification': 'malicious',
                        'command': f'C:\\Temp\\{choice(["malware", "trojan", "backdoor"])}_{i}.exe',
                        'process_name': f'{choice(["malware", "trojan", "backdoor"])}_{i}.exe',
                        'parent_process': 'explorer.exe'
                    },
                    {
                        'type': 'files',
                        'classification': 'malicious',
                        'path': f'C:\\Windows\\System32\\{choice(["evil", "malicious", "suspicious"])}_{i}.dll',
                        'operation': 'create'
                    },
                    {
                        'type': 'registry',
                        'classification': 'malicious',
                        'key': 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                        'value': f'C:\\Temp\\persistence_{i}.exe'
                    },
                    {
                        'type': 'network',
                        'classification': 'malicious',
                        'destination': f'{choice(["evil", "malicious", "c2"])}-{i}.{choice(["tk", "ml", "cf"])}',
                        'domain': f'{choice(["evil", "malicious", "c2"])}-{i}.{choice(["tk", "ml", "cf"])}',
                        'protocol': 'http'
                    }
                ])
        
        else:  # mixed
            # Generate mix of benign and malicious
            benign_samples = self._generate_synthetic_test_data('baseline')[:self.test_config['mixed_samples']//2]
            malicious_samples = self._generate_synthetic_test_data('malware')[:self.test_config['mixed_samples']//2]
            synthetic_data = benign_samples + malicious_samples
        
        return synthetic_data
    
    def choice(self, items):
        """Simple choice function to avoid importing random."""
        return items[len(items) % 3]  # Simple deterministic selection
    
    def _validate_filter_category(self, filter_engine, filter_type: str, category: str, 
                                   test_datasets: Dict[str, List[Dict]]) -> Dict[str, Any]:
        """Validate a specific filter category."""
        start_time = time.perf_counter()
        
        # Combine all test samples
        all_samples = []
        for dataset in test_datasets.values():
            all_samples.extend([sample for sample in dataset if sample.get('type') == category])
        
        if not all_samples:
            return {
                'precision': 0.0, 'recall': 0.0, 'f1_score': 0.0, 'accuracy': 0.0,
                'confusion_matrix': {'true_positives': 0, 'false_positives': 0, 'true_negatives': 0, 'false_negatives': 0},
                'test_samples': 0, 'validation_time_ms': 0.0, 'error': 'No test samples for category'
            }
        
        # Test each sample
        tp = tn = fp = fn = 0
        
        for sample in all_samples:
            actual_malicious = sample.get('classification', '').lower() in ['malicious', 'ransomware', 'trojan']
            
            # Get filter decision
            should_filter, reason = filter_engine.should_filter_event(sample, category)
            
            # For whitelist: should_filter=True means benign (filter out)
            # For blacklist: should_filter=False and suspicious reason means malicious (keep for analysis)
            if filter_type == 'whitelist':
                predicted_benign = should_filter
            elif filter_type == 'blacklist':
                predicted_benign = should_filter and 'blacklist' not in reason.lower()
            else:  # custom
                predicted_benign = should_filter
            
            predicted_malicious = not predicted_benign
            
            # Calculate confusion matrix
            if actual_malicious and predicted_malicious:
                tp += 1
            elif actual_malicious and predicted_benign:
                fn += 1
            elif not actual_malicious and predicted_malicious:
                fp += 1
            else:  # not actual_malicious and predicted_benign
                tn += 1
        
        # Calculate metrics
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0.0
        
        validation_time_ms = (time.perf_counter() - start_time) * 1000
        
        return {
            'precision': precision,
            'recall': recall,
            'f1_score': f1_score,
            'accuracy': accuracy,
            'confusion_matrix': {
                'true_positives': tp,
                'false_positives': fp,
                'true_negatives': tn,
                'false_negatives': fn
            },
            'test_samples': len(all_samples),
            'validation_time_ms': validation_time_ms
        }
    
    def _test_single_pattern(self, pattern: str, category: str, test_samples: List[Dict], 
                             filter_engine) -> Dict[str, Any]:
        """Test a single filter pattern against test samples."""
        matches = 0
        false_positives = 0
        false_negatives = 0
        
        for sample in test_samples:
            if sample.get('type') != category:
                continue
            
            # Simulate pattern matching
            sample_data = self._extract_sample_data(sample, category)
            pattern_matches = any(pattern.lower() in str(data).lower() for data in sample_data)
            
            actual_malicious = sample.get('classification', '').lower() in ['malicious', 'ransomware', 'trojan']
            
            if pattern_matches:
                matches += 1
                if not actual_malicious:  # Pattern matched benign sample
                    false_positives += 1
            else:
                if actual_malicious:  # Pattern didn't match malicious sample
                    false_negatives += 1
        
        total_samples = len([s for s in test_samples if s.get('type') == category])
        precision = (matches - false_positives) / matches if matches > 0 else 0.0
        recall = (matches - false_positives) / (matches - false_positives + false_negatives) if (matches - false_positives + false_negatives) > 0 else 0.0
        
        return {
            'matches': matches,
            'false_positives': false_positives,
            'false_negatives': false_negatives,
            'total_samples': total_samples,
            'precision': precision,
            'recall': recall,
            'f1_score': 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        }
    
    def _extract_sample_data(self, sample: Dict[str, Any], category: str) -> List[str]:
        """Extract relevant data from a sample for pattern matching."""
        data = []
        
        if category == 'processes':
            data.extend([sample.get('command', ''), sample.get('process_name', ''), sample.get('parent_process', '')])
        elif category == 'files':
            data.extend([sample.get('path', ''), sample.get('operation', '')])
        elif category == 'registry':
            data.extend([sample.get('key', ''), str(sample.get('value', ''))])
        elif category == 'network':
            data.extend([sample.get('destination', ''), sample.get('domain', ''), sample.get('protocol', '')])
        
        return [d for d in data if d]
    
    def _test_performance(self, filter_engine, test_datasets: Dict[str, List[Dict]]) -> Dict[str, Any]:
        """Test filter engine performance."""
        # Use benchmark method
        metrics = self.benchmark_performance(filter_engine, 
                                           self.test_config['performance_iterations'],
                                           self.test_config['concurrent_threads'])
        
        return {
            'avg_filter_time_ms': metrics.avg_filter_time_ms,
            'max_filter_time_ms': metrics.max_filter_time_ms,
            'min_filter_time_ms': metrics.min_filter_time_ms,
            'throughput_per_second': metrics.throughput_per_second,
            'memory_usage_mb': metrics.memory_usage_mb,
            'cpu_usage_percent': metrics.cpu_usage_percent,
            'performance_grade': self._grade_performance(metrics)
        }
    
    def _grade_performance(self, metrics: PerformanceMetrics) -> str:
        """Grade performance metrics."""
        if metrics.avg_filter_time_ms <= 1.0 and metrics.throughput_per_second >= 5000:
            return 'A'
        elif metrics.avg_filter_time_ms <= 2.0 and metrics.throughput_per_second >= 2000:
            return 'B'
        elif metrics.avg_filter_time_ms <= 5.0 and metrics.throughput_per_second >= 1000:
            return 'C'
        else:
            return 'D'
    
    def _generate_performance_test_events(self, count: int) -> List[Dict[str, Any]]:
        """Generate test events for performance testing."""
        events = []
        event_types = ['processes', 'files', 'registry', 'network']
        
        for i in range(count):
            event_type = event_types[i % len(event_types)]
            
            if event_type == 'processes':
                event = {
                    'type': 'processes',
                    'command': f'C:\\Program Files\\App\\process_{i}.exe',
                    'process_name': f'process_{i}.exe',
                    'parent_process': 'explorer.exe'
                }
            elif event_type == 'files':
                event = {
                    'type': 'files',
                    'path': f'C:\\Users\\User\\Documents\\file_{i}.txt',
                    'operation': 'create'
                }
            elif event_type == 'registry':
                event = {
                    'type': 'registry',
                    'key': f'HKEY_CURRENT_USER\\Software\\TestApp_{i}',
                    'value': f'test_value_{i}'
                }
            else:  # network
                event = {
                    'type': 'network',
                    'destination': f'test-server-{i % 100}.com',
                    'domain': f'test-server-{i % 100}.com',
                    'protocol': 'https'
                }
            
            events.append(event)
        
        return events
    
    def _calculate_overall_scores(self, filter_results: Dict[str, Dict[str, Dict]]) -> Dict[str, float]:
        """Calculate overall scores across all filters."""
        all_results = []
        
        for filter_type, categories in filter_results.items():
            for category, results in categories.items():
                if 'precision' in results:
                    all_results.append(results)
        
        if not all_results:
            return {'precision': 0.0, 'recall': 0.0, 'f1_score': 0.0, 'accuracy': 0.0}
        
        return {
            'precision': statistics.mean(r['precision'] for r in all_results),
            'recall': statistics.mean(r['recall'] for r in all_results),
            'f1_score': statistics.mean(r['f1_score'] for r in all_results),
            'accuracy': statistics.mean(r['accuracy'] for r in all_results)
        }
    
    def _generate_recommendations(self, validation_report: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on validation results."""
        recommendations = []
        overall = validation_report.get('overall_scores', {})
        
        if overall.get('precision', 0) < self.thresholds['min_precision']:
            recommendations.append(f"Low precision ({overall['precision']:.3f}): Consider increasing filter specificity to reduce false positives")
        
        if overall.get('recall', 0) < self.thresholds['min_recall']:
            recommendations.append(f"Low recall ({overall['recall']:.3f}): Consider adding more malware indicators to improve detection coverage")
        
        if overall.get('f1_score', 0) < self.thresholds['min_f1_score']:
            recommendations.append(f"Low F1 score ({overall['f1_score']:.3f}): Review balance between precision and recall")
        
        # Performance recommendations
        perf = validation_report.get('performance_metrics', {})
        if perf.get('avg_filter_time_ms', 0) > self.thresholds['max_filter_time_ms']:
            recommendations.append(f"Slow filtering ({perf['avg_filter_time_ms']:.3f}ms): Consider optimizing filter patterns for better performance")
        
        if perf.get('throughput_per_second', 0) < self.thresholds['min_throughput_per_second']:
            recommendations.append(f"Low throughput ({perf['throughput_per_second']:.0f} events/sec): Review filter complexity and consider pattern optimization")
        
        if not recommendations:
            recommendations.append("Filter validation passed all thresholds. Continue regular monitoring.")
        
        return recommendations
    
    def _evaluate_pass_fail(self, validation_report: Dict[str, Any]) -> Dict[str, bool]:
        """Evaluate pass/fail status based on thresholds."""
        overall = validation_report.get('overall_scores', {})
        perf = validation_report.get('performance_metrics', {})
        
        return {
            'precision': overall.get('precision', 0) >= self.thresholds['min_precision'],
            'recall': overall.get('recall', 0) >= self.thresholds['min_recall'],
            'f1_score': overall.get('f1_score', 0) >= self.thresholds['min_f1_score'],
            'performance': (perf.get('avg_filter_time_ms', 0) <= self.thresholds['max_filter_time_ms'] and
                          perf.get('throughput_per_second', 0) >= self.thresholds['min_throughput_per_second']),
            'overall': all([
                overall.get('precision', 0) >= self.thresholds['min_precision'],
                overall.get('recall', 0) >= self.thresholds['min_recall'],
                overall.get('f1_score', 0) >= self.thresholds['min_f1_score'],
                perf.get('avg_filter_time_ms', 0) <= self.thresholds['max_filter_time_ms']
            ])
        }
    
    def _get_memory_usage(self) -> float:
        """Get current memory usage in MB."""
        try:
            import psutil
            process = psutil.Process()
            return process.memory_info().rss / 1024 / 1024  # Convert to MB
        except ImportError:
            return 0.0
    
    def _get_cpu_usage(self) -> float:
        """Get current CPU usage percentage."""
        try:
            import psutil
            return psutil.cpu_percent(interval=1)
        except ImportError:
            return 0.0