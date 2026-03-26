import json
import time
from datetime import datetime

import psutil


class PerformanceTracker:
    """Track and report performance metrics for research documentation"""

    def __init__(self):
        self.start_time = time.time()
        self.process = psutil.Process()
        self.metrics = {
            'start_timestamp': datetime.now().isoformat(),
            'dataset_info': {},
            'processing_steps': [],
            'node_counts': {},
            'edge_counts': {},
            'temporal_reduction': {},
            'memory_usage': {},
            'timings': {}
        }
        self.step_times = {}

    def start_step(self, step_name):
        """Mark the start of a processing step"""
        self.step_times[step_name] = time.time()
        print(f"\n[{step_name}] Starting...")

    def end_step(self, step_name, additional_info=None):
        """Mark the end of a processing step and record metrics"""
        elapsed = time.time() - self.step_times[step_name]
        mem_info = self.process.memory_info()

        step_data = {
            'duration_seconds': round(elapsed, 3),
            'memory_mb': round(mem_info.rss / 1024 / 1024, 2),
            'memory_percent': round(self.process.memory_percent(), 2)
        }

        if additional_info:
            step_data.update(additional_info)

        self.metrics['processing_steps'].append({
            'step': step_name,
            **step_data
        })

        print(f"[{step_name}] Completed in {elapsed:.2f}s (Memory: {step_data['memory_mb']:.0f} MB)")

    def record_dataset_size(self, con, table_name, description):
        """Record the size of a dataset"""
        result = con.execute(f"SELECT COUNT(*) as count FROM {table_name}").fetchone()
        count = result[0] if result else 0
        self.metrics['dataset_info'][table_name] = {
            'description': description,
            'row_count': count
        }
        return count

    def record_node_count(self, con, table_name, node_type):
        """Record node counts"""
        count = con.execute(f"SELECT COUNT(*) FROM {table_name}").fetchone()[0]
        self.metrics['node_counts'][node_type] = count
        print(f"  {node_type}: {count:,}")
        return count

    def record_edge_count(self, con, table_name, edge_type):
        """Record edge counts"""
        count = con.execute(f"SELECT COUNT(*) FROM {table_name}").fetchone()[0]
        self.metrics['edge_counts'][edge_type] = count
        print(f"  {edge_type}: {count:,}")
        return count

    def record_temporal_reduction(self, con, original_view, filtered_table, event_type):
        """Calculate and record data reduction statistics"""
        original_count = con.execute(f"SELECT COUNT(*) FROM {original_view}").fetchone()[0]
        filtered_count = con.execute(f"SELECT COUNT(*) FROM {filtered_table}").fetchone()[0]
        reduction_percent = ((original_count - filtered_count) / original_count * 100) if original_count > 0 else 0

        self.metrics['temporal_reduction'][event_type] = {
            'original_count': original_count,
            'filtered_count': filtered_count,
            'removed_count': original_count - filtered_count,
            'reduction_percent': round(reduction_percent, 2),
            'retention_percent': round(100 - reduction_percent, 2)
        }

        print(f"  {event_type}:")
        print(f"    Original: {original_count:,}")
        print(f"    Filtered: {filtered_count:,}")
        print(f"    Reduction: {reduction_percent:.2f}%")

    def finalize(self):
        """Calculate final metrics"""
        total_time = time.time() - self.start_time
        mem_info = self.process.memory_info()

        self.metrics['end_timestamp'] = datetime.now().isoformat()
        self.metrics['timings']['total_duration_seconds'] = round(total_time, 3)
        self.metrics['timings']['total_duration_formatted'] = f"{int(total_time // 60)}m {int(total_time % 60)}s"

        self.metrics['memory_usage']['final_mb'] = round(mem_info.rss / 1024 / 1024, 2)
        self.metrics['memory_usage']['peak_mb'] = round(self.process.memory_info().rss / 1024 / 1024, 2)
        self.metrics['memory_usage']['final_percent'] = round(self.process.memory_percent(), 2)

        # Calculate total reduction
        total_original = sum(r['original_count'] for r in self.metrics['temporal_reduction'].values())
        total_filtered = sum(r['filtered_count'] for r in self.metrics['temporal_reduction'].values())
        total_reduction = ((total_original - total_filtered) / total_original * 100) if total_original > 0 else 0

        self.metrics['temporal_reduction']['total'] = {
            'original_count': total_original,
            'filtered_count': total_filtered,
            'removed_count': total_original - total_filtered,
            'reduction_percent': round(total_reduction, 2)
        }

    def print_summary(self):
        """Print a formatted summary for the terminal"""
        print("\n" + "="*70)
        print("PERFORMANCE SUMMARY")
        print("="*70)

        print(f"\nTotal Processing Time: {self.metrics['timings']['total_duration_formatted']}")
        print(f"Peak Memory Usage: {self.metrics['memory_usage']['peak_mb']:.0f} MB")

        print("\n--- Node Counts ---")
        for node_type, count in self.metrics['node_counts'].items():
            print(f"  {node_type}: {count:,}")

        print("\n--- Edge Counts ---")
        for edge_type, count in self.metrics['edge_counts'].items():
            print(f"  {edge_type}: {count:,}")

        print("\n--- Data Reduction (Temporal Events) ---")
        for event_type, stats in self.metrics['temporal_reduction'].items():
            if event_type != 'total':
                print(f"  {event_type}:")
                print(f"    {stats['original_count']:,} → {stats['filtered_count']:,} ({stats['reduction_percent']:.1f}% reduction)")

        if 'total' in self.metrics['temporal_reduction']:
            total = self.metrics['temporal_reduction']['total']
            print(f"\n  Total Events:")
            print(f"    {total['original_count']:,} → {total['filtered_count']:,} ({total['reduction_percent']:.1f}% reduction)")

        print("\n" + "="*70)

    def save_to_json(self, filepath='data/etl_metrics.json'):
        """Save metrics to JSON for research documentation"""
        with open(filepath, 'w') as f:
            json.dump(self.metrics, f, indent=2)
        print(f"\nDetailed metrics saved to: {filepath}")

    def save_to_markdown(self, filepath='data/etl_report.md'):
        """Generate a markdown report for research papers"""
        with open(filepath, 'w') as f:
            f.write("# LANL Dataset ETL Performance Report\n\n")

            f.write(f"**Generated:** {self.metrics['start_timestamp']}\n\n")
            f.write(f"**Processing Time:** {self.metrics['timings']['total_duration_formatted']}\n\n")
            f.write(f"**Peak Memory Usage:** {self.metrics['memory_usage']['peak_mb']:.0f} MB\n\n")

            f.write("## Dataset Statistics\n\n")
            f.write("### Node Counts\n\n")
            f.write("| Node Type | Count |\n")
            f.write("|-----------|-------|\n")
            for node_type, count in self.metrics['node_counts'].items():
                f.write(f"| {node_type} | {count:,} |\n")

            f.write("\n### Edge Counts\n\n")
            f.write("| Edge Type | Count |\n")
            f.write("|-----------|-------|\n")
            for edge_type, count in self.metrics['edge_counts'].items():
                f.write(f"| {edge_type} | {count:,} |\n")

            f.write("\n### Temporal Event Reduction\n\n")
            f.write("| Event Type | Original | Filtered | Reduction |\n")
            f.write("|------------|----------|----------|----------|\n")
            for event_type, stats in self.metrics['temporal_reduction'].items():
                if event_type != 'total':
                    f.write(f"| {event_type} | {stats['original_count']:,} | {stats['filtered_count']:,} | {stats['reduction_percent']:.2f}% |\n")

            if 'total' in self.metrics['temporal_reduction']:
                total = self.metrics['temporal_reduction']['total']
                f.write(f"| **Total** | **{total['original_count']:,}** | **{total['filtered_count']:,}** | **{total['reduction_percent']:.2f}%** |\n")

            f.write("\n## Processing Steps\n\n")
            f.write("| Step | Duration (s) | Memory (MB) |\n")
            f.write("|------|--------------|-------------|\n")
            for step in self.metrics['processing_steps']:
                f.write(f"| {step['step']} | {step['duration_seconds']:.3f} | {step['memory_mb']:.0f} |\n")

        print(f"Markdown report saved to: {filepath}")
