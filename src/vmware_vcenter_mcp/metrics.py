"""
Metrics Collection System for VMware vCenter MCP Server
"""

import time
from typing import Dict, Any
from collections import defaultdict, deque


class MetricsCollector:
    """Collect and aggregate system metrics."""
    
    def __init__(self):
        self.counters: Dict[str, int] = defaultdict(int)
        self.gauges: Dict[str, float] = {}
        self.histograms: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
    
    def increment(self, metric: str, value: int = 1) -> None:
        """Increment a counter metric."""
        self.counters[metric] += value
    
    def set_gauge(self, metric: str, value: float) -> None:
        """Set a gauge metric."""
        self.gauges[metric] = value
    
    def record_histogram(self, metric: str, value: float) -> None:
        """Record a histogram value."""
        self.histograms[metric].append(value)
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get all collected metrics."""
        return {
            'counters': dict(self.counters),
            'gauges': dict(self.gauges),
            'histograms': {k: list(v) for k, v in self.histograms.items()},
            'timestamp': time.time()
        }


# Global metrics collector
metrics = MetricsCollector()