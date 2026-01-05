"""
Enhanced Logging Configuration for VMware vCenter MCP Server
Provides comprehensive logging capabilities with structured output and performance monitoring.
"""

import logging
import logging.handlers
import json
import time
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path


class StructuredFormatter(logging.Formatter):
    """Custom formatter for structured JSON logging."""
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as structured JSON."""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        # Add exception information if present
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)
        
        # Add custom fields if present
        if hasattr(record, 'user_id'):
            log_entry['user_id'] = record.user_id
        if hasattr(record, 'operation'):
            log_entry['operation'] = record.operation
        if hasattr(record, 'duration'):
            log_entry['duration_ms'] = record.duration
            
        return json.dumps(log_entry)


class PerformanceLogger:
    """Logger for performance monitoring and metrics."""
    
    def __init__(self, logger_name: str = 'performance'):
        self.logger = logging.getLogger(logger_name)
        self.start_times: Dict[str, float] = {}
    
    def start_operation(self, operation_id: str, operation_name: str) -> None:
        """Start timing an operation."""
        self.start_times[operation_id] = time.time()
        self.logger.info(
            f"Operation started: {operation_name}",
            extra={'operation': operation_name, 'operation_id': operation_id}
        )
    
    def end_operation(self, operation_id: str, operation_name: str, 
                     success: bool = True, **kwargs) -> None:
        """End timing an operation and log results."""
        if operation_id in self.start_times:
            duration = (time.time() - self.start_times[operation_id]) * 1000
            del self.start_times[operation_id]
            
            self.logger.info(
                f"Operation completed: {operation_name}",
                extra={
                    'operation': operation_name,
                    'operation_id': operation_id,
                    'duration': duration,
                    'success': success,
                    **kwargs
                }
            )


def setup_logging(log_level: str = 'INFO', log_dir: Optional[str] = None) -> None:
    """
    Setup comprehensive logging configuration.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_dir: Directory for log files (optional)
    """
    # Create log directory if specified
    if log_dir:
        Path(log_dir).mkdir(parents=True, exist_ok=True)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper()))
    
    # Clear existing handlers
    root_logger.handlers.clear()
    
    # Console handler with structured formatting
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(StructuredFormatter())
    root_logger.addHandler(console_handler)
    
    # File handler if log directory specified
    if log_dir:
        file_handler = logging.handlers.RotatingFileHandler(
            filename=f"{log_dir}/vmware_vcenter_mcp.log",
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5
        )
        file_handler.setFormatter(StructuredFormatter())
        root_logger.addHandler(file_handler)
        
        # Separate performance log
        perf_handler = logging.handlers.RotatingFileHandler(
            filename=f"{log_dir}/performance.log",
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=3
        )
        perf_handler.setFormatter(StructuredFormatter())
        
        perf_logger = logging.getLogger('performance')
        perf_logger.addHandler(perf_handler)
        perf_logger.setLevel(logging.INFO)


# Global performance logger instance
performance_logger = PerformanceLogger()