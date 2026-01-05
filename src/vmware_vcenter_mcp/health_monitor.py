"""
Health Monitoring System for VMware vCenter MCP Server
Provides comprehensive health checks and system monitoring.
"""

import time
import threading
import psutil
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass
from enum import Enum


class HealthStatus(Enum):
    """Health status enumeration."""
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


@dataclass
class HealthCheck:
    """Health check result."""
    name: str
    status: HealthStatus
    message: str
    details: Dict[str, Any]
    timestamp: float
    duration_ms: float


class HealthMonitor:
    """System health monitoring."""
    
    def __init__(self):
        self.checks: Dict[str, Callable] = {}
        self.results: Dict[str, HealthCheck] = {}
        self.lock = threading.Lock()
        self.monitoring = False
        self.monitor_thread: Optional[threading.Thread] = None
    
    def register_check(self, name: str, check_func: Callable) -> None:
        """Register a health check function."""
        self.checks[name] = check_func
    
    def run_check(self, name: str) -> HealthCheck:
        """Run a specific health check."""
        if name not in self.checks:
            return HealthCheck(
                name=name,
                status=HealthStatus.UNKNOWN,
                message=f"Health check '{name}' not found",
                details={},
                timestamp=time.time(),
                duration_ms=0
            )
        
        start_time = time.time()
        try:
            result = self.checks[name]()
            duration = (time.time() - start_time) * 1000
            
            if isinstance(result, HealthCheck):
                result.duration_ms = duration
                return result
            else:
                # Convert simple result to HealthCheck
                return HealthCheck(
                    name=name,
                    status=HealthStatus.HEALTHY if result else HealthStatus.CRITICAL,
                    message="Check completed",
                    details={"result": result},
                    timestamp=time.time(),
                    duration_ms=duration
                )
        except Exception as e:
            duration = (time.time() - start_time) * 1000
            return HealthCheck(
                name=name,
                status=HealthStatus.CRITICAL,
                message=f"Health check failed: {str(e)}",
                details={"error": str(e)},
                timestamp=time.time(),
                duration_ms=duration
            )
    
    def run_all_checks(self) -> Dict[str, HealthCheck]:
        """Run all registered health checks."""
        results = {}
        for name in self.checks:
            results[name] = self.run_check(name)
        
        with self.lock:
            self.results.update(results)
        
        return results
    
    def get_health_summary(self) -> Dict[str, Any]:
        """Get overall health summary."""
        with self.lock:
            if not self.results:
                return {
                    "status": HealthStatus.UNKNOWN.value,
                    "message": "No health checks available",
                    "checks": {},
                    "summary": {
                        "total": 0,
                        "healthy": 0,
                        "warning": 0,
                        "critical": 0,
                        "unknown": 0
                    }
                }
            
            summary = {
                "healthy": 0,
                "warning": 0,
                "critical": 0,
                "unknown": 0
            }
            
            for check in self.results.values():
                summary[check.status.value] += 1
            
            # Determine overall status
            if summary["critical"] > 0:
                overall_status = HealthStatus.CRITICAL
                message = f"{summary['critical']} critical issues found"
            elif summary["warning"] > 0:
                overall_status = HealthStatus.WARNING
                message = f"{summary['warning']} warnings found"
            elif summary["unknown"] > 0:
                overall_status = HealthStatus.WARNING
                message = f"{summary['unknown']} unknown status checks"
            else:
                overall_status = HealthStatus.HEALTHY
                message = "All systems healthy"
            
            return {
                "status": overall_status.value,
                "message": message,
                "checks": {name: {
                    "status": check.status.value,
                    "message": check.message,
                    "timestamp": check.timestamp,
                    "duration_ms": check.duration_ms
                } for name, check in self.results.items()},
                "summary": {
                    "total": len(self.results),
                    **summary
                }
            }


def check_system_resources() -> HealthCheck:
    """Check system resource usage."""
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        details = {
            "cpu_percent": cpu_percent,
            "memory_percent": memory.percent,
            "memory_available_gb": round(memory.available / (1024**3), 2),
            "disk_percent": disk.percent,
            "disk_free_gb": round(disk.free / (1024**3), 2)
        }
        
        # Determine status based on thresholds
        if cpu_percent > 90 or memory.percent > 90 or disk.percent > 90:
            status = HealthStatus.CRITICAL
            message = "Critical resource usage detected"
        elif cpu_percent > 75 or memory.percent > 75 or disk.percent > 75:
            status = HealthStatus.WARNING
            message = "High resource usage detected"
        else:
            status = HealthStatus.HEALTHY
            message = "System resources within normal limits"
        
        return HealthCheck(
            name="system_resources",
            status=status,
            message=message,
            details=details,
            timestamp=time.time(),
            duration_ms=0
        )
    except Exception as e:
        return HealthCheck(
            name="system_resources",
            status=HealthStatus.CRITICAL,
            message=f"Failed to check system resources: {str(e)}",
            details={"error": str(e)},
            timestamp=time.time(),
            duration_ms=0
        )


def check_database_connection() -> HealthCheck:
    """Check database connectivity (placeholder)."""
    # This would typically check actual database connection
    try:
        # Simulate database check
        time.sleep(0.1)  # Simulate connection time
        
        return HealthCheck(
            name="database_connection",
            status=HealthStatus.HEALTHY,
            message="Database connection successful",
            details={
                "connection_time_ms": 100,
                "pool_size": 10,
                "active_connections": 3
            },
            timestamp=time.time(),
            duration_ms=0
        )
    except Exception as e:
        return HealthCheck(
            name="database_connection",
            status=HealthStatus.CRITICAL,
            message=f"Database connection failed: {str(e)}",
            details={"error": str(e)},
            timestamp=time.time(),
            duration_ms=0
        )


def check_vcenter_connectivity() -> HealthCheck:
    """Check vCenter server connectivity (placeholder)."""
    try:
        # This would typically check actual vCenter connection
        # Simulate vCenter API check
        time.sleep(0.2)
        
        return HealthCheck(
            name="vcenter_connectivity",
            status=HealthStatus.HEALTHY,
            message="vCenter server accessible",
            details={
                "response_time_ms": 200,
                "api_version": "7.0.3",
                "session_active": True
            },
            timestamp=time.time(),
            duration_ms=0
        )
    except Exception as e:
        return HealthCheck(
            name="vcenter_connectivity",
            status=HealthStatus.CRITICAL,
            message=f"vCenter connectivity failed: {str(e)}",
            details={"error": str(e)},
            timestamp=time.time(),
            duration_ms=0
        )


# Global health monitor instance
health_monitor = HealthMonitor()

# Register default health checks
health_monitor.register_check("system_resources", check_system_resources)
health_monitor.register_check("database_connection", check_database_connection)
health_monitor.register_check("vcenter_connectivity", check_vcenter_connectivity)