"""
VMware vCenter MCP Server - Enterprise Core Architecture

This module provides the enterprise-grade core architecture for the VMware vCenter
MCP Server, including multi-tenancy, RBAC, high availability, and scalability features.

Author: uldyssian-sh
License: MIT
Version: 1.0.0
"""

# Import only existing modules to avoid import errors
try:
    from .auth import AuthenticationManager, AuthorizationManager, RBACManager
    _AUTH_AVAILABLE = True
except ImportError:
    _AUTH_AVAILABLE = False

try:
    from .security import SecurityManager, EncryptionManager
    _SECURITY_AVAILABLE = True
except ImportError:
    _SECURITY_AVAILABLE = False

try:
    from .tenant import TenantManager
    _TENANT_AVAILABLE = True
except ImportError:
    _TENANT_AVAILABLE = False

try:
    from .database import DatabaseManager
    _DATABASE_AVAILABLE = True
except ImportError:
    _DATABASE_AVAILABLE = False

try:
    from .monitoring import MetricsCollector, HealthCheckManager
    _MONITORING_AVAILABLE = True
except ImportError:
    _MONITORING_AVAILABLE = False

try:
    from .ha import HighAvailabilityManager
    _HA_AVAILABLE = True
except ImportError:
    _HA_AVAILABLE = False

try:
    from .orchestration import OrchestrationEngine
    _ORCHESTRATION_AVAILABLE = True
except ImportError:
    _ORCHESTRATION_AVAILABLE = False

try:
    from .api import APIGateway
    _API_AVAILABLE = True
except ImportError:
    _API_AVAILABLE = False

# Build __all__ dynamically based on available imports
__all__ = []

if _AUTH_AVAILABLE:
    __all__.extend(["AuthenticationManager", "AuthorizationManager", "RBACManager"])

if _SECURITY_AVAILABLE:
    __all__.extend(["SecurityManager", "EncryptionManager"])

if _TENANT_AVAILABLE:
    __all__.extend(["TenantManager"])

if _DATABASE_AVAILABLE:
    __all__.extend(["DatabaseManager"])

if _MONITORING_AVAILABLE:
    __all__.extend(["MetricsCollector", "HealthCheckManager"])

if _HA_AVAILABLE:
    __all__.extend(["HighAvailabilityManager"])

if _ORCHESTRATION_AVAILABLE:
    __all__.extend(["OrchestrationEngine"])

if _API_AVAILABLE:
    __all__.extend(["APIGateway"])
