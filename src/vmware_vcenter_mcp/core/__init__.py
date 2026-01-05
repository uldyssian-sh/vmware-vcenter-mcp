"""
VMware vCenter MCP Server - Enterprise Core Architecture

This module provides the enterprise-grade core architecture for the VMware vCenter
MCP Server, including multi-tenancy, RBAC, high availability, and scalability features.

Author: uldyssian-sh
License: MIT
Version: 1.0.0
"""

from .auth import AuthenticationManager, AuthorizationManager, RBACManager
from .tenant import TenantManager, TenantIsolationManager
from .database import DatabaseManager, ConnectionPoolManager
from .cache import CacheManager, DistributedCacheManager
from .monitoring import MetricsCollector, HealthCheckManager, AuditLogger
from .ha import HighAvailabilityManager, LoadBalancerManager
from .security import SecurityManager, EncryptionManager, ComplianceManager
from .orchestration import OrchestrationEngine, WorkflowManager
from .api import APIGateway, RateLimitManager, RequestValidator

__all__ = [
    # Authentication & Authorization
    "AuthenticationManager",
    "AuthorizationManager", 
    "RBACManager",
    
    # Multi-tenancy
    "TenantManager",
    "TenantIsolationManager",
    
    # Data Layer
    "DatabaseManager",
    "ConnectionPoolManager",
    "CacheManager",
    "DistributedCacheManager",
    
    # Monitoring & Observability
    "MetricsCollector",
    "HealthCheckManager",
    "AuditLogger",
    
    # High Availability
    "HighAvailabilityManager",
    "LoadBalancerManager",
    
    # Security & Compliance
    "SecurityManager",
    "EncryptionManager",
    "ComplianceManager",
    
    # Orchestration
    "OrchestrationEngine",
    "WorkflowManager",
    
    # API Management
    "APIGateway",
    "RateLimitManager",
    "RequestValidator"
]
