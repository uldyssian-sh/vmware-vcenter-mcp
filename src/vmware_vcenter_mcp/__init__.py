"""
VMware vCenter MCP Server

An enterprise-grade Model Context Protocol (MCP) server for comprehensive VMware 
vCenter Server management. This professional solution provides centralized 
virtualization infrastructure control, advanced automation capabilities, and 
enterprise-scale operations management.

Author: uldyssian-sh
License: MIT
Version: 1.0.0
"""

__version__ = "1.0.0"
__author__ = "uldyssian-sh"
__license__ = "MIT"
__description__ = "VMware vCenter MCP Server - Enterprise virtualization management via MCP"

# Core MCP Server
from .server import VCenterMCPServer

# Enterprise Server
from .enterprise_server import EnterpriseServer, EnterpriseConfig, create_server_from_config

# Core Architecture Components
from .core import (
    # Authentication & Authorization
    AuthenticationManager,
    AuthorizationManager,
    RBACManager,
    
    # Multi-tenancy
    TenantManager,
    TenantIsolationManager,
    
    # Data Layer
    DatabaseManager,
    ConnectionPoolManager,
    CacheManager,
    DistributedCacheManager,
    
    # Monitoring & Observability
    MetricsCollector,
    HealthCheckManager,
    AuditLogger,
    
    # High Availability
    HighAvailabilityManager,
    LoadBalancerManager,
    
    # Security & Compliance
    SecurityManager,
    EncryptionManager,
    ComplianceManager,
    
    # Orchestration
    OrchestrationEngine,
    WorkflowManager,
    
    # API Management
    APIGateway,
    RateLimitManager,
    RequestValidator
)

# Exceptions
from .exceptions import (
    VCenterConnectionError,
    VCenterAuthenticationError,
    VCenterOperationError,
    ValidationError,
    ClusterOperationError,
    DatacenterOperationError
)

__all__ = [
    # Core MCP Server
    "VCenterMCPServer",
    
    # Enterprise Server
    "EnterpriseServer",
    "EnterpriseConfig",
    "create_server_from_config",
    
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
    "RequestValidator",
    
    # Exceptions
    "VCenterConnectionError",
    "VCenterAuthenticationError", 
    "VCenterOperationError",
    "ValidationError",
    "ClusterOperationError",
    "DatacenterOperationError",
    
    # Metadata
    "__version__",
    "__author__",
    "__license__",
    "__description__"
]