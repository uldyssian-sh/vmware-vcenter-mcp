"""
VMware vCenter MCP Server

An enterprise-grade Model Context Protocol (MCP) server for comprehensive VMware 
vCenter Server management. This professional solution provides centralized 
virtualization infrastructure control, advanced automation capabilities, and 
enterprise-scale operations management.

Author: uldyssian-sh
License: MIT
Version: 1.5.0
"""

__version__ = "1.5.0"
__author__ = "uldyssian-sh"
__license__ = "MIT"
__description__ = "VMware vCenter MCP Server - Enterprise virtualization management via MCP"

# Import only existing modules to avoid import errors
try:
    # Security and compliance modules
    from .core.security import SecurityManager, EncryptionManager
    from .core.auth import AuthenticationManager, AuthorizationManager, RBACManager
    from .audit_logger import EnterpriseAuditLogger
    from .gdpr_compliance import GDPRComplianceManager
    from .session_manager import SessionManager
    from .threat_intelligence import ThreatIntelligenceManager
    
    # Exception handling
    from .exceptions import (
        VCenterConnectionError,
        VCenterAuthenticationError,
        VCenterOperationError,
        ValidationError,
        ClusterOperationError,
        DatacenterOperationError
    )
    
    _IMPORTS_AVAILABLE = True
    
except ImportError as e:
    # Graceful degradation if some modules are not available
    _IMPORTS_AVAILABLE = False
    import warnings
    warnings.warn(f"Some modules could not be imported: {e}", ImportWarning)

# Core functionality that should always be available
def get_version():
    """Get the current version of VMware vCenter MCP Server."""
    return __version__

def get_info():
    """Get information about VMware vCenter MCP Server."""
    return {
        "name": "VMware vCenter MCP Server",
        "version": __version__,
        "author": __author__,
        "license": __license__,
        "description": __description__,
        "imports_available": _IMPORTS_AVAILABLE
    }

# Export available components
__all__ = [
    # Metadata
    "__version__",
    "__author__",
    "__license__",
    "__description__",
    
    # Core functions
    "get_version",
    "get_info"
]

# Add available imports to __all__
if _IMPORTS_AVAILABLE:
    __all__.extend([
        # Security & Compliance
        "SecurityManager",
        "EncryptionManager",
        "AuthenticationManager",
        "AuthorizationManager", 
        "RBACManager",
        "EnterpriseAuditLogger",
        "GDPRComplianceManager",
        "SessionManager",
        "ThreatIntelligenceManager",
        
        # Exceptions
        "VCenterConnectionError",
        "VCenterAuthenticationError",
        "VCenterOperationError",
        "ValidationError",
        "ClusterOperationError",
        "DatacenterOperationError"
    ])
