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

from .server import VCenterMCPServer
from .exceptions import (
    VCenterConnectionError,
    VCenterAuthenticationError,
    VCenterOperationError,
    ValidationError,
    ClusterOperationError,
    DatacenterOperationError
)

__all__ = [
    "VCenterMCPServer",
    "VCenterConnectionError",
    "VCenterAuthenticationError", 
    "VCenterOperationError",
    "ValidationError",
    "ClusterOperationError",
    "DatacenterOperationError",
    "__version__",
    "__author__",
    "__license__",
    "__description__"
]