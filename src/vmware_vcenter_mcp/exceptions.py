"""
VMware vCenter MCP Server Exceptions

Custom exception classes for VMware vCenter MCP Server operations.

Author: uldyssian-sh
License: MIT
"""


class VCenterMCPError(Exception):
    """Base exception for VMware vCenter MCP Server"""
    pass


class VCenterConnectionError(VCenterMCPError):
    """Raised when connection to vCenter fails"""
    pass


class VCenterAuthenticationError(VCenterMCPError):
    """Raised when vCenter authentication fails"""
    pass


class VCenterOperationError(VCenterMCPError):
    """Raised when vCenter operation fails"""
    pass


class ValidationError(VCenterMCPError):
    """Raised when input validation fails"""
    pass


class ClusterOperationError(VCenterMCPError):
    """Raised when cluster operation fails"""
    pass


class DatacenterOperationError(VCenterMCPError):
    """Raised when datacenter operation fails"""
    pass


class VMOperationError(VCenterMCPError):
    """Raised when VM operation fails"""
    pass


class StorageOperationError(VCenterMCPError):
    """Raised when storage operation fails"""
    pass


class NetworkOperationError(VCenterMCPError):
    """Raised when network operation fails"""
    pass


class PermissionError(VCenterMCPError):
    """Raised when user lacks required permissions"""
    pass


class ResourceNotFoundError(VCenterMCPError):
    """Raised when requested resource is not found"""
    pass


class ConfigurationError(VCenterMCPError):
    """Raised when configuration is invalid"""
    pass
