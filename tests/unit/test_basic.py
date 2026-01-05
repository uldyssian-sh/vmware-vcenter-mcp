"""
Basic tests for VMware vCenter MCP Server

Author: uldyssian-sh
License: MIT
"""

import pytest
import sys
import os

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from vmware_vcenter_mcp.exceptions import (
    VCenterMCPError,
    VCenterConnectionError,
    VCenterAuthenticationError,
    VCenterOperationError,
    ValidationError
)


class TestExceptions:
    """Test custom exceptions"""
    
    def test_base_exception(self):
        """Test base exception"""
        error = VCenterMCPError("Test error")
        assert str(error) == "Test error"
        assert isinstance(error, Exception)
    
    def test_connection_error(self):
        """Test connection error"""
        error = VCenterConnectionError("Connection failed")
        assert str(error) == "Connection failed"
        assert isinstance(error, VCenterMCPError)
    
    def test_authentication_error(self):
        """Test authentication error"""
        error = VCenterAuthenticationError("Auth failed")
        assert str(error) == "Auth failed"
        assert isinstance(error, VCenterMCPError)
    
    def test_operation_error(self):
        """Test operation error"""
        error = VCenterOperationError("Operation failed")
        assert str(error) == "Operation failed"
        assert isinstance(error, VCenterMCPError)
    
    def test_validation_error(self):
        """Test validation error"""
        error = ValidationError("Validation failed")
        assert str(error) == "Validation failed"
        assert isinstance(error, VCenterMCPError)


class TestModuleImports:
    """Test module imports"""
    
    def test_server_import(self):
        """Test server module import"""
        from vmware_vcenter_mcp.server import VCenterMCPServer
        assert VCenterMCPServer is not None
    
    def test_enterprise_server_import(self):
        """Test enterprise server module import"""
        from vmware_vcenter_mcp.enterprise_server import EnterpriseServer
        assert EnterpriseServer is not None
    
    def test_exceptions_import(self):
        """Test exceptions module import"""
        from vmware_vcenter_mcp import exceptions
        assert exceptions is not None
    
    def test_main_module_import(self):
        """Test main module import"""
        import vmware_vcenter_mcp
        assert vmware_vcenter_mcp.__version__ == "1.0.0"
        assert vmware_vcenter_mcp.__author__ == "uldyssian-sh"


class TestConfiguration:
    """Test configuration handling"""
    
    def test_vcenter_config_creation(self):
        """Test vCenter configuration creation"""
        from vmware_vcenter_mcp.server import VCenterConfig
        
        config = VCenterConfig(
            host="vcenter.example.com",
            username="administrator@vsphere.local",
            password="password123",
            port=443,
            ssl_verify=True,
            timeout=60
        )
        
        assert config.host == "vcenter.example.com"
        assert config.username == "administrator@vsphere.local"
        assert config.password == "password123"
        assert config.port == 443
        assert config.ssl_verify is True
        assert config.timeout == 60
    
    def test_enterprise_config_creation(self):
        """Test enterprise configuration creation"""
        from vmware_vcenter_mcp.enterprise_server import EnterpriseConfig
        
        config = EnterpriseConfig(
            host="0.0.0.0",
            port=8080,
            vcenter_host="vcenter.example.com",
            multi_tenant=True,
            ha_enabled=True
        )
        
        assert config.host == "0.0.0.0"
        assert config.port == 8080
        assert config.vcenter_host == "vcenter.example.com"
        assert config.multi_tenant is True
        assert config.ha_enabled is True


if __name__ == "__main__":
    pytest.main([__file__])