"""
Basic tests for VMware vCenter MCP Server

Author: uldyssian-sh
License: MIT
"""

import pytest
import sys
import os

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))


class TestExceptions:
    """Test custom exceptions"""
    
    def test_base_exception(self):
        """Test base exception"""
        from vmware_vcenter_mcp.exceptions import VCenterMCPError
        error = VCenterMCPError("Test error")
        assert str(error) == "Test error"
        assert isinstance(error, Exception)
    
    def test_connection_error(self):
        """Test connection error"""
        from vmware_vcenter_mcp.exceptions import VCenterConnectionError, VCenterMCPError
        error = VCenterConnectionError("Connection failed")
        assert str(error) == "Connection failed"
        assert isinstance(error, VCenterMCPError)
    
    def test_authentication_error(self):
        """Test authentication error"""
        from vmware_vcenter_mcp.exceptions import VCenterAuthenticationError, VCenterMCPError
        error = VCenterAuthenticationError("Auth failed")
        assert str(error) == "Auth failed"
        assert isinstance(error, VCenterMCPError)
    
    def test_operation_error(self):
        """Test operation error"""
        from vmware_vcenter_mcp.exceptions import VCenterOperationError, VCenterMCPError
        error = VCenterOperationError("Operation failed")
        assert str(error) == "Operation failed"
        assert isinstance(error, VCenterMCPError)
    
    def test_validation_error(self):
        """Test validation error"""
        from vmware_vcenter_mcp.exceptions import ValidationError, VCenterMCPError
        error = ValidationError("Validation failed")
        assert str(error) == "Validation failed"
        assert isinstance(error, VCenterMCPError)


class TestModuleImports:
    """Test module imports"""
    
    def test_exceptions_import(self):
        """Test exceptions module import"""
        from vmware_vcenter_mcp import exceptions
        assert exceptions is not None
    
    def test_main_module_import(self):
        """Test main module import"""
        # Only test what we can import without dependencies
        try:
            import vmware_vcenter_mcp
            assert vmware_vcenter_mcp.__version__ == "1.0.0"
            assert vmware_vcenter_mcp.__author__ == "uldyssian-sh"
        except ImportError:
            # Skip if dependencies are not available
            pass


if __name__ == "__main__":
    pytest.main([__file__])