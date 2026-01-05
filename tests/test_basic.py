"""
Basic tests for VMware vCenter MCP Server

Tests basic functionality and imports without requiring external dependencies.

Author: uldyssian-sh
License: MIT
"""

import sys
import os
import unittest

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))


class TestBasicFunctionality(unittest.TestCase):
    """Test basic functionality"""
    
    def test_package_import(self):
        """Test that the main package imports successfully"""
        try:
            import vmware_vcenter_mcp
            self.assertTrue(True)
        except ImportError as e:
            self.fail(f"Failed to import vmware_vcenter_mcp: {e}")
    
    def test_version_exists(self):
        """Test that version is defined"""
        import vmware_vcenter_mcp
        self.assertTrue(hasattr(vmware_vcenter_mcp, '__version__'))
        self.assertIsNotNone(vmware_vcenter_mcp.__version__)
        self.assertIsInstance(vmware_vcenter_mcp.__version__, str)
    
    def test_author_exists(self):
        """Test that author is defined"""
        import vmware_vcenter_mcp
        self.assertTrue(hasattr(vmware_vcenter_mcp, '__author__'))
        self.assertEqual(vmware_vcenter_mcp.__author__, 'uldyssian-sh')
    
    def test_core_imports(self):
        """Test that core modules import successfully"""
        try:
            from vmware_vcenter_mcp.core import security
            from vmware_vcenter_mcp import threat_intelligence
            from vmware_vcenter_mcp import session_manager
            from vmware_vcenter_mcp import audit_logger
            from vmware_vcenter_mcp import gdpr_compliance
            self.assertTrue(True)
        except ImportError as e:
            self.fail(f"Failed to import core modules: {e}")
    
    def test_server_import(self):
        """Test that server module imports successfully"""
        try:
            from vmware_vcenter_mcp import server
            self.assertTrue(True)
        except ImportError as e:
            self.fail(f"Failed to import server module: {e}")
    
    def test_exceptions_import(self):
        """Test that exceptions module imports successfully"""
        try:
            from vmware_vcenter_mcp import exceptions
            self.assertTrue(True)
        except ImportError as e:
            self.fail(f"Failed to import exceptions module: {e}")


class TestSecurityModules(unittest.TestCase):
    """Test security-related modules"""
    
    def test_threat_intelligence_manager(self):
        """Test ThreatIntelligenceManager can be instantiated"""
        try:
            from vmware_vcenter_mcp.threat_intelligence import ThreatIntelligenceManager
            config = {"enabled": True}
            manager = ThreatIntelligenceManager(config)
            self.assertIsNotNone(manager)
            self.assertEqual(manager.enabled, True)
        except Exception as e:
            self.fail(f"Failed to create ThreatIntelligenceManager: {e}")
    
    def test_session_manager(self):
        """Test SessionManager can be instantiated"""
        try:
            from vmware_vcenter_mcp.session_manager import SessionManager
            config = {"redis_url": "redis://localhost:6379/0"}
            manager = SessionManager(config)
            self.assertIsNotNone(manager)
        except Exception as e:
            self.fail(f"Failed to create SessionManager: {e}")
    
    def test_audit_logger(self):
        """Test EnterpriseAuditLogger can be instantiated"""
        try:
            from vmware_vcenter_mcp.audit_logger import EnterpriseAuditLogger
            config = {"enabled": True, "destinations": []}
            logger = EnterpriseAuditLogger(config)
            self.assertIsNotNone(logger)
            self.assertEqual(logger.enabled, True)
        except Exception as e:
            self.fail(f"Failed to create EnterpriseAuditLogger: {e}")
    
    def test_gdpr_compliance(self):
        """Test GDPRComplianceManager can be instantiated"""
        try:
            from vmware_vcenter_mcp.gdpr_compliance import GDPRComplianceManager
            config = {"data_retention_days": 2555}
            manager = GDPRComplianceManager(config)
            self.assertIsNotNone(manager)
            self.assertEqual(manager.data_retention_days, 2555)
        except Exception as e:
            self.fail(f"Failed to create GDPRComplianceManager: {e}")


if __name__ == '__main__':
    unittest.main()