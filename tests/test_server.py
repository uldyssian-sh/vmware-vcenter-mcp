"""
Tests for VMware vCenter MCP Server

Unit tests for core server functionality.

Author: uldyssian-sh
License: MIT
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from vmware_vcenter_mcp.server import VCenterMCPServer, VCenterClient, VCenterConfig
from vmware_vcenter_mcp.exceptions import VCenterConnectionError, ValidationError


class TestVCenterConfig:
    """Test VCenterConfig class"""
    
    def test_default_values(self):
        """Test default configuration values"""
        config = VCenterConfig(
            host="test.example.com",
            username="test@vsphere.local",
            password="password"
        )
        
        assert config.host == "test.example.com"
        assert config.username == "test@vsphere.local"
        assert config.password == "password"
        assert config.port == 443
        assert config.ssl_verify == True
        assert config.timeout == 60
        assert config.session_timeout == 1800
    
    def test_custom_values(self):
        """Test custom configuration values"""
        config = VCenterConfig(
            host="custom.example.com",
            username="custom@vsphere.local",
            password="custom_password",
            port=8443,
            ssl_verify=False,
            timeout=120,
            session_timeout=3600
        )
        
        assert config.host == "custom.example.com"
        assert config.port == 8443
        assert config.ssl_verify == False
        assert config.timeout == 120
        assert config.session_timeout == 3600


class TestVCenterClient:
    """Test VCenterClient class"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.config = VCenterConfig(
            host="test.example.com",
            username="test@vsphere.local",
            password="password"
        )
        self.client = VCenterClient(self.config)
    
    def test_initialization(self):
        """Test client initialization"""
        assert self.client.config == self.config
        assert self.client.service_instance is None
        assert self.client.content is None
        assert self.client._connected == False
    
    def test_is_connected_false(self):
        """Test is_connected returns False when not connected"""
        assert self.client.is_connected() == False
    
    @patch('vmware_vcenter_mcp.server.SmartConnect')
    async def test_connect_success(self, mock_connect):
        """Test successful connection"""
        # Mock successful connection
        mock_service_instance = Mock()
        mock_content = Mock()
        mock_service_instance.RetrieveContent.return_value = mock_content
        mock_connect.return_value = mock_service_instance
        
        await self.client.connect()
        
        assert self.client.service_instance == mock_service_instance
        assert self.client.content == mock_content
        assert self.client._connected == True
        assert self.client.is_connected() == True
    
    @patch('vmware_vcenter_mcp.server.SmartConnect')
    async def test_connect_failure(self, mock_connect):
        """Test connection failure"""
        # Mock connection failure
        mock_connect.return_value = None
        
        with pytest.raises(VCenterConnectionError):
            await self.client.connect()
        
        assert self.client._connected == False
    
    @patch('vmware_vcenter_mcp.server.SmartConnect')
    async def test_connect_exception(self, mock_connect):
        """Test connection exception"""
        # Mock connection exception
        mock_connect.side_effect = Exception("Connection failed")
        
        with pytest.raises(VCenterConnectionError):
            await self.client.connect()
        
        assert self.client._connected == False
    
    @patch('vmware_vcenter_mcp.server.Disconnect')
    async def test_disconnect(self, mock_disconnect):
        """Test disconnection"""
        # Setup connected state
        self.client.service_instance = Mock()
        self.client._connected = True
        
        await self.client.disconnect()
        
        mock_disconnect.assert_called_once_with(self.client.service_instance)
        assert self.client._connected == False


class TestVCenterMCPServer:
    """Test VCenterMCPServer class"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.config = {
            "vcenter_host": "test.example.com",
            "vcenter_username": "test@vsphere.local",
            "vcenter_password": "password",
            "vcenter_port": 443,
            "vcenter_ssl_verify": True
        }
        self.server = VCenterMCPServer(self.config)
    
    def test_initialization(self):
        """Test server initialization"""
        assert self.server.config == self.config
        assert self.server.vcenter_config.host == "test.example.com"
        assert self.server.vcenter_config.username == "test@vsphere.local"
        assert self.server.vcenter_config.password == "password"
        assert self.server.vcenter_client is not None
        assert self.server.server is not None
    
    @pytest.mark.asyncio
    async def test_create_datacenter_validation_error(self):
        """Test create_datacenter with validation error"""
        # Test missing name
        args = {}
        
        with pytest.raises(ValidationError, match="Datacenter name is required"):
            await self.server._create_datacenter(args)
    
    @pytest.mark.asyncio
    async def test_create_datacenter_success(self):
        """Test successful datacenter creation"""
        # Mock vCenter client
        mock_datacenter = Mock()
        mock_datacenter.name = "test-dc"
        mock_datacenter._moId = "datacenter-123"
        
        mock_folder = Mock()
        mock_folder.CreateDatacenter.return_value = mock_datacenter
        
        self.server.vcenter_client.content = Mock()
        self.server.vcenter_client.content.rootFolder = mock_folder
        
        args = {"name": "test-dc"}
        result = await self.server._create_datacenter(args)
        
        assert result["success"] == True
        assert result["datacenter"]["name"] == "test-dc"
        assert result["datacenter"]["moid"] == "datacenter-123"
        assert "created successfully" in result["message"]
    
    @pytest.mark.asyncio
    async def test_list_datacenters_success(self):
        """Test successful datacenter listing"""
        # Mock datacenters
        mock_dc1 = Mock()
        mock_dc1.name = "dc1"
        mock_dc1._moId = "datacenter-1"
        mock_dc1.overallStatus = "green"
        
        mock_dc2 = Mock()
        mock_dc2.name = "dc2"
        mock_dc2._moId = "datacenter-2"
        mock_dc2.overallStatus = "yellow"
        
        self.server.vcenter_client.get_all_objs = Mock(return_value=[mock_dc1, mock_dc2])
        
        args = {}
        result = await self.server._list_datacenters(args)
        
        assert result["success"] == True
        assert result["count"] == 2
        assert len(result["datacenters"]) == 2
        assert result["datacenters"][0]["name"] == "dc1"
        assert result["datacenters"][1]["name"] == "dc2"
    
    @pytest.mark.asyncio
    async def test_power_vm_validation_error(self):
        """Test power_vm with validation error"""
        # Test missing vm_name
        args = {"action": "on"}
        
        with pytest.raises(ValidationError, match="VM name and action are required"):
            await self.server._power_vm(args)
        
        # Test missing action
        args = {"vm_name": "test-vm"}
        
        with pytest.raises(ValidationError, match="VM name and action are required"):
            await self.server._power_vm(args)
    
    @pytest.mark.asyncio
    async def test_power_vm_invalid_action(self):
        """Test power_vm with invalid action"""
        # Mock VM
        mock_vm = Mock()
        self.server.vcenter_client.get_obj = Mock(return_value=mock_vm)
        
        args = {"vm_name": "test-vm", "action": "invalid"}
        
        with pytest.raises(ValidationError, match="Invalid power action"):
            await self.server._power_vm(args)
    
    @pytest.mark.asyncio
    async def test_get_vm_info_validation_error(self):
        """Test get_vm_info with validation error"""
        args = {}
        
        with pytest.raises(ValidationError, match="VM name is required"):
            await self.server._get_vm_info(args)
    
    @pytest.mark.asyncio
    async def test_get_vm_info_vm_not_found(self):
        """Test get_vm_info with VM not found"""
        self.server.vcenter_client.get_obj = Mock(return_value=None)
        
        args = {"vm_name": "nonexistent-vm"}
        
        with pytest.raises(Exception, match="not found"):
            await self.server._get_vm_info(args)


class TestIntegration:
    """Integration tests"""
    
    @pytest.mark.asyncio
    async def test_server_tool_registration(self):
        """Test that all tools are properly registered"""
        config = {
            "vcenter_host": "test.example.com",
            "vcenter_username": "test@vsphere.local",
            "vcenter_password": "password"
        }
        
        server = VCenterMCPServer(config)
        
        # Get list of tools
        tools = await server.server._list_tools_handler()
        
        # Verify expected tools are present
        tool_names = [tool.name for tool in tools]
        
        expected_tools = [
            "create_datacenter",
            "list_datacenters", 
            "create_cluster",
            "list_clusters",
            "list_vms",
            "create_vm",
            "power_vm",
            "get_vm_info",
            "list_datastores",
            "get_performance_stats"
        ]
        
        for expected_tool in expected_tools:
            assert expected_tool in tool_names
    
    def test_configuration_validation(self):
        """Test configuration validation"""
        # Test valid configuration
        valid_config = {
            "vcenter_host": "test.example.com",
            "vcenter_username": "test@vsphere.local",
            "vcenter_password": "password"
        }
        
        server = VCenterMCPServer(valid_config)
        assert server.vcenter_config.host == "test.example.com"
        
        # Test configuration with defaults
        minimal_config = {
            "vcenter_host": "minimal.example.com",
            "vcenter_username": "user",
            "vcenter_password": "pass"
        }
        
        server = VCenterMCPServer(minimal_config)
        assert server.vcenter_config.port == 443
        assert server.vcenter_config.ssl_verify == True


if __name__ == "__main__":
    pytest.main([__file__])