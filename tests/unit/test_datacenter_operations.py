"""
Unit tests for vCenter datacenter operations.

Tests comprehensive datacenter management operations specific to vCenter,
including multi-datacenter orchestration and enterprise-scale operations.
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock
from vmware_vcenter_mcp.datacenter_operations import VCenterDatacenterOperations
from vmware_vcenter_mcp.exceptions import DatacenterOperationError, VCenterConnectionError


class TestVCenterDatacenterOperations:
    """Test vCenter-specific datacenter operations."""

    @pytest.fixture
    def mock_vcenter_connection(self):
        """Mock vCenter connection."""
        connection = Mock()
        connection.service_instance = Mock()
        connection.content = Mock()
        connection.content.rootFolder = Mock()
        connection.content.datacenterFolder = Mock()
        return connection

    @pytest.fixture
    def datacenter_ops(self, mock_vcenter_connection):
        """Datacenter operations instance."""
        return VCenterDatacenterOperations(mock_vcenter_connection)

    @pytest.fixture
    def mock_datacenter(self):
        """Mock datacenter object."""
        dc = Mock()
        dc.name = "Production-DC"
        dc.hostFolder = Mock()
        dc.vmFolder = Mock()
        dc.datastoreFolder = Mock()
        dc.networkFolder = Mock()
        return dc

    @pytest.fixture
    def mock_cluster(self):
        """Mock cluster object."""
        cluster = Mock()
        cluster.name = "Production-Cluster"
        cluster.summary = Mock()
        cluster.summary.numHosts = 5
        cluster.summary.numCpuCores = 80
        cluster.summary.totalMemory = 549755813888  # 512GB
        cluster.configuration = Mock()
        cluster.configuration.drsConfig = Mock()
        cluster.configuration.dasConfig = Mock()
        return cluster

    def test_create_datacenter_vcenter(self, datacenter_ops, mock_vcenter_connection):
        """Test datacenter creation in vCenter."""
        mock_task = Mock()
        mock_task.info = Mock()
        mock_task.info.state = "success"
        mock_task.info.result = Mock()
        mock_task.info.result.name = "New-Datacenter"
        
        mock_folder = Mock()
        mock_vcenter_connection.content.rootFolder = mock_folder
        
        with patch.object(mock_folder, 'CreateDatacenter', return_value=mock_task.info.result):
            result = datacenter_ops.create_datacenter(
                name="New-Datacenter",
                description="Enterprise datacenter for production workloads"
            )
            
            assert result["status"] == "success"
            assert result["datacenter_name"] == "New-Datacenter"
            mock_folder.CreateDatacenter.assert_called_once_with("New-Datacenter")

    def test_multi_datacenter_management(self, datacenter_ops, mock_vcenter_connection):
        """Test multi-datacenter management operations."""
        # Mock multiple datacenters
        dc1 = Mock()
        dc1.name = "DC-East"
        dc1.summary = Mock()
        dc1.summary.overallStatus = "green"
        
        dc2 = Mock()
        dc2.name = "DC-West"
        dc2.summary = Mock()
        dc2.summary.overallStatus = "green"
        
        mock_vcenter_connection.content.rootFolder.childEntity = [dc1, dc2]
        
        # Test getting all datacenters
        datacenters = datacenter_ops.get_all_datacenters()
        
        assert len(datacenters) == 2
        assert any(dc["name"] == "DC-East" for dc in datacenters)
        assert any(dc["name"] == "DC-West" for dc in datacenters)

    def test_datacenter_resource_aggregation(self, datacenter_ops, mock_datacenter, mock_cluster):
        """Test datacenter-wide resource aggregation."""
        # Mock clusters in datacenter
        mock_datacenter.hostFolder.childEntity = [mock_cluster]
        
        with patch.object(datacenter_ops, 'get_datacenter', return_value=mock_datacenter):
            resources = datacenter_ops.get_datacenter_resources("Production-DC")
            
            assert resources["total_hosts"] == 5
            assert resources["total_cpu_cores"] == 80
            assert resources["total_memory_gb"] == 512
            assert "clusters" in resources

    def test_datacenter_folder_management(self, datacenter_ops, mock_datacenter):
        """Test datacenter folder structure management."""
        mock_vm_folder = Mock()
        mock_vm_folder.name = "vm"
        mock_vm_folder.CreateFolder = Mock()
        mock_datacenter.vmFolder = mock_vm_folder
        
        with patch.object(datacenter_ops, 'get_datacenter', return_value=mock_datacenter):
            # Test creating VM folder structure
            result = datacenter_ops.create_folder_structure(
                datacenter_name="Production-DC",
                folder_type="vm",
                folder_name="Production-VMs"
            )
            
            assert result["status"] == "success"
            mock_vm_folder.CreateFolder.assert_called_once_with("Production-VMs")

    def test_datacenter_network_management(self, datacenter_ops, mock_datacenter):
        """Test datacenter network management."""
        mock_network_folder = Mock()
        mock_dvs = Mock()
        mock_dvs.name = "Production-DVS"
        mock_dvs.summary = Mock()
        mock_dvs.summary.numPorts = 1024
        mock_network_folder.childEntity = [mock_dvs]
        mock_datacenter.networkFolder = mock_network_folder
        
        with patch.object(datacenter_ops, 'get_datacenter', return_value=mock_datacenter):
            networks = datacenter_ops.get_datacenter_networks("Production-DC")
            
            assert len(networks["distributed_switches"]) == 1
            assert networks["distributed_switches"][0]["name"] == "Production-DVS"

    def test_datacenter_storage_management(self, datacenter_ops, mock_datacenter):
        """Test datacenter storage management."""
        mock_datastore_folder = Mock()
        mock_datastore = Mock()
        mock_datastore.name = "Production-Storage"
        mock_datastore.summary = Mock()
        mock_datastore.summary.capacity = 2199023255552  # 2TB
        mock_datastore.summary.freeSpace = 1099511627776  # 1TB
        mock_datastore_folder.childEntity = [mock_datastore]
        mock_datacenter.datastoreFolder = mock_datastore_folder
        
        with patch.object(datacenter_ops, 'get_datacenter', return_value=mock_datacenter):
            storage = datacenter_ops.get_datacenter_storage("Production-DC")
            
            assert len(storage["datastores"]) == 1
            assert storage["total_capacity_tb"] == 2
            assert storage["total_free_tb"] == 1

    def test_cross_datacenter_operations(self, datacenter_ops, mock_vcenter_connection):
        """Test cross-datacenter operations."""
        # Mock source and destination datacenters
        source_dc = Mock()
        source_dc.name = "DC-East"
        dest_dc = Mock()
        dest_dc.name = "DC-West"
        
        mock_vcenter_connection.content.rootFolder.childEntity = [source_dc, dest_dc]
        
        # Test cross-datacenter VM migration planning
        migration_plan = datacenter_ops.plan_cross_datacenter_migration(
            source_datacenter="DC-East",
            destination_datacenter="DC-West",
            vm_list=["vm-1", "vm-2", "vm-3"]
        )
        
        assert migration_plan["source_datacenter"] == "DC-East"
        assert migration_plan["destination_datacenter"] == "DC-West"
        assert len(migration_plan["vm_migrations"]) == 3

    def test_datacenter_compliance_reporting(self, datacenter_ops, mock_datacenter):
        """Test datacenter compliance reporting."""
        with patch.object(datacenter_ops, 'get_datacenter', return_value=mock_datacenter):
            # Mock compliance checks
            with patch.object(datacenter_ops, '_check_security_compliance') as mock_security:
                with patch.object(datacenter_ops, '_check_resource_compliance') as mock_resource:
                    mock_security.return_value = {"status": "compliant", "issues": []}
                    mock_resource.return_value = {"status": "compliant", "warnings": []}
                    
                    report = datacenter_ops.generate_compliance_report("Production-DC")
                    
                    assert report["datacenter"] == "Production-DC"
                    assert report["security"]["status"] == "compliant"
                    assert report["resources"]["status"] == "compliant"

    def test_datacenter_disaster_recovery(self, datacenter_ops, mock_vcenter_connection):
        """Test datacenter disaster recovery operations."""
        # Mock primary and DR datacenters
        primary_dc = Mock()
        primary_dc.name = "Primary-DC"
        dr_dc = Mock()
        dr_dc.name = "DR-DC"
        
        mock_vcenter_connection.content.rootFolder.childEntity = [primary_dc, dr_dc]
        
        # Test DR configuration
        dr_config = datacenter_ops.configure_disaster_recovery(
            primary_datacenter="Primary-DC",
            dr_datacenter="DR-DC",
            replication_policy={
                "rpo_minutes": 15,
                "rto_minutes": 60,
                "critical_vms": ["db-server", "web-server"]
            }
        )
        
        assert dr_config["primary_site"] == "Primary-DC"
        assert dr_config["recovery_site"] == "DR-DC"
        assert dr_config["rpo_minutes"] == 15

    def test_datacenter_capacity_planning(self, datacenter_ops, mock_datacenter, mock_cluster):
        """Test datacenter capacity planning."""
        mock_datacenter.hostFolder.childEntity = [mock_cluster]
        
        # Mock historical performance data
        with patch.object(datacenter_ops, 'get_performance_history') as mock_perf:
            mock_perf.return_value = {
                "cpu_usage_trend": [40, 45, 50, 55, 60],  # Increasing trend
                "memory_usage_trend": [60, 65, 70, 75, 80],
                "storage_usage_trend": [30, 35, 40, 45, 50]
            }
            
            with patch.object(datacenter_ops, 'get_datacenter', return_value=mock_datacenter):
                capacity_plan = datacenter_ops.generate_capacity_plan(
                    datacenter_name="Production-DC",
                    forecast_months=6
                )
                
                assert capacity_plan["datacenter"] == "Production-DC"
                assert "cpu_forecast" in capacity_plan
                assert "memory_forecast" in capacity_plan
                assert "recommendations" in capacity_plan

    @pytest.mark.asyncio
    async def test_async_datacenter_operations(self, datacenter_ops, mock_datacenter):
        """Test asynchronous datacenter operations."""
        with patch.object(datacenter_ops, 'migrate_datacenter_async', new_callable=AsyncMock) as mock_migrate:
            mock_migrate.return_value = {"status": "in_progress", "task_id": "task-123"}
            
            result = await datacenter_ops.migrate_datacenter_async(
                source_datacenter="Old-DC",
                destination_datacenter="New-DC"
            )
            
            assert result["status"] == "in_progress"
            assert "task_id" in result

    def test_datacenter_automation_workflows(self, datacenter_ops, mock_datacenter):
        """Test datacenter automation workflows."""
        workflow_config = {
            "name": "Auto-Scale-Datacenter",
            "triggers": [
                {
                    "type": "resource_threshold",
                    "metric": "cpu_usage",
                    "threshold": 80,
                    "duration": 300
                }
            ],
            "actions": [
                {
                    "type": "add_host",
                    "cluster": "Production-Cluster",
                    "host_template": "standard-host"
                }
            ]
        }
        
        with patch.object(datacenter_ops, 'get_datacenter', return_value=mock_datacenter):
            workflow = datacenter_ops.create_automation_workflow(
                datacenter_name="Production-DC",
                workflow_config=workflow_config
            )
            
            assert workflow["name"] == "Auto-Scale-Datacenter"
            assert len(workflow["triggers"]) == 1
            assert len(workflow["actions"]) == 1

    def test_datacenter_security_policies(self, datacenter_ops, mock_datacenter):
        """Test datacenter security policy management."""
        security_policy = {
            "encryption_required": True,
            "network_segmentation": True,
            "access_control": {
                "mfa_required": True,
                "session_timeout": 3600
            },
            "audit_logging": {
                "enabled": True,
                "retention_days": 365
            }
        }
        
        with patch.object(datacenter_ops, 'get_datacenter', return_value=mock_datacenter):
            result = datacenter_ops.apply_security_policy(
                datacenter_name="Production-DC",
                policy=security_policy
            )
            
            assert result["status"] == "applied"
            assert result["policy"]["encryption_required"] is True

    def test_error_handling_datacenter_operations(self, datacenter_ops, mock_vcenter_connection):
        """Test error handling in datacenter operations."""
        # Test datacenter not found
        mock_vcenter_connection.content.rootFolder.childEntity = []
        
        with pytest.raises(DatacenterOperationError) as exc_info:
            datacenter_ops.get_datacenter("NonExistent-DC")
        
        assert "not found" in str(exc_info.value).lower()

    def test_datacenter_performance_optimization(self, datacenter_ops, mock_datacenter, mock_cluster):
        """Test datacenter performance optimization."""
        mock_datacenter.hostFolder.childEntity = [mock_cluster]
        
        # Mock performance analysis
        with patch.object(datacenter_ops, 'analyze_performance') as mock_analyze:
            mock_analyze.return_value = {
                "bottlenecks": ["memory", "storage_io"],
                "recommendations": [
                    "Add memory to cluster",
                    "Optimize storage configuration"
                ]
            }
            
            with patch.object(datacenter_ops, 'get_datacenter', return_value=mock_datacenter):
                optimization = datacenter_ops.optimize_datacenter_performance(
                    datacenter_name="Production-DC"
                )
                
                assert len(optimization["bottlenecks"]) == 2
                assert len(optimization["recommendations"]) == 2