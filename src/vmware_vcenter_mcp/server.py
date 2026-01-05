"""
VMware vCenter MCP Server

Core MCP server implementation for VMware vCenter management.
Provides Model Context Protocol interface for vCenter operations.

Author: uldyssian-sh
License: MIT
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any, Sequence
from dataclasses import dataclass
import ssl

# MCP imports
from mcp.server import Server
from mcp.server.models import InitializationOptions
from mcp.server.stdio import stdio_server
from mcp.types import (
    Resource, Tool, TextContent, ImageContent, EmbeddedResource,
    CallToolRequest, CallToolResult, ListResourcesRequest, ListResourcesResult,
    ListToolsRequest, ListToolsResult, ReadResourceRequest, ReadResourceResult
)

# VMware imports
from pyVmomi import vim, vmodl
from pyVim.connect import SmartConnect, Disconnect
from pyVim.task import WaitForTask

# Local imports
from .exceptions import (
    VCenterConnectionError, VCenterAuthenticationError, VCenterOperationError,
    ValidationError, ClusterOperationError, DatacenterOperationError,
    VMOperationError, StorageOperationError, NetworkOperationError,
    ResourceNotFoundError, PermissionError
)

logger = logging.getLogger(__name__)


@dataclass
class VCenterConfig:
    """vCenter connection configuration"""
    host: str
    username: str
    password: str
    port: int = 443
    ssl_verify: bool = True
    timeout: int = 60
    session_timeout: int = 1800


class VCenterClient:
    """VMware vCenter API client"""
    
    def __init__(self, config: VCenterConfig):
        self.config = config
        self.service_instance = None
        self.content = None
        self._connected = False
    
    async def connect(self):
        """Connect to vCenter"""
        try:
            # Create SSL context
            if not self.config.ssl_verify:
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
            else:
                ssl_context = None
            
            # Connect to vCenter
            self.service_instance = SmartConnect(
                host=self.config.host,
                user=self.config.username,
                pwd=self.config.password,
                port=self.config.port,
                sslContext=ssl_context
            )
            
            if not self.service_instance:
                raise VCenterConnectionError(f"Failed to connect to vCenter {self.config.host}")
            
            self.content = self.service_instance.RetrieveContent()
            self._connected = True
            
            logger.info(f"Connected to vCenter {self.config.host}")
            
        except Exception as e:
            logger.error(f"vCenter connection failed: {str(e)}")
            raise VCenterConnectionError(f"Connection failed: {str(e)}")
    
    async def disconnect(self):
        """Disconnect from vCenter"""
        if self.service_instance:
            try:
                Disconnect(self.service_instance)
                self._connected = False
                logger.info("Disconnected from vCenter")
            except Exception as e:
                logger.error(f"Disconnect error: {str(e)}")
    
    def is_connected(self) -> bool:
        """Check if connected to vCenter"""
        return self._connected and self.service_instance is not None
    
    def get_obj(self, vimtype: Any, name: Optional[str] = None) -> Any:
        """Get vSphere object by type and name"""
        if not self.content:
            raise VCenterConnectionError("Not connected to vCenter")
        
        container = self.content.viewManager.CreateContainerView(
            self.content.rootFolder, [vimtype], True
        )
        
        try:
            if name:
                for obj in container.view:
                    if obj.name == name:
                        return obj
                return None
            else:
                return container.view
        finally:
            container.Destroy()
    
    def get_all_objs(self, vimtype: Any) -> Any:
        """Get all objects of specified type"""
        return self.get_obj(vimtype)
    
    async def wait_for_task(self, task: Any) -> Any:
        """Wait for vCenter task completion"""
        try:
            result = WaitForTask(task)
            return result
        except Exception as e:
            logger.error(f"Task failed: {str(e)}")
            raise VCenterOperationError(f"Task failed: {str(e)}")


class VCenterMCPServer:
    """VMware vCenter MCP Server"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.vcenter_config = VCenterConfig(
            host=config.get("vcenter_host", ""),
            username=config.get("vcenter_username", ""),
            password=config.get("vcenter_password", ""),
            port=config.get("vcenter_port", 443),
            ssl_verify=config.get("vcenter_ssl_verify", True),
            timeout=config.get("vcenter_timeout", 60),
            session_timeout=config.get("vcenter_session_timeout", 1800)
        )
        
        self.vcenter_client = VCenterClient(self.vcenter_config)
        self.server = Server("vmware-vcenter-mcp")
        
        # Register MCP handlers
        self._register_handlers()
        
        logger.info("VMware vCenter MCP Server initialized")
    
    def _register_handlers(self) -> None:
        """Register MCP protocol handlers"""
        
        @self.server.list_tools()
        async def handle_list_tools() -> List[Tool]:
            """List available MCP tools"""
            return [
                Tool(
                    name="create_datacenter",
                    description="Create a new datacenter in vCenter",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "name": {"type": "string", "description": "Datacenter name"},
                            "folder": {"type": "string", "description": "Parent folder path"},
                            "description": {"type": "string", "description": "Datacenter description"}
                        },
                        "required": ["name"]
                    }
                ),
                Tool(
                    name="list_datacenters",
                    description="List all datacenters",
                    inputSchema={
                        "type": "object",
                        "properties": {}
                    }
                ),
                Tool(
                    name="create_cluster",
                    description="Create a new cluster",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "name": {"type": "string", "description": "Cluster name"},
                            "datacenter": {"type": "string", "description": "Parent datacenter name"},
                            "drs_enabled": {"type": "boolean", "description": "Enable DRS"},
                            "ha_enabled": {"type": "boolean", "description": "Enable HA"},
                            "vsan_enabled": {"type": "boolean", "description": "Enable vSAN"}
                        },
                        "required": ["name", "datacenter"]
                    }
                ),
                Tool(
                    name="list_clusters",
                    description="List all clusters",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "datacenter": {"type": "string", "description": "Filter by datacenter"}
                        }
                    }
                ),
                Tool(
                    name="list_vms",
                    description="List virtual machines",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "datacenter": {"type": "string", "description": "Filter by datacenter"},
                            "cluster": {"type": "string", "description": "Filter by cluster"},
                            "power_state": {"type": "string", "description": "Filter by power state"}
                        }
                    }
                ),
                Tool(
                    name="create_vm",
                    description="Create a new virtual machine",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "name": {"type": "string", "description": "VM name"},
                            "datacenter": {"type": "string", "description": "Target datacenter"},
                            "cluster": {"type": "string", "description": "Target cluster"},
                            "datastore": {"type": "string", "description": "Target datastore"},
                            "guest_os": {"type": "string", "description": "Guest OS type"},
                            "memory_mb": {"type": "integer", "description": "Memory in MB"},
                            "num_cpus": {"type": "integer", "description": "Number of CPUs"},
                            "disk_size_gb": {"type": "integer", "description": "Disk size in GB"}
                        },
                        "required": ["name", "datacenter"]
                    }
                ),
                Tool(
                    name="power_vm",
                    description="Control VM power state",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "vm_name": {"type": "string", "description": "VM name"},
                            "action": {"type": "string", "enum": ["on", "off", "reset", "suspend"], "description": "Power action"}
                        },
                        "required": ["vm_name", "action"]
                    }
                ),
                Tool(
                    name="get_vm_info",
                    description="Get detailed VM information",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "vm_name": {"type": "string", "description": "VM name"}
                        },
                        "required": ["vm_name"]
                    }
                ),
                Tool(
                    name="list_datastores",
                    description="List all datastores",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "datacenter": {"type": "string", "description": "Filter by datacenter"}
                        }
                    }
                ),
                Tool(
                    name="get_performance_stats",
                    description="Get performance statistics",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "entity_name": {"type": "string", "description": "Entity name (VM, host, cluster)"},
                            "entity_type": {"type": "string", "enum": ["vm", "host", "cluster"], "description": "Entity type"},
                            "metrics": {"type": "array", "items": {"type": "string"}, "description": "Metrics to collect"}
                        },
                        "required": ["entity_name", "entity_type"]
                    }
                )
            ]
        
        @self.server.call_tool()
        async def handle_call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
            """Handle tool calls"""
            
            # Ensure connection
            if not self.vcenter_client.is_connected():
                await self.vcenter_client.connect()
            
            try:
                if name == "create_datacenter":
                    result = await self._create_datacenter(arguments)
                elif name == "list_datacenters":
                    result = await self._list_datacenters(arguments)
                elif name == "create_cluster":
                    result = await self._create_cluster(arguments)
                elif name == "list_clusters":
                    result = await self._list_clusters(arguments)
                elif name == "list_vms":
                    result = await self._list_vms(arguments)
                elif name == "create_vm":
                    result = await self._create_vm(arguments)
                elif name == "power_vm":
                    result = await self._power_vm(arguments)
                elif name == "get_vm_info":
                    result = await self._get_vm_info(arguments)
                elif name == "list_datastores":
                    result = await self._list_datastores(arguments)
                elif name == "get_performance_stats":
                    result = await self._get_performance_stats(arguments)
                else:
                    raise ValidationError(f"Unknown tool: {name}")
                
                return [TextContent(type="text", text=json.dumps(result, indent=2))]
                
            except Exception as e:
                logger.error(f"Tool {name} failed: {str(e)}")
                error_result = {
                    "error": str(e),
                    "tool": name,
                    "timestamp": datetime.utcnow().isoformat()
                }
                return [TextContent(type="text", text=json.dumps(error_result, indent=2))]
    
    # Tool implementations
    async def _create_datacenter(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new datacenter"""
        name = args.get("name")
        if not name:
            raise ValidationError("Datacenter name is required")
        
        try:
            folder = self.vcenter_client.content.rootFolder
            datacenter = folder.CreateDatacenter(name=name)
            
            return {
                "success": True,
                "datacenter": {
                    "name": datacenter.name,
                    "moid": datacenter._moId
                },
                "message": f"Datacenter "{name}" created successfully"
            }
            
        except Exception as e:
            raise DatacenterOperationError(f"Failed to create datacenter: {str(e)}")
    
    async def _list_datacenters(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """List all datacenters"""
        try:
            datacenters = self.vcenter_client.get_all_objs(vim.Datacenter)
            
            datacenter_list = []
            for dc in datacenters:
                datacenter_list.append({
                    "name": dc.name,
                    "moid": dc._moId,
                    "overall_status": str(dc.overallStatus) if hasattr(dc, "overallStatus") else "unknown"
                })
            
            return {
                "success": True,
                "datacenters": datacenter_list,
                "count": len(datacenter_list)
            }
            
        except Exception as e:
            raise DatacenterOperationError(f"Failed to list datacenters: {str(e)}")
    
    async def _create_cluster(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new cluster"""
        name = args.get("name")
        datacenter_name = args.get("datacenter")
        
        if not name or not datacenter_name:
            raise ValidationError("Cluster name and datacenter are required")
        
        try:
            # Get datacenter
            datacenter = self.vcenter_client.get_obj(vim.Datacenter, datacenter_name)
            if not datacenter:
                raise ResourceNotFoundError(f"Datacenter "{datacenter_name}" not found")
            
            # Create cluster spec
            cluster_spec = vim.cluster.ConfigSpecEx()
            cluster_spec.drsConfig = vim.cluster.DrsConfigInfo()
            cluster_spec.drsConfig.enabled = args.get("drs_enabled", True)
            cluster_spec.drsConfig.defaultVmBehavior = vim.cluster.DrsConfigInfo.DrsBehavior.fullyAutomated
            
            cluster_spec.dasConfig = vim.cluster.DasConfigInfo()
            cluster_spec.dasConfig.enabled = args.get("ha_enabled", True)
            
            # Create cluster
            cluster = datacenter.hostFolder.CreateClusterEx(name, cluster_spec)
            
            return {
                "success": True,
                "cluster": {
                    "name": cluster.name,
                    "moid": cluster._moId,
                    "datacenter": datacenter_name
                },
                "message": f"Cluster "{name}" created successfully"
            }
            
        except Exception as e:
            raise ClusterOperationError(f"Failed to create cluster: {str(e)}")
    
    async def _list_clusters(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """List all clusters"""
        try:
            clusters = self.vcenter_client.get_all_objs(vim.ClusterComputeResource)
            datacenter_filter = args.get("datacenter")
            
            cluster_list = []
            for cluster in clusters:
                # Filter by datacenter if specified
                if datacenter_filter:
                    parent_dc = cluster.parent
                    while parent_dc and not isinstance(parent_dc, vim.Datacenter):
                        parent_dc = parent_dc.parent
                    if not parent_dc or parent_dc.name != datacenter_filter:
                        continue
                
                cluster_info = {
                    "name": cluster.name,
                    "moid": cluster._moId,
                    "overall_status": str(cluster.overallStatus),
                    "drs_enabled": cluster.configuration.drsConfig.enabled if cluster.configuration.drsConfig else False,
                    "ha_enabled": cluster.configuration.dasConfig.enabled if cluster.configuration.dasConfig else False,
                    "num_hosts": len(cluster.host),
                    "num_vms": len(cluster.resourcePool.vm) if cluster.resourcePool else 0
                }
                cluster_list.append(cluster_info)
            
            return {
                "success": True,
                "clusters": cluster_list,
                "count": len(cluster_list)
            }
            
        except Exception as e:
            raise ClusterOperationError(f"Failed to list clusters: {str(e)}")
    
    async def _list_vms(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """List virtual machines"""
        try:
            vms = self.vcenter_client.get_all_objs(vim.VirtualMachine)
            datacenter_filter = args.get("datacenter")
            cluster_filter = args.get("cluster")
            power_state_filter = args.get("power_state")
            
            vm_list = []
            for vm in vms:
                # Apply filters
                if datacenter_filter:
                    parent_dc = vm.parent
                    while parent_dc and not isinstance(parent_dc, vim.Datacenter):
                        parent_dc = parent_dc.parent
                    if not parent_dc or parent_dc.name != datacenter_filter:
                        continue
                
                if cluster_filter:
                    if not vm.runtime.host or not vm.runtime.host.parent or vm.runtime.host.parent.name != cluster_filter:
                        continue
                
                if power_state_filter:
                    if str(vm.runtime.powerState).lower() != power_state_filter.lower():
                        continue
                
                vm_info = {
                    "name": vm.name,
                    "moid": vm._moId,
                    "power_state": str(vm.runtime.powerState),
                    "guest_os": vm.config.guestFullName if vm.config else "Unknown",
                    "memory_mb": vm.config.hardware.memoryMB if vm.config else 0,
                    "num_cpus": vm.config.hardware.numCPU if vm.config else 0,
                    "host": vm.runtime.host.name if vm.runtime.host else None,
                    "overall_status": str(vm.overallStatus)
                }
                vm_list.append(vm_info)
            
            return {
                "success": True,
                "vms": vm_list,
                "count": len(vm_list)
            }
            
        except Exception as e:
            raise VMOperationError(f"Failed to list VMs: {str(e)}")
    
    async def _create_vm(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new virtual machine"""
        name = args.get("name")
        datacenter_name = args.get("datacenter")
        
        if not name or not datacenter_name:
            raise ValidationError("VM name and datacenter are required")
        
        try:
            # Get datacenter
            datacenter = self.vcenter_client.get_obj(vim.Datacenter, datacenter_name)
            if not datacenter:
                raise ResourceNotFoundError(f"Datacenter "{datacenter_name}" not found")
            
            # Get cluster or use first available
            cluster_name = args.get("cluster")
            if cluster_name:
                cluster = self.vcenter_client.get_obj(vim.ClusterComputeResource, cluster_name)
                if not cluster:
                    raise ResourceNotFoundError(f"Cluster "{cluster_name}" not found")
                resource_pool = cluster.resourcePool
            else:
                clusters = self.vcenter_client.get_all_objs(vim.ClusterComputeResource)
                if not clusters:
                    raise ResourceNotFoundError("No clusters available")
                resource_pool = clusters[0].resourcePool
            
            # Get datastore
            datastore_name = args.get("datastore")
            if datastore_name:
                datastore = self.vcenter_client.get_obj(vim.Datastore, datastore_name)
                if not datastore:
                    raise ResourceNotFoundError(f"Datastore "{datastore_name}" not found")
            else:
                datastores = self.vcenter_client.get_all_objs(vim.Datastore)
                if not datastores:
                    raise ResourceNotFoundError("No datastores available")
                # Use datastore with most free space
                datastore = max(datastores, key=lambda ds: ds.summary.freeSpace)
            
            # Create VM configuration
            vm_config = vim.vm.ConfigSpec()
            vm_config.name = name
            vm_config.memoryMB = args.get("memory_mb", 1024)
            vm_config.numCPUs = args.get("num_cpus", 1)
            vm_config.guestId = args.get("guest_os", "otherGuest")
            
            # Add disk
            disk_size_gb = args.get("disk_size_gb", 10)
            disk_spec = vim.vm.device.VirtualDeviceSpec()
            disk_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
            disk_spec.fileOperation = vim.vm.device.VirtualDeviceSpec.FileOperation.create
            
            disk = vim.vm.device.VirtualDisk()
            disk.capacityInKB = disk_size_gb * 1024 * 1024
            disk.unitNumber = 0
            
            disk_spec.device = disk
            vm_config.deviceChange = [disk_spec]
            
            # Set datastore
            vm_config.files = vim.vm.FileInfo()
            vm_config.files.vmPathName = f"[{datastore.name}]"
            
            # Create VM
            task = datacenter.vmFolder.CreateVM_Task(config=vm_config, pool=resource_pool)
            result = await self.vcenter_client.wait_for_task(task)
            
            return {
                "success": True,
                "vm": {
                    "name": name,
                    "moid": result._moId,
                    "datacenter": datacenter_name
                },
                "message": f"VM "{name}" created successfully"
            }
            
        except Exception as e:
            raise VMOperationError(f"Failed to create VM: {str(e)}")
    
    async def _power_vm(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Control VM power state"""
        vm_name = args.get("vm_name")
        action = args.get("action")
        
        if not vm_name or not action:
            raise ValidationError("VM name and action are required")
        
        try:
            vm = self.vcenter_client.get_obj(vim.VirtualMachine, vm_name)
            if not vm:
                raise ResourceNotFoundError(f"VM "{vm_name}" not found")
            
            if action == "on":
                task = vm.PowerOnVM_Task()
            elif action == "off":
                task = vm.PowerOffVM_Task()
            elif action == "reset":
                task = vm.ResetVM_Task()
            elif action == "suspend":
                task = vm.SuspendVM_Task()
            else:
                raise ValidationError(f"Invalid power action: {action}")
            
            await self.vcenter_client.wait_for_task(task)
            
            return {
                "success": True,
                "vm": vm_name,
                "action": action,
                "message": f"VM "{vm_name}" power {action} completed successfully"
            }
            
        except Exception as e:
            raise VMOperationError(f"Failed to {action} VM: {str(e)}")
    
    async def _get_vm_info(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Get detailed VM information"""
        vm_name = args.get("vm_name")
        
        if not vm_name:
            raise ValidationError("VM name is required")
        
        try:
            vm = self.vcenter_client.get_obj(vim.VirtualMachine, vm_name)
            if not vm:
                raise ResourceNotFoundError(f"VM "{vm_name}" not found")
            
            vm_info = {
                "name": vm.name,
                "moid": vm._moId,
                "power_state": str(vm.runtime.powerState),
                "overall_status": str(vm.overallStatus),
                "guest_os": vm.config.guestFullName if vm.config else "Unknown",
                "memory_mb": vm.config.hardware.memoryMB if vm.config else 0,
                "num_cpus": vm.config.hardware.numCPU if vm.config else 0,
                "host": vm.runtime.host.name if vm.runtime.host else None,
                "cluster": vm.runtime.host.parent.name if vm.runtime.host and vm.runtime.host.parent else None,
                "datastore": [ds.name for ds in vm.datastore] if vm.datastore else [],
                "network": [net.name for net in vm.network] if vm.network else [],
                "tools_status": str(vm.guest.toolsStatus) if vm.guest else "unknown",
                "ip_address": vm.guest.ipAddress if vm.guest else None
            }
            
            return {
                "success": True,
                "vm_info": vm_info
            }
            
        except Exception as e:
            raise VMOperationError(f"Failed to get VM info: {str(e)}")
    
    async def _list_datastores(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """List all datastores"""
        try:
            datastores = self.vcenter_client.get_all_objs(vim.Datastore)
            datacenter_filter = args.get("datacenter")
            
            datastore_list = []
            for ds in datastores:
                # Filter by datacenter if specified
                if datacenter_filter:
                    parent_dc = ds.parent
                    while parent_dc and not isinstance(parent_dc, vim.Datacenter):
                        parent_dc = parent_dc.parent
                    if not parent_dc or parent_dc.name != datacenter_filter:
                        continue
                
                ds_info = {
                    "name": ds.name,
                    "moid": ds._moId,
                    "type": ds.summary.type,
                    "capacity_gb": round(ds.summary.capacity / (1024**3), 2),
                    "free_space_gb": round(ds.summary.freeSpace / (1024**3), 2),
                    "used_space_gb": round((ds.summary.capacity - ds.summary.freeSpace) / (1024**3), 2),
                    "accessible": ds.summary.accessible,
                    "maintenance_mode": ds.summary.maintenanceMode if hasattr(ds.summary, "maintenanceMode") else "normal"
                }
                datastore_list.append(ds_info)
            
            return {
                "success": True,
                "datastores": datastore_list,
                "count": len(datastore_list)
            }
            
        except Exception as e:
            raise StorageOperationError(f"Failed to list datastores: {str(e)}")
    
    async def _get_performance_stats(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Get performance statistics"""
        entity_name = args.get("entity_name")
        entity_type = args.get("entity_type")
        
        if not entity_name or not entity_type:
            raise ValidationError("Entity name and type are required")
        
        try:
            # Get entity object
            if entity_type == "vm":
                entity = self.vcenter_client.get_obj(vim.VirtualMachine, entity_name)
            elif entity_type == "host":
                entity = self.vcenter_client.get_obj(vim.HostSystem, entity_name)
            elif entity_type == "cluster":
                entity = self.vcenter_client.get_obj(vim.ClusterComputeResource, entity_name)
            else:
                raise ValidationError(f"Invalid entity type: {entity_type}")
            
            if not entity:
                raise ResourceNotFoundError(f"{entity_type.title()} "{entity_name}" not found")
            
            # Get basic performance info
            perf_info = {
                "entity_name": entity_name,
                "entity_type": entity_type,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            if entity_type == "vm" and hasattr(entity, "runtime"):
                perf_info.update({
                    "power_state": str(entity.runtime.powerState),
                    "memory_mb": entity.config.hardware.memoryMB if entity.config else 0,
                    "num_cpus": entity.config.hardware.numCPU if entity.config else 0,
                    "host": entity.runtime.host.name if entity.runtime.host else None
                })
            elif entity_type == "host" and hasattr(entity, "summary"):
                perf_info.update({
                    "connection_state": str(entity.runtime.connectionState),
                    "power_state": str(entity.runtime.powerState),
                    "cpu_mhz": entity.summary.hardware.cpuMhz if entity.summary.hardware else 0,
                    "memory_mb": entity.summary.hardware.memorySize // (1024*1024) if entity.summary.hardware else 0,
                    "num_vms": len(entity.vm) if entity.vm else 0
                })
            elif entity_type == "cluster" and hasattr(entity, "summary"):
                perf_info.update({
                    "overall_status": str(entity.overallStatus),
                    "num_hosts": len(entity.host) if entity.host else 0,
                    "num_vms": len(entity.resourcePool.vm) if entity.resourcePool and entity.resourcePool.vm else 0,
                    "drs_enabled": entity.configuration.drsConfig.enabled if entity.configuration.drsConfig else False,
                    "ha_enabled": entity.configuration.dasConfig.enabled if entity.configuration.dasConfig else False
                })
            
            return {
                "success": True,
                "performance_stats": perf_info
            }
            
        except Exception as e:
            raise VCenterOperationError(f"Failed to get performance stats: {str(e)}")
    
    async def start(self) -> None:
        """Start the MCP server"""
        try:
            # Connect to vCenter
            await self.vcenter_client.connect()
            
            # Start MCP server
            async with stdio_server() as (read_stream, write_stream):
                await self.server.run(
                    read_stream,
                    write_stream,
                    InitializationOptions(
                        server_name="vmware-vcenter-mcp",
                        server_version="1.0.0",
                        capabilities=self.server.get_capabilities(
                            notification_options=None,
                            experimental_capabilities=None
                        )
                    )
                )
        except Exception as e:
            logger.error(f"Server startup failed: {str(e)}")
            raise
        finally:
            await self.vcenter_client.disconnect()
    
    async def stop(self) -> None:
        """Stop the MCP server"""
        await self.vcenter_client.disconnect()
        logger.info("VMware vCenter MCP Server stopped")


async def main() -> None:
    """Main entry point"""
    import os
    import yaml
    
    # Load configuration
    config_file = os.getenv("CONFIG_FILE", "config.yaml")
    if os.path.exists(config_file):
        with open(config_file, "r") as f:
            config = yaml.safe_load(f)
    else:
        config = {
            "vcenter_host": os.getenv("VCENTER_HOST", ""),
            "vcenter_username": os.getenv("VCENTER_USERNAME", ""),
            "vcenter_password": os.getenv("VCENTER_PASSWORD", ""),
            "vcenter_port": int(os.getenv("VCENTER_PORT", "443")),
            "vcenter_ssl_verify": os.getenv("VCENTER_SSL_VERIFY", "true").lower() == "true"
        }
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    
    # Create and start server
    server = VCenterMCPServer(config)
    await server.start()


if __name__ == "__main__":
    asyncio.run(main())
