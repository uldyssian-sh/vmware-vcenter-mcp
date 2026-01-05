"""
Enterprise Multi-Tenancy Management

Provides comprehensive multi-tenant isolation, resource management, and tenant
administration for enterprise VMware vCenter MCP Server deployments.

Author: uldyssian-sh
License: MIT
"""

import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Any, Union
from dataclasses import dataclass, field
from enum import Enum
import uuid
import structlog

logger = structlog.get_logger(__name__)


class TenantStatus(Enum):
    """Tenant status enumeration"""
    ACTIVE = "active"
    SUSPENDED = "suspended"
    INACTIVE = "inactive"
    PENDING = "pending"
    TERMINATED = "terminated"


class IsolationLevel(Enum):
    """Tenant isolation levels"""
    STRICT = "strict"          # Complete isolation
    MODERATE = "moderate"      # Shared infrastructure, isolated data
    SHARED = "shared"          # Shared resources with quotas


@dataclass
class ResourceQuota:
    """Resource quota definition"""
    max_vms: Optional[int] = None
    max_cpu_cores: Optional[int] = None
    max_memory_gb: Optional[int] = None
    max_storage_gb: Optional[int] = None
    max_networks: Optional[int] = None
    max_snapshots: Optional[int] = None
    max_templates: Optional[int] = None
    max_users: Optional[int] = None
    
    # Rate limits
    api_requests_per_minute: Optional[int] = None
    concurrent_operations: Optional[int] = None


@dataclass
class ResourceUsage:
    """Current resource usage"""
    vms: int = 0
    cpu_cores: int = 0
    memory_gb: float = 0.0
    storage_gb: float = 0.0
    networks: int = 0
    snapshots: int = 0
    templates: int = 0
    users: int = 0
    
    # Usage metrics
    api_requests_last_minute: int = 0
    concurrent_operations: int = 0
    
    last_updated: datetime = field(default_factory=datetime.utcnow)


@dataclass
class TenantConfiguration:
    """Tenant-specific configuration"""
    vcenter_instances: List[str] = field(default_factory=list)
    allowed_datacenters: List[str] = field(default_factory=list)
    allowed_clusters: List[str] = field(default_factory=list)
    allowed_datastores: List[str] = field(default_factory=list)
    allowed_networks: List[str] = field(default_factory=list)
    
    # Feature flags
    features: Dict[str, bool] = field(default_factory=dict)
    
    # Custom settings
    settings: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Tenant:
    """Enterprise tenant representation"""
    id: str
    name: str
    description: str
    status: TenantStatus = TenantStatus.ACTIVE
    isolation_level: IsolationLevel = IsolationLevel.MODERATE
    
    # Resource management
    quota: ResourceQuota = field(default_factory=ResourceQuota)
    usage: ResourceUsage = field(default_factory=ResourceUsage)
    
    # Configuration
    config: TenantConfiguration = field(default_factory=TenantConfiguration)
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    created_by: Optional[str] = None
    
    # Billing and contact info
    contact_email: Optional[str] = None
    billing_info: Dict[str, Any] = field(default_factory=dict)
    
    # Custom metadata
    metadata: Dict[str, Any] = field(default_factory=dict)


class TenantManager:
    """Enterprise tenant management"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.default_isolation = IsolationLevel(
            config.get("default_isolation", "moderate")
        )
        
        # In production, store in database
        self.tenants: Dict[str, Tenant] = {}
        
        # Initialize default tenant if configured
        if config.get("create_default_tenant", True):
            self._create_default_tenant()
        
        logger.info("Tenant manager initialized", 
                   default_isolation=self.default_isolation.value)
    
    def _create_default_tenant(self):
        """Create default tenant for single-tenant deployments"""
        default_tenant = Tenant(
            id="default",
            name="Default Tenant",
            description="Default tenant for single-tenant deployment",
            isolation_level=self.default_isolation,
            quota=ResourceQuota(
                max_vms=1000,
                max_cpu_cores=500,
                max_memory_gb=2048,
                max_storage_gb=10240,
                max_networks=50,
                max_snapshots=5000,
                max_templates=100,
                max_users=100,
                api_requests_per_minute=1000,
                concurrent_operations=50
            )
        )
        
        self.tenants["default"] = default_tenant
        logger.info("Default tenant created", tenant_id="default")
    
    async def create_tenant(self, tenant_data: Dict[str, Any], 
                           created_by: str) -> Tenant:
        """Create new tenant"""
        
        tenant_id = tenant_data.get("id") or str(uuid.uuid4())
        
        if tenant_id in self.tenants:
            raise ValueError(f"Tenant {tenant_id} already exists")
        
        # Create tenant object
        tenant = Tenant(
            id=tenant_id,
            name=tenant_data["name"],
            description=tenant_data.get("description", ""),
            status=TenantStatus(tenant_data.get("status", "active")),
            isolation_level=IsolationLevel(
                tenant_data.get("isolation_level", self.default_isolation.value)
            ),
            created_by=created_by,
            contact_email=tenant_data.get("contact_email")
        )
        
        # Set quota if provided
        if "quota" in tenant_data:
            quota_data = tenant_data["quota"]
            tenant.quota = ResourceQuota(**quota_data)
        
        # Set configuration if provided
        if "config" in tenant_data:
            config_data = tenant_data["config"]
            tenant.config = TenantConfiguration(**config_data)
        
        # Set metadata if provided
        if "metadata" in tenant_data:
            tenant.metadata = tenant_data["metadata"]
        
        self.tenants[tenant_id] = tenant
        
        logger.info("Tenant created", 
                   tenant_id=tenant_id, 
                   tenant_name=tenant.name,
                   created_by=created_by)
        
        return tenant
    
    async def get_tenant(self, tenant_id: str) -> Optional[Tenant]:
        """Get tenant by ID"""
        return self.tenants.get(tenant_id)
    
    async def update_tenant(self, tenant_id: str, 
                           updates: Dict[str, Any]) -> Tenant:
        """Update tenant"""
        tenant = self.tenants.get(tenant_id)
        if not tenant:
            raise ValueError(f"Tenant {tenant_id} not found")
        
        # Update basic fields
        for field in ["name", "description", "contact_email"]:
            if field in updates:
                setattr(tenant, field, updates[field])
        
        # Update status
        if "status" in updates:
            tenant.status = TenantStatus(updates["status"])
        
        # Update isolation level
        if "isolation_level" in updates:
            tenant.isolation_level = IsolationLevel(updates["isolation_level"])
        
        # Update quota
        if "quota" in updates:
            quota_updates = updates["quota"]
            for field, value in quota_updates.items():
                if hasattr(tenant.quota, field):
                    setattr(tenant.quota, field, value)
        
        # Update configuration
        if "config" in updates:
            config_updates = updates["config"]
            for field, value in config_updates.items():
                if hasattr(tenant.config, field):
                    setattr(tenant.config, field, value)
        
        # Update metadata
        if "metadata" in updates:
            tenant.metadata.update(updates["metadata"])
        
        tenant.updated_at = datetime.utcnow()
        
        logger.info("Tenant updated", 
                   tenant_id=tenant_id,
                   updates=list(updates.keys()))
        
        return tenant
    
    async def delete_tenant(self, tenant_id: str):
        """Delete tenant"""
        if tenant_id == "default":
            raise ValueError("Cannot delete default tenant")
        
        tenant = self.tenants.get(tenant_id)
        if not tenant:
            raise ValueError(f"Tenant {tenant_id} not found")
        
        # Mark as terminated instead of immediate deletion
        tenant.status = TenantStatus.TERMINATED
        tenant.updated_at = datetime.utcnow()
        
        logger.info("Tenant marked for deletion", tenant_id=tenant_id)
    
    async def list_tenants(self, status: Optional[TenantStatus] = None,
                          limit: int = 100, offset: int = 0) -> List[Tenant]:
        """List tenants with optional filtering"""
        tenants = list(self.tenants.values())
        
        if status:
            tenants = [t for t in tenants if t.status == status]
        
        # Sort by creation date
        tenants.sort(key=lambda t: t.created_at, reverse=True)
        
        # Apply pagination
        return tenants[offset:offset + limit]
    
    async def get_tenant_usage(self, tenant_id: str) -> ResourceUsage:
        """Get current resource usage for tenant"""
        tenant = await self.get_tenant(tenant_id)
        if not tenant:
            raise ValueError(f"Tenant {tenant_id} not found")
        
        # In production, calculate from actual resources
        # This is a simplified implementation
        return tenant.usage
    
    async def update_tenant_usage(self, tenant_id: str, 
                                 usage_updates: Dict[str, Any]):
        """Update tenant resource usage"""
        tenant = await self.get_tenant(tenant_id)
        if not tenant:
            raise ValueError(f"Tenant {tenant_id} not found")
        
        for field, value in usage_updates.items():
            if hasattr(tenant.usage, field):
                setattr(tenant.usage, field, value)
        
        tenant.usage.last_updated = datetime.utcnow()
        
        logger.debug("Tenant usage updated", 
                    tenant_id=tenant_id,
                    updates=usage_updates)
    
    async def check_quota(self, tenant_id: str, 
                         resource_type: str, 
                         requested_amount: int = 1) -> bool:
        """Check if tenant has quota for resource"""
        tenant = await self.get_tenant(tenant_id)
        if not tenant:
            return False
        
        quota_field = f"max_{resource_type}"
        usage_field = resource_type
        
        max_allowed = getattr(tenant.quota, quota_field, None)
        current_usage = getattr(tenant.usage, usage_field, 0)
        
        if max_allowed is None:
            return True  # No limit set
        
        return (current_usage + requested_amount) <= max_allowed
    
    async def get_tenant_stats(self) -> Dict[str, Any]:
        """Get tenant statistics"""
        total_tenants = len(self.tenants)
        active_tenants = len([t for t in self.tenants.values() 
                             if t.status == TenantStatus.ACTIVE])
        
        return {
            "total_tenants": total_tenants,
            "active_tenants": active_tenants,
            "suspended_tenants": len([t for t in self.tenants.values() 
                                    if t.status == TenantStatus.SUSPENDED]),
            "terminated_tenants": len([t for t in self.tenants.values() 
                                     if t.status == TenantStatus.TERMINATED])
        }


class TenantIsolationManager:
    """Manages tenant isolation and resource boundaries"""
    
    def __init__(self, tenant_manager: TenantManager):
        self.tenant_manager = tenant_manager
        logger.info("Tenant isolation manager initialized")
    
    async def validate_resource_access(self, tenant_id: str, 
                                     resource_type: str,
                                     resource_id: str) -> bool:
        """Validate tenant access to specific resource"""
        tenant = await self.tenant_manager.get_tenant(tenant_id)
        if not tenant:
            return False
        
        if tenant.status != TenantStatus.ACTIVE:
            return False
        
        # Check isolation level
        if tenant.isolation_level == IsolationLevel.STRICT:
            return await self._validate_strict_isolation(tenant, resource_type, resource_id)
        elif tenant.isolation_level == IsolationLevel.MODERATE:
            return await self._validate_moderate_isolation(tenant, resource_type, resource_id)
        else:  # SHARED
            return await self._validate_shared_isolation(tenant, resource_type, resource_id)
    
    async def _validate_strict_isolation(self, tenant: Tenant, 
                                       resource_type: str, 
                                       resource_id: str) -> bool:
        """Validate access under strict isolation"""
        # In strict isolation, tenant can only access explicitly assigned resources
        
        if resource_type == "datacenter":
            return resource_id in tenant.config.allowed_datacenters
        elif resource_type == "cluster":
            return resource_id in tenant.config.allowed_clusters
        elif resource_type == "datastore":
            return resource_id in tenant.config.allowed_datastores
        elif resource_type == "network":
            return resource_id in tenant.config.allowed_networks
        
        return False
    
    async def _validate_moderate_isolation(self, tenant: Tenant, 
                                         resource_type: str, 
                                         resource_id: str) -> bool:
        """Validate access under moderate isolation"""
        # In moderate isolation, tenant has access to shared infrastructure
        # but with data isolation
        
        # Check if resource is in allowed list (if specified)
        if resource_type == "datacenter" and tenant.config.allowed_datacenters:
            return resource_id in tenant.config.allowed_datacenters
        elif resource_type == "cluster" and tenant.config.allowed_clusters:
            return resource_id in tenant.config.allowed_clusters
        
        # Default allow for moderate isolation
        return True
    
    async def _validate_shared_isolation(self, tenant: Tenant, 
                                       resource_type: str, 
                                       resource_id: str) -> bool:
        """Validate access under shared isolation"""
        # In shared isolation, tenant has access to all resources
        # with quota-based limitations
        return True
    
    async def get_tenant_resources(self, tenant_id: str) -> Dict[str, List[str]]:
        """Get all resources accessible to tenant"""
        tenant = await self.tenant_manager.get_tenant(tenant_id)
        if not tenant:
            return {}
        
        resources = {
            "datacenters": [],
            "clusters": [],
            "datastores": [],
            "networks": []
        }
        
        if tenant.isolation_level == IsolationLevel.STRICT:
            resources["datacenters"] = tenant.config.allowed_datacenters
            resources["clusters"] = tenant.config.allowed_clusters
            resources["datastores"] = tenant.config.allowed_datastores
            resources["networks"] = tenant.config.allowed_networks
        else:
            # For moderate and shared isolation, return all available resources
            # In production, query from vCenter
            pass
        
        return resources
    
    async def create_tenant_namespace(self, tenant_id: str, 
                                    resource_type: str) -> str:
        """Create namespaced resource identifier for tenant"""
        tenant = await self.tenant_manager.get_tenant(tenant_id)
        if not tenant:
            raise ValueError(f"Tenant {tenant_id} not found")
        
        if tenant.isolation_level == IsolationLevel.STRICT:
            # Use tenant-specific namespace
            return f"{tenant_id}_{resource_type}"
        else:
            # Use shared namespace with tenant prefix
            return f"shared_{resource_type}"
    
    async def filter_resources_by_tenant(self, tenant_id: str, 
                                       resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filter resources based on tenant access"""
        tenant = await self.tenant_manager.get_tenant(tenant_id)
        if not tenant:
            return []
        
        if tenant.isolation_level == IsolationLevel.SHARED:
            return resources
        
        filtered_resources = []
        for resource in resources:
            resource_type = resource.get("type", "")
            resource_id = resource.get("id", "")
            
            if await self.validate_resource_access(tenant_id, resource_type, resource_id):
                filtered_resources.append(resource)
        
        return filtered_resources
    
    async def enforce_tenant_quotas(self, tenant_id: str, 
                                  operation: str, 
                                  resource_count: int = 1) -> bool:
        """Enforce tenant quotas for operations"""
        tenant = await self.tenant_manager.get_tenant(tenant_id)
        if not tenant:
            return False
        
        # Check quota based on operation type
        if operation.startswith("create_vm"):
            return await self.tenant_manager.check_quota(tenant_id, "vms", resource_count)
        elif operation.startswith("create_network"):
            return await self.tenant_manager.check_quota(tenant_id, "networks", resource_count)
        elif operation.startswith("create_snapshot"):
            return await self.tenant_manager.check_quota(tenant_id, "snapshots", resource_count)
        
        return True
    
    async def get_isolation_report(self, tenant_id: str) -> Dict[str, Any]:
        """Generate tenant isolation report"""
        tenant = await self.tenant_manager.get_tenant(tenant_id)
        if not tenant:
            return {}
        
        accessible_resources = await self.get_tenant_resources(tenant_id)
        
        return {
            "tenant_id": tenant_id,
            "tenant_name": tenant.name,
            "isolation_level": tenant.isolation_level.value,
            "status": tenant.status.value,
            "accessible_resources": accessible_resources,
            "quota": {
                "max_vms": tenant.quota.max_vms,
                "max_cpu_cores": tenant.quota.max_cpu_cores,
                "max_memory_gb": tenant.quota.max_memory_gb,
                "max_storage_gb": tenant.quota.max_storage_gb
            },
            "current_usage": {
                "vms": tenant.usage.vms,
                "cpu_cores": tenant.usage.cpu_cores,
                "memory_gb": tenant.usage.memory_gb,
                "storage_gb": tenant.usage.storage_gb
            },
            "quota_utilization": {
                "vms": (tenant.usage.vms / tenant.quota.max_vms * 100) 
                       if tenant.quota.max_vms else 0,
                "cpu_cores": (tenant.usage.cpu_cores / tenant.quota.max_cpu_cores * 100) 
                            if tenant.quota.max_cpu_cores else 0,
                "memory_gb": (tenant.usage.memory_gb / tenant.quota.max_memory_gb * 100) 
                            if tenant.quota.max_memory_gb else 0,
                "storage_gb": (tenant.usage.storage_gb / tenant.quota.max_storage_gb * 100) 
                             if tenant.quota.max_storage_gb else 0
            }
        }