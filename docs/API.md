# VMware vCenter MCP Server API Documentation

## Overview

The VMware vCenter MCP Server provides an enterprise-grade Model Context Protocol (MCP) interface for comprehensive VMware vCenter Server management. This API documentation covers all available tools, advanced features, and enterprise integration capabilities.

## Authentication

The server supports multiple authentication methods for enterprise environments:

### API Key Authentication
```http
Authorization: Bearer YOUR_API_KEY
```

### Single Sign-On (SSO)
```http
Authorization: Bearer SSO_TOKEN
```

### Multi-Factor Authentication
```http
Authorization: Bearer MFA_TOKEN
X-MFA-Code: 123456
```

## Base URL

```
http://localhost:8080/mcp
```

## Enterprise Features

### Multi-Tenancy Support
All API endpoints support tenant isolation:
```http
X-Tenant-ID: tenant-123
```

### Audit Logging
All operations are automatically logged with:
- User identification
- Timestamp
- Operation details
- Result status

## MCP Tools

### Datacenter Management

#### create_datacenter

Creates a new datacenter in vCenter.

**Parameters:**
- `name` (string, required): Datacenter name
- `folder` (string, optional): Parent folder path
- `description` (string, optional): Datacenter description

**Example Request:**
```json
{
  "tool": "create_datacenter",
  "arguments": {
    "name": "Production-DC",
    "folder": "/Datacenters",
    "description": "Production datacenter for enterprise workloads"
  }
}
```

**Example Response:**
```json
{
  "status": "success",
  "data": {
    "datacenter_id": "datacenter-123",
    "name": "Production-DC",
    "path": "/Datacenters/Production-DC",
    "created_at": "2026-01-05T10:30:00Z"
  },
  "metadata": {
    "timestamp": "2026-01-05T10:30:00Z",
    "operation": "create_datacenter",
    "duration_ms": 2500,
    "user": "administrator@vsphere.local"
  }
}
```

#### manage_cluster

Comprehensive cluster management operations.

**Parameters:**
- `cluster_name` (string, required): Name of the cluster
- `action` (string, required): Action ("create", "configure", "delete")
- `datacenter` (string, required): Parent datacenter name
- `drs_enabled` (boolean, optional): Enable DRS (default: true)
- `ha_enabled` (boolean, optional): Enable HA (default: true)
- `vsan_enabled` (boolean, optional): Enable vSAN (default: false)
- `drs_automation_level` (string, optional): DRS automation level
- `ha_admission_control` (object, optional): HA admission control settings

**Example Request:**
```json
{
  "tool": "manage_cluster",
  "arguments": {
    "cluster_name": "Production-Cluster",
    "action": "create",
    "datacenter": "Production-DC",
    "drs_enabled": true,
    "ha_enabled": true,
    "drs_automation_level": "fullyAutomated",
    "ha_admission_control": {
      "policy": "resourcePercentage",
      "cpu_percentage": 25,
      "memory_percentage": 25
    }
  }
}
```

### Advanced VM Operations

#### deploy_from_template

Deploy VMs from templates with advanced customization.

**Parameters:**
- `template_name` (string, required): Source template name
- `vm_name` (string, required): New VM name
- `datacenter` (string, required): Target datacenter
- `cluster` (string, optional): Target cluster
- `datastore` (string, optional): Target datastore
- `resource_pool` (string, optional): Target resource pool
- `customization` (object, optional): Guest OS customization
- `network_config` (array, optional): Network adapter configuration
- `disk_config` (array, optional): Additional disk configuration

**Example Request:**
```json
{
  "tool": "deploy_from_template",
  "arguments": {
    "template_name": "Ubuntu-20.04-Template",
    "vm_name": "web-server-001",
    "datacenter": "Production-DC",
    "cluster": "Production-Cluster",
    "customization": {
      "hostname": "web-server-001",
      "domain": "example.com",
      "ip_settings": {
        "ip": "192.168.1.100",
        "subnet_mask": "255.255.255.0",
        "gateway": "192.168.1.1",
        "dns_servers": ["8.8.8.8", "8.8.4.4"]
      }
    },
    "network_config": [
      {
        "network": "Production-Network",
        "type": "vmxnet3"
      }
    ]
  }
}
```

#### vmotion_migrate

Perform vMotion migrations with advanced options.

**Parameters:**
- `vm_name` (string, required): VM to migrate
- `destination_host` (string, optional): Target ESXi host
- `destination_datastore` (string, optional): Target datastore
- `destination_cluster` (string, optional): Target cluster
- `priority` (string, optional): Migration priority ("low", "normal", "high")
- `migrate_storage` (boolean, optional): Include storage migration
- `network_mapping` (object, optional): Network remapping

**Example Request:**
```json
{
  "tool": "vmotion_migrate",
  "arguments": {
    "vm_name": "web-server-001",
    "destination_cluster": "DR-Cluster",
    "destination_datastore": "DR-Storage",
    "priority": "high",
    "migrate_storage": true,
    "network_mapping": {
      "Production-Network": "DR-Network"
    }
  }
}
```

### Resource Management

#### configure_drs

Configure Distributed Resource Scheduler settings.

**Parameters:**
- `cluster_name` (string, required): Target cluster
- `automation_level` (string, optional): Automation level
- `migration_threshold` (integer, optional): Migration threshold (1-5)
- `vm_overrides` (array, optional): Per-VM DRS settings
- `affinity_rules` (array, optional): VM affinity rules
- `anti_affinity_rules` (array, optional): VM anti-affinity rules

**Example Request:**
```json
{
  "tool": "configure_drs",
  "arguments": {
    "cluster_name": "Production-Cluster",
    "automation_level": "fullyAutomated",
    "migration_threshold": 3,
    "affinity_rules": [
      {
        "name": "Web-Tier-Affinity",
        "vms": ["web-01", "web-02", "web-03"],
        "type": "affinity"
      }
    ],
    "anti_affinity_rules": [
      {
        "name": "DB-Anti-Affinity",
        "vms": ["db-primary", "db-secondary"],
        "type": "anti_affinity"
      }
    ]
  }
}
```

#### manage_resource_pools

Create and manage resource pools with advanced settings.

**Parameters:**
- `action` (string, required): Action ("create", "modify", "delete")
- `pool_name` (string, required): Resource pool name
- `parent` (string, optional): Parent resource pool or cluster
- `cpu_allocation` (object, optional): CPU resource settings
- `memory_allocation` (object, optional): Memory resource settings
- `expandable_reservation` (boolean, optional): Expandable reservation

**Example Request:**
```json
{
  "tool": "manage_resource_pools",
  "arguments": {
    "action": "create",
    "pool_name": "Production-Web-Tier",
    "parent": "Production-Cluster",
    "cpu_allocation": {
      "shares": "high",
      "reservation": 2000,
      "limit": 8000,
      "expandable_reservation": true
    },
    "memory_allocation": {
      "shares": "high",
      "reservation": 4096,
      "limit": 16384,
      "expandable_reservation": true
    }
  }
}
```

### Storage Operations

#### configure_vsan

Configure vSAN storage policies and settings.

**Parameters:**
- `cluster_name` (string, required): Target cluster
- `action` (string, required): Action ("enable", "disable", "configure")
- `storage_policy` (object, optional): Storage policy configuration
- `deduplication` (boolean, optional): Enable deduplication
- `compression` (boolean, optional): Enable compression
- `encryption` (boolean, optional): Enable encryption

**Example Request:**
```json
{
  "tool": "configure_vsan",
  "arguments": {
    "cluster_name": "Production-Cluster",
    "action": "configure",
    "storage_policy": {
      "name": "Production-Policy",
      "failures_to_tolerate": 1,
      "stripe_width": 2,
      "force_provisioning": false
    },
    "deduplication": true,
    "compression": true,
    "encryption": true
  }
}
```

#### manage_datastores

Manage datastores and storage configurations.

**Parameters:**
- `action` (string, required): Action ("create", "extend", "delete", "configure")
- `datastore_name` (string, required): Datastore name
- `type` (string, optional): Datastore type ("vmfs", "nfs", "vsan")
- `hosts` (array, optional): Target hosts
- `configuration` (object, required): Type-specific configuration

**Example Request:**
```json
{
  "tool": "manage_datastores",
  "arguments": {
    "action": "create",
    "datastore_name": "Production-NFS",
    "type": "nfs",
    "hosts": ["esxi-01", "esxi-02", "esxi-03"],
    "configuration": {
      "server": "nfs-server.example.com",
      "path": "/exports/production",
      "version": "4.1",
      "security": "krb5"
    }
  }
}
```

### Network Management

#### configure_distributed_switch

Manage distributed virtual switches.

**Parameters:**
- `action` (string, required): Action ("create", "configure", "delete")
- `switch_name` (string, required): Switch name
- `datacenter` (string, required): Parent datacenter
- `version` (string, optional): Switch version
- `uplinks` (array, optional): Uplink configuration
- `port_groups` (array, optional): Port group configuration

**Example Request:**
```json
{
  "tool": "configure_distributed_switch",
  "arguments": {
    "action": "create",
    "switch_name": "Production-DVS",
    "datacenter": "Production-DC",
    "version": "7.0.0",
    "uplinks": [
      {
        "name": "Uplink1",
        "active": true
      },
      {
        "name": "Uplink2",
        "active": true
      }
    ],
    "port_groups": [
      {
        "name": "Production-Network",
        "vlan_id": 100,
        "ports": 128
      },
      {
        "name": "Management-Network",
        "vlan_id": 200,
        "ports": 64
      }
    ]
  }
}
```

### Monitoring & Analytics

#### get_cluster_performance

Retrieve comprehensive cluster performance metrics.

**Parameters:**
- `cluster_name` (string, required): Target cluster
- `metrics` (array, optional): Specific metrics to retrieve
- `interval` (integer, optional): Sampling interval
- `duration` (integer, optional): Time range duration
- `aggregation` (string, optional): Aggregation method

**Available Metrics:**
- `cpu.usage.average`
- `mem.usage.average`
- `disk.usage.average`
- `net.usage.average`
- `power.usage.average`
- `drs.migrations`
- `ha.failovers`

**Example Response:**
```json
{
  "status": "success",
  "data": {
    "cluster_name": "Production-Cluster",
    "time_range": {
      "start": "2026-01-05T09:30:00Z",
      "end": "2026-01-05T10:30:00Z"
    },
    "metrics": {
      "cpu": {
        "average": 45.2,
        "peak": 78.5,
        "trend": "stable"
      },
      "memory": {
        "average": 67.8,
        "peak": 89.2,
        "trend": "increasing"
      },
      "storage": {
        "iops": 1250,
        "latency_ms": 12.5,
        "throughput_mbps": 450
      }
    },
    "hosts": [
      {
        "name": "esxi-01.example.com",
        "cpu_usage": 42.1,
        "memory_usage": 65.3,
        "vm_count": 15
      }
    ]
  }
}
```

#### generate_capacity_report

Generate comprehensive capacity planning reports.

**Parameters:**
- `scope` (string, required): Report scope ("datacenter", "cluster", "host")
- `target` (string, required): Target name
- `forecast_days` (integer, optional): Forecast period (default: 30)
- `include_recommendations` (boolean, optional): Include recommendations

**Example Response:**
```json
{
  "status": "success",
  "data": {
    "report_id": "cap-report-123",
    "scope": "cluster",
    "target": "Production-Cluster",
    "generated_at": "2026-01-05T10:30:00Z",
    "current_utilization": {
      "cpu": {
        "total_ghz": 240,
        "used_ghz": 108.5,
        "utilization_percent": 45.2
      },
      "memory": {
        "total_gb": 512,
        "used_gb": 347.2,
        "utilization_percent": 67.8
      },
      "storage": {
        "total_tb": 10,
        "used_tb": 5.2,
        "utilization_percent": 52.0
      }
    },
    "forecast": {
      "30_days": {
        "cpu_utilization": 52.1,
        "memory_utilization": 74.5,
        "storage_utilization": 58.3
      }
    },
    "recommendations": [
      {
        "type": "capacity_expansion",
        "priority": "medium",
        "description": "Consider adding memory to cluster within 60 days",
        "estimated_cost": "$15000"
      }
    ]
  }
}
```

### Automation & Orchestration

#### create_automation_workflow

Create automated workflows for common operations.

**Parameters:**
- `workflow_name` (string, required): Workflow name
- `description` (string, optional): Workflow description
- `triggers` (array, required): Workflow triggers
- `actions` (array, required): Workflow actions
- `conditions` (array, optional): Conditional logic

**Example Request:**
```json
{
  "tool": "create_automation_workflow",
  "arguments": {
    "workflow_name": "Auto-Scale-Web-Tier",
    "description": "Automatically scale web tier based on CPU usage",
    "triggers": [
      {
        "type": "metric_threshold",
        "metric": "cpu.usage.average",
        "threshold": 80,
        "duration": 300
      }
    ],
    "actions": [
      {
        "type": "deploy_vm",
        "template": "Web-Server-Template",
        "count": 1,
        "resource_pool": "Production-Web-Tier"
      },
      {
        "type": "update_load_balancer",
        "add_targets": true
      }
    ]
  }
}
```

## Enterprise Integration

### Backup Integration

#### configure_backup_policy

Configure backup policies for VMs.

**Parameters:**
- `policy_name` (string, required): Backup policy name
- `vms` (array, required): Target VMs or VM patterns
- `schedule` (object, required): Backup schedule
- `retention` (object, required): Retention settings
- `backup_type` (string, optional): Backup type

### Disaster Recovery

#### configure_site_recovery

Configure Site Recovery Manager integration.

**Parameters:**
- `protected_site` (string, required): Protected site name
- `recovery_site` (string, required): Recovery site name
- `protection_groups` (array, required): Protection group configuration
- `recovery_plans` (array, required): Recovery plan configuration

## Security & Compliance

### Role-Based Access Control

#### manage_roles

Manage custom roles and permissions.

**Parameters:**
- `action` (string, required): Action ("create", "modify", "delete")
- `role_name` (string, required): Role name
- `permissions` (array, required): Permission list
- `description` (string, optional): Role description

### Compliance Reporting

#### generate_compliance_report

Generate compliance reports for various standards.

**Parameters:**
- `standard` (string, required): Compliance standard ("soc2", "iso27001", "pci")
- `scope` (string, required): Report scope
- `format` (string, optional): Output format ("json", "pdf", "csv")

## Error Handling

Enterprise error responses include additional context:

```json
{
  "status": "error",
  "error": {
    "code": "VCENTER_OPERATION_FAILED",
    "message": "Failed to create virtual machine",
    "details": {
      "operation": "create_vm",
      "vcenter_task_id": "task-123",
      "vcenter_error": "Insufficient resources"
    },
    "remediation": {
      "suggestions": [
        "Check available resources in target cluster",
        "Consider using different resource pool",
        "Verify datastore capacity"
      ],
      "documentation_url": "https://docs.vmware.com/..."
    }
  },
  "metadata": {
    "timestamp": "2026-01-05T10:30:00Z",
    "request_id": "req-12345",
    "user": "administrator@vsphere.local",
    "tenant": "production"
  }
}
```

## Performance & Scalability

### Connection Pooling
- Automatic connection pool management
- Configurable pool sizes
- Connection health monitoring

### Caching
- Multi-level caching strategy
- Configurable TTL values
- Cache invalidation policies

### Load Balancing
- Multiple vCenter support
- Automatic failover
- Load distribution algorithms

## Monitoring & Observability

### Metrics Export
- Prometheus metrics endpoint
- Custom metric definitions
- Performance dashboards

### Distributed Tracing
- OpenTelemetry integration
- Request correlation
- Performance analysis

## SDK Examples

### Python Enterprise SDK
```python
from vmware_vcenter_mcp import VCenterMCPClient
from vmware_vcenter_mcp.auth import SSOAuthenticator

# Enterprise authentication
auth = SSOAuthenticator(
    idp_url="https://sso.example.com",
    client_id="vcenter-mcp",
    client_secret="secret"
)

client = VCenterMCPClient(
    host="vcenter-mcp.example.com",
    authenticator=auth,
    tenant_id="production"
)

# Deploy VM from template with customization
result = await client.deploy_from_template(
    template_name="Ubuntu-20.04-Template",
    vm_name="web-server-001",
    datacenter="Production-DC",
    customization={
        "hostname": "web-server-001",
        "domain": "example.com",
        "ip_settings": {
            "ip": "192.168.1.100",
            "subnet_mask": "255.255.255.0",
            "gateway": "192.168.1.1"
        }
    }
)
```

## Best Practices

### Enterprise Deployment
1. Use load balancers for high availability
2. Implement proper monitoring and alerting
3. Configure backup and disaster recovery
4. Use infrastructure as code

### Security
1. Enable audit logging
2. Use least privilege access
3. Implement network segmentation
4. Regular security assessments

### Performance
1. Optimize connection pooling
2. Use appropriate caching strategies
3. Monitor resource utilization
4. Implement proper scaling policies

## Support

Enterprise support options:
- Priority support channel
- Dedicated technical account manager
- Custom integration assistance
- Training and certification programs

For technical support:
- Enterprise Portal: https://support.example.com
- Email: enterprise-support@example.com
- Phone: +1-800-SUPPORT