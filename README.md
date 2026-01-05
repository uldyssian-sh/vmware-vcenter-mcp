# VMware vCenter MCP Server

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![MCP Compatible](https://img.shields.io/badge/MCP-Compatible-green.svg)](https://modelcontextprotocol.io/)
[![Security Scan](https://img.shields.io/badge/security-scanned-brightgreen.svg)](https://github.com/uldyssian-sh/vmware-vcenter-mcp/security)

An enterprise-grade Model Context Protocol (MCP) server for comprehensive VMware vCenter Server management. This professional solution provides centralized virtualization infrastructure control, advanced automation capabilities, and enterprise-scale operations management.

## Features

### Core MCP Tools
- **Datacenter Operations**: Multi-datacenter management and orchestration
- **Cluster Management**: DRS, HA, vMotion configuration and monitoring
- **VM Lifecycle**: Complete virtual machine lifecycle management
- **Resource Pools**: Dynamic resource allocation and management
- **Storage Management**: vSAN, VMFS, NFS, and iSCSI operations
- **Network Management**: Distributed switches and advanced networking
- **Template Operations**: Enterprise template deployment and customization
- **Snapshot Management**: Enterprise snapshot management and consolidation
- **Performance Monitoring**: Real-time metrics and analytics
- **Automation Workflows**: Complex workflow orchestration

### Enterprise Architecture
- **Multi-Tenancy**: Complete tenant isolation with resource quotas and RBAC
- **High Availability**: Active-active clustering with automatic failover and load balancing
- **Enterprise Security**: Advanced threat detection, encryption, and compliance management
- **Authentication**: LDAP, SAML, OAuth2, and multi-factor authentication support
- **Authorization**: Fine-grained RBAC with role-based permissions and tenant isolation
- **Monitoring**: Comprehensive observability with Prometheus metrics, health checks, and audit logging
- **Orchestration**: Workflow automation engine with complex task dependencies and scheduling
- **API Gateway**: Enterprise API management with rate limiting, validation, and circuit breakers
- **Database Layer**: High-performance async PostgreSQL with connection pooling and read replicas
- **Caching**: Distributed Redis caching with cluster support and intelligent invalidation

### Advanced Enterprise Features
- **Multi-vCenter Support**: Manage multiple vCenter instances with intelligent load balancing
- **Bulk Operations**: Perform operations across multiple VMs/hosts with orchestration engine
- **Custom Workflows**: Define and execute complex automation sequences with YAML configuration
- **Performance Analytics**: Advanced monitoring with Prometheus and Grafana integration
- **Compliance Management**: SOC2, ISO27001, and PCI-DSS compliance reporting and automation
- **Enterprise Deployment**: Docker Swarm and Kubernetes deployment with HA configurations
- **Integration Ready**: RESTful APIs with comprehensive documentation and enterprise SDKs
- **Disaster Recovery**: Cross-site replication, automated failover, and recovery workflows
- **Audit & Compliance**: Comprehensive audit trails with retention policies and compliance reporting

## Quick Start

### Prerequisites
- Python 3.8 or higher
- VMware vCenter Server 7.0 or later
- Network connectivity to vCenter Server
- Valid vCenter credentials with administrative privileges

### Installation

```bash
# Clone the repository
git clone https://github.com/uldyssian-sh/vmware-vcenter-mcp.git
cd vmware-vcenter-mcp

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp config.example.yaml config.yaml
# Edit config.yaml with your vCenter details
```

### Configuration

Create `config.yaml`:

```yaml
vcenter:
  host: "vcenter.example.com"
  username: "administrator@vsphere.local"
  password: "${VCENTER_PASSWORD}"
  port: 443
  ssl_verify: true
  timeout: 60
  session_timeout: 1800

mcp:
  server_name: "vmware-vcenter-mcp"
  version: "1.0.0"
  capabilities:
    - "datacenter_management"
    - "cluster_operations"
    - "vm_lifecycle"
    - "resource_management"
    - "automation"

logging:
  level: "INFO"
  file: "vcenter-mcp.log"
  max_size: "50MB"
  backup_count: 10
  format: "json"

security:
  api_key: "${MCP_API_KEY}"
  rate_limit: 200
  session_timeout: 7200
  encryption: "AES256"

performance:
  connection_pool_size: 10
  cache_ttl: 300
  batch_size: 100
  async_operations: true
```

### Usage

```bash
# Start the MCP server
python -m vmware_vcenter_mcp --config config.yaml

# Or use environment variables
export VCENTER_HOST="vcenter.example.com"
export VCENTER_USERNAME="administrator@vsphere.local"
export VCENTER_PASSWORD="your-password"
export MCP_API_KEY="your-api-key"

python -m vmware_vcenter_mcp
```

## MCP Tools

### Datacenter Management

#### create_datacenter
Create and configure a new datacenter.

```json
{
  "name": "create_datacenter",
  "description": "Create a new datacenter",
  "inputSchema": {
    "type": "object",
    "properties": {
      "name": {"type": "string"},
      "folder": {"type": "string"},
      "description": {"type": "string"}
    },
    "required": ["name"]
  }
}
```

#### manage_cluster
Comprehensive cluster management operations.

```json
{
  "name": "manage_cluster",
  "description": "Manage cluster configuration",
  "inputSchema": {
    "type": "object",
    "properties": {
      "cluster_name": {"type": "string"},
      "action": {"type": "string", "enum": ["create", "configure", "delete"]},
      "drs_enabled": {"type": "boolean"},
      "ha_enabled": {"type": "boolean"},
      "vsan_enabled": {"type": "boolean"}
    },
    "required": ["cluster_name", "action"]
  }
}
```

### Virtual Machine Operations

#### deploy_from_template
Deploy VMs from templates with advanced configuration.

```json
{
  "name": "deploy_from_template",
  "description": "Deploy VM from template",
  "inputSchema": {
    "type": "object",
    "properties": {
      "template_name": {"type": "string"},
      "vm_name": {"type": "string"},
      "datacenter": {"type": "string"},
      "cluster": {"type": "string"},
      "datastore": {"type": "string"},
      "customization": {"type": "object"},
      "resource_pool": {"type": "string"}
    },
    "required": ["template_name", "vm_name"]
  }
}
```

#### vmotion_migrate
Perform vMotion migrations with advanced options.

```json
{
  "name": "vmotion_migrate",
  "description": "Migrate VM using vMotion",
  "inputSchema": {
    "type": "object",
    "properties": {
      "vm_name": {"type": "string"},
      "destination_host": {"type": "string"},
      "destination_datastore": {"type": "string"},
      "priority": {"type": "string", "enum": ["low", "normal", "high"]},
      "migrate_storage": {"type": "boolean"}
    },
    "required": ["vm_name", "destination_host"]
  }
}
```

### Resource Management

#### configure_drs
Configure Distributed Resource Scheduler settings.

```json
{
  "name": "configure_drs",
  "description": "Configure DRS settings",
  "inputSchema": {
    "type": "object",
    "properties": {
      "cluster_name": {"type": "string"},
      "automation_level": {"type": "string", "enum": ["manual", "partiallyAutomated", "fullyAutomated"]},
      "migration_threshold": {"type": "integer", "minimum": 1, "maximum": 5},
      "vm_overrides": {"type": "array"}
    },
    "required": ["cluster_name"]
  }
}
```

#### manage_resource_pools
Create and manage resource pools.

```json
{
  "name": "manage_resource_pools",
  "description": "Manage resource pools",
  "inputSchema": {
    "type": "object",
    "properties": {
      "action": {"type": "string", "enum": ["create", "modify", "delete"]},
      "pool_name": {"type": "string"},
      "cpu_shares": {"type": "integer"},
      "memory_shares": {"type": "integer"},
      "cpu_limit": {"type": "integer"},
      "memory_limit": {"type": "integer"}
    },
    "required": ["action", "pool_name"]
  }
}
```

### Storage Operations

#### configure_vsan
Configure vSAN storage policies and settings.

```json
{
  "name": "configure_vsan",
  "description": "Configure vSAN settings",
  "inputSchema": {
    "type": "object",
    "properties": {
      "cluster_name": {"type": "string"},
      "action": {"type": "string", "enum": ["enable", "disable", "configure"]},
      "storage_policy": {"type": "object"},
      "deduplication": {"type": "boolean"},
      "compression": {"type": "boolean"}
    },
    "required": ["cluster_name", "action"]
  }
}
```

## Architecture

### System Architecture
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   MCP Client    │────│  vCenter MCP    │────│   VMware        │
│   Applications  │    │  Server         │    │   vCenter       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │                        │
                       ┌─────────────────┐    ┌─────────────────┐
                       │   Event         │    │   Multiple      │
                       │   Processing    │    │   ESXi Hosts    │
                       └─────────────────┘    └─────────────────┘
```

### High Availability Design
- **Connection Redundancy**: Multiple vCenter connection paths
- **Session Management**: Automatic session recovery and failover
- **Load Balancing**: Intelligent request distribution
- **Circuit Breaker**: Automatic failure detection and recovery
- **Health Monitoring**: Continuous system health assessment

## Development

### Project Structure
```
vmware-vcenter-mcp/
├── src/
│   ├── vmware_vcenter_mcp/
│   │   ├── __init__.py
│   │   ├── server.py
│   │   ├── tools/
│   │   │   ├── datacenter.py
│   │   │   ├── cluster.py
│   │   │   ├── vm_operations.py
│   │   │   └── storage.py
│   │   ├── auth/
│   │   ├── events/
│   │   └── utils/
├── tests/
│   ├── unit/
│   ├── integration/
│   └── performance/
├── docs/
├── examples/
├── requirements.txt
└── setup.py
```

### Testing Strategy

```bash
# Unit tests
python -m pytest tests/unit/

# Integration tests with vCenter
python -m pytest tests/integration/ --vcenter-host=test-vcenter

# Performance tests
python -m pytest tests/performance/ --benchmark

# Security tests
python -m pytest tests/security/
```

### Development Environment

```bash
# Setup development environment
python -m venv venv
source venv/bin/activate
pip install -r requirements-dev.txt

# Run linting
flake8 src/
black src/
mypy src/

# Generate documentation
sphinx-build -b html docs/ docs/_build/
```

## Security Framework

### Authentication & Authorization
- **SSO Integration**: Active Directory and LDAP support
- **Multi-Factor Authentication**: TOTP and hardware token support
- **Role-Based Access Control**: Granular permission management
- **API Key Management**: Secure key generation and rotation
- **Session Security**: Encrypted session tokens with expiration

### Data Protection
- **Encryption at Rest**: AES-256 encryption for sensitive data
- **Encryption in Transit**: TLS 1.3 for all communications
- **Data Masking**: Automatic PII and credential masking
- **Audit Logging**: Comprehensive security event logging
- **Compliance**: SOC 2, ISO 27001 compliance features

## Performance Optimization

### Scalability Features
- **Horizontal Scaling**: Multi-instance deployment support
- **Connection Pooling**: Efficient vCenter API connection management
- **Caching Strategy**: Multi-level caching for improved response times
- **Async Operations**: Non-blocking operation processing
- **Batch Processing**: Bulk operation optimization

### Monitoring & Metrics
- **Prometheus Integration**: Comprehensive metrics export
- **Health Checks**: Automated system health monitoring
- **Performance Dashboards**: Real-time performance visualization
- **Alerting**: Proactive issue detection and notification
- **Capacity Planning**: Resource utilization trending

## Enterprise Deployment

### Production-Ready Architecture

The VMware vCenter MCP Server includes comprehensive enterprise architecture with:

- **8 Core Architecture Modules**: Authentication, Multi-tenancy, Database, Monitoring, HA, Security, Orchestration, API Gateway
- **High Availability**: Active-active clustering with PostgreSQL and Redis clusters
- **Enterprise Security**: Multi-layer security with threat detection and compliance
- **Comprehensive Monitoring**: Prometheus, Grafana, and ELK stack integration
- **Workflow Orchestration**: Complex automation with dependency management
- **Multi-tenant Isolation**: Complete resource and data isolation

### Quick Enterprise Setup

```bash
# Clone and setup enterprise deployment
git clone https://github.com/uldyssian-sh/vmware-vcenter-mcp.git
cd vmware-vcenter-mcp

# Configure environment variables
cp .env.example .env
# Edit .env with your enterprise settings

# Deploy enterprise stack
docker-compose -f docker-compose.enterprise.yml up -d

# Verify deployment
curl http://localhost/health
```

### Enterprise Configuration

```yaml
# config/enterprise.yaml
host: "0.0.0.0"
port: 8080
workers: 8

# vCenter Configuration
vcenter_host: "vcenter.example.com"
vcenter_username: "svc-vcenter-mcp@vsphere.local"
vcenter_password: "${VCENTER_PASSWORD}"

# Enterprise Features
multi_tenant: true
ha_enabled: true
security_level: "high"
encryption_enabled: true
metrics_enabled: true
orchestration_enabled: true
compliance_standards: ["soc2", "iso27001", "pci-dss"]
```

### Kubernetes Enterprise Deployment

```yaml
# Deploy with Helm
helm repo add vmware-vcenter-mcp https://charts.example.com/vmware-vcenter-mcp
helm install vcenter-mcp vmware-vcenter-mcp/vmware-vcenter-mcp \
  --values values-production.yaml \
  --namespace vmware-vcenter-mcp \
  --create-namespace
```

## Deployment

### Production Deployment

```yaml
# docker-compose.yml
version: '3.8'
services:
  vcenter-mcp:
    image: uldyssian-sh/vmware-vcenter-mcp:latest
    environment:
      - VCENTER_HOST=${VCENTER_HOST}
      - VCENTER_USERNAME=${VCENTER_USERNAME}
      - VCENTER_PASSWORD=${VCENTER_PASSWORD}
    volumes:
      - ./config:/app/config
      - ./logs:/app/logs
    ports:
      - "8080:8080"
    restart: unless-stopped
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vcenter-mcp
spec:
  replicas: 3
  selector:
    matchLabels:
      app: vcenter-mcp
  template:
    metadata:
      labels:
        app: vcenter-mcp
    spec:
      containers:
      - name: vcenter-mcp
        image: uldyssian-sh/vmware-vcenter-mcp:latest
        env:
        - name: VCENTER_HOST
          valueFrom:
            secretKeyRef:
              name: vcenter-credentials
              key: host
```

## Troubleshooting

### Common Issues

**vCenter Connection Issues**
```bash
# Test vCenter connectivity
curl -k https://vcenter.example.com/rest/com/vmware/cis/session

# Check SSL certificate
openssl s_client -connect vcenter.example.com:443
```

**Performance Issues**
- Monitor connection pool utilization
- Check vCenter API response times
- Review caching effectiveness
- Analyze batch operation efficiency

**Authentication Problems**
- Verify vCenter user permissions
- Check session timeout settings
- Validate SSL certificate chain
- Review audit logs for failed attempts

## Migration Guide

### From vSphere PowerCLI
- Tool mapping reference
- Script conversion utilities
- Best practices for migration
- Performance comparison

### From REST API
- Endpoint mapping
- Authentication migration
- Error handling updates
- Feature enhancement guide

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributors

- **uldyssian-sh LT** - *Initial work and maintenance*
- **dependabot[bot]** - *Dependency updates*
- **actions-user** - *Automated workflows*

## References

- [VMware vCenter Server API Documentation](https://developer.vmware.com/apis/vsphere-automation/)
- [Model Context Protocol Specification](https://modelcontextprotocol.io/)
- [VMware vSphere Security Guide](https://docs.vmware.com/en/VMware-vSphere/index.html)
- [Python vSphere Automation SDK](https://github.com/vmware/vsphere-automation-sdk-python)
- [vCenter Server Performance Best Practices](https://docs.vmware.com/en/VMware-vSphere/index.html)

## Support

For support and questions:
- Create an issue in this repository
- Check the [documentation](docs/)
- Review [API reference](docs/api/)
- Consult [troubleshooting guide](docs/troubleshooting.md)

---

**Maintained by: uldyssian-sh**

**Disclaimer: Use of this code is at your own risk. Author bears no responsibility for any damages caused by the code.**

⭐ Star this repository if you find it helpful!