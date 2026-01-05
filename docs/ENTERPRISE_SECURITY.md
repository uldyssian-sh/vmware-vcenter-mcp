# Enterprise Security Features

This document describes the advanced enterprise security features available in VMware vCenter MCP Server, including secrets management and configuration protection.

## Overview

The VMware vCenter MCP Server provides enterprise-grade security features designed for production deployments in secure environments. These features address common security concerns raised by enterprise users:

- **Environment Variable Storage**: Secure storage using Python keyring or HashiCorp Vault
- **Config.yaml Protection**: Encryption and integrity protection for configuration files
- **Secrets Management**: Multiple backend support for sensitive data
- **Access Control**: File permissions and integrity validation

## Secrets Management

### Supported Backends

#### 1. System Keyring (Recommended for Desktop/Development)
Uses the operating system's native keyring service:
- **macOS**: Keychain
- **Windows**: Windows Credential Store
- **Linux**: Secret Service (GNOME Keyring, KDE Wallet)

```python
from vmware_vcenter_mcp.secrets_manager import create_keyring_manager

# Create keyring-based secrets manager
secrets_manager = create_keyring_manager("vmware-vcenter-mcp")

# Store sensitive data
secrets_manager.store_secret("vcenter_password", "SuperSecretPassword123!")
secrets_manager.store_secret("api_key", "abc123def456ghi789")

# Retrieve sensitive data
password = secrets_manager.retrieve_secret("vcenter_password")
api_key = secrets_manager.retrieve_secret("api_key")
```

#### 2. HashiCorp Vault (Recommended for Production)
Enterprise-grade secret management with centralized control:

```python
from vmware_vcenter_mcp.secrets_manager import create_vault_manager

# Create Vault-based secrets manager
secrets_manager = create_vault_manager(
    vault_url="https://vault.company.com:8200",
    vault_token="s.xyz123abc456def789",
    service_name="vmware-vcenter-mcp"
)

# Store complex configuration
database_config = {
    "host": "db.company.com",
    "username": "mcp_user",
    "password": "DatabasePassword123!"
}
secrets_manager.store_secret("database_config", database_config)

# Retrieve configuration
config = secrets_manager.retrieve_secret("database_config")
```

#### 3. Encrypted File Storage
Local encrypted storage with automatic key management:

```python
from vmware_vcenter_mcp.secrets_manager import create_encrypted_file_manager

# Create encrypted file-based secrets manager
secrets_manager = create_encrypted_file_manager(
    file_path="/secure/path/secrets.enc",
    service_name="vmware-vcenter-mcp"
)

# Store and retrieve secrets
secrets_manager.store_secret("backup_key", "BackupEncryptionKey123!")
backup_key = secrets_manager.retrieve_secret("backup_key")
```

### Advanced Features

#### Multiple Backend Support
Automatic fallback between backends:

```python
from vmware_vcenter_mcp.secrets_manager import (
    EnterpriseSecretsManager, SecretConfig, SecretBackend, VaultConfig
)

# Primary: Vault, Fallback: Keyring
vault_config = VaultConfig(
    url="https://vault.company.com:8200",
    token="s.xyz123abc456def789"
)

config = SecretConfig(
    backend=SecretBackend.VAULT,
    service_name="vmware-vcenter-mcp",
    vault_config=vault_config
)

secrets_manager = EnterpriseSecretsManager(config)
```

#### Secret Listing and Management
```python
# List all stored secrets
secret_keys = secrets_manager.list_secrets()
print(f"Stored secrets: {secret_keys}")

# Get backend information
info = secrets_manager.get_backend_info()
print(f"Current backend: {info['backend']}")
print(f"Available backends: {info['available_backends']}")

# Delete secrets
secrets_manager.delete_secret("old_api_key")
```

## Configuration Protection

### Features

- **Selective Field Encryption**: Automatically encrypts sensitive fields
- **File Permissions**: Restricts access to configuration files
- **Integrity Validation**: Detects unauthorized modifications
- **Backup Management**: Automatic backup creation and rotation
- **Template Generation**: Creates deployment templates

### Basic Usage

```python
from vmware_vcenter_mcp.config_protection import create_protected_config_manager

# Create protected configuration manager
config_manager = create_protected_config_manager(
    config_path="/etc/vmware-mcp/config.yaml",
    use_keyring=True  # Use system keyring for encryption keys
)

# Configuration with sensitive data
config = {
    "server": {
        "host": "0.0.0.0",
        "port": 8080
    },
    "vcenter": {
        "host": "vcenter.company.com",
        "username": "administrator@vsphere.local",
        "password": "SensitivePassword123!",  # Will be encrypted
        "ssl_verify": True
    },
    "database": {
        "host": "db.company.com",
        "username": "mcp_user",
        "password": "DatabaseSecret456!"  # Will be encrypted
    }
}

# Save with automatic encryption
config_manager.save_config(config)

# Load with automatic decryption
loaded_config = config_manager.load_config()
```

### Advanced Configuration

```python
from vmware_vcenter_mcp.config_protection import (
    ConfigProtectionManager, ConfigProtectionSettings
)

# Custom protection settings
settings = ConfigProtectionSettings(
    encrypt_sensitive_fields=True,
    use_file_permissions=True,
    create_backup=True,
    validate_integrity=True,
    sensitive_field_patterns=[
        "*password*", "*secret*", "*key*", "*token*", 
        "*credential*", "*auth*", "*cert*", "*private*"
    ],
    file_permissions=0o600,  # Owner read/write only
    backup_retention=10  # Keep 10 backup versions
)

config_manager = ConfigProtectionManager(
    config_path="/etc/vmware-mcp/config.yaml",
    settings=settings,
    secrets_manager=secrets_manager  # Use existing secrets manager
)
```

### Security Features

#### Automatic Field Detection
The system automatically detects and encrypts sensitive fields based on configurable patterns:

```yaml
# Before encryption (in memory)
vcenter:
  password: "ActualPassword123!"
  api_key: "secret_api_key_xyz"

# After encryption (on disk)
vcenter:
  password: "encrypted:gAAAAABh..."
  api_key: "encrypted:gAAAAABh..."
```

#### File Permissions
Automatically sets restrictive file permissions:
- **0o600**: Owner read/write only (default)
- **0o640**: Owner read/write, group read
- **0o644**: Owner read/write, group/other read

#### Integrity Validation
Adds SHA-256 hash for tamper detection:

```yaml
# Configuration file includes integrity hash
_integrity_hash: "sha256:abc123def456..."
server:
  host: "0.0.0.0"
  port: 8080
```

#### Backup Management
Automatic backup creation with rotation:
```
/etc/vmware-mcp/
├── config.yaml
└── backups/
    ├── config_20240105_143022.yaml
    ├── config_20240105_142015.yaml
    └── config_20240105_141008.yaml
```

### Template Generation

Generate deployment templates without sensitive data:

```python
# Export template for deployment
config_manager.export_config_template(
    output_path="/tmp/config_template.yaml",
    include_sensitive=False  # Replace sensitive fields with placeholders
)
```

Generated template:
```yaml
server:
  host: "example_string_value"
  port: 12345
vcenter:
  host: "example_string_value"
  username: "example_string_value"
  password: "*** SENSITIVE - CONFIGURE SEPARATELY ***"
```

## Integration Examples

### Complete Enterprise Setup

```python
from vmware_vcenter_mcp.secrets_manager import create_vault_manager
from vmware_vcenter_mcp.config_protection import create_protected_config_manager

# 1. Setup Vault-based secrets management
secrets_manager = create_vault_manager(
    vault_url="https://vault.company.com:8200",
    vault_token="s.enterprise_token_xyz",
    service_name="vmware-vcenter-mcp"
)

# 2. Store sensitive configuration in Vault
secrets_manager.store_secret("vcenter_credentials", {
    "host": "vcenter.company.com",
    "username": "svc-mcp@company.local",
    "password": "EnterprisePassword123!"
})

secrets_manager.store_secret("database_credentials", {
    "host": "db.company.com",
    "username": "mcp_service",
    "password": "DatabasePassword456!"
})

# 3. Setup protected configuration
config_manager = create_protected_config_manager(
    config_path="/etc/vmware-mcp/production.yaml",
    use_vault=True,
    vault_url="https://vault.company.com:8200",
    vault_token="s.enterprise_token_xyz"
)

# 4. Application configuration (non-sensitive)
app_config = {
    "mcp_server": {
        "name": "VMware vCenter MCP Server",
        "version": "1.6.0",
        "environment": "production"
    },
    "logging": {
        "level": "INFO",
        "file": "/var/log/vmware-mcp.log"
    },
    "monitoring": {
        "enabled": True,
        "endpoint": "https://monitoring.company.com/metrics"
    }
}

# 5. Save configuration (encryption keys managed by Vault)
config_manager.save_config(app_config)

# 6. Runtime: Load configuration and secrets
config = config_manager.load_config()
vcenter_creds = secrets_manager.retrieve_secret("vcenter_credentials")
db_creds = secrets_manager.retrieve_secret("database_credentials")

# 7. Use in application
print(f"Connecting to vCenter: {vcenter_creds['host']}")
print(f"Database host: {db_creds['host']}")
```

### Development Environment Setup

```python
from vmware_vcenter_mcp.secrets_manager import create_keyring_manager
from vmware_vcenter_mcp.config_protection import create_protected_config_manager

# Simple keyring-based setup for development
secrets_manager = create_keyring_manager("vmware-vcenter-mcp-dev")
config_manager = create_protected_config_manager(
    config_path="./config/development.yaml",
    use_keyring=True
)

# Store development credentials
secrets_manager.store_secret("dev_vcenter_password", "DevPassword123!")

# Development configuration
dev_config = {
    "server": {"host": "localhost", "port": 8080, "debug": True},
    "vcenter": {
        "host": "vcenter-dev.local",
        "username": "administrator@vsphere.local",
        "password": "DevPassword123!",  # Will be encrypted
        "ssl_verify": False
    }
}

config_manager.save_config(dev_config)
```

## Security Best Practices

### 1. Backend Selection
- **Development**: Use system keyring for simplicity
- **Production**: Use HashiCorp Vault for centralized management
- **Containerized**: Use encrypted file storage with external key management

### 2. Key Management
- Rotate encryption keys regularly using `config_manager.rotate_encryption_key()`
- Use separate encryption keys for different environments
- Store Vault tokens securely and rotate them regularly

### 3. File Permissions
- Use restrictive permissions (0o600) for configuration files
- Ensure backup directories have appropriate permissions
- Monitor file access using system audit logs

### 4. Monitoring
- Monitor secret access patterns
- Set up alerts for configuration file modifications
- Log all encryption/decryption operations

### 5. Backup and Recovery
- Regularly backup encrypted configuration files
- Test configuration recovery procedures
- Maintain secure backup of encryption keys

## Troubleshooting

### Common Issues

#### 1. Keyring Access Denied
```
Error: Failed to store secret in keyring
```
**Solution**: Ensure the application has access to the system keyring service.

#### 2. Vault Authentication Failed
```
Error: Vault authentication failed
```
**Solution**: Verify Vault URL and token. Check network connectivity.

#### 3. Encryption Key Not Found
```
Error: Failed to decrypt configuration
```
**Solution**: Ensure encryption key is available in the secrets backend.

#### 4. File Permission Denied
```
Error: Permission denied accessing configuration file
```
**Solution**: Check file permissions and ownership.

### Debug Mode

Enable debug logging for troubleshooting:

```python
import logging
logging.basicConfig(level=logging.DEBUG)

# Or with structlog
import structlog
structlog.configure(
    wrapper_class=structlog.make_filtering_bound_logger(logging.DEBUG)
)
```

## Migration Guide

### From Plain Configuration

1. **Backup existing configuration**:
   ```bash
   cp config.yaml config.yaml.backup
   ```

2. **Create protected configuration manager**:
   ```python
   config_manager = create_protected_config_manager("config.yaml")
   ```

3. **Load and save with protection**:
   ```python
   import yaml
   with open("config.yaml.backup", 'r') as f:
       config = yaml.safe_load(f)
   
   config_manager.save_config(config)  # Automatically encrypts sensitive fields
   ```

### From Environment Variables

1. **Extract secrets to secrets manager**:
   ```python
   import os
   secrets_manager = create_keyring_manager()
   
   # Migrate environment variables
   secrets_manager.store_secret("vcenter_password", os.getenv("VCENTER_PASSWORD"))
   secrets_manager.store_secret("api_key", os.getenv("API_KEY"))
   ```

2. **Update configuration to reference secrets**:
   ```python
   config = {
       "vcenter": {
           "password": secrets_manager.retrieve_secret("vcenter_password")
       }
   }
   ```

---

**Maintained by:** uldyssian-sh  
**Disclaimer:** Use of this code is at your own risk. Author bears no responsibility for any damages caused by the code.

⭐ Star this repository if you find it helpful!