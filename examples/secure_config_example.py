#!/usr/bin/env python3
"""
Secure Configuration Management Example

Demonstrates enterprise-grade configuration protection and secrets management
for VMware vCenter MCP Server deployments.

Author: uldyssian-sh
License: MIT
"""

import os
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from vmware_vcenter_mcp.secrets_manager import (
    EnterpriseSecretsManager, SecretBackend, SecretConfig, VaultConfig,
    create_keyring_manager, create_vault_manager, create_encrypted_file_manager
)
from vmware_vcenter_mcp.config_protection import (
    ConfigProtectionManager, ConfigProtectionSettings,
    create_protected_config_manager
)


def example_keyring_secrets():
    """Example: Using system keyring for secrets management"""
    print("=== System Keyring Secrets Management ===")
    
    # Create keyring-based secrets manager
    secrets_manager = create_keyring_manager("vmware-vcenter-example")
    
    # Store various types of secrets
    secrets = {
        "vcenter_password": "SuperSecretPassword123!",
        "api_key": "abc123def456ghi789",
        "database_config": {
            "host": "db.example.com",
            "username": "dbuser",
            "password": "dbpass123"
        }
    }
    
    print("Storing secrets in system keyring...")
    for key, value in secrets.items():
        success = secrets_manager.store_secret(key, value)
        print(f"  {key}: {'✅ Stored' if success else '❌ Failed'}")
    
    print("\nRetrieving secrets from system keyring...")
    for key in secrets.keys():
        value = secrets_manager.retrieve_secret(key)
        if value:
            if isinstance(value, dict):
                print(f"  {key}: ✅ Retrieved (dict with {len(value)} keys)")
            else:
                print(f"  {key}: ✅ Retrieved (length: {len(str(value))})")
        else:
            print(f"  {key}: ❌ Not found")
    
    # Get backend information
    info = secrets_manager.get_backend_info()
    print(f"\nBackend Info:")
    print(f"  Current backend: {info['backend']}")
    print(f"  Available backends: {', '.join(info['available_backends'])}")


def example_vault_secrets():
    """Example: Using HashiCorp Vault for secrets management"""
    print("\n=== HashiCorp Vault Secrets Management ===")
    
    # Note: This requires a running Vault instance
    vault_url = os.getenv("VAULT_URL", "http://localhost:8200")
    vault_token = os.getenv("VAULT_TOKEN", "dev-token")
    
    if not vault_token or vault_token == "dev-token":
        print("⚠️  Vault example skipped - set VAULT_URL and VAULT_TOKEN environment variables")
        return
    
    try:
        # Create Vault-based secrets manager
        secrets_manager = create_vault_manager(vault_url, vault_token, "vmware-vcenter-example")
        
        # Store secrets in Vault
        secrets = {
            "vcenter_credentials": {
                "host": "vcenter.example.com",
                "username": "administrator@vsphere.local",
                "password": "VaultSecurePassword123!"
            },
            "ssl_certificate": "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----"
        }
        
        print("Storing secrets in HashiCorp Vault...")
        for key, value in secrets.items():
            success = secrets_manager.store_secret(key, value)
            print(f"  {key}: {'✅ Stored' if success else '❌ Failed'}")
        
        print("\nRetrieving secrets from HashiCorp Vault...")
        for key in secrets.keys():
            value = secrets_manager.retrieve_secret(key)
            if value:
                if isinstance(value, dict):
                    print(f"  {key}: ✅ Retrieved (dict with {len(value)} keys)")
                else:
                    print(f"  {key}: ✅ Retrieved (length: {len(str(value))})")
            else:
                print(f"  {key}: ❌ Not found")
        
        # List all secrets
        secret_keys = secrets_manager.list_secrets()
        print(f"\nAll secrets in Vault: {secret_keys}")
        
    except Exception as e:
        print(f"❌ Vault example failed: {e}")


def example_encrypted_file_secrets():
    """Example: Using encrypted file for secrets management"""
    print("\n=== Encrypted File Secrets Management ===")
    
    # Create encrypted file-based secrets manager
    secrets_file = "/tmp/vmware_secrets.enc"
    secrets_manager = create_encrypted_file_manager(secrets_file, "vmware-vcenter-example")
    
    # Store secrets in encrypted file
    secrets = {
        "backup_encryption_key": "BackupKey123!@#",
        "monitoring_token": "mon_token_xyz789",
        "ldap_config": {
            "server": "ldap.example.com",
            "bind_dn": "cn=service,dc=example,dc=com",
            "bind_password": "ldap_secret_pass"
        }
    }
    
    print("Storing secrets in encrypted file...")
    for key, value in secrets.items():
        success = secrets_manager.store_secret(key, value)
        print(f"  {key}: {'✅ Stored' if success else '❌ Failed'}")
    
    print(f"\nEncrypted file created: {secrets_file}")
    if os.path.exists(secrets_file):
        file_size = os.path.getsize(secrets_file)
        print(f"File size: {file_size} bytes")
    
    print("\nRetrieving secrets from encrypted file...")
    for key in secrets.keys():
        value = secrets_manager.retrieve_secret(key)
        if value:
            if isinstance(value, dict):
                print(f"  {key}: ✅ Retrieved (dict with {len(value)} keys)")
            else:
                print(f"  {key}: ✅ Retrieved (length: {len(str(value))})")
        else:
            print(f"  {key}: ❌ Not found")
    
    # List all secrets
    secret_keys = secrets_manager.list_secrets()
    print(f"\nAll secrets in file: {secret_keys}")
    
    # Cleanup
    if os.path.exists(secrets_file):
        os.remove(secrets_file)
        print(f"Cleaned up: {secrets_file}")


def example_config_protection():
    """Example: Protected configuration file management"""
    print("\n=== Protected Configuration Management ===")
    
    # Create temporary config file
    config_file = "/tmp/vmware_config.yaml"
    
    # Create configuration protection manager
    settings = ConfigProtectionSettings(
        encrypt_sensitive_fields=True,
        use_file_permissions=True,
        create_backup=True,
        validate_integrity=True,
        file_permissions=0o600
    )
    
    # Use keyring for encryption key storage
    secrets_manager = create_keyring_manager("vmware-config-example")
    config_manager = ConfigProtectionManager(config_file, settings, secrets_manager)
    
    # Sample configuration with sensitive data
    config = {
        "server": {
            "host": "0.0.0.0",
            "port": 8080,
            "debug": False
        },
        "vcenter": {
            "host": "vcenter.example.com",
            "username": "administrator@vsphere.local",
            "password": "SensitivePassword123!",  # Will be encrypted
            "ssl_verify": True
        },
        "database": {
            "host": "db.example.com",
            "port": 5432,
            "name": "vmware_mcp",
            "username": "dbuser",
            "password": "DatabaseSecret456!",  # Will be encrypted
            "ssl_mode": "require"
        },
        "security": {
            "api_key": "secret_api_key_789",  # Will be encrypted
            "jwt_secret": "jwt_signing_secret",  # Will be encrypted
            "encryption_enabled": True
        },
        "logging": {
            "level": "INFO",
            "file": "/var/log/vmware-mcp.log"
        }
    }
    
    print("Saving protected configuration...")
    success = config_manager.save_config(config)
    print(f"Configuration saved: {'✅ Success' if success else '❌ Failed'}")
    
    if os.path.exists(config_file):
        # Check file permissions
        import stat
        file_stat = os.stat(config_file)
        permissions = oct(stat.S_IMODE(file_stat.st_mode))
        print(f"File permissions: {permissions}")
        
        # Show encrypted content
        print("\nRaw file content (with encrypted fields):")
        with open(config_file, 'r') as f:
            content = f.read()
            lines = content.split('\n')
            for i, line in enumerate(lines[:15], 1):  # Show first 15 lines
                print(f"  {i:2d}: {line}")
            if len(lines) > 15:
                print(f"  ... ({len(lines) - 15} more lines)")
    
    print("\nLoading and decrypting configuration...")
    loaded_config = config_manager.load_config()
    
    if loaded_config:
        print("✅ Configuration loaded and decrypted successfully")
        print(f"Configuration sections: {list(loaded_config.keys())}")
        
        # Verify sensitive fields are decrypted
        vcenter_password = loaded_config.get('vcenter', {}).get('password')
        if vcenter_password == "SensitivePassword123!":
            print("✅ Sensitive fields decrypted correctly")
        else:
            print("❌ Sensitive field decryption failed")
    else:
        print("❌ Failed to load configuration")
    
    # Get protection status
    status = config_manager.get_protection_status()
    print(f"\nProtection Status:")
    print(f"  Encryption enabled: {status['encryption_enabled']}")
    print(f"  Encrypted fields: {status.get('encrypted_fields_count', 'unknown')}")
    print(f"  Total fields: {status.get('total_fields_count', 'unknown')}")
    
    # Export template
    template_file = "/tmp/vmware_config_template.yaml"
    print(f"\nExporting configuration template...")
    success = config_manager.export_config_template(template_file, include_sensitive=False)
    if success:
        print(f"✅ Template exported to: {template_file}")
        
        # Show template content
        print("\nTemplate content:")
        with open(template_file, 'r') as f:
            content = f.read()
            lines = content.split('\n')
            for i, line in enumerate(lines[:10], 1):  # Show first 10 lines
                print(f"  {i:2d}: {line}")
            if len(lines) > 10:
                print(f"  ... ({len(lines) - 10} more lines)")
    
    # Cleanup
    for file_path in [config_file, template_file]:
        if os.path.exists(file_path):
            os.remove(file_path)
            print(f"Cleaned up: {file_path}")
    
    # Clean up backup directory
    backup_dir = Path(config_file).parent / 'backups'
    if backup_dir.exists():
        import shutil
        shutil.rmtree(backup_dir)
        print(f"Cleaned up backup directory: {backup_dir}")


def example_integration():
    """Example: Complete integration with VMware vCenter MCP"""
    print("\n=== Complete Integration Example ===")
    
    # Create integrated configuration manager
    config_file = "/tmp/vmware_vcenter_mcp.yaml"
    config_manager = create_protected_config_manager(
        config_path=config_file,
        use_keyring=True,
        use_vault=False  # Set to True and provide vault_url/vault_token for Vault
    )
    
    # Enterprise configuration
    enterprise_config = {
        "mcp_server": {
            "name": "VMware vCenter MCP Server",
            "version": "1.5.0",
            "host": "0.0.0.0",
            "port": 8080
        },
        "vcenter": {
            "host": "vcenter.enterprise.com",
            "username": "svc-mcp@enterprise.local",
            "password": "EnterprisePassword123!",  # Encrypted
            "ssl_verify": True,
            "timeout": 30
        },
        "security": {
            "encryption_key": "enterprise_encryption_key_2024",  # Encrypted
            "jwt_secret": "jwt_enterprise_secret_key",  # Encrypted
            "session_timeout": 7200,
            "max_sessions_per_user": 5
        },
        "threat_intelligence": {
            "enabled": True,
            "ml_enabled": True,
            "threat_feeds": [
                {
                    "name": "enterprise_feed",
                    "url": "https://threat-intel.enterprise.com/api/v1/feeds",
                    "api_key": "threat_intel_api_key_xyz"  # Encrypted
                }
            ]
        },
        "audit": {
            "enabled": True,
            "destinations": [
                {
                    "type": "siem",
                    "endpoint": "https://siem.enterprise.com/api/events",
                    "api_key": "siem_api_key_abc123"  # Encrypted
                },
                {
                    "type": "file",
                    "path": "/var/log/audit/vmware-mcp-audit.log"
                }
            ]
        },
        "redis": {
            "url": "redis://redis.enterprise.com:6379/0",
            "password": "redis_enterprise_password"  # Encrypted
        }
    }
    
    print("Saving enterprise configuration with encryption...")
    success = config_manager.save_config(enterprise_config)
    print(f"Enterprise config saved: {'✅ Success' if success else '❌ Failed'}")
    
    print("\nLoading enterprise configuration...")
    loaded_config = config_manager.load_config()
    
    if loaded_config:
        print("✅ Enterprise configuration loaded successfully")
        
        # Demonstrate usage in application
        vcenter_config = loaded_config.get('vcenter', {})
        security_config = loaded_config.get('security', {})
        
        print(f"\nConfiguration ready for use:")
        print(f"  vCenter host: {vcenter_config.get('host')}")
        print(f"  vCenter user: {vcenter_config.get('username')}")
        print(f"  Security enabled: {bool(security_config.get('encryption_key'))}")
        print(f"  Session timeout: {security_config.get('session_timeout')} seconds")
        
        # Show that sensitive data is properly decrypted
        if vcenter_config.get('password') == "EnterprisePassword123!":
            print("✅ Sensitive configuration data properly decrypted")
        else:
            print("❌ Configuration decryption issue detected")
    
    # Cleanup
    if os.path.exists(config_file):
        os.remove(config_file)
        print(f"\nCleaned up: {config_file}")


def main():
    """Run all examples"""
    print("VMware vCenter MCP - Enterprise Secrets & Configuration Management Examples")
    print("=" * 80)
    
    try:
        # Run examples
        example_keyring_secrets()
        example_vault_secrets()
        example_encrypted_file_secrets()
        example_config_protection()
        example_integration()
        
        print("\n" + "=" * 80)
        print("✅ All examples completed successfully!")
        print("\nKey Features Demonstrated:")
        print("  • System keyring integration for secure secret storage")
        print("  • HashiCorp Vault integration for enterprise secret management")
        print("  • Encrypted file storage with automatic key management")
        print("  • Configuration file encryption with selective field protection")
        print("  • File permission management and integrity validation")
        print("  • Backup creation and rotation")
        print("  • Template generation for deployment")
        print("  • Complete enterprise integration example")
        
    except Exception as e:
        print(f"\n❌ Example failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()