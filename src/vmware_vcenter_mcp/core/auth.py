"""
Enterprise Authentication and Authorization Management

Provides comprehensive authentication, authorization, and role-based access control
for enterprise VMware vCenter MCP Server deployments.

Author: uldyssian-sh
License: MIT
"""

import asyncio
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Any, Union
from dataclasses import dataclass, field
from enum import Enum
import jwt
import ldap3
from passlib.context import CryptContext
from cryptography.fernet import Fernet
import structlog

logger = structlog.get_logger(__name__)


class AuthProvider(Enum):
    """Supported authentication providers"""
    LOCAL = "local"
    LDAP = "ldap"
    ACTIVE_DIRECTORY = "active_directory"
    SAML = "saml"
    OAUTH2 = "oauth2"
    MULTI_FACTOR = "mfa"


class Permission(Enum):
    """Enterprise permission levels"""
    # Datacenter permissions
    DATACENTER_READ = "datacenter:read"
    DATACENTER_CREATE = "datacenter:create"
    DATACENTER_MODIFY = "datacenter:modify"
    DATACENTER_DELETE = "datacenter:delete"
    DATACENTER_ADMIN = "datacenter:*"
    
    # Cluster permissions
    CLUSTER_READ = "cluster:read"
    CLUSTER_CREATE = "cluster:create"
    CLUSTER_MODIFY = "cluster:modify"
    CLUSTER_DELETE = "cluster:delete"
    CLUSTER_ADMIN = "cluster:*"
    
    # VM permissions
    VM_READ = "vm:read"
    VM_CREATE = "vm:create"
    VM_MODIFY = "vm:modify"
    VM_DELETE = "vm:delete"
    VM_POWER = "vm:power"
    VM_SNAPSHOT = "vm:snapshot"
    VM_ADMIN = "vm:*"
    
    # Storage permissions
    STORAGE_READ = "storage:read"
    STORAGE_CREATE = "storage:create"
    STORAGE_MODIFY = "storage:modify"
    STORAGE_DELETE = "storage:delete"
    STORAGE_ADMIN = "storage:*"
    
    # Network permissions
    NETWORK_READ = "network:read"
    NETWORK_CREATE = "network:create"
    NETWORK_MODIFY = "network:modify"
    NETWORK_DELETE = "network:delete"
    NETWORK_ADMIN = "network:*"
    
    # System permissions
    SYSTEM_READ = "system:read"
    SYSTEM_ADMIN = "system:admin"
    AUDIT_READ = "audit:read"
    TENANT_ADMIN = "tenant:admin"


@dataclass
class User:
    """Enterprise user representation"""
    id: str
    username: str
    email: str
    full_name: str
    tenant_id: Optional[str] = None
    roles: Set[str] = field(default_factory=set)
    groups: Set[str] = field(default_factory=set)
    permissions: Set[Permission] = field(default_factory=set)
    is_active: bool = True
    is_admin: bool = False
    last_login: Optional[datetime] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Role:
    """Enterprise role definition"""
    name: str
    description: str
    permissions: Set[Permission]
    tenant_scope: Optional[str] = None
    is_system_role: bool = False
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class AuthSession:
    """Authentication session"""
    session_id: str
    user_id: str
    tenant_id: Optional[str]
    created_at: datetime
    expires_at: datetime
    last_activity: datetime
    ip_address: str
    user_agent: str
    is_mfa_verified: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


class AuthenticationManager:
    """Enterprise authentication manager"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        self.jwt_secret = config.get("jwt_secret", secrets.token_urlsafe(32))
        self.jwt_algorithm = config.get("jwt_algorithm", "HS256")
        self.session_timeout = config.get("session_timeout", 7200)  # 2 hours
        self.max_login_attempts = config.get("max_login_attempts", 5)
        self.lockout_duration = config.get("lockout_duration", 900)  # 15 minutes
        
        # Initialize providers
        self.providers = {}
        self._init_providers()
        
        # Session storage (in production, use Redis or database)
        self.sessions: Dict[str, AuthSession] = {}
        self.failed_attempts: Dict[str, List[datetime]] = {}
        
        logger.info("Authentication manager initialized", 
                   providers=list(self.providers.keys()))
    
    def _init_providers(self):
        """Initialize authentication providers"""
        for provider_config in self.config.get("providers", []):
            provider_type = AuthProvider(provider_config["type"])
            
            if provider_type == AuthProvider.LDAP:
                self.providers[provider_config["name"]] = LDAPProvider(provider_config)
            elif provider_type == AuthProvider.SAML:
                self.providers[provider_config["name"]] = SAMLProvider(provider_config)
            elif provider_type == AuthProvider.OAUTH2:
                self.providers[provider_config["name"]] = OAuth2Provider(provider_config)
    
    async def authenticate(self, username: str, password: str, 
                          provider: str = "local", 
                          ip_address: str = "unknown",
                          user_agent: str = "unknown") -> Optional[AuthSession]:
        """Authenticate user with specified provider"""
        
        # Check for account lockout
        if self._is_account_locked(username):
            logger.warning("Authentication attempt on locked account", 
                          username=username, ip_address=ip_address)
            raise AuthenticationError("Account is temporarily locked")
        
        try:
            # Authenticate with provider
            if provider == "local":
                user = await self._authenticate_local(username, password)
            else:
                auth_provider = self.providers.get(provider)
                if not auth_provider:
                    raise AuthenticationError(f"Unknown provider: {provider}")
                user = await auth_provider.authenticate(username, password)
            
            if not user:
                self._record_failed_attempt(username)
                raise AuthenticationError("Invalid credentials")
            
            # Create session
            session = await self._create_session(user, ip_address, user_agent)
            
            # Clear failed attempts
            self.failed_attempts.pop(username, None)
            
            logger.info("User authenticated successfully", 
                       user_id=user.id, username=username, 
                       provider=provider, ip_address=ip_address)
            
            return session
            
        except Exception as e:
            self._record_failed_attempt(username)
            logger.error("Authentication failed", 
                        username=username, provider=provider, 
                        error=str(e), ip_address=ip_address)
            raise
    
    async def _authenticate_local(self, username: str, password: str) -> Optional[User]:
        """Authenticate against local user store"""
        # In production, query from database
        # This is a simplified implementation
        return None
    
    async def _create_session(self, user: User, ip_address: str, 
                             user_agent: str) -> AuthSession:
        """Create authenticated session"""
        session_id = secrets.token_urlsafe(32)
        now = datetime.utcnow()
        expires_at = now + timedelta(seconds=self.session_timeout)
        
        session = AuthSession(
            session_id=session_id,
            user_id=user.id,
            tenant_id=user.tenant_id,
            created_at=now,
            expires_at=expires_at,
            last_activity=now,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        self.sessions[session_id] = session
        return session
    
    def _is_account_locked(self, username: str) -> bool:
        """Check if account is locked due to failed attempts"""
        attempts = self.failed_attempts.get(username, [])
        if len(attempts) < self.max_login_attempts:
            return False
        
        # Check if lockout period has expired
        latest_attempt = max(attempts)
        lockout_expires = latest_attempt + timedelta(seconds=self.lockout_duration)
        
        if datetime.utcnow() > lockout_expires:
            # Clear expired attempts
            self.failed_attempts.pop(username, None)
            return False
        
        return True
    
    def _record_failed_attempt(self, username: str):
        """Record failed authentication attempt"""
        now = datetime.utcnow()
        if username not in self.failed_attempts:
            self.failed_attempts[username] = []
        
        self.failed_attempts[username].append(now)
        
        # Keep only recent attempts
        cutoff = now - timedelta(seconds=self.lockout_duration)
        self.failed_attempts[username] = [
            attempt for attempt in self.failed_attempts[username]
            if attempt > cutoff
        ]
    
    async def validate_session(self, session_id: str) -> Optional[AuthSession]:
        """Validate and refresh session"""
        session = self.sessions.get(session_id)
        if not session:
            return None
        
        now = datetime.utcnow()
        if now > session.expires_at:
            # Session expired
            self.sessions.pop(session_id, None)
            return None
        
        # Update last activity
        session.last_activity = now
        return session
    
    async def logout(self, session_id: str):
        """Logout user and invalidate session"""
        session = self.sessions.pop(session_id, None)
        if session:
            logger.info("User logged out", 
                       session_id=session_id, user_id=session.user_id)
    
    def generate_jwt_token(self, user: User, session: AuthSession) -> str:
        """Generate JWT token for API access"""
        payload = {
            "user_id": user.id,
            "username": user.username,
            "tenant_id": user.tenant_id,
            "session_id": session.session_id,
            "roles": list(user.roles),
            "permissions": [p.value for p in user.permissions],
            "iat": datetime.utcnow(),
            "exp": session.expires_at
        }
        
        return jwt.encode(payload, self.jwt_secret, algorithm=self.jwt_algorithm)
    
    def verify_jwt_token(self, token: str) -> Dict[str, Any]:
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=[self.jwt_algorithm])
            return payload
        except jwt.ExpiredSignatureError:
            raise AuthenticationError("Token has expired")
        except jwt.InvalidTokenError:
            raise AuthenticationError("Invalid token")


class AuthorizationManager:
    """Enterprise authorization manager"""
    
    def __init__(self, rbac_manager: "RBACManager"):
        self.rbac = rbac_manager
        logger.info("Authorization manager initialized")
    
    async def check_permission(self, user: User, permission: Permission, 
                              resource: Optional[str] = None,
                              tenant_id: Optional[str] = None) -> bool:
        """Check if user has specific permission"""
        
        # System admin has all permissions
        if user.is_admin:
            return True
        
        # Check direct permissions
        if permission in user.permissions:
            return self._check_tenant_scope(user, tenant_id)
        
        # Check role-based permissions
        for role_name in user.roles:
            role = await self.rbac.get_role(role_name)
            if role and permission in role.permissions:
                if self._check_role_scope(role, user.tenant_id, tenant_id):
                    return True
        
        return False
    
    def _check_tenant_scope(self, user: User, required_tenant_id: Optional[str]) -> bool:
        """Check tenant scope for permission"""
        if not required_tenant_id:
            return True
        
        return user.tenant_id == required_tenant_id
    
    def _check_role_scope(self, role: Role, user_tenant_id: Optional[str], 
                         required_tenant_id: Optional[str]) -> bool:
        """Check role scope for permission"""
        if role.is_system_role:
            return True
        
        if role.tenant_scope and role.tenant_scope != user_tenant_id:
            return False
        
        if required_tenant_id and user_tenant_id != required_tenant_id:
            return False
        
        return True
    
    async def get_user_permissions(self, user: User) -> Set[Permission]:
        """Get all permissions for user"""
        permissions = set(user.permissions)
        
        # Add role-based permissions
        for role_name in user.roles:
            role = await self.rbac.get_role(role_name)
            if role:
                permissions.update(role.permissions)
        
        return permissions


class RBACManager:
    """Role-Based Access Control Manager"""
    
    def __init__(self):
        # In production, store in database
        self.roles: Dict[str, Role] = {}
        self._init_system_roles()
        logger.info("RBAC manager initialized")
    
    def _init_system_roles(self):
        """Initialize system roles"""
        
        # Datacenter Administrator
        self.roles["datacenter_admin"] = Role(
            name="datacenter_admin",
            description="Full datacenter administration privileges",
            permissions={
                Permission.DATACENTER_ADMIN,
                Permission.CLUSTER_ADMIN,
                Permission.VM_ADMIN,
                Permission.STORAGE_ADMIN,
                Permission.NETWORK_ADMIN,
                Permission.SYSTEM_READ
            },
            is_system_role=True
        )
        
        # VM Operator
        self.roles["vm_operator"] = Role(
            name="vm_operator",
            description="Virtual machine operations",
            permissions={
                Permission.VM_READ,
                Permission.VM_POWER,
                Permission.VM_SNAPSHOT,
                Permission.VM_MODIFY
            }
        )
        
        # Read Only
        self.roles["read_only"] = Role(
            name="read_only",
            description="Read-only access to all resources",
            permissions={
                Permission.DATACENTER_READ,
                Permission.CLUSTER_READ,
                Permission.VM_READ,
                Permission.STORAGE_READ,
                Permission.NETWORK_READ,
                Permission.SYSTEM_READ
            }
        )
        
        # Tenant Administrator
        self.roles["tenant_admin"] = Role(
            name="tenant_admin",
            description="Tenant administration privileges",
            permissions={
                Permission.DATACENTER_READ,
                Permission.CLUSTER_READ,
                Permission.VM_ADMIN,
                Permission.STORAGE_READ,
                Permission.NETWORK_READ,
                Permission.TENANT_ADMIN
            }
        )
    
    async def create_role(self, role: Role) -> Role:
        """Create new role"""
        if role.name in self.roles:
            raise ValueError(f"Role {role.name} already exists")
        
        self.roles[role.name] = role
        logger.info("Role created", role_name=role.name)
        return role
    
    async def get_role(self, role_name: str) -> Optional[Role]:
        """Get role by name"""
        return self.roles.get(role_name)
    
    async def update_role(self, role_name: str, updates: Dict[str, Any]) -> Role:
        """Update existing role"""
        role = self.roles.get(role_name)
        if not role:
            raise ValueError(f"Role {role_name} not found")
        
        if role.is_system_role:
            raise ValueError("Cannot modify system role")
        
        # Apply updates
        for key, value in updates.items():
            if hasattr(role, key):
                setattr(role, key, value)
        
        logger.info("Role updated", role_name=role_name)
        return role
    
    async def delete_role(self, role_name: str):
        """Delete role"""
        role = self.roles.get(role_name)
        if not role:
            raise ValueError(f"Role {role_name} not found")
        
        if role.is_system_role:
            raise ValueError("Cannot delete system role")
        
        del self.roles[role_name]
        logger.info("Role deleted", role_name=role_name)
    
    async def assign_role_to_user(self, user: User, role_name: str):
        """Assign role to user"""
        role = await self.get_role(role_name)
        if not role:
            raise ValueError(f"Role {role_name} not found")
        
        user.roles.add(role_name)
        logger.info("Role assigned to user", 
                   user_id=user.id, role_name=role_name)
    
    async def revoke_role_from_user(self, user: User, role_name: str):
        """Revoke role from user"""
        user.roles.discard(role_name)
        logger.info("Role revoked from user", 
                   user_id=user.id, role_name=role_name)


class LDAPProvider:
    """LDAP authentication provider"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.server_uri = config["server"]
        self.base_dn = config["base_dn"]
        self.bind_dn = config["bind_dn"]
        self.bind_password = config["bind_password"]
        self.user_filter = config.get("user_filter", "(uid={username})")
        self.group_filter = config.get("group_filter", "(member={user_dn})")
    
    async def authenticate(self, username: str, password: str) -> Optional[User]:
        """Authenticate user against LDAP"""
        try:
            server = ldap3.Server(self.server_uri)
            conn = ldap3.Connection(server, self.bind_dn, self.bind_password)
            
            if not conn.bind():
                logger.error("LDAP bind failed", server=self.server_uri)
                return None
            
            # Search for user
            user_filter = self.user_filter.format(username=username)
            conn.search(self.base_dn, user_filter, attributes=["cn", "mail", "memberOf"])
            
            if not conn.entries:
                return None
            
            user_entry = conn.entries[0]
            user_dn = user_entry.entry_dn
            
            # Verify password
            user_conn = ldap3.Connection(server, user_dn, password)
            if not user_conn.bind():
                return None
            
            # Create user object
            user = User(
                id=f"ldap:{username}",
                username=username,
                email=str(user_entry.mail) if user_entry.mail else f"{username}@example.com",
                full_name=str(user_entry.cn) if user_entry.cn else username
            )
            
            # Get groups
            if user_entry.memberOf:
                user.groups = {str(group) for group in user_entry.memberOf}
            
            return user
            
        except Exception as e:
            logger.error("LDAP authentication failed", 
                        username=username, error=str(e))
            return None


class SAMLProvider:
    """SAML authentication provider"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        # SAML implementation would go here
    
    async def authenticate(self, username: str, password: str) -> Optional[User]:
        """Authenticate user via SAML"""
        # SAML authentication implementation
        return None


class OAuth2Provider:
    """OAuth2 authentication provider"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        # OAuth2 implementation would go here
    
    async def authenticate(self, username: str, password: str) -> Optional[User]:
        """Authenticate user via OAuth2"""
        # OAuth2 authentication implementation
        return None


class AuthenticationError(Exception):
    """Authentication related errors"""
    pass


class AuthorizationError(Exception):
    """Authorization related errors"""
    pass
