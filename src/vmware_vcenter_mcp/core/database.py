"""
Enterprise Database Management

Provides comprehensive database management, connection pooling, and data persistence
for enterprise VMware vCenter MCP Server deployments.

Author: uldyssian-sh
License: MIT
"""

import asyncio
import asyncpg
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, AsyncGenerator
from dataclasses import dataclass, field
from enum import Enum
import json
import uuid
from contextlib import asynccontextmanager
import structlog
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy import Column, String, DateTime, Integer, Boolean, Text, JSON, Index
from sqlalchemy.dialects.postgresql import UUID
import redis.asyncio as redis
from alembic import command
from alembic.config import Config

logger = structlog.get_logger(__name__)

Base = declarative_base()


class ConnectionStatus(Enum):
    """Database connection status"""
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    ERROR = "error"
    RECONNECTING = "reconnecting"


@dataclass
class DatabaseConfig:
    """Database configuration"""
    host: str
    port: int = 5432
    database: str = "vcenter_mcp"
    username: str = "vcenter_mcp"
    password: str = ""
    
    # Connection pool settings
    min_connections: int = 5
    max_connections: int = 50
    max_overflow: int = 100
    pool_timeout: int = 30
    pool_recycle: int = 3600
    
    # SSL settings
    ssl_mode: str = "prefer"
    ssl_cert: Optional[str] = None
    ssl_key: Optional[str] = None
    ssl_ca: Optional[str] = None
    
    # Performance settings
    statement_timeout: int = 300000  # 5 minutes
    idle_in_transaction_timeout: int = 60000  # 1 minute
    
    # High availability
    read_replicas: List[str] = field(default_factory=list)
    auto_failover: bool = True
    health_check_interval: int = 30


@dataclass
class ConnectionMetrics:
    """Connection pool metrics"""
    total_connections: int = 0
    active_connections: int = 0
    idle_connections: int = 0
    waiting_connections: int = 0
    failed_connections: int = 0
    total_queries: int = 0
    slow_queries: int = 0
    last_health_check: Optional[datetime] = None


# Database Models
class TenantModel(Base):
    """Tenant database model"""
    __tablename__ = "tenants"
    
    id = Column(String(255), primary_key=True)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    status = Column(String(50), nullable=False, default="active")
    isolation_level = Column(String(50), nullable=False, default="moderate")
    
    # Configuration as JSON
    quota = Column(JSON)
    config = Column(JSON)
    metadata = Column(JSON)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = Column(String(255))
    
    # Contact info
    contact_email = Column(String(255))
    billing_info = Column(JSON)
    
    __table_args__ = (
        Index("idx_tenant_status", "status"),
        Index("idx_tenant_created_at", "created_at"))


class UserModel(Base):
    """User database model"""
    __tablename__ = "users"
    
    id = Column(String(255), primary_key=True)
    username = Column(String(255), unique=True, nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    full_name = Column(String(255))
    password_hash = Column(String(255))
    
    # Tenant association
    tenant_id = Column(String(255))
    
    # Roles and permissions as JSON arrays
    roles = Column(JSON)
    groups = Column(JSON)
    permissions = Column(JSON)
    
    # Status
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = Column(DateTime)
    
    # Metadata
    metadata = Column(JSON)
    
    __table_args__ = (
        Index("idx_user_username", "username"),
        Index("idx_user_email", "email"),
        Index("idx_user_tenant", "tenant_id"),
        Index("idx_user_active", "is_active"))


class SessionModel(Base):
    """Session database model"""
    __tablename__ = "sessions"
    
    session_id = Column(String(255), primary_key=True)
    user_id = Column(String(255), nullable=False)
    tenant_id = Column(String(255))
    
    # Session data
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    last_activity = Column(DateTime, default=datetime.utcnow)
    
    # Client info
    ip_address = Column(String(45))  # IPv6 compatible
    user_agent = Column(Text)
    
    # Security
    is_mfa_verified = Column(Boolean, default=False)
    
    # Metadata
    metadata = Column(JSON)
    
    __table_args__ = (
        Index("idx_session_user", "user_id"),
        Index("idx_session_expires", "expires_at"),
        Index("idx_session_tenant", "tenant_id"))


class AuditLogModel(Base):
    """Audit log database model"""
    __tablename__ = "audit_logs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Event details
    event_type = Column(String(100), nullable=False)
    event_category = Column(String(50), nullable=False)
    event_description = Column(Text)
    
    # Actor information
    user_id = Column(String(255))
    tenant_id = Column(String(255))
    session_id = Column(String(255))
    
    # Target information
    target_type = Column(String(100))
    target_id = Column(String(255))
    
    # Request details
    ip_address = Column(String(45))
    user_agent = Column(Text)
    request_id = Column(String(255))
    
    # Result
    success = Column(Boolean, nullable=False)
    error_message = Column(Text)
    
    # Additional data
    event_data = Column(JSON)
    
    # Timestamp
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    __table_args__ = (
        Index("idx_audit_timestamp", "timestamp"),
        Index("idx_audit_user", "user_id"),
        Index("idx_audit_tenant", "tenant_id"),
        Index("idx_audit_event_type", "event_type"),
        Index("idx_audit_success", "success"))


class DatabaseManager:
    """Enterprise database manager"""
    
    def __init__(self, config: DatabaseConfig):
        self.config = config
        self.engine = None
        self.session_factory = None
        self.connection_pool = None
        self.metrics = ConnectionMetrics()
        self.status = ConnectionStatus.DISCONNECTED
        
        # Health check task
        self._health_check_task = None
        
        logger.info("Database manager initialized", 
                   host=config.host, database=config.database)
    
    async def initialize(self):
        """Initialize database connection and schema"""
        try:
            # Create async engine
            database_url = self._build_database_url()
            
            self.engine = create_async_engine(
                database_url,
                pool_size=self.config.min_connections,
                max_overflow=self.config.max_overflow,
                pool_timeout=self.config.pool_timeout,
                pool_recycle=self.config.pool_recycle,
                echo=False,  # Set to True for SQL debugging
                connect_args={
                    "server_settings": {
                        "statement_timeout": str(self.config.statement_timeout),
                        "idle_in_transaction_session_timeout": str(self.config.idle_in_transaction_timeout)
                    }
                }
            )
            
            # Create session factory
            self.session_factory = async_sessionmaker(
                self.engine,
                class_=AsyncSession,
                expire_on_commit=False
            )
            
            # Test connection
            await self._test_connection()
            
            # Run migrations
            await self._run_migrations()
            
            # Start health check
            self._health_check_task = asyncio.create_task(self._health_check_loop())
            
            self.status = ConnectionStatus.CONNECTED
            logger.info("Database initialized successfully")
            
        except Exception as e:
            self.status = ConnectionStatus.ERROR
            logger.error("Database initialization failed", error=str(e))
            raise
    
    def _build_database_url(self) -> str:
        """Build database connection URL"""
        url = f"postgresql+asyncpg://{self.config.username}:{self.config.password}@{self.config.host}:{self.config.port}/{self.config.database}"
        
        # Add SSL parameters
        if self.config.ssl_mode != "disable":
            url += f"?sslmode={self.config.ssl_mode}"
            
            if self.config.ssl_cert:
                url += f"&sslcert={self.config.ssl_cert}"
            if self.config.ssl_key:
                url += f"&sslkey={self.config.ssl_key}"
            if self.config.ssl_ca:
                url += f"&sslrootcert={self.config.ssl_ca}"
        
        return url
    
    async def _test_connection(self):
        """Test database connection"""
        async with self.engine.begin() as conn:
            result = await conn.execute("SELECT 1")
            assert result.scalar() == 1
    
    async def _run_migrations(self):
        """Run database migrations"""
        try:
            # Create tables if they don't exist
            async with self.engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            
            logger.info("Database migrations completed")
            
        except Exception as e:
            logger.error("Migration failed", error=str(e))
            raise
    
    async def _health_check_loop(self):
        """Periodic health check loop"""
        while True:
            try:
                await asyncio.sleep(self.config.health_check_interval)
                await self._perform_health_check()
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Health check failed", error=str(e))
                self.status = ConnectionStatus.ERROR
    
    async def _perform_health_check(self):
        """Perform database health check"""
        try:
            async with self.get_session() as session:
                result = await session.execute("SELECT 1")
                assert result.scalar() == 1
            
            self.metrics.last_health_check = datetime.utcnow()
            
            if self.status == ConnectionStatus.ERROR:
                self.status = ConnectionStatus.CONNECTED
                logger.info("Database connection restored")
                
        except Exception as e:
            if self.status == ConnectionStatus.CONNECTED:
                self.status = ConnectionStatus.ERROR
                logger.error("Database health check failed", error=str(e))
            raise
    
    @asynccontextmanager
    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        """Get database session with automatic cleanup"""
        if not self.session_factory:
            raise RuntimeError("Database not initialized")
        
        session = self.session_factory()
        try:
            self.metrics.active_connections += 1
            yield session
            await session.commit()
            
        except Exception:
            await session.rollback()
            raise
            
        finally:
            await session.close()
            self.metrics.active_connections -= 1
    
    async def execute_query(self, query: str, params: Optional[Dict] = None) -> Any:
        """Execute raw SQL query"""
        async with self.get_session() as session:
            result = await session.execute(query, params or {})
            self.metrics.total_queries += 1
            return result
    
    async def get_connection_metrics(self) -> ConnectionMetrics:
        """Get connection pool metrics"""
        if self.engine:
            pool = self.engine.pool
            self.metrics.total_connections = pool.size()
            self.metrics.active_connections = pool.checkedout()
            self.metrics.idle_connections = pool.checkedin()
            self.metrics.waiting_connections = pool.overflow()
        
        return self.metrics
    
    async def close(self):
        """Close database connections"""
        if self._health_check_task:
            self._health_check_task.cancel()
            try:
                await self._health_check_task
            except asyncio.CancelledError:
                pass
        
        if self.engine:
            await self.engine.dispose()
        
        self.status = ConnectionStatus.DISCONNECTED
        logger.info("Database connections closed")


class ConnectionPoolManager:
    """Advanced connection pool management"""
    
    def __init__(self, database_manager: DatabaseManager):
        self.db_manager = database_manager
        self.read_pools: Dict[str, Any] = {}
        self.write_pool = None
        
        logger.info("Connection pool manager initialized")
    
    async def initialize_read_replicas(self):
        """Initialize read replica connections"""
        for replica_url in self.db_manager.config.read_replicas:
            try:
                engine = create_async_engine(
                    replica_url,
                    pool_size=self.db_manager.config.min_connections // 2,
                    max_overflow=self.db_manager.config.max_overflow // 2
                )
                
                # Test connection
                async with engine.begin() as conn:
                    await conn.execute("SELECT 1")
                
                self.read_pools[replica_url] = engine
                logger.info("Read replica connected", replica=replica_url)
                
            except Exception as e:
                logger.error("Failed to connect to read replica", 
                           replica=replica_url, error=str(e))
    
    @asynccontextmanager
    async def get_read_session(self) -> AsyncGenerator[AsyncSession, None]:
        """Get read-only session (uses replica if available)"""
        if self.read_pools:
            # Use read replica
            replica_engine = next(iter(self.read_pools.values()))
            session_factory = async_sessionmaker(replica_engine, class_=AsyncSession)
            session = session_factory()
        else:
            # Fall back to main database
            session = self.db_manager.session_factory()
        
        try:
            yield session
        finally:
            await session.close()
    
    @asynccontextmanager
    async def get_write_session(self) -> AsyncGenerator[AsyncSession, None]:
        """Get write session (always uses primary)"""
        async with self.db_manager.get_session() as session:
            yield session
    
    async def get_pool_status(self) -> Dict[str, Any]:
        """Get status of all connection pools"""
        status = {
            "primary": {
                "status": self.db_manager.status.value,
                "metrics": await self.db_manager.get_connection_metrics()
            },
            "replicas": {}
        }
        
        for replica_url, engine in self.read_pools.items():
            try:
                async with engine.begin() as conn:
                    await conn.execute("SELECT 1")
                status["replicas"][replica_url] = "connected"
            except Exception:
                status["replicas"][replica_url] = "error"
        
        return status


class CacheManager:
    """Enterprise caching management"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.redis_client = None
        self.default_ttl = config.get("default_ttl", 300)  # 5 minutes
        
        logger.info("Cache manager initialized")
    
    async def initialize(self):
        """Initialize cache connections"""
        redis_config = self.config.get("redis", {})
        
        if redis_config.get("cluster_mode", False):
            # Redis Cluster
            from redis.asyncio.cluster import RedisCluster
            
            startup_nodes = [
                {"host": node.split(":")[0], "port": int(node.split(":")[1])}
                for node in redis_config.get("nodes", [])
            ]
            
            self.redis_client = RedisCluster(
                startup_nodes=startup_nodes,
                decode_responses=True,
                skip_full_coverage_check=True
            )
        else:
            # Single Redis instance
            self.redis_client = redis.Redis(
                host=redis_config.get("host", "localhost"),
                port=redis_config.get("port", 6379),
                db=redis_config.get("db", 0),
                password=redis_config.get("password"),
                decode_responses=True
            )
        
        # Test connection
        await self.redis_client.ping()
        logger.info("Cache initialized successfully")
    
    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        try:
            value = await self.redis_client.get(key)
            if value:
                return json.loads(value)
            return None
        except Exception as e:
            logger.error("Cache get failed", key=key, error=str(e))
            return None
    
    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set value in cache"""
        try:
            ttl = ttl or self.default_ttl
            serialized_value = json.dumps(value, default=str)
            await self.redis_client.setex(key, ttl, serialized_value)
            return True
        except Exception as e:
            logger.error("Cache set failed", key=key, error=str(e))
            return False
    
    async def delete(self, key: str) -> bool:
        """Delete value from cache"""
        try:
            result = await self.redis_client.delete(key)
            return result > 0
        except Exception as e:
            logger.error("Cache delete failed", key=key, error=str(e))
            return False
    
    async def exists(self, key: str) -> bool:
        """Check if key exists in cache"""
        try:
            result = await self.redis_client.exists(key)
            return result > 0
        except Exception as e:
            logger.error("Cache exists check failed", key=key, error=str(e))
            return False
    
    async def increment(self, key: str, amount: int = 1) -> Optional[int]:
        """Increment counter in cache"""
        try:
            result = await self.redis_client.incrby(key, amount)
            return result
        except Exception as e:
            logger.error("Cache increment failed", key=key, error=str(e))
            return None
    
    async def expire(self, key: str, ttl: int) -> bool:
        """Set expiration for key"""
        try:
            result = await self.redis_client.expire(key, ttl)
            return result
        except Exception as e:
            logger.error("Cache expire failed", key=key, error=str(e))
            return False
    
    async def flush_pattern(self, pattern: str) -> int:
        """Delete all keys matching pattern"""
        try:
            keys = await self.redis_client.keys(pattern)
            if keys:
                result = await self.redis_client.delete(*keys)
                return result
            return 0
        except Exception as e:
            logger.error("Cache flush pattern failed", pattern=pattern, error=str(e))
            return 0
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        try:
            info = await self.redis_client.info()
            return {
                "connected_clients": info.get("connected_clients", 0),
                "used_memory": info.get("used_memory", 0),
                "used_memory_human": info.get("used_memory_human", "0B"),
                "keyspace_hits": info.get("keyspace_hits", 0),
                "keyspace_misses": info.get("keyspace_misses", 0),
                "total_commands_processed": info.get("total_commands_processed", 0)
            }
        except Exception as e:
            logger.error("Failed to get cache stats", error=str(e))
            return {}
    
    async def close(self):
        """Close cache connections"""
        if self.redis_client:
            await self.redis_client.close()
        logger.info("Cache connections closed")


class DistributedCacheManager(CacheManager):
    """Distributed cache management with advanced features"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.cache_prefix = config.get("prefix", "vcenter_mcp:")
        self.compression_enabled = config.get("compression", False)
    
    def _build_key(self, key: str, tenant_id: Optional[str] = None) -> str:
        """Build cache key with prefix and tenant isolation"""
        if tenant_id:
            return f"{self.cache_prefix}tenant:{tenant_id}:{key}"
        return f"{self.cache_prefix}{key}"
    
    async def get_tenant_cache(self, tenant_id: str, key: str) -> Optional[Any]:
        """Get value from tenant-specific cache"""
        cache_key = self._build_key(key, tenant_id)
        return await self.get(cache_key)
    
    async def set_tenant_cache(self, tenant_id: str, key: str, 
                              value: Any, ttl: Optional[int] = None) -> bool:
        """Set value in tenant-specific cache"""
        cache_key = self._build_key(key, tenant_id)
        return await self.set(cache_key, value, ttl)
    
    async def invalidate_tenant_cache(self, tenant_id: str) -> int:
        """Invalidate all cache entries for tenant"""
        pattern = self._build_key("*", tenant_id)
        return await self.flush_pattern(pattern)
    
    async def cache_with_lock(self, key: str, value: Any, 
                             ttl: Optional[int] = None,
                             lock_timeout: int = 10) -> bool:
        """Set cache value with distributed lock"""
        lock_key = f"{key}:lock"
        
        # Acquire lock
        lock_acquired = await self.redis_client.set(
            lock_key, "locked", nx=True, ex=lock_timeout
        )
        
        if not lock_acquired:
            return False
        
        try:
            # Set the actual value
            result = await self.set(key, value, ttl)
            return result
        finally:
            # Release lock
            await self.delete(lock_key)
    
    async def get_or_compute(self, key: str, compute_func, 
                            ttl: Optional[int] = None) -> Any:
        """Get value from cache or compute and cache it"""
        # Try to get from cache first
        cached_value = await self.get(key)
        if cached_value is not None:
            return cached_value
        
        # Compute value
        computed_value = await compute_func()
        
        # Cache the computed value
        await self.set(key, computed_value, ttl)
        
        return computed_value
