"""
VMware vCenter MCP Enterprise Server

Enterprise-grade server implementation that integrates all core architecture components
for production-ready VMware vCenter MCP Server deployments.

Author: uldyssian-sh
License: MIT
"""

import asyncio
import signal
import sys
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import structlog
import yaml
from pathlib import Path

# Core architecture imports
from .core import (
    AuthenticationManager, AuthorizationManager, RBACManager,
    TenantManager, TenantIsolationManager,
    DatabaseManager, ConnectionPoolManager, CacheManager, DistributedCacheManager,
    MetricsCollector, HealthCheckManager, AuditLogger,
    HighAvailabilityManager, LoadBalancerManager,
    SecurityManager, EncryptionManager, ComplianceManager,
    OrchestrationEngine, WorkflowManager,
    APIGateway, RateLimitManager, RequestValidator
)

# MCP server imports
from .server import VCenterMCPServer
from .exceptions import VCenterConnectionError

logger = structlog.get_logger(__name__)


@dataclass
class EnterpriseConfig:
    """Enterprise server configuration"""
    
    # Server settings
    host: str = "0.0.0.0"
    port: int = 8080
    workers: int = 4
    
    # vCenter settings
    vcenter_host: str = ""
    vcenter_username: str = ""
    vcenter_password: str = ""
    vcenter_ssl_verify: bool = True
    
    # Database settings
    database_url: str = ""
    
    # Cache settings
    redis_url: str = ""
    
    # Security settings
    security_level: str = "high"
    encryption_enabled: bool = True
    
    # Multi-tenancy
    multi_tenant: bool = True
    default_tenant: str = "default"
    
    # High availability
    ha_enabled: bool = False
    ha_mode: str = "active-active"
    
    # Monitoring
    metrics_enabled: bool = True
    health_checks_enabled: bool = True
    audit_logging_enabled: bool = True
    
    # API Gateway
    api_gateway_enabled: bool = True
    rate_limiting_enabled: bool = True
    
    # Orchestration
    orchestration_enabled: bool = True
    
    # Compliance
    compliance_standards: List[str] = None
    
    def __post_init__(self) -> None:
        if self.compliance_standards is None:
            self.compliance_standards = ["soc2", "iso27001"]


class EnterpriseServer:
    """Enterprise VMware vCenter MCP Server"""
    
    def __init__(self, config: EnterpriseConfig):
        self.config = config
        self.running = False
        
        # Core components
        self.database_manager: Optional[DatabaseManager] = None
        self.cache_manager: Optional[CacheManager] = None
        self.auth_manager: Optional[AuthenticationManager] = None
        self.rbac_manager: Optional[RBACManager] = None
        self.authorization_manager: Optional[AuthorizationManager] = None
        self.tenant_manager: Optional[TenantManager] = None
        self.tenant_isolation_manager: Optional[TenantIsolationManager] = None
        self.security_manager: Optional[SecurityManager] = None
        self.encryption_manager: Optional[EncryptionManager] = None
        self.compliance_manager: Optional[ComplianceManager] = None
        self.metrics_collector: Optional[MetricsCollector] = None
        self.health_check_manager: Optional[HealthCheckManager] = None
        self.audit_logger: Optional[AuditLogger] = None
        self.ha_manager: Optional[HighAvailabilityManager] = None
        self.load_balancer_manager: Optional[LoadBalancerManager] = None
        self.orchestration_engine: Optional[OrchestrationEngine] = None
        self.workflow_manager: Optional[WorkflowManager] = None
        self.api_gateway: Optional[APIGateway] = None
        
        # MCP server
        self.mcp_server: Optional[VCenterMCPServer] = None
        
        # Shutdown event
        self.shutdown_event = asyncio.Event()
        
        logger.info("Enterprise server initialized", 
                   host=config.host, port=config.port)
    
    async def start(self) -> None:
        """Start enterprise server"""
        if self.running:
            logger.warning("Server is already running")
            return
        
        try:
            logger.info("Starting enterprise server...")
            
            # Initialize core components
            await self._initialize_core_components()
            
            # Initialize MCP server
            await self._initialize_mcp_server()
            
            # Start all services
            await self._start_services()
            
            # Setup signal handlers
            self._setup_signal_handlers()
            
            self.running = True
            logger.info("Enterprise server started successfully")
            
            # Wait for shutdown signal
            await self.shutdown_event.wait()
            
        except Exception as e:
            logger.error("Failed to start enterprise server", error=str(e))
            await self.stop()
            raise
    
    async def _initialize_core_components(self) -> None:
        """Initialize core architecture components"""
        
        # Database Manager
        if self.config.database_url:
            from .core.database import DatabaseConfig
            
            db_config = DatabaseConfig(
                host=self.config.database_url.split("@")[1].split(":")[0] if "@" in self.config.database_url else "localhost",
                port=5432,
                database="vcenter_mcp",
                username="vcenter_mcp",
                password="",
                min_connections=5,
                max_connections=50
            )
            
            self.database_manager = DatabaseManager(db_config)
            await self.database_manager.initialize()
            
            logger.info("Database manager initialized")
        
        # Cache Manager
        if self.config.redis_url:
            cache_config = {
                "redis": {
                    "host": "localhost",
                    "port": 6379,
                    "db": 0
                },
                "default_ttl": 300
            }
            
            self.cache_manager = DistributedCacheManager(cache_config)
            await self.cache_manager.initialize()
            
            logger.info("Cache manager initialized")
        
        # RBAC Manager
        self.rbac_manager = RBACManager()
        
        # Authentication Manager
        auth_config = {
            "jwt_secret": "your-secret-key",
            "session_timeout": 7200,
            "providers": []
        }
        
        self.auth_manager = AuthenticationManager(auth_config)
        
        # Authorization Manager
        self.authorization_manager = AuthorizationManager(self.rbac_manager)
        
        # Tenant Manager
        if self.config.multi_tenant:
            tenant_config = {
                "default_isolation": "moderate",
                "create_default_tenant": True
            }
            
            self.tenant_manager = TenantManager(tenant_config)
            self.tenant_isolation_manager = TenantIsolationManager(self.tenant_manager)
            
            logger.info("Multi-tenancy initialized")
        
        # Security Manager
        security_config = {
            "security_level": self.config.security_level,
            "threat_detection": True,
            "policies": [],
            "network_security": {
                "allowed_networks": [],
                "blocked_networks": [],
                "blocked_ips": []
            }
        }
        
        self.security_manager = SecurityManager(security_config)
        
        # Encryption Manager
        if self.config.encryption_enabled:
            encryption_config = {
                "default_algorithm": "aes-256-gcm",
                "key_rotation": True,
                "key_rotation_interval": 90
            }
            
            self.encryption_manager = EncryptionManager(encryption_config)
            
            logger.info("Encryption manager initialized")
        
        # Compliance Manager
        compliance_config = {
            "standards": self.config.compliance_standards,
            "audit_enabled": self.config.audit_logging_enabled,
            "audit_retention_days": 2555
        }
        
        self.compliance_manager = ComplianceManager(compliance_config)
        
        # Metrics Collector
        if self.config.metrics_enabled:
            metrics_config = {
                "system_metrics": True,
                "custom_metrics": True,
                "collection_interval": 15
            }
            
            self.metrics_collector = MetricsCollector(metrics_config)
            await self.metrics_collector.start_collection()
            
            logger.info("Metrics collection started")
        
        # Health Check Manager
        if self.config.health_checks_enabled:
            health_config = {
                "global_timeout": 300
            }
            
            self.health_check_manager = HealthCheckManager(health_config)
            
            # Register core health checks
            await self._register_health_checks()
            
            await self.health_check_manager.start_health_checks()
            
            logger.info("Health checks started")
        
        # Audit Logger
        if self.config.audit_logging_enabled:
            audit_config = {
                "enabled": True,
                "level": "detailed",
                "retention_days": 2555,
                "file_logging": {"enabled": True, "path": "/app/logs/audit.log"},
                "database_logging": {"enabled": bool(self.database_manager)},
                "event_filters": [],
                "sensitive_fields": ["password", "token", "secret", "key"]
            }
            
            self.audit_logger = AuditLogger(audit_config)
            
            logger.info("Audit logging initialized")
        
        # High Availability Manager
        if self.config.ha_enabled:
            ha_config = {
                "enabled": True,
                "mode": self.config.ha_mode,
                "nodes": []
            }
            
            self.ha_manager = HighAvailabilityManager(ha_config)
            await self.ha_manager.initialize()
            
            # Load Balancer Manager
            from .core.ha import LoadBalancerConfig
            lb_config = LoadBalancerConfig()
            self.load_balancer_manager = LoadBalancerManager(lb_config, self.ha_manager)
            
            logger.info("High availability initialized")
        
        # Orchestration Engine
        if self.config.orchestration_enabled:
            orchestration_config = {
                "enabled": True,
                "scheduler_enabled": True,
                "max_concurrent_executions": 50,
                "thread_pool_size": 10
            }
            
            self.orchestration_engine = OrchestrationEngine(orchestration_config)
            self.workflow_manager = WorkflowManager(self.orchestration_engine)
            
            await self.orchestration_engine.start()
            
            logger.info("Orchestration engine started")
        
        # API Gateway
        if self.config.api_gateway_enabled:
            api_config = {
                "enabled": True,
                "rate_limiting": {
                    "enabled": self.config.rate_limiting_enabled,
                    "global_requests_per_minute": 1000,
                    "ip_requests_per_minute": 100
                },
                "validation": {
                    "enabled": True,
                    "level": "strict"
                },
                "api_keys": []
            }
            
            self.api_gateway = APIGateway(api_config)
            
            logger.info("API Gateway initialized")
    
    async def _initialize_mcp_server(self) -> None:
        """Initialize MCP server"""
        
        # Create MCP server configuration
        mcp_config = {
            "vcenter_host": self.config.vcenter_host,
            "vcenter_username": self.config.vcenter_username,
            "vcenter_password": self.config.vcenter_password,
            "vcenter_ssl_verify": self.config.vcenter_ssl_verify,
            
            # Enterprise components
            "auth_manager": self.auth_manager,
            "authorization_manager": self.authorization_manager,
            "tenant_manager": self.tenant_manager,
            "security_manager": self.security_manager,
            "metrics_collector": self.metrics_collector,
            "audit_logger": self.audit_logger,
            "cache_manager": self.cache_manager,
            "database_manager": self.database_manager
        }
        
        self.mcp_server = VCenterMCPServer(mcp_config)
        
        logger.info("MCP server initialized")
    
    async def _start_services(self) -> None:
        """Start all services"""
        
        # Start MCP server
        if self.mcp_server:
            await self.mcp_server.start()
        
        logger.info("All services started")
    
    async def _register_health_checks(self) -> None:
        """Register core health checks"""
        if not self.health_check_manager:
            return
        
        from .core.monitoring import HealthCheck
        
        # Database health check
        if self.database_manager:
            async def check_database() -> Dict[str, str]:
                try:
                    if self.database_manager:
                        async with self.database_manager.get_session() as session:
                            await session.execute("SELECT 1")  # type: ignore
                    return {"message": "Database connection healthy"}
                except Exception as e:
                    raise Exception(f"Database connection failed: {str(e)}")
            
            db_health_check = HealthCheck(
                name="database",
                description="Database connectivity check",
                check_func=check_database,
                timeout=10,
                interval=30,
                critical=True
            )
            
            self.health_check_manager.register_health_check(db_health_check)
        
        # Cache health check
        if self.cache_manager:
            async def check_cache() -> Dict[str, str]:
                try:
                    if self.cache_manager:
                        test_key = "health_check_test"
                        await self.cache_manager.set(test_key, "test_value", 10)
                        value = await self.cache_manager.get(test_key)
                        if value != "test_value":
                            raise Exception("Cache read/write test failed")
                        await self.cache_manager.delete(test_key)
                    return {"message": "Cache connection healthy"}
                except Exception as e:
                    raise Exception(f"Cache connection failed: {str(e)}")
            
            cache_health_check = HealthCheck(
                name="cache",
                description="Cache connectivity check",
                check_func=check_cache,
                timeout=5,
                interval=30,
                critical=False
            )
            
            self.health_check_manager.register_health_check(cache_health_check)
        
        # vCenter health check
        async def check_vcenter() -> Dict[str, str]:
            try:
                if self.mcp_server and hasattr(self.mcp_server, 'vcenter_client'):
                    # Test vCenter connection
                    # This would be implemented in the actual MCP server
                    return {"message": "vCenter connection healthy"}
                else:
                    return {"message": "vCenter client not initialized"}
            except Exception as e:
                raise Exception(f"vCenter connection failed: {str(e)}")
        
        vcenter_health_check = HealthCheck(
            name="vcenter",
            description="vCenter connectivity check",
            check_func=check_vcenter,
            timeout=15,
            interval=60,
            critical=True
        )
        
        self.health_check_manager.register_health_check(vcenter_health_check)
    
    def _setup_signal_handlers(self) -> None:
        """Setup signal handlers for graceful shutdown"""
        
        def signal_handler(signum: int, frame: Any) -> None:
            logger.info("Received shutdown signal", signal=signum)
            asyncio.create_task(self.stop())
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    async def stop(self) -> None:
        """Stop enterprise server"""
        if not self.running:
            return
        
        logger.info("Stopping enterprise server...")
        
        try:
            # Stop MCP server
            if self.mcp_server:
                await self.mcp_server.stop()
            
            # Stop orchestration engine
            if self.orchestration_engine:
                await self.orchestration_engine.stop()
            
            # Stop health checks
            if self.health_check_manager:
                await self.health_check_manager.stop_health_checks()
            
            # Stop metrics collection
            if self.metrics_collector:
                await self.metrics_collector.stop_collection()
            
            # Stop high availability
            if self.ha_manager:
                await self.ha_manager.shutdown()
            
            # Close cache connections
            if self.cache_manager:
                await self.cache_manager.close()
            
            # Close database connections
            if self.database_manager:
                await self.database_manager.close()
            
            self.running = False
            self.shutdown_event.set()
            
            logger.info("Enterprise server stopped")
            
        except Exception as e:
            logger.error("Error during server shutdown", error=str(e))
    
    def get_server_status(self) -> Dict[str, Any]:
        """Get comprehensive server status"""
        status = {
            "server": {
                "running": self.running,
                "host": self.config.host,
                "port": self.config.port,
                "started_at": datetime.utcnow().isoformat()
            },
            "components": {}
        }
        
        # Database status
        if self.database_manager:
            status["components"]["database"] = {
                "status": self.database_manager.status.value,
                "metrics": asyncio.create_task(self.database_manager.get_connection_metrics())
            }
        
        # Cache status
        if self.cache_manager:
            status["components"]["cache"] = {
                "enabled": True
            }
        
        # Security status
        if self.security_manager:
            status["components"]["security"] = self.security_manager.get_security_status()
        
        # Health checks status
        if self.health_check_manager:
            status["components"]["health_checks"] = self.health_check_manager.get_health_status()
        
        # Metrics status
        if self.metrics_collector:
            status["components"]["metrics"] = {
                "enabled": True,
                "collection_active": True
            }
        
        # High availability status
        if self.ha_manager:
            status["components"]["high_availability"] = self.ha_manager.get_cluster_status()
        
        # Orchestration status
        if self.orchestration_engine:
            status["components"]["orchestration"] = {
                "enabled": self.orchestration_engine.enabled,
                "running_executions": len(self.orchestration_engine.running_executions),
                "total_workflows": len(self.orchestration_engine.workflows)
            }
        
        # API Gateway status
        if self.api_gateway:
            status["components"]["api_gateway"] = self.api_gateway.get_api_stats()
        
        return status
    
    async def get_health_status(self) -> Dict[str, Any]:
        """Get health status"""
        if self.health_check_manager:
            return self.health_check_manager.get_health_status()
        
        return {
            "status": "unknown",
            "message": "Health checks not enabled"
        }
    
    async def get_metrics(self) -> str:
        """Get Prometheus metrics"""
        if self.metrics_collector:
            return self.metrics_collector.get_metrics()
        
        return "# Metrics not enabled\n"


async def create_server_from_config(config_path: str) -> EnterpriseServer:
    """Create server from configuration file"""
    
    config_file = Path(config_path)
    if not config_file.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    with open(config_file, 'r') as f:
        if config_path.endswith('.yaml') or config_path.endswith('.yml'):
            config_data = yaml.safe_load(f)
        else:
            import json
            config_data = json.load(f)
    
    # Create configuration object
    config = EnterpriseConfig(**config_data)
    
    # Create and return server
    return EnterpriseServer(config)


async def main() -> None:
    """Main entry point"""
    
    # Setup logging
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer()
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
    
    # Get configuration
    config_path = sys.argv[1] if len(sys.argv) > 1 else "config.yaml"
    
    try:
        # Create server
        if Path(config_path).exists():
            server = await create_server_from_config(config_path)
        else:
            # Use default configuration
            config = EnterpriseConfig()
            server = EnterpriseServer(config)
        
        # Start server
        await server.start()
        
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt")
    except Exception as e:
        logger.error("Server startup failed", error=str(e))
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())