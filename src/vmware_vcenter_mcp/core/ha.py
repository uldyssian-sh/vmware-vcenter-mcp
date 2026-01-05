"""
Enterprise High Availability Management

Provides comprehensive high availability, load balancing, and failover capabilities
for enterprise VMware vCenter MCP Server deployments.

Author: uldyssian-sh
License: MIT
"""

import asyncio
import time
import random
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Set
from dataclasses import dataclass, field
from enum import Enum
import json
import uuid
from contextlib import asynccontextmanager
import structlog
import aiohttp
from urllib.parse import urlparse

logger = structlog.get_logger(__name__)


class NodeStatus(Enum):
    """Node status enumeration"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    MAINTENANCE = "maintenance"
    UNKNOWN = "unknown"


class LoadBalancingAlgorithm(Enum):
    """Load balancing algorithms"""
    ROUND_ROBIN = "round_robin"
    WEIGHTED_ROUND_ROBIN = "weighted_round_robin"
    LEAST_CONNECTIONS = "least_connections"
    WEIGHTED_LEAST_CONNECTIONS = "weighted_least_connections"
    IP_HASH = "ip_hash"
    RANDOM = "random"
    HEALTH_BASED = "health_based"


class FailoverStrategy(Enum):
    """Failover strategies"""
    IMMEDIATE = "immediate"
    GRACEFUL = "graceful"
    MANUAL = "manual"


@dataclass
class ServiceNode:
    """Service node representation"""
    id: str
    name: str
    host: str
    port: int
    weight: int = 100
    max_connections: int = 1000
    current_connections: int = 0
    status: NodeStatus = NodeStatus.UNKNOWN
    
    # Health check configuration
    health_check_url: str = "/health"
    health_check_interval: int = 30
    health_check_timeout: int = 10
    health_check_retries: int = 3
    
    # Performance metrics
    response_time_ms: float = 0.0
    error_rate: float = 0.0
    last_health_check: Optional[datetime] = None
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    @property
    def url(self) -> str:
        """Get node base URL"""
        return f"http://{self.host}:{self.port}"
    
    @property
    def health_check_full_url(self) -> str:
        """Get full health check URL"""
        return f"{self.url}{self.health_check_url}"
    
    @property
    def is_available(self) -> bool:
        """Check if node is available for requests"""
        return (self.status in [NodeStatus.HEALTHY, NodeStatus.DEGRADED] and
                self.current_connections < self.max_connections)


@dataclass
class LoadBalancerConfig:
    """Load balancer configuration"""
    algorithm: LoadBalancingAlgorithm = LoadBalancingAlgorithm.ROUND_ROBIN
    health_check_enabled: bool = True
    health_check_interval: int = 30
    failover_strategy: FailoverStrategy = FailoverStrategy.GRACEFUL
    
    # Circuit breaker settings
    circuit_breaker_enabled: bool = True
    failure_threshold: int = 5
    recovery_timeout: int = 60
    
    # Session affinity
    session_affinity: bool = False
    affinity_cookie_name: str = "lb_session"
    affinity_timeout: int = 3600
    
    # Request routing
    max_retries: int = 3
    retry_delay: float = 1.0
    timeout: int = 30


@dataclass
class HealthCheckResult:
    """Health check result"""
    node_id: str
    status: NodeStatus
    response_time_ms: float
    timestamp: datetime
    error: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


class HighAvailabilityManager:
    """Enterprise high availability management"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled = config.get("enabled", True)
        self.mode = config.get("mode", "active-active")  # active-active, active-passive
        
        # Node management
        self.nodes: Dict[str, ServiceNode] = {}
        self.primary_node_id: Optional[str] = None
        
        # Health monitoring
        self.health_check_tasks: Dict[str, asyncio.Task] = {}
        self.health_results: Dict[str, HealthCheckResult] = {}
        
        # Failover management
        self.failover_in_progress = False
        self.failover_callbacks: List[Callable] = []
        
        logger.info("High availability manager initialized", 
                   enabled=self.enabled, mode=self.mode)
    
    async def initialize(self):
        """Initialize HA manager"""
        if not self.enabled:
            return
        
        # Load node configuration
        await self._load_node_configuration()
        
        # Start health monitoring
        await self._start_health_monitoring()
        
        # Determine primary node
        await self._elect_primary_node()
        
        logger.info("High availability manager started", 
                   nodes=len(self.nodes), primary=self.primary_node_id)
    
    async def _load_node_configuration(self):
        """Load node configuration"""
        nodes_config = self.config.get("nodes", [])
        
        for node_config in nodes_config:
            node = ServiceNode(
                id=node_config["id"],
                name=node_config["name"],
                host=node_config["host"],
                port=node_config["port"],
                weight=node_config.get("weight", 100),
                max_connections=node_config.get("max_connections", 1000),
                health_check_url=node_config.get("health_check_url", "/health"),
                health_check_interval=node_config.get("health_check_interval", 30),
                health_check_timeout=node_config.get("health_check_timeout", 10),
                health_check_retries=node_config.get("health_check_retries", 3),
                metadata=node_config.get("metadata", {})
            )
            
            self.nodes[node.id] = node
            logger.info("Node registered", node_id=node.id, 
                       host=node.host, port=node.port)
    
    async def _start_health_monitoring(self):
        """Start health monitoring for all nodes"""
        for node_id, node in self.nodes.items():
            task = asyncio.create_task(self._health_check_loop(node))
            self.health_check_tasks[node_id] = task
        
        logger.info("Health monitoring started", nodes=len(self.nodes))
    
    async def _health_check_loop(self, node: ServiceNode):
        """Health check loop for a node"""
        while True:
            try:
                await self._perform_health_check(node)
                await asyncio.sleep(node.health_check_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Health check loop failed", 
                           node_id=node.id, error=str(e))
                await asyncio.sleep(node.health_check_interval)
    
    async def _perform_health_check(self, node: ServiceNode):
        """Perform health check on a node"""
        start_time = time.time()
        
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=node.health_check_timeout)
            ) as session:
                async with session.get(node.health_check_full_url) as response:
                    response_time_ms = (time.time() - start_time) * 1000
                    
                    if response.status == 200:
                        # Parse health check response
                        try:
                            health_data = await response.json()
                            status = NodeStatus(health_data.get("status", "healthy"))
                        except:
                            status = NodeStatus.HEALTHY
                        
                        result = HealthCheckResult(
                            node_id=node.id,
                            status=status,
                            response_time_ms=response_time_ms,
                            timestamp=datetime.utcnow()
                        )
                    else:
                        result = HealthCheckResult(
                            node_id=node.id,
                            status=NodeStatus.UNHEALTHY,
                            response_time_ms=response_time_ms,
                            timestamp=datetime.utcnow(),
                            error=f"HTTP {response.status}"
                        )
                        
        except asyncio.TimeoutError:
            response_time_ms = (time.time() - start_time) * 1000
            result = HealthCheckResult(
                node_id=node.id,
                status=NodeStatus.UNHEALTHY,
                response_time_ms=response_time_ms,
                timestamp=datetime.utcnow(),
                error="timeout"
            )
            
        except Exception as e:
            response_time_ms = (time.time() - start_time) * 1000
            result = HealthCheckResult(
                node_id=node.id,
                status=NodeStatus.UNHEALTHY,
                response_time_ms=response_time_ms,
                timestamp=datetime.utcnow(),
                error=str(e)
            )
        
        # Update node status
        await self._update_node_status(node, result)
    
    async def _update_node_status(self, node: ServiceNode, result: HealthCheckResult):
        """Update node status based on health check result"""
        previous_status = node.status
        node.status = result.status
        node.response_time_ms = result.response_time_ms
        node.last_health_check = result.timestamp
        
        self.health_results[node.id] = result
        
        # Check for status changes
        if previous_status != node.status:
            logger.info("Node status changed", 
                       node_id=node.id, 
                       previous_status=previous_status.value,
                       new_status=node.status.value)
            
            # Trigger failover if primary node becomes unhealthy
            if (node.id == self.primary_node_id and 
                node.status == NodeStatus.UNHEALTHY):
                await self._trigger_failover()
    
    async def _elect_primary_node(self):
        """Elect primary node"""
        if self.mode == "active-passive":
            # Find the healthiest node with highest weight
            healthy_nodes = [
                node for node in self.nodes.values()
                if node.status in [NodeStatus.HEALTHY, NodeStatus.DEGRADED]
            ]
            
            if healthy_nodes:
                # Sort by weight (descending) and response time (ascending)
                healthy_nodes.sort(
                    key=lambda n: (-n.weight, n.response_time_ms)
                )
                self.primary_node_id = healthy_nodes[0].id
                
                logger.info("Primary node elected", 
                           node_id=self.primary_node_id)
    
    async def _trigger_failover(self):
        """Trigger failover process"""
        if self.failover_in_progress:
            return
        
        self.failover_in_progress = True
        
        try:
            logger.warning("Failover triggered", 
                          primary_node=self.primary_node_id)
            
            # Elect new primary node
            old_primary = self.primary_node_id
            await self._elect_primary_node()
            
            if self.primary_node_id != old_primary:
                logger.info("Failover completed", 
                           old_primary=old_primary,
                           new_primary=self.primary_node_id)
                
                # Execute failover callbacks
                for callback in self.failover_callbacks:
                    try:
                        await callback(old_primary, self.primary_node_id)
                    except Exception as e:
                        logger.error("Failover callback failed", error=str(e))
            
        finally:
            self.failover_in_progress = False
    
    def register_failover_callback(self, callback: Callable):
        """Register failover callback"""
        self.failover_callbacks.append(callback)
    
    def get_primary_node(self) -> Optional[ServiceNode]:
        """Get current primary node"""
        if self.primary_node_id:
            return self.nodes.get(self.primary_node_id)
        return None
    
    def get_healthy_nodes(self) -> List[ServiceNode]:
        """Get all healthy nodes"""
        return [
            node for node in self.nodes.values()
            if node.status in [NodeStatus.HEALTHY, NodeStatus.DEGRADED]
        ]
    
    def get_cluster_status(self) -> Dict[str, Any]:
        """Get cluster status"""
        healthy_nodes = len(self.get_healthy_nodes())
        total_nodes = len(self.nodes)
        
        return {
            "mode": self.mode,
            "primary_node": self.primary_node_id,
            "total_nodes": total_nodes,
            "healthy_nodes": healthy_nodes,
            "unhealthy_nodes": total_nodes - healthy_nodes,
            "failover_in_progress": self.failover_in_progress,
            "nodes": {
                node_id: {
                    "status": node.status.value,
                    "response_time_ms": node.response_time_ms,
                    "current_connections": node.current_connections,
                    "last_health_check": node.last_health_check.isoformat() if node.last_health_check else None
                }
                for node_id, node in self.nodes.items()
            }
        }
    
    async def shutdown(self):
        """Shutdown HA manager"""
        # Cancel health check tasks
        for task in self.health_check_tasks.values():
            task.cancel()
        
        if self.health_check_tasks:
            await asyncio.gather(*self.health_check_tasks.values(), return_exceptions=True)
        
        self.health_check_tasks.clear()
        logger.info("High availability manager shutdown")


class LoadBalancerManager:
    """Enterprise load balancer management"""
    
    def __init__(self, config: LoadBalancerConfig, ha_manager: HighAvailabilityManager):
        self.config = config
        self.ha_manager = ha_manager
        
        # Load balancing state
        self.current_node_index = 0
        self.session_affinity_map: Dict[str, str] = {}
        
        # Circuit breaker state
        self.circuit_breaker_state: Dict[str, Dict[str, Any]] = {}
        
        # Request statistics
        self.request_stats: Dict[str, Dict[str, Any]] = {}
        
        logger.info("Load balancer manager initialized", 
                   algorithm=config.algorithm.value)
    
    async def route_request(self, request_data: Dict[str, Any]) -> Optional[ServiceNode]:
        """Route request to appropriate node"""
        
        # Get available nodes
        available_nodes = self._get_available_nodes()
        
        if not available_nodes:
            logger.error("No available nodes for request routing")
            return None
        
        # Check session affinity
        if self.config.session_affinity:
            session_id = request_data.get("session_id")
            if session_id and session_id in self.session_affinity_map:
                node_id = self.session_affinity_map[session_id]
                node = self.ha_manager.nodes.get(node_id)
                if node and node.is_available:
                    return node
        
        # Apply load balancing algorithm
        selected_node = await self._apply_load_balancing_algorithm(
            available_nodes, request_data
        )
        
        if selected_node:
            # Update session affinity
            if self.config.session_affinity:
                session_id = request_data.get("session_id")
                if session_id:
                    self.session_affinity_map[session_id] = selected_node.id
            
            # Update connection count
            selected_node.current_connections += 1
            
            # Update request statistics
            self._update_request_stats(selected_node.id)
        
        return selected_node
    
    def _get_available_nodes(self) -> List[ServiceNode]:
        """Get available nodes (excluding circuit breaker failures)"""
        available_nodes = []
        
        for node in self.ha_manager.get_healthy_nodes():
            if not node.is_available:
                continue
            
            # Check circuit breaker
            if self.config.circuit_breaker_enabled:
                cb_state = self.circuit_breaker_state.get(node.id, {})
                if cb_state.get("state") == "open":
                    # Check if recovery timeout has passed
                    last_failure = cb_state.get("last_failure")
                    if last_failure:
                        recovery_time = last_failure + timedelta(
                            seconds=self.config.recovery_timeout
                        )
                        if datetime.utcnow() < recovery_time:
                            continue
                        else:
                            # Reset circuit breaker to half-open
                            cb_state["state"] = "half-open"
                            cb_state["failure_count"] = 0
            
            available_nodes.append(node)
        
        return available_nodes
    
    async def _apply_load_balancing_algorithm(self, nodes: List[ServiceNode],
                                            request_data: Dict[str, Any]) -> Optional[ServiceNode]:
        """Apply load balancing algorithm"""
        
        if not nodes:
            return None
        
        if self.config.algorithm == LoadBalancingAlgorithm.ROUND_ROBIN:
            return self._round_robin(nodes)
        
        elif self.config.algorithm == LoadBalancingAlgorithm.WEIGHTED_ROUND_ROBIN:
            return self._weighted_round_robin(nodes)
        
        elif self.config.algorithm == LoadBalancingAlgorithm.LEAST_CONNECTIONS:
            return self._least_connections(nodes)
        
        elif self.config.algorithm == LoadBalancingAlgorithm.WEIGHTED_LEAST_CONNECTIONS:
            return self._weighted_least_connections(nodes)
        
        elif self.config.algorithm == LoadBalancingAlgorithm.IP_HASH:
            return self._ip_hash(nodes, request_data.get("client_ip", ""))
        
        elif self.config.algorithm == LoadBalancingAlgorithm.RANDOM:
            return self._random(nodes)
        
        elif self.config.algorithm == LoadBalancingAlgorithm.HEALTH_BASED:
            return self._health_based(nodes)
        
        else:
            return self._round_robin(nodes)
    
    def _round_robin(self, nodes: List[ServiceNode]) -> ServiceNode:
        """Round robin load balancing"""
        node = nodes[self.current_node_index % len(nodes)]
        self.current_node_index += 1
        return node
    
    def _weighted_round_robin(self, nodes: List[ServiceNode]) -> ServiceNode:
        """Weighted round robin load balancing"""
        # Create weighted list
        weighted_nodes = []
        for node in nodes:
            weighted_nodes.extend([node] * node.weight)
        
        if not weighted_nodes:
            return nodes[0]
        
        node = weighted_nodes[self.current_node_index % len(weighted_nodes)]
        self.current_node_index += 1
        return node
    
    def _least_connections(self, nodes: List[ServiceNode]) -> ServiceNode:
        """Least connections load balancing"""
        return min(nodes, key=lambda n: n.current_connections)
    
    def _weighted_least_connections(self, nodes: List[ServiceNode]) -> ServiceNode:
        """Weighted least connections load balancing"""
        return min(nodes, key=lambda n: n.current_connections / n.weight)
    
    def _ip_hash(self, nodes: List[ServiceNode], client_ip: str) -> ServiceNode:
        """IP hash load balancing"""
        if not client_ip:
            return self._round_robin(nodes)
        
        hash_value = hash(client_ip)
        index = hash_value % len(nodes)
        return nodes[index]
    
    def _random(self, nodes: List[ServiceNode]) -> ServiceNode:
        """Random load balancing"""
        return random.choice(nodes)
    
    def _health_based(self, nodes: List[ServiceNode]) -> ServiceNode:
        """Health-based load balancing (prefer faster nodes)"""
        # Sort by response time and connection count
        sorted_nodes = sorted(
            nodes,
            key=lambda n: (n.response_time_ms, n.current_connections)
        )
        return sorted_nodes[0]
    
    def _update_request_stats(self, node_id: str):
        """Update request statistics"""
        if node_id not in self.request_stats:
            self.request_stats[node_id] = {
                "total_requests": 0,
                "successful_requests": 0,
                "failed_requests": 0,
                "last_request": None
            }
        
        stats = self.request_stats[node_id]
        stats["total_requests"] += 1
        stats["last_request"] = datetime.utcnow()
    
    async def handle_request_completion(self, node_id: str, success: bool):
        """Handle request completion"""
        node = self.ha_manager.nodes.get(node_id)
        if node:
            node.current_connections = max(0, node.current_connections - 1)
        
        # Update statistics
        if node_id in self.request_stats:
            stats = self.request_stats[node_id]
            if success:
                stats["successful_requests"] += 1
                # Reset circuit breaker on success
                if self.config.circuit_breaker_enabled:
                    cb_state = self.circuit_breaker_state.get(node_id, {})
                    if cb_state.get("state") == "half-open":
                        cb_state["state"] = "closed"
                        cb_state["failure_count"] = 0
            else:
                stats["failed_requests"] += 1
                # Update circuit breaker on failure
                await self._update_circuit_breaker(node_id)
    
    async def _update_circuit_breaker(self, node_id: str):
        """Update circuit breaker state"""
        if not self.config.circuit_breaker_enabled:
            return
        
        if node_id not in self.circuit_breaker_state:
            self.circuit_breaker_state[node_id] = {
                "state": "closed",
                "failure_count": 0,
                "last_failure": None
            }
        
        cb_state = self.circuit_breaker_state[node_id]
        cb_state["failure_count"] += 1
        cb_state["last_failure"] = datetime.utcnow()
        
        # Open circuit breaker if threshold exceeded
        if cb_state["failure_count"] >= self.config.failure_threshold:
            cb_state["state"] = "open"
            logger.warning("Circuit breaker opened", 
                          node_id=node_id,
                          failure_count=cb_state["failure_count"])
    
    def get_load_balancer_stats(self) -> Dict[str, Any]:
        """Get load balancer statistics"""
        return {
            "algorithm": self.config.algorithm.value,
            "session_affinity": self.config.session_affinity,
            "circuit_breaker_enabled": self.config.circuit_breaker_enabled,
            "active_sessions": len(self.session_affinity_map),
            "node_stats": self.request_stats,
            "circuit_breaker_state": {
                node_id: {
                    "state": state.get("state", "closed"),
                    "failure_count": state.get("failure_count", 0),
                    "last_failure": state.get("last_failure").isoformat() if state.get("last_failure") else None
                }
                for node_id, state in self.circuit_breaker_state.items()
            }
        }
