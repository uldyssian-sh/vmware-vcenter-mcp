"""
Enterprise API Gateway and Management

Provides comprehensive API gateway, rate limiting, request validation, and API management
for enterprise VMware vCenter MCP Server deployments.

Author: uldyssian-sh
License: MIT
"""

import asyncio
import time
import json
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Set, Union
from dataclasses import dataclass, field
from enum import Enum
import uuid
from urllib.parse import urlparse, parse_qs
import structlog
from pydantic import BaseModel, ValidationError
import aiohttp
from aiohttp import web
import jwt

logger = structlog.get_logger(__name__)


class RateLimitType(Enum):
    """Rate limit types"""
    REQUESTS_PER_SECOND = "requests_per_second"
    REQUESTS_PER_MINUTE = "requests_per_minute"
    REQUESTS_PER_HOUR = "requests_per_hour"
    REQUESTS_PER_DAY = "requests_per_day"
    CONCURRENT_REQUESTS = "concurrent_requests"
    BANDWIDTH = "bandwidth"


class ValidationLevel(Enum):
    """Request validation levels"""
    NONE = "none"
    BASIC = "basic"
    STRICT = "strict"
    ENTERPRISE = "enterprise"


class APIKeyScope(Enum):
    """API key scopes"""
    READ = "read"
    WRITE = "write"
    ADMIN = "admin"
    FULL_ACCESS = "full_access"


@dataclass
class RateLimitRule:
    """Rate limit rule definition"""
    name: str
    limit_type: RateLimitType
    limit_value: int
    window_seconds: int
    scope: str  # "global", "ip", "user", "tenant", "api_key"
    
    # Advanced settings
    burst_limit: Optional[int] = None
    reset_on_success: bool = False
    
    # Exemptions
    exempt_ips: List[str] = field(default_factory=list)
    exempt_users: List[str] = field(default_factory=list)
    exempt_api_keys: List[str] = field(default_factory=list)
    
    # Actions
    block_duration: int = 300  # 5 minutes
    custom_response: Optional[Dict[str, Any]] = None


@dataclass
class APIEndpoint:
    """API endpoint definition"""
    path: str
    methods: List[str]
    handler: Callable
    
    # Authentication and authorization
    auth_required: bool = True
    required_scopes: List[APIKeyScope] = field(default_factory=list)
    required_permissions: List[str] = field(default_factory=list)
    
    # Rate limiting
    rate_limits: List[RateLimitRule] = field(default_factory=list)
    
    # Validation
    validation_level: ValidationLevel = ValidationLevel.BASIC
    request_schema: Optional[BaseModel] = None
    response_schema: Optional[BaseModel] = None
    
    # Caching
    cache_enabled: bool = False
    cache_ttl: int = 300
    cache_key_generator: Optional[Callable] = None
    
    # Metadata
    description: str = ""
    tags: List[str] = field(default_factory=list)
    deprecated: bool = False
    version: str = "1.0.0"


@dataclass
class APIKey:
    """API key representation"""
    id: str
    key: str
    name: str
    scopes: List[APIKeyScope]
    
    # Ownership
    user_id: Optional[str] = None
    tenant_id: Optional[str] = None
    
    # Status
    enabled: bool = True
    
    # Expiration
    expires_at: Optional[datetime] = None
    
    # Usage tracking
    usage_count: int = 0
    last_used: Optional[datetime] = None
    
    # Rate limiting
    rate_limits: List[RateLimitRule] = field(default_factory=list)
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RequestContext:
    """Request context information"""
    request_id: str
    method: str
    path: str
    query_params: Dict[str, Any]
    headers: Dict[str, str]
    body: Optional[bytes] = None
    
    # Client information
    client_ip: str = "unknown"
    user_agent: str = "unknown"
    
    # Authentication
    user_id: Optional[str] = None
    tenant_id: Optional[str] = None
    api_key_id: Optional[str] = None
    session_id: Optional[str] = None
    
    # Timing
    start_time: datetime = field(default_factory=datetime.utcnow)
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)


class APIGateway:
    """Enterprise API Gateway"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled = config.get("enabled", True)
        
        # API endpoints
        self.endpoints: Dict[str, APIEndpoint] = {}
        
        # Rate limiting
        self.rate_limiter = None
        
        # Request validation
        self.request_validator = None
        
        # Middleware
        self.middleware: List[Callable] = []
        
        # API keys
        self.api_keys: Dict[str, APIKey] = {}
        
        # Request tracking
        self.active_requests: Dict[str, RequestContext] = {}
        self.request_history: List[Dict[str, Any]] = []
        
        # Initialize components
        self._init_components()
        
        logger.info("API Gateway initialized", enabled=self.enabled)
    
    def _init_components(self):
        """Initialize API Gateway components"""
        # Initialize rate limiter
        rate_limit_config = self.config.get("rate_limiting", {})
        if rate_limit_config.get("enabled", True):
            self.rate_limiter = RateLimitManager(rate_limit_config)
        
        # Initialize request validator
        validation_config = self.config.get("validation", {})
        if validation_config.get("enabled", True):
            self.request_validator = RequestValidator(validation_config)
        
        # Load API keys
        self._load_api_keys()
    
    def _load_api_keys(self):
        """Load API keys from configuration"""
        api_keys_config = self.config.get("api_keys", [])
        
        for key_config in api_keys_config:
            api_key = APIKey(
                id=key_config["id"],
                key=key_config["key"],
                name=key_config["name"],
                scopes=[APIKeyScope(scope) for scope in key_config.get("scopes", [])],
                user_id=key_config.get("user_id"),
                tenant_id=key_config.get("tenant_id"),
                enabled=key_config.get("enabled", True),
                expires_at=datetime.fromisoformat(key_config["expires_at"]) if key_config.get("expires_at") else None,
                metadata=key_config.get("metadata", {})
            )
            
            self.api_keys[api_key.key] = api_key
            logger.info("API key loaded", key_id=api_key.id, name=api_key.name)
    
    def register_endpoint(self, endpoint: APIEndpoint):
        """Register API endpoint"""
        self.endpoints[endpoint.path] = endpoint
        logger.info("API endpoint registered", 
                   path=endpoint.path, 
                   methods=endpoint.methods)
    
    def add_middleware(self, middleware: Callable):
        """Add middleware function"""
        self.middleware.append(middleware)
        logger.info("Middleware added", middleware=middleware.__name__)
    
    async def handle_request(self, request: web.Request) -> web.Response:
        """Handle incoming API request"""
        request_id = str(uuid.uuid4())
        
        # Create request context
        context = RequestContext(
            request_id=request_id,
            method=request.method,
            path=request.path,
            query_params=dict(request.query),
            headers=dict(request.headers),
            client_ip=request.remote or "unknown",
            user_agent=request.headers.get("User-Agent", "unknown")
        )
        
        # Read request body if present
        if request.can_read_body:
            context.body = await request.read()
        
        self.active_requests[request_id] = context
        
        try:
            # Process request through pipeline
            response = await self._process_request(context, request)
            
            # Log successful request
            self._log_request(context, response.status, None)
            
            return response
            
        except Exception as e:
            # Log failed request
            self._log_request(context, 500, str(e))
            
            # Return error response
            return web.json_response(
                {"error": "Internal server error", "request_id": request_id},
                status=500
            )
            
        finally:
            # Clean up
            self.active_requests.pop(request_id, None)
    
    async def _process_request(self, context: RequestContext, 
                              request: web.Request) -> web.Response:
        """Process request through middleware pipeline"""
        
        # 1. Authentication
        auth_result = await self._authenticate_request(context)
        if not auth_result["success"]:
            return web.json_response(
                {"error": auth_result["error"]},
                status=401
            )
        
        # 2. Rate limiting
        if self.rate_limiter:
            rate_limit_result = await self.rate_limiter.check_rate_limit(context)
            if not rate_limit_result["allowed"]:
                return web.json_response(
                    {"error": "Rate limit exceeded", "retry_after": rate_limit_result.get("retry_after")},
                    status=429
                )
        
        # 3. Request validation
        if self.request_validator:
            validation_result = await self.request_validator.validate_request(context)
            if not validation_result["valid"]:
                return web.json_response(
                    {"error": "Request validation failed", "details": validation_result["errors"]},
                    status=400
                )
        
        # 4. Find endpoint
        endpoint = self._find_endpoint(context.path, context.method)
        if not endpoint:
            return web.json_response(
                {"error": "Endpoint not found"},
                status=404
            )
        
        # 5. Authorization
        auth_check = await self._authorize_request(context, endpoint)
        if not auth_check["authorized"]:
            return web.json_response(
                {"error": auth_check["error"]},
                status=403
            )
        
        # 6. Execute middleware
        for middleware in self.middleware:
            middleware_result = await middleware(context, request)
            if isinstance(middleware_result, web.Response):
                return middleware_result
        
        # 7. Execute endpoint handler
        try:
            response_data = await endpoint.handler(context, request)
            
            if isinstance(response_data, web.Response):
                return response_data
            
            return web.json_response(response_data)
            
        except Exception as e:
            logger.error("Endpoint handler failed", 
                        path=context.path, error=str(e))
            raise
    
    async def _authenticate_request(self, context: RequestContext) -> Dict[str, Any]:
        """Authenticate request"""
        
        # Check for API key in header
        api_key = context.headers.get("X-API-Key") or context.headers.get("Authorization", "").replace("Bearer ", "")
        
        if api_key:
            key_obj = self.api_keys.get(api_key)
            if not key_obj:
                return {"success": False, "error": "Invalid API key"}
            
            if not key_obj.enabled:
                return {"success": False, "error": "API key disabled"}
            
            if key_obj.expires_at and datetime.utcnow() > key_obj.expires_at:
                return {"success": False, "error": "API key expired"}
            
            # Update usage
            key_obj.usage_count += 1
            key_obj.last_used = datetime.utcnow()
            
            # Set context
            context.api_key_id = key_obj.id
            context.user_id = key_obj.user_id
            context.tenant_id = key_obj.tenant_id
            
            return {"success": True, "api_key": key_obj}
        
        # Check for JWT token
        jwt_token = context.headers.get("Authorization", "").replace("Bearer ", "")
        if jwt_token and jwt_token != api_key:
            try:
                # Verify JWT token (simplified)
                payload = jwt.decode(jwt_token, "secret", algorithms=["HS256"])
                
                context.user_id = payload.get("user_id")
                context.tenant_id = payload.get("tenant_id")
                context.session_id = payload.get("session_id")
                
                return {"success": True, "jwt_payload": payload}
                
            except jwt.InvalidTokenError:
                return {"success": False, "error": "Invalid JWT token"}
        
        # No authentication provided
        return {"success": False, "error": "Authentication required"}
    
    async def _authorize_request(self, context: RequestContext, 
                                endpoint: APIEndpoint) -> Dict[str, Any]:
        """Authorize request for endpoint"""
        
        if not endpoint.auth_required:
            return {"authorized": True}
        
        # Check API key scopes
        if context.api_key_id:
            api_key = next(
                (key for key in self.api_keys.values() if key.id == context.api_key_id),
                None
            )
            
            if api_key:
                # Check required scopes
                for required_scope in endpoint.required_scopes:
                    if required_scope not in api_key.scopes:
                        return {
                            "authorized": False,
                            "error": f"Missing required scope: {required_scope.value}"
                        }
        
        # Check permissions (would integrate with RBAC system)
        for required_permission in endpoint.required_permissions:
            # Simplified permission check
            if not await self._check_permission(context.user_id, required_permission):
                return {
                    "authorized": False,
                    "error": f"Missing required permission: {required_permission}"
                }
        
        return {"authorized": True}
    
    async def _check_permission(self, user_id: Optional[str], permission: str) -> bool:
        """Check user permission (simplified)"""
        # In production, integrate with RBAC system
        return True
    
    def _find_endpoint(self, path: str, method: str) -> Optional[APIEndpoint]:
        """Find matching endpoint"""
        for endpoint_path, endpoint in self.endpoints.items():
            if self._path_matches(path, endpoint_path) and method in endpoint.methods:
                return endpoint
        return None
    
    def _path_matches(self, request_path: str, endpoint_path: str) -> bool:
        """Check if request path matches endpoint path pattern"""
        # Simple path matching (can be extended for path parameters)
        return request_path == endpoint_path or request_path.startswith(endpoint_path.rstrip("*"))
    
    def _log_request(self, context: RequestContext, status_code: int, error: Optional[str]):
        """Log request"""
        duration_ms = (datetime.utcnow() - context.start_time).total_seconds() * 1000
        
        log_entry = {
            "request_id": context.request_id,
            "method": context.method,
            "path": context.path,
            "status_code": status_code,
            "duration_ms": duration_ms,
            "client_ip": context.client_ip,
            "user_agent": context.user_agent,
            "user_id": context.user_id,
            "tenant_id": context.tenant_id,
            "api_key_id": context.api_key_id,
            "timestamp": context.start_time.isoformat(),
            "error": error
        }
        
        self.request_history.append(log_entry)
        
        # Keep only recent history
        if len(self.request_history) > 10000:
            self.request_history = self.request_history[-5000:]
        
        if error:
            logger.error("API request failed", **log_entry)
        else:
            logger.info("API request completed", **log_entry)
    
    def get_api_stats(self) -> Dict[str, Any]:
        """Get API statistics"""
        now = datetime.utcnow()
        last_hour = now - timedelta(hours=1)
        
        recent_requests = [
            req for req in self.request_history
            if datetime.fromisoformat(req["timestamp"]) > last_hour
        ]
        
        return {
            "total_endpoints": len(self.endpoints),
            "active_requests": len(self.active_requests),
            "total_api_keys": len(self.api_keys),
            "enabled_api_keys": len([k for k in self.api_keys.values() if k.enabled]),
            "requests_last_hour": len(recent_requests),
            "error_rate_last_hour": len([r for r in recent_requests if r["status_code"] >= 400]) / len(recent_requests) if recent_requests else 0,
            "average_response_time_ms": sum(r["duration_ms"] for r in recent_requests) / len(recent_requests) if recent_requests else 0
        }


class RateLimitManager:
    """Rate limiting management"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled = config.get("enabled", True)
        
        # Rate limit storage (in production, use Redis)
        self.rate_limit_data: Dict[str, Dict[str, Any]] = {}
        
        # Default rules
        self.default_rules = [
            RateLimitRule(
                name="global_requests_per_minute",
                limit_type=RateLimitType.REQUESTS_PER_MINUTE,
                limit_value=config.get("global_requests_per_minute", 1000),
                window_seconds=60,
                scope="global"
            ),
            RateLimitRule(
                name="ip_requests_per_minute",
                limit_type=RateLimitType.REQUESTS_PER_MINUTE,
                limit_value=config.get("ip_requests_per_minute", 100),
                window_seconds=60,
                scope="ip"
            )
        ]
        
        logger.info("Rate limit manager initialized", enabled=self.enabled)
    
    async def check_rate_limit(self, context: RequestContext) -> Dict[str, Any]:
        """Check rate limits for request"""
        if not self.enabled:
            return {"allowed": True}
        
        # Check default rules
        for rule in self.default_rules:
            result = await self._check_rule(rule, context)
            if not result["allowed"]:
                return result
        
        # Check API key specific rules
        if context.api_key_id:
            # Get API key rules (would be loaded from database)
            api_key_rules = []  # Placeholder
            
            for rule in api_key_rules:
                result = await self._check_rule(rule, context)
                if not result["allowed"]:
                    return result
        
        return {"allowed": True}
    
    async def _check_rule(self, rule: RateLimitRule, context: RequestContext) -> Dict[str, Any]:
        """Check individual rate limit rule"""
        
        # Generate key based on scope
        if rule.scope == "global":
            key = "global"
        elif rule.scope == "ip":
            key = f"ip:{context.client_ip}"
        elif rule.scope == "user":
            key = f"user:{context.user_id}" if context.user_id else f"ip:{context.client_ip}"
        elif rule.scope == "tenant":
            key = f"tenant:{context.tenant_id}" if context.tenant_id else f"ip:{context.client_ip}"
        elif rule.scope == "api_key":
            key = f"api_key:{context.api_key_id}" if context.api_key_id else f"ip:{context.client_ip}"
        else:
            key = f"unknown:{context.client_ip}"
        
        # Check exemptions
        if (context.client_ip in rule.exempt_ips or
            context.user_id in rule.exempt_users or
            context.api_key_id in rule.exempt_api_keys):
            return {"allowed": True}
        
        # Get or create rate limit data
        if key not in self.rate_limit_data:
            self.rate_limit_data[key] = {
                "requests": [],
                "blocked_until": None
            }
        
        rate_data = self.rate_limit_data[key]
        now = datetime.utcnow()
        
        # Check if currently blocked
        if rate_data["blocked_until"] and now < rate_data["blocked_until"]:
            return {
                "allowed": False,
                "rule": rule.name,
                "retry_after": int((rate_data["blocked_until"] - now).total_seconds())
            }
        
        # Clean old requests
        cutoff = now - timedelta(seconds=rule.window_seconds)
        rate_data["requests"] = [
            req_time for req_time in rate_data["requests"]
            if req_time > cutoff
        ]
        
        # Check limit
        current_count = len(rate_data["requests"])
        
        if current_count >= rule.limit_value:
            # Rate limit exceeded
            rate_data["blocked_until"] = now + timedelta(seconds=rule.block_duration)
            
            return {
                "allowed": False,
                "rule": rule.name,
                "retry_after": rule.block_duration
            }
        
        # Add current request
        rate_data["requests"].append(now)
        
        return {"allowed": True}
    
    def get_rate_limit_stats(self) -> Dict[str, Any]:
        """Get rate limiting statistics"""
        now = datetime.utcnow()
        
        active_limits = 0
        blocked_clients = 0
        
        for key, data in self.rate_limit_data.items():
            if data["requests"]:
                active_limits += 1
            
            if data["blocked_until"] and now < data["blocked_until"]:
                blocked_clients += 1
        
        return {
            "enabled": self.enabled,
            "active_limits": active_limits,
            "blocked_clients": blocked_clients,
            "total_tracked_clients": len(self.rate_limit_data)
        }


class RequestValidator:
    """Request validation management"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled = config.get("enabled", True)
        self.validation_level = ValidationLevel(config.get("level", "basic"))
        
        # Validation rules
        self.validation_rules = config.get("rules", [])
        
        logger.info("Request validator initialized", 
                   enabled=self.enabled,
                   level=self.validation_level.value)
    
    async def validate_request(self, context: RequestContext) -> Dict[str, Any]:
        """Validate request"""
        if not self.enabled:
            return {"valid": True}
        
        errors = []
        
        # Basic validation
        if self.validation_level in [ValidationLevel.BASIC, ValidationLevel.STRICT, ValidationLevel.ENTERPRISE]:
            basic_errors = await self._basic_validation(context)
            errors.extend(basic_errors)
        
        # Strict validation
        if self.validation_level in [ValidationLevel.STRICT, ValidationLevel.ENTERPRISE]:
            strict_errors = await self._strict_validation(context)
            errors.extend(strict_errors)
        
        # Enterprise validation
        if self.validation_level == ValidationLevel.ENTERPRISE:
            enterprise_errors = await self._enterprise_validation(context)
            errors.extend(enterprise_errors)
        
        return {
            "valid": len(errors) == 0,
            "errors": errors
        }
    
    async def _basic_validation(self, context: RequestContext) -> List[str]:
        """Basic request validation"""
        errors = []
        
        # Check required headers
        required_headers = ["Content-Type", "User-Agent"]
        for header in required_headers:
            if header not in context.headers:
                errors.append(f"Missing required header: {header}")
        
        # Check content type for POST/PUT requests
        if context.method in ["POST", "PUT", "PATCH"]:
            content_type = context.headers.get("Content-Type", "")
            if not content_type.startswith("application/json"):
                errors.append("Invalid content type for request method")
        
        # Check request size
        if context.body and len(context.body) > 10 * 1024 * 1024:  # 10MB
            errors.append("Request body too large")
        
        return errors
    
    async def _strict_validation(self, context: RequestContext) -> List[str]:
        """Strict request validation"""
        errors = []
        
        # Validate JSON body
        if context.body and context.headers.get("Content-Type", "").startswith("application/json"):
            try:
                json.loads(context.body.decode('utf-8'))
            except (json.JSONDecodeError, UnicodeDecodeError):
                errors.append("Invalid JSON in request body")
        
        # Check for suspicious patterns
        suspicious_patterns = [
            r"<script",
            r"javascript:",
            r"onload=",
            r"onerror=",
            r"union\s+select",
            r"drop\s+table"
        ]
        
        request_text = f"{context.path} {json.dumps(context.query_params)} {context.body.decode('utf-8', errors='ignore') if context.body else ''}"
        
        for pattern in suspicious_patterns:
            if re.search(pattern, request_text, re.IGNORECASE):
                errors.append(f"Suspicious pattern detected: {pattern}")
        
        return errors
    
    async def _enterprise_validation(self, context: RequestContext) -> List[str]:
        """Enterprise request validation"""
        errors = []
        
        # Check for required security headers
        security_headers = ["X-Request-ID", "X-Forwarded-For"]
        for header in security_headers:
            if header not in context.headers:
                errors.append(f"Missing security header: {header}")
        
        # Validate API versioning
        if "Accept" in context.headers:
            accept_header = context.headers["Accept"]
            if "application/vnd.api+json" not in accept_header:
                errors.append("Invalid API version in Accept header")
        
        return errors