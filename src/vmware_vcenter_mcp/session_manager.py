"""
Enhanced Session Management with Redis Support

Provides persistent session storage and enhanced security features
for enterprise VMware vCenter MCP Server deployments.

Author: uldyssian-sh
License: MIT
"""

import asyncio
import json
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
# Optional imports with graceful fallback
try:
    import redis.asyncio as redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    import warnings
    warnings.warn("Redis not available. Using in-memory session storage.", ImportWarning)

try:
    import structlog
    logger = structlog.get_logger(__name__)
except ImportError:
    import logging
    logger = logging.getLogger(__name__)


@dataclass
class EnhancedAuthSession:
    """Enhanced authentication session with security features"""
    session_id: str
    user_id: str
    tenant_id: Optional[str]
    created_at: datetime
    expires_at: datetime
    last_activity: datetime
    ip_address: str
    user_agent: str
    is_mfa_verified: bool = False
    security_level: str = "standard"
    permissions: List[str] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.permissions is None:
            self.permissions = []
        if self.metadata is None:
            self.metadata = {}


class SessionManager:
    """Enhanced session manager with Redis persistence"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.redis_url = config.get("redis_url", "redis://localhost:6379/0")
        self.session_prefix = "session:"
        self.session_timeout = config.get("session_timeout", 7200)  # 2 hours
        self.max_sessions_per_user = config.get("max_sessions_per_user", 5)
        self.redis_client = None
        
        logger.info("Session manager initialized", 
                   redis_url=self.redis_url,
                   session_timeout=self.session_timeout)
    
    async def initialize(self):
        """Initialize Redis connection"""
        if not REDIS_AVAILABLE:
            logger.warning("Redis not available, using in-memory session storage")
            self.redis_client = None
            self._memory_sessions = {}
            return
            
        try:
            self.redis_client = redis.from_url(self.redis_url)
            await self.redis_client.ping()
            logger.info("Redis connection established")
        except Exception as e:
            logger.error("Failed to connect to Redis", error=str(e))
            # Fallback to in-memory storage
            self.redis_client = None
            self._memory_sessions = {}
    
    async def create_session(self, user_id: str, tenant_id: Optional[str],
                           ip_address: str, user_agent: str,
                           permissions: List[str] = None,
                           security_level: str = "standard") -> EnhancedAuthSession:
        """Create new authenticated session"""
        
        # Check session limits per user
        await self._enforce_session_limits(user_id)
        
        session_id = secrets.token_urlsafe(32)
        now = datetime.utcnow()
        expires_at = now + timedelta(seconds=self.session_timeout)
        
        session = EnhancedAuthSession(
            session_id=session_id,
            user_id=user_id,
            tenant_id=tenant_id,
            created_at=now,
            expires_at=expires_at,
            last_activity=now,
            ip_address=ip_address,
            user_agent=user_agent,
            security_level=security_level,
            permissions=permissions or []
        )
        
        await self._store_session(session)
        
        logger.info("Session created", 
                   session_id=session_id,
                   user_id=user_id,
                   security_level=security_level,
                   expires_at=expires_at.isoformat())
        
        return session
    
    async def get_session(self, session_id: str) -> Optional[EnhancedAuthSession]:
        """Get session by ID"""
        session_data = await self._get_session_data(session_id)
        if not session_data:
            return None
        
        # Check expiration
        expires_at = datetime.fromisoformat(session_data["expires_at"])
        if datetime.utcnow() > expires_at:
            await self.delete_session(session_id)
            return None
        
        # Convert back to session object
        session_data["created_at"] = datetime.fromisoformat(session_data["created_at"])
        session_data["expires_at"] = expires_at
        session_data["last_activity"] = datetime.fromisoformat(session_data["last_activity"])
        
        return EnhancedAuthSession(**session_data)
    
    async def update_session_activity(self, session_id: str) -> bool:
        """Update session last activity"""
        session = await self.get_session(session_id)
        if not session:
            return False
        
        session.last_activity = datetime.utcnow()
        await self._store_session(session)
        return True
    
    async def delete_session(self, session_id: str) -> bool:
        """Delete session"""
        if self.redis_client:
            key = f"{self.session_prefix}{session_id}"
            result = await self.redis_client.delete(key)
            success = result > 0
        else:
            success = self._memory_sessions.pop(session_id, None) is not None
        
        if success:
            logger.info("Session deleted", session_id=session_id)
        
        return success
    
    async def delete_user_sessions(self, user_id: str) -> int:
        """Delete all sessions for a user (GDPR compliance)"""
        deleted_count = 0
        
        if self.redis_client:
            # Get all session keys
            pattern = f"{self.session_prefix}*"
            async for key in self.redis_client.scan_iter(match=pattern):
                session_data = await self.redis_client.get(key)
                if session_data:
                    data = json.loads(session_data)
                    if data.get("user_id") == user_id:
                        await self.redis_client.delete(key)
                        deleted_count += 1
        else:
            # Memory storage
            to_delete = []
            for session_id, session_data in self._memory_sessions.items():
                if session_data.get("user_id") == user_id:
                    to_delete.append(session_id)
            
            for session_id in to_delete:
                del self._memory_sessions[session_id]
                deleted_count += 1
        
        logger.info("User sessions deleted", 
                   user_id=user_id, 
                   deleted_count=deleted_count)
        
        return deleted_count
    
    async def get_user_sessions(self, user_id: str) -> List[EnhancedAuthSession]:
        """Get all active sessions for a user"""
        sessions = []
        
        if self.redis_client:
            pattern = f"{self.session_prefix}*"
            async for key in self.redis_client.scan_iter(match=pattern):
                session_data = await self.redis_client.get(key)
                if session_data:
                    data = json.loads(session_data)
                    if data.get("user_id") == user_id:
                        # Check expiration
                        expires_at = datetime.fromisoformat(data["expires_at"])
                        if datetime.utcnow() <= expires_at:
                            data["created_at"] = datetime.fromisoformat(data["created_at"])
                            data["expires_at"] = expires_at
                            data["last_activity"] = datetime.fromisoformat(data["last_activity"])
                            sessions.append(EnhancedAuthSession(**data))
        else:
            # Memory storage
            for session_data in self._memory_sessions.values():
                if session_data.get("user_id") == user_id:
                    expires_at = datetime.fromisoformat(session_data["expires_at"])
                    if datetime.utcnow() <= expires_at:
                        session_data["created_at"] = datetime.fromisoformat(session_data["created_at"])
                        session_data["expires_at"] = expires_at
                        session_data["last_activity"] = datetime.fromisoformat(session_data["last_activity"])
                        sessions.append(EnhancedAuthSession(**session_data))
        
        return sessions
    
    async def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions"""
        cleaned_count = 0
        now = datetime.utcnow()
        
        if self.redis_client:
            pattern = f"{self.session_prefix}*"
            async for key in self.redis_client.scan_iter(match=pattern):
                session_data = await self.redis_client.get(key)
                if session_data:
                    data = json.loads(session_data)
                    expires_at = datetime.fromisoformat(data["expires_at"])
                    if now > expires_at:
                        await self.redis_client.delete(key)
                        cleaned_count += 1
        else:
            # Memory storage
            to_delete = []
            for session_id, session_data in self._memory_sessions.items():
                expires_at = datetime.fromisoformat(session_data["expires_at"])
                if now > expires_at:
                    to_delete.append(session_id)
            
            for session_id in to_delete:
                del self._memory_sessions[session_id]
                cleaned_count += 1
        
        if cleaned_count > 0:
            logger.info("Expired sessions cleaned", count=cleaned_count)
        
        return cleaned_count
    
    async def _store_session(self, session: EnhancedAuthSession):
        """Store session data"""
        session_data = asdict(session)
        
        # Convert datetime objects to ISO strings
        session_data["created_at"] = session.created_at.isoformat()
        session_data["expires_at"] = session.expires_at.isoformat()
        session_data["last_activity"] = session.last_activity.isoformat()
        
        if self.redis_client:
            key = f"{self.session_prefix}{session.session_id}"
            ttl = int((session.expires_at - datetime.utcnow()).total_seconds())
            await self.redis_client.setex(key, ttl, json.dumps(session_data))
        else:
            # Fallback to memory storage
            self._memory_sessions[session.session_id] = session_data
    
    async def _get_session_data(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session data"""
        if self.redis_client:
            key = f"{self.session_prefix}{session_id}"
            session_data = await self.redis_client.get(key)
            return json.loads(session_data) if session_data else None
        else:
            # Memory storage
            return self._memory_sessions.get(session_id)
    
    async def _enforce_session_limits(self, user_id: str):
        """Enforce maximum sessions per user"""
        user_sessions = await self.get_user_sessions(user_id)
        
        if len(user_sessions) >= self.max_sessions_per_user:
            # Remove oldest session
            oldest_session = min(user_sessions, key=lambda s: s.created_at)
            await self.delete_session(oldest_session.session_id)
            
            logger.warning("Session limit exceeded, removed oldest session",
                          user_id=user_id,
                          removed_session=oldest_session.session_id)
    
    async def get_session_stats(self) -> Dict[str, Any]:
        """Get session statistics"""
        total_sessions = 0
        active_sessions = 0
        now = datetime.utcnow()
        
        if self.redis_client:
            pattern = f"{self.session_prefix}*"
            async for key in self.redis_client.scan_iter(match=pattern):
                total_sessions += 1
                session_data = await self.redis_client.get(key)
                if session_data:
                    data = json.loads(session_data)
                    expires_at = datetime.fromisoformat(data["expires_at"])
                    if now <= expires_at:
                        active_sessions += 1
        else:
            total_sessions = len(self._memory_sessions)
            for session_data in self._memory_sessions.values():
                expires_at = datetime.fromisoformat(session_data["expires_at"])
                if now <= expires_at:
                    active_sessions += 1
        
        return {
            "total_sessions": total_sessions,
            "active_sessions": active_sessions,
            "expired_sessions": total_sessions - active_sessions,
            "session_timeout": self.session_timeout,
            "max_sessions_per_user": self.max_sessions_per_user
        }