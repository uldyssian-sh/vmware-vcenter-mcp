"""
Enterprise Audit Logging System

Provides comprehensive audit logging with multiple destinations,
compliance features, and forensic capabilities.

Author: uldyssian-sh
License: MIT
"""

import asyncio
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
# Optional imports with graceful fallback
try:
    import structlog
    logger = structlog.get_logger(__name__)
except ImportError:
    import logging
    logger = logging.getLogger(__name__)

import uuid
import os


class AuditEventType(Enum):
    """Types of audit events"""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    DATA_ACCESS = "data_access"
    DATA_MODIFICATION = "data_modification"
    SYSTEM_CHANGE = "system_change"
    SECURITY_INCIDENT = "security_incident"
    COMPLIANCE_EVENT = "compliance_event"
    ERROR = "error"
    ADMIN_ACTION = "admin_action"


class AuditSeverity(Enum):
    """Audit event severity levels"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class AuditEvent:
    """Comprehensive audit event record"""
    # Core identification
    event_id: str
    timestamp: datetime
    event_type: AuditEventType
    severity: AuditSeverity
    
    # Actor information
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    tenant_id: Optional[str] = None
    
    # Source information
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    source_system: Optional[str] = None
    
    # Action details
    action: Optional[str] = None
    resource: Optional[str] = None
    resource_type: Optional[str] = None
    
    # Result information
    result: str = "unknown"  # success, failure, error
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    
    # Additional context
    description: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    
    # Compliance and forensics
    compliance_tags: List[str] = field(default_factory=list)
    retention_period: int = 2555  # days (7 years default)
    
    # Security context
    risk_score: int = 0
    threat_indicators: List[str] = field(default_factory=list)
    
    # Correlation
    correlation_id: Optional[str] = None
    parent_event_id: Optional[str] = None


class AuditDestination:
    """Base class for audit destinations"""
    
    async def write_event(self, event: AuditEvent) -> bool:
        """Write audit event to destination"""
        raise NotImplementedError


class FileAuditDestination(AuditDestination):
    """File-based audit destination"""
    
    def __init__(self, config: Dict[str, Any]):
        self.file_path = config.get("path", "/app/logs/audit.log")
        self.rotation = config.get("rotation", "daily")
        self.max_size = config.get("max_size", "100MB")
        self.backup_count = config.get("backup_count", 30)
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(self.file_path), exist_ok=True)
    
    async def write_event(self, event: AuditEvent) -> bool:
        """Write event to file"""
        try:
            event_data = asdict(event)
            event_data["timestamp"] = event.timestamp.isoformat()
            event_data["event_type"] = event.event_type.value
            event_data["severity"] = event.severity.value
            
            log_line = json.dumps(event_data) + "\n"
            
            # In production, implement proper file rotation
            with open(self.file_path, "a", encoding="utf-8") as f:
                f.write(log_line)
            
            return True
            
        except Exception as e:
            logger.error("Failed to write audit event to file", 
                        error=str(e), event_id=event.event_id)
            return False


class DatabaseAuditDestination(AuditDestination):
    """Database audit destination"""
    
    def __init__(self, config: Dict[str, Any]):
        self.connection_string = config.get("connection_string")
        self.table_name = config.get("table", "audit_events")
        # Database connection would be initialized here
    
    async def write_event(self, event: AuditEvent) -> bool:
        """Write event to database"""
        try:
            # In production, implement actual database writing
            # This is a placeholder implementation
            logger.debug("Audit event written to database", 
                        event_id=event.event_id,
                        table=self.table_name)
            return True
            
        except Exception as e:
            logger.error("Failed to write audit event to database", 
                        error=str(e), event_id=event.event_id)
            return False


class SyslogAuditDestination(AuditDestination):
    """Syslog audit destination"""
    
    def __init__(self, config: Dict[str, Any]):
        self.server = config.get("server", "localhost:514")
        self.facility = config.get("facility", "local0")
        # Syslog client would be initialized here
    
    async def write_event(self, event: AuditEvent) -> bool:
        """Write event to syslog"""
        try:
            # In production, implement actual syslog sending
            logger.debug("Audit event sent to syslog", 
                        event_id=event.event_id,
                        server=self.server)
            return True
            
        except Exception as e:
            logger.error("Failed to send audit event to syslog", 
                        error=str(e), event_id=event.event_id)
            return False


class SIEMAuditDestination(AuditDestination):
    """SIEM integration audit destination"""
    
    def __init__(self, config: Dict[str, Any]):
        self.endpoint = config.get("endpoint")
        self.api_key = config.get("api_key")
        self.format = config.get("format", "cef")  # CEF, LEEF, JSON
    
    async def write_event(self, event: AuditEvent) -> bool:
        """Write event to SIEM"""
        try:
            if self.format == "cef":
                cef_message = self._format_cef(event)
            else:
                cef_message = json.dumps(asdict(event))
            
            # In production, send to actual SIEM endpoint
            logger.debug("Audit event sent to SIEM", 
                        event_id=event.event_id,
                        format=self.format)
            return True
            
        except Exception as e:
            logger.error("Failed to send audit event to SIEM", 
                        error=str(e), event_id=event.event_id)
            return False
    
    def _format_cef(self, event: AuditEvent) -> str:
        """Format event as CEF (Common Event Format)"""
        # CEF format: CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]
        cef_header = f"CEF:0|uldyssian-sh|VMware vCenter MCP|1.0|{event.event_type.value}|{event.action or 'Unknown'}|{event.severity.value}"
        
        extensions = []
        if event.source_ip:
            extensions.append(f"src={event.source_ip}")
        if event.user_id:
            extensions.append(f"suser={event.user_id}")
        if event.resource:
            extensions.append(f"fname={event.resource}")
        if event.result:
            extensions.append(f"outcome={event.result}")
        
        cef_extensions = " ".join(extensions)
        return f"{cef_header}|{cef_extensions}"


class EnterpriseAuditLogger:
    """Enterprise audit logging system"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled = config.get("enabled", True)
        self.level = config.get("level", "INFO")
        self.retention_days = config.get("retention_days", 2555)  # 7 years
        
        # Initialize destinations
        self.destinations: List[AuditDestination] = []
        self._init_destinations()
        
        # Event buffer for batch processing
        self.buffer_size = config.get("buffer_size", 100)
        self.buffer_timeout = config.get("buffer_timeout", 30)  # seconds
        self.event_buffer: List[AuditEvent] = []
        self.last_flush = datetime.utcnow()
        
        # Statistics
        self.stats = {
            "events_logged": 0,
            "events_failed": 0,
            "destinations_failed": 0
        }
        
        logger.info("Enterprise audit logger initialized",
                   enabled=self.enabled,
                   destinations=len(self.destinations),
                   retention_days=self.retention_days)
    
    def _init_destinations(self):
        """Initialize audit destinations"""
        destinations_config = self.config.get("destinations", [])
        
        for dest_config in destinations_config:
            dest_type = dest_config.get("type")
            
            if dest_type == "file":
                destination = FileAuditDestination(dest_config)
            elif dest_type == "database":
                destination = DatabaseAuditDestination(dest_config)
            elif dest_type == "syslog":
                destination = SyslogAuditDestination(dest_config)
            elif dest_type == "siem":
                destination = SIEMAuditDestination(dest_config)
            else:
                logger.warning("Unknown audit destination type", type=dest_type)
                continue
            
            self.destinations.append(destination)
            logger.info("Audit destination initialized", type=dest_type)
    
    async def log_event(self, event_type: AuditEventType, severity: AuditSeverity,
                       action: Optional[str] = None, resource: Optional[str] = None,
                       user_id: Optional[str] = None, source_ip: Optional[str] = None,
                       result: str = "unknown", description: Optional[str] = None,
                       details: Optional[Dict[str, Any]] = None,
                       compliance_tags: Optional[List[str]] = None,
                       correlation_id: Optional[str] = None) -> str:
        """Log an audit event"""
        
        if not self.enabled:
            return ""
        
        event_id = str(uuid.uuid4())
        
        event = AuditEvent(
            event_id=event_id,
            timestamp=datetime.utcnow(),
            event_type=event_type,
            severity=severity,
            action=action,
            resource=resource,
            user_id=user_id,
            source_ip=source_ip,
            result=result,
            description=description,
            details=details or {},
            compliance_tags=compliance_tags or [],
            correlation_id=correlation_id
        )
        
        # Calculate risk score
        event.risk_score = self._calculate_risk_score(event)
        
        # Add to buffer
        self.event_buffer.append(event)
        
        # Check if we need to flush
        if (len(self.event_buffer) >= self.buffer_size or 
            (datetime.utcnow() - self.last_flush).seconds >= self.buffer_timeout):
            await self._flush_buffer()
        
        return event_id
    
    async def log_authentication_event(self, user_id: str, source_ip: str,
                                     result: str, method: str = "password",
                                     details: Optional[Dict[str, Any]] = None) -> str:
        """Log authentication event"""
        severity = AuditSeverity.INFO if result == "success" else AuditSeverity.WARNING
        
        return await self.log_event(
            event_type=AuditEventType.AUTHENTICATION,
            severity=severity,
            action=f"login_{method}",
            user_id=user_id,
            source_ip=source_ip,
            result=result,
            description=f"User authentication attempt via {method}",
            details=details,
            compliance_tags=["authentication", "access_control"]
        )
    
    async def log_authorization_event(self, user_id: str, resource: str,
                                    action: str, result: str,
                                    details: Optional[Dict[str, Any]] = None) -> str:
        """Log authorization event"""
        severity = AuditSeverity.WARNING if result == "denied" else AuditSeverity.INFO
        
        return await self.log_event(
            event_type=AuditEventType.AUTHORIZATION,
            severity=severity,
            action=action,
            resource=resource,
            user_id=user_id,
            result=result,
            description=f"Authorization check for {action} on {resource}",
            details=details,
            compliance_tags=["authorization", "access_control"]
        )
    
    async def log_data_access_event(self, user_id: str, resource: str,
                                  action: str, result: str,
                                  details: Optional[Dict[str, Any]] = None) -> str:
        """Log data access event"""
        return await self.log_event(
            event_type=AuditEventType.DATA_ACCESS,
            severity=AuditSeverity.INFO,
            action=action,
            resource=resource,
            user_id=user_id,
            result=result,
            description=f"Data access: {action} on {resource}",
            details=details,
            compliance_tags=["data_access", "gdpr"]
        )
    
    async def log_security_incident(self, title: str, description: str,
                                  severity: AuditSeverity, source_ip: Optional[str] = None,
                                  user_id: Optional[str] = None,
                                  details: Optional[Dict[str, Any]] = None) -> str:
        """Log security incident"""
        return await self.log_event(
            event_type=AuditEventType.SECURITY_INCIDENT,
            severity=severity,
            action="security_incident",
            source_ip=source_ip,
            user_id=user_id,
            result="detected",
            description=f"Security incident: {title} - {description}",
            details=details,
            compliance_tags=["security", "incident_response"]
        )
    
    def _calculate_risk_score(self, event: AuditEvent) -> int:
        """Calculate risk score for event"""
        score = 0
        
        # Base score by event type
        type_scores = {
            AuditEventType.AUTHENTICATION: 10,
            AuditEventType.AUTHORIZATION: 15,
            AuditEventType.DATA_ACCESS: 20,
            AuditEventType.DATA_MODIFICATION: 30,
            AuditEventType.SYSTEM_CHANGE: 40,
            AuditEventType.SECURITY_INCIDENT: 80,
            AuditEventType.ADMIN_ACTION: 50
        }
        score += type_scores.get(event.event_type, 10)
        
        # Severity multiplier
        severity_multipliers = {
            AuditSeverity.INFO: 1.0,
            AuditSeverity.WARNING: 1.5,
            AuditSeverity.ERROR: 2.0,
            AuditSeverity.CRITICAL: 3.0
        }
        score *= severity_multipliers.get(event.severity, 1.0)
        
        # Result modifier
        if event.result == "failure":
            score *= 1.5
        elif event.result == "error":
            score *= 2.0
        
        return int(score)
    
    async def _flush_buffer(self):
        """Flush event buffer to destinations"""
        if not self.event_buffer:
            return
        
        events_to_flush = self.event_buffer.copy()
        self.event_buffer.clear()
        self.last_flush = datetime.utcnow()
        
        # Write to all destinations
        for event in events_to_flush:
            success_count = 0
            
            for destination in self.destinations:
                try:
                    success = await destination.write_event(event)
                    if success:
                        success_count += 1
                    else:
                        self.stats["destinations_failed"] += 1
                except Exception as e:
                    logger.error("Audit destination failed", 
                                destination=type(destination).__name__,
                                error=str(e))
                    self.stats["destinations_failed"] += 1
            
            if success_count > 0:
                self.stats["events_logged"] += 1
            else:
                self.stats["events_failed"] += 1
        
        logger.debug("Audit buffer flushed", 
                    events_count=len(events_to_flush),
                    destinations=len(self.destinations))
    
    async def search_events(self, filters: Dict[str, Any], 
                          limit: int = 100) -> List[AuditEvent]:
        """Search audit events (placeholder implementation)"""
        # In production, implement actual search functionality
        # This would query the audit destinations
        return []
    
    async def generate_compliance_report(self, start_date: datetime,
                                       end_date: datetime,
                                       compliance_standard: str) -> Dict[str, Any]:
        """Generate compliance report"""
        # In production, implement actual report generation
        return {
            "report_period": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat()
            },
            "compliance_standard": compliance_standard,
            "total_events": self.stats["events_logged"],
            "failed_events": self.stats["events_failed"],
            "compliance_status": "compliant"
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get audit logging statistics"""
        return {
            "enabled": self.enabled,
            "destinations_count": len(self.destinations),
            "buffer_size": len(self.event_buffer),
            "events_logged": self.stats["events_logged"],
            "events_failed": self.stats["events_failed"],
            "destinations_failed": self.stats["destinations_failed"],
            "retention_days": self.retention_days
        }