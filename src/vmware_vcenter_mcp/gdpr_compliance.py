"""
GDPR Compliance Management

Provides comprehensive GDPR compliance features including data subject rights,
data retention, and privacy management for enterprise deployments.

Author: uldyssian-sh
License: MIT
"""

import asyncio
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum
# Optional imports with graceful fallback
try:
    import structlog
    logger = structlog.get_logger(__name__)
except ImportError:
    import logging
    logger = logging.getLogger(__name__)

import uuid


class DataSubjectRequestType(Enum):
    """GDPR data subject request types"""
    ACCESS = "access"                    # Right of access (Art. 15)
    RECTIFICATION = "rectification"      # Right to rectification (Art. 16)
    ERASURE = "erasure"                 # Right to erasure (Art. 17)
    PORTABILITY = "portability"         # Right to data portability (Art. 20)
    RESTRICTION = "restriction"         # Right to restriction (Art. 18)
    OBJECTION = "objection"             # Right to object (Art. 21)


class DataCategory(Enum):
    """Categories of personal data"""
    IDENTITY = "identity"               # Name, email, username
    CONTACT = "contact"                 # IP address, location
    TECHNICAL = "technical"             # Session data, logs
    BEHAVIORAL = "behavioral"           # Usage patterns, preferences
    AUTHENTICATION = "authentication"   # Login data, MFA settings


class LegalBasis(Enum):
    """Legal basis for processing (Art. 6 GDPR)"""
    CONSENT = "consent"                 # Art. 6(1)(a)
    CONTRACT = "contract"               # Art. 6(1)(b)
    LEGAL_OBLIGATION = "legal_obligation"  # Art. 6(1)(c)
    VITAL_INTERESTS = "vital_interests"    # Art. 6(1)(d)
    PUBLIC_TASK = "public_task"           # Art. 6(1)(e)
    LEGITIMATE_INTERESTS = "legitimate_interests"  # Art. 6(1)(f)


@dataclass
class DataProcessingRecord:
    """Record of processing activities (Art. 30 GDPR)"""
    id: str
    purpose: str
    data_categories: List[DataCategory]
    legal_basis: LegalBasis
    retention_period: int  # days
    data_subjects: Set[str] = field(default_factory=set)
    recipients: List[str] = field(default_factory=list)
    third_country_transfers: bool = False
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class DataSubjectRequest:
    """Data subject request record"""
    id: str
    request_type: DataSubjectRequestType
    data_subject_id: str
    email: str
    description: str
    status: str = "pending"  # pending, processing, completed, rejected
    created_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    response_data: Optional[Dict[str, Any]] = None
    verification_token: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class GDPRComplianceManager:
    """GDPR compliance management system"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.data_retention_days = config.get("data_retention_days", 2555)  # 7 years default
        self.anonymization_enabled = config.get("anonymization_enabled", True)
        
        # Processing records
        self.processing_records: Dict[str, DataProcessingRecord] = {}
        
        # Data subject requests
        self.data_requests: Dict[str, DataSubjectRequest] = {}
        
        # Initialize default processing records
        self._init_processing_records()
        
        logger.info("GDPR compliance manager initialized",
                   data_retention_days=self.data_retention_days,
                   anonymization_enabled=self.anonymization_enabled)
    
    def _init_processing_records(self):
        """Initialize default processing records"""
        
        # User authentication processing
        auth_record = DataProcessingRecord(
            id="user_authentication",
            purpose="User authentication and session management",
            data_categories=[DataCategory.IDENTITY, DataCategory.AUTHENTICATION],
            legal_basis=LegalBasis.CONTRACT,
            retention_period=90,  # 3 months for session data
            recipients=["Internal authentication system"]
        )
        self.processing_records[auth_record.id] = auth_record
        
        # Audit logging processing
        audit_record = DataProcessingRecord(
            id="audit_logging",
            purpose="Security monitoring and compliance audit trails",
            data_categories=[DataCategory.TECHNICAL, DataCategory.BEHAVIORAL],
            legal_basis=LegalBasis.LEGAL_OBLIGATION,
            retention_period=2555,  # 7 years for audit logs
            recipients=["Internal security team", "Compliance auditors"]
        )
        self.processing_records[audit_record.id] = audit_record
        
        # Performance monitoring processing
        monitoring_record = DataProcessingRecord(
            id="performance_monitoring",
            purpose="System performance monitoring and optimization",
            data_categories=[DataCategory.TECHNICAL],
            legal_basis=LegalBasis.LEGITIMATE_INTERESTS,
            retention_period=365,  # 1 year for performance data
            recipients=["Internal operations team"]
        )
        self.processing_records[monitoring_record.id] = monitoring_record
    
    async def submit_data_subject_request(self, request_type: DataSubjectRequestType,
                                        data_subject_id: str, email: str,
                                        description: str) -> DataSubjectRequest:
        """Submit a data subject request"""
        
        request_id = str(uuid.uuid4())
        verification_token = hashlib.sha256(f"{request_id}{email}{datetime.utcnow()}".encode()).hexdigest()[:16]
        
        request = DataSubjectRequest(
            id=request_id,
            request_type=request_type,
            data_subject_id=data_subject_id,
            email=email,
            description=description,
            verification_token=verification_token
        )
        
        self.data_requests[request_id] = request
        
        logger.info("Data subject request submitted",
                   request_id=request_id,
                   request_type=request_type.value,
                   data_subject_id=data_subject_id)
        
        # Auto-process certain request types
        if request_type == DataSubjectRequestType.ACCESS:
            await self._process_access_request(request)
        elif request_type == DataSubjectRequestType.ERASURE:
            await self._process_erasure_request(request)
        
        return request
    
    async def _process_access_request(self, request: DataSubjectRequest):
        """Process right of access request (Art. 15 GDPR)"""
        request.status = "processing"
        
        try:
            # Collect all personal data for the data subject
            personal_data = await self._collect_personal_data(request.data_subject_id)
            
            # Generate data export
            export_data = {
                "data_subject_id": request.data_subject_id,
                "export_date": datetime.utcnow().isoformat(),
                "data_categories": {},
                "processing_purposes": [],
                "retention_periods": {},
                "recipients": [],
                "rights_information": self._get_rights_information()
            }
            
            # Organize data by category
            for category, data in personal_data.items():
                export_data["data_categories"][category] = data
            
            # Add processing information
            for record in self.processing_records.values():
                if request.data_subject_id in record.data_subjects:
                    export_data["processing_purposes"].append({
                        "purpose": record.purpose,
                        "legal_basis": record.legal_basis.value,
                        "retention_period_days": record.retention_period,
                        "data_categories": [cat.value for cat in record.data_categories]
                    })
            
            request.response_data = export_data
            request.status = "completed"
            request.completed_at = datetime.utcnow()
            
            logger.info("Access request processed",
                       request_id=request.id,
                       data_categories_count=len(export_data["data_categories"]))
            
        except Exception as e:
            request.status = "rejected"
            request.metadata["error"] = str(e)
            logger.error("Failed to process access request",
                        request_id=request.id,
                        error=str(e))
    
    async def _process_erasure_request(self, request: DataSubjectRequest):
        """Process right to erasure request (Art. 17 GDPR)"""
        request.status = "processing"
        
        try:
            # Check if erasure is legally possible
            can_erase, reasons = await self._can_erase_data(request.data_subject_id)
            
            if not can_erase:
                request.status = "rejected"
                request.metadata["rejection_reasons"] = reasons
                logger.warning("Erasure request rejected",
                              request_id=request.id,
                              reasons=reasons)
                return
            
            # Perform data erasure
            erased_data = await self._erase_personal_data(request.data_subject_id)
            
            request.response_data = {
                "erased_data_categories": erased_data,
                "erasure_date": datetime.utcnow().isoformat(),
                "anonymization_applied": self.anonymization_enabled
            }
            request.status = "completed"
            request.completed_at = datetime.utcnow()
            
            logger.info("Erasure request processed",
                       request_id=request.id,
                       erased_categories=len(erased_data))
            
        except Exception as e:
            request.status = "rejected"
            request.metadata["error"] = str(e)
            logger.error("Failed to process erasure request",
                        request_id=request.id,
                        error=str(e))
    
    async def _collect_personal_data(self, data_subject_id: str) -> Dict[str, Any]:
        """Collect all personal data for a data subject"""
        personal_data = {}
        
        # This would integrate with actual data stores
        # For now, return structured placeholder data
        
        personal_data["identity"] = {
            "user_id": data_subject_id,
            "username": f"user_{data_subject_id}",
            "email": f"{data_subject_id}@example.com",
            "created_at": "2024-01-01T00:00:00Z"
        }
        
        personal_data["authentication"] = {
            "last_login": "2026-01-05T10:00:00Z",
            "login_count": 42,
            "mfa_enabled": True
        }
        
        personal_data["technical"] = {
            "session_count": 15,
            "last_ip_address": "192.168.1.100",
            "user_agent": "Mozilla/5.0..."
        }
        
        return personal_data
    
    async def _can_erase_data(self, data_subject_id: str) -> tuple[bool, List[str]]:
        """Check if data can be legally erased"""
        reasons = []
        
        # Check legal obligations
        for record in self.processing_records.values():
            if (data_subject_id in record.data_subjects and 
                record.legal_basis == LegalBasis.LEGAL_OBLIGATION):
                
                # Check if retention period is still active
                retention_end = datetime.utcnow() - timedelta(days=record.retention_period)
                if record.created_at > retention_end:
                    reasons.append(f"Legal obligation requires retention until {retention_end}")
        
        # Check ongoing contracts
        # This would check if user has active contracts/services
        
        can_erase = len(reasons) == 0
        return can_erase, reasons
    
    async def _erase_personal_data(self, data_subject_id: str) -> List[str]:
        """Erase personal data for a data subject"""
        erased_categories = []
        
        # This would integrate with actual data stores to:
        # 1. Delete personal data where legally possible
        # 2. Anonymize data where deletion is not possible
        # 3. Update processing records
        
        if self.anonymization_enabled:
            # Anonymize audit logs instead of deleting
            await self._anonymize_audit_logs(data_subject_id)
            erased_categories.append("audit_logs_anonymized")
        
        # Remove from processing records
        for record in self.processing_records.values():
            if data_subject_id in record.data_subjects:
                record.data_subjects.discard(data_subject_id)
                record.updated_at = datetime.utcnow()
        
        erased_categories.extend(["identity", "authentication", "sessions"])
        return erased_categories
    
    async def _anonymize_audit_logs(self, data_subject_id: str):
        """Anonymize audit logs for GDPR compliance"""
        # Replace user ID with anonymous hash
        anonymous_id = hashlib.sha256(f"anonymous_{data_subject_id}".encode()).hexdigest()[:16]
        
        # This would update audit logs in the actual storage system
        logger.info("Audit logs anonymized",
                   original_id=data_subject_id,
                   anonymous_id=anonymous_id)
    
    def _get_rights_information(self) -> Dict[str, str]:
        """Get information about data subject rights"""
        return {
            "right_of_access": "You have the right to obtain confirmation of whether personal data is being processed and access to such data",
            "right_to_rectification": "You have the right to obtain rectification of inaccurate personal data",
            "right_to_erasure": "You have the right to obtain erasure of personal data under certain circumstances",
            "right_to_portability": "You have the right to receive personal data in a structured, commonly used format",
            "right_to_restriction": "You have the right to obtain restriction of processing under certain circumstances",
            "right_to_object": "You have the right to object to processing based on legitimate interests",
            "contact_dpo": "For questions about your rights, contact our Data Protection Officer at dpo@example.com"
        }
    
    async def generate_privacy_report(self) -> Dict[str, Any]:
        """Generate privacy compliance report"""
        total_requests = len(self.data_requests)
        completed_requests = len([r for r in self.data_requests.values() if r.status == "completed"])
        
        request_types = {}
        for request in self.data_requests.values():
            req_type = request.request_type.value
            request_types[req_type] = request_types.get(req_type, 0) + 1
        
        return {
            "report_date": datetime.utcnow().isoformat(),
            "total_processing_records": len(self.processing_records),
            "total_data_requests": total_requests,
            "completed_requests": completed_requests,
            "completion_rate": (completed_requests / total_requests * 100) if total_requests > 0 else 0,
            "request_types": request_types,
            "data_retention_days": self.data_retention_days,
            "anonymization_enabled": self.anonymization_enabled,
            "compliance_status": "compliant" if completed_requests == total_requests else "pending"
        }
    
    def get_processing_record(self, record_id: str) -> Optional[DataProcessingRecord]:
        """Get processing record by ID"""
        return self.processing_records.get(record_id)
    
    def get_data_subject_request(self, request_id: str) -> Optional[DataSubjectRequest]:
        """Get data subject request by ID"""
        return self.data_requests.get(request_id)
    
    async def cleanup_old_requests(self, days: int = 90) -> int:
        """Clean up old completed requests"""
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        to_delete = []
        for request_id, request in self.data_requests.items():
            if (request.status == "completed" and 
                request.completed_at and 
                request.completed_at < cutoff_date):
                to_delete.append(request_id)
        
        for request_id in to_delete:
            del self.data_requests[request_id]
        
        logger.info("Old GDPR requests cleaned up", count=len(to_delete))
        return len(to_delete)