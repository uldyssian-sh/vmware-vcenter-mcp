"""
Advanced Threat Intelligence and Detection System

Provides ML-based threat detection, behavioral analysis, and real-time
threat intelligence integration for enterprise security.

Author: uldyssian-sh
License: MIT
"""

import asyncio
import json
import hashlib
import statistics
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import structlog
import re
import ipaddress
from collections import defaultdict, deque
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import requests

logger = structlog.get_logger(__name__)


class ThreatLevel(Enum):
    """Threat severity levels"""
    BENIGN = "benign"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatCategory(Enum):
    """Categories of threats"""
    BRUTE_FORCE = "brute_force"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    DDOS = "ddos"
    MALWARE = "malware"
    PHISHING = "phishing"
    INSIDER_THREAT = "insider_threat"
    APT = "apt"  # Advanced Persistent Threat
    ZERO_DAY = "zero_day"


@dataclass
class ThreatIndicator:
    """Threat indicator record"""
    indicator_type: str  # ip, domain, hash, pattern
    value: str
    threat_level: ThreatLevel
    category: ThreatCategory
    confidence: float  # 0.0 - 1.0
    source: str
    first_seen: datetime
    last_seen: datetime
    description: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BehavioralProfile:
    """User behavioral profile for anomaly detection"""
    user_id: str
    login_times: List[int] = field(default_factory=list)  # Hours of day
    login_locations: Set[str] = field(default_factory=set)  # IP addresses
    request_patterns: Dict[str, int] = field(default_factory=dict)  # Endpoint counts
    session_durations: List[int] = field(default_factory=list)  # Minutes
    failed_attempts: int = 0
    risk_score: float = 0.0
    last_updated: datetime = field(default_factory=datetime.utcnow)


@dataclass
class ThreatEvent:
    """Detected threat event"""
    event_id: str
    timestamp: datetime
    threat_level: ThreatLevel
    category: ThreatCategory
    confidence: float
    source_ip: Optional[str]
    user_id: Optional[str]
    description: str
    indicators: List[ThreatIndicator]
    risk_score: float
    recommended_actions: List[str]
    metadata: Dict[str, Any] = field(default_factory=dict)


class ThreatIntelligenceManager:
    """Advanced threat intelligence and detection system"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled = config.get("enabled", True)
        
        # Threat intelligence feeds
        self.threat_feeds = config.get("threat_feeds", [])
        self.indicators: Dict[str, ThreatIndicator] = {}
        
        # Behavioral analysis
        self.behavioral_profiles: Dict[str, BehavioralProfile] = {}
        self.anomaly_detector = None
        self.scaler = StandardScaler()
        
        # ML models
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.model_trained = False
        
        # Threat patterns
        self.threat_patterns = self._init_threat_patterns()
        
        # Statistics
        self.stats = {
            "threats_detected": 0,
            "false_positives": 0,
            "indicators_loaded": 0,
            "behavioral_anomalies": 0
        }
        
        logger.info("Threat intelligence manager initialized",
                   enabled=self.enabled,
                   threat_feeds=len(self.threat_feeds))
    
    def _init_threat_patterns(self) -> Dict[ThreatCategory, List[Dict[str, Any]]]:
        """Initialize threat detection patterns"""
        return {
            ThreatCategory.SQL_INJECTION: [
                {
                    "pattern": r"(?i)(union|select|insert|update|delete|drop|create|alter)\s+",
                    "confidence": 0.8,
                    "description": "SQL injection keywords detected"
                },
                {
                    "pattern": r"(?i)(\'\s*(or|and)\s*\'\s*=\s*\'|\'\s*(or|and)\s*1\s*=\s*1)",
                    "confidence": 0.9,
                    "description": "SQL injection boolean logic detected"
                }
            ],
            ThreatCategory.XSS: [
                {
                    "pattern": r"(?i)<script[^>]*>.*?</script>",
                    "confidence": 0.9,
                    "description": "Script tag injection detected"
                },
                {
                    "pattern": r"(?i)(javascript:|onload=|onerror=|onclick=)",
                    "confidence": 0.7,
                    "description": "JavaScript event handler injection detected"
                }
            ],
            ThreatCategory.COMMAND_INJECTION: [
                {
                    "pattern": r"(?i)(;|\||\&\&|\|\|)\s*(cat|ls|pwd|whoami|id|uname)",
                    "confidence": 0.8,
                    "description": "Command injection attempt detected"
                },
                {
                    "pattern": r"(?i)(`|\$\(|\$\{).*(\)|`|\})",
                    "confidence": 0.7,
                    "description": "Command substitution detected"
                }
            ],
            ThreatCategory.PATH_TRAVERSAL: [
                {
                    "pattern": r"(?i)(\.\./|\.\.\\\|%2e%2e%2f|%2e%2e%5c)",
                    "confidence": 0.8,
                    "description": "Path traversal attempt detected"
                }
            ]
        }
    
    async def analyze_request(self, request_data: Dict[str, Any]) -> ThreatEvent:
        """Analyze request for threats using ML and pattern matching"""
        if not self.enabled:
            return None
        
        threats_detected = []
        total_risk_score = 0.0
        
        # Pattern-based detection
        pattern_threats = await self._pattern_based_detection(request_data)
        threats_detected.extend(pattern_threats)
        
        # Behavioral analysis
        if request_data.get("user_id"):
            behavioral_threat = await self._behavioral_analysis(request_data)
            if behavioral_threat:
                threats_detected.append(behavioral_threat)
        
        # IP reputation check
        if request_data.get("source_ip"):
            ip_threat = await self._ip_reputation_check(request_data["source_ip"])
            if ip_threat:
                threats_detected.append(ip_threat)
        
        # ML-based anomaly detection
        ml_threat = await self._ml_anomaly_detection(request_data)
        if ml_threat:
            threats_detected.append(ml_threat)
        
        if not threats_detected:
            return None
        
        # Calculate overall threat level and risk score
        threat_level = max(threat.threat_level for threat in threats_detected)
        total_risk_score = sum(threat.confidence * 100 for threat in threats_detected)
        
        # Create threat event
        threat_event = ThreatEvent(
            event_id=hashlib.sha256(f"{datetime.utcnow()}{request_data}".encode()).hexdigest()[:16],
            timestamp=datetime.utcnow(),
            threat_level=threat_level,
            category=threats_detected[0].category,  # Primary category
            confidence=max(threat.confidence for threat in threats_detected),
            source_ip=request_data.get("source_ip"),
            user_id=request_data.get("user_id"),
            description=f"Multiple threats detected: {len(threats_detected)} indicators",
            indicators=threats_detected,
            risk_score=min(total_risk_score, 100.0),
            recommended_actions=self._generate_recommendations(threats_detected)
        )
        
        self.stats["threats_detected"] += 1
        
        logger.warning("Threat detected",
                      event_id=threat_event.event_id,
                      threat_level=threat_level.value,
                      risk_score=threat_event.risk_score,
                      indicators_count=len(threats_detected))
        
        return threat_event
    
    async def _pattern_based_detection(self, request_data: Dict[str, Any]) -> List[ThreatIndicator]:
        """Detect threats using pattern matching"""
        threats = []
        
        # Combine all request data for analysis
        content = " ".join([
            str(request_data.get("url", "")),
            str(request_data.get("headers", {})),
            str(request_data.get("body", "")),
            str(request_data.get("query_params", {}))
        ]).lower()
        
        for category, patterns in self.threat_patterns.items():
            for pattern_info in patterns:
                if re.search(pattern_info["pattern"], content):
                    threat = ThreatIndicator(
                        indicator_type="pattern",
                        value=pattern_info["pattern"],
                        threat_level=self._calculate_threat_level(pattern_info["confidence"]),
                        category=category,
                        confidence=pattern_info["confidence"],
                        source="pattern_detection",
                        first_seen=datetime.utcnow(),
                        last_seen=datetime.utcnow(),
                        description=pattern_info["description"]
                    )
                    threats.append(threat)
        
        return threats
    
    async def _behavioral_analysis(self, request_data: Dict[str, Any]) -> Optional[ThreatIndicator]:
        """Analyze user behavior for anomalies"""
        user_id = request_data.get("user_id")
        if not user_id:
            return None
        
        # Get or create behavioral profile
        if user_id not in self.behavioral_profiles:
            self.behavioral_profiles[user_id] = BehavioralProfile(user_id=user_id)
        
        profile = self.behavioral_profiles[user_id]
        current_time = datetime.utcnow()
        
        # Update profile with current request
        profile.login_times.append(current_time.hour)
        if request_data.get("source_ip"):
            profile.login_locations.add(request_data["source_ip"])
        
        endpoint = request_data.get("endpoint", "unknown")
        profile.request_patterns[endpoint] = profile.request_patterns.get(endpoint, 0) + 1
        profile.last_updated = current_time
        
        # Detect anomalies
        anomaly_score = 0.0
        
        # Time-based anomaly (unusual login hours)
        if len(profile.login_times) > 10:
            avg_hour = statistics.mean(profile.login_times[-10:])
            if abs(current_time.hour - avg_hour) > 6:  # More than 6 hours difference
                anomaly_score += 0.3
        
        # Location-based anomaly (new IP address)
        if len(profile.login_locations) > 5 and request_data.get("source_ip"):
            recent_ips = list(profile.login_locations)[-5:]
            if request_data["source_ip"] not in recent_ips:
                anomaly_score += 0.4
        
        # Frequency anomaly (unusual request patterns)
        if len(profile.request_patterns) > 0:
            avg_requests = statistics.mean(profile.request_patterns.values())
            current_requests = profile.request_patterns.get(endpoint, 0)
            if current_requests > avg_requests * 3:  # 3x more than average
                anomaly_score += 0.5
        
        profile.risk_score = anomaly_score
        
        if anomaly_score > 0.6:  # Threshold for behavioral anomaly
            self.stats["behavioral_anomalies"] += 1
            
            return ThreatIndicator(
                indicator_type="behavioral",
                value=f"user_behavior_{user_id}",
                threat_level=self._calculate_threat_level(anomaly_score),
                category=ThreatCategory.INSIDER_THREAT,
                confidence=anomaly_score,
                source="behavioral_analysis",
                first_seen=current_time,
                last_seen=current_time,
                description=f"Behavioral anomaly detected for user {user_id}",
                metadata={"anomaly_score": anomaly_score, "profile": profile.__dict__}
            )
        
        return None
    
    async def _ip_reputation_check(self, ip_address: str) -> Optional[ThreatIndicator]:
        """Check IP address against threat intelligence feeds"""
        # Check local indicators first
        ip_indicator = self.indicators.get(f"ip:{ip_address}")
        if ip_indicator:
            return ip_indicator
        
        # Check if IP is in known malicious ranges
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            
            # Check against known malicious networks
            malicious_networks = [
                "10.0.0.0/8",      # Private networks (suspicious for external access)
                "172.16.0.0/12",   # Private networks
                "192.168.0.0/16"   # Private networks
            ]
            
            for network in malicious_networks:
                if ip_obj in ipaddress.ip_network(network):
                    return ThreatIndicator(
                        indicator_type="ip",
                        value=ip_address,
                        threat_level=ThreatLevel.MEDIUM,
                        category=ThreatCategory.APT,
                        confidence=0.6,
                        source="network_analysis",
                        first_seen=datetime.utcnow(),
                        last_seen=datetime.utcnow(),
                        description=f"IP {ip_address} in suspicious network range"
                    )
        
        except ValueError:
            # Invalid IP address
            return ThreatIndicator(
                indicator_type="ip",
                value=ip_address,
                threat_level=ThreatLevel.HIGH,
                category=ThreatCategory.MALWARE,
                confidence=0.8,
                source="ip_validation",
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                description=f"Invalid IP address format: {ip_address}"
            )
        
        return None
    
    async def _ml_anomaly_detection(self, request_data: Dict[str, Any]) -> Optional[ThreatIndicator]:
        """Use ML models for anomaly detection"""
        if not self.model_trained:
            return None
        
        try:
            # Extract features from request
            features = self._extract_features(request_data)
            
            # Normalize features
            features_scaled = self.scaler.transform([features])
            
            # Predict anomaly
            anomaly_score = self.isolation_forest.decision_function(features_scaled)[0]
            is_anomaly = self.isolation_forest.predict(features_scaled)[0] == -1
            
            if is_anomaly and anomaly_score < -0.1:  # Threshold for anomaly
                confidence = min(abs(anomaly_score), 1.0)
                
                return ThreatIndicator(
                    indicator_type="ml_anomaly",
                    value=f"request_anomaly_{hashlib.sha256(str(features).encode()).hexdigest()[:8]}",
                    threat_level=self._calculate_threat_level(confidence),
                    category=ThreatCategory.APT,
                    confidence=confidence,
                    source="ml_detection",
                    first_seen=datetime.utcnow(),
                    last_seen=datetime.utcnow(),
                    description=f"ML-based anomaly detected (score: {anomaly_score:.3f})",
                    metadata={"anomaly_score": anomaly_score, "features": features}
                )
        
        except Exception as e:
            logger.error("ML anomaly detection failed", error=str(e))
        
        return None
    
    def _extract_features(self, request_data: Dict[str, Any]) -> List[float]:
        """Extract numerical features from request data for ML analysis"""
        features = []
        
        # Request size features
        url_length = len(str(request_data.get("url", "")))
        body_length = len(str(request_data.get("body", "")))
        headers_count = len(request_data.get("headers", {}))
        
        features.extend([url_length, body_length, headers_count])
        
        # Time-based features
        current_time = datetime.utcnow()
        hour_of_day = current_time.hour
        day_of_week = current_time.weekday()
        
        features.extend([hour_of_day, day_of_week])
        
        # Content analysis features
        content = str(request_data.get("body", "")).lower()
        special_chars_count = len(re.findall(r'[<>"\';(){}[\]]', content))
        sql_keywords_count = len(re.findall(r'\b(select|insert|update|delete|union|drop)\b', content))
        script_tags_count = len(re.findall(r'<script', content))
        
        features.extend([special_chars_count, sql_keywords_count, script_tags_count])
        
        # Pad or truncate to fixed size (10 features)
        while len(features) < 10:
            features.append(0.0)
        
        return features[:10]
    
    def _calculate_threat_level(self, confidence: float) -> ThreatLevel:
        """Calculate threat level based on confidence score"""
        if confidence >= 0.9:
            return ThreatLevel.CRITICAL
        elif confidence >= 0.7:
            return ThreatLevel.HIGH
        elif confidence >= 0.5:
            return ThreatLevel.MEDIUM
        elif confidence >= 0.3:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.BENIGN
    
    def _generate_recommendations(self, threats: List[ThreatIndicator]) -> List[str]:
        """Generate recommended actions based on detected threats"""
        recommendations = []
        
        threat_categories = {threat.category for threat in threats}
        max_confidence = max(threat.confidence for threat in threats)
        
        if ThreatCategory.SQL_INJECTION in threat_categories:
            recommendations.append("Block request and sanitize database inputs")
            recommendations.append("Review database access permissions")
        
        if ThreatCategory.XSS in threat_categories:
            recommendations.append("Sanitize user inputs and implement CSP headers")
            recommendations.append("Review output encoding mechanisms")
        
        if ThreatCategory.BRUTE_FORCE in threat_categories:
            recommendations.append("Implement account lockout policies")
            recommendations.append("Enable MFA for affected accounts")
        
        if max_confidence > 0.8:
            recommendations.append("Immediately block source IP address")
            recommendations.append("Escalate to security team")
        
        if not recommendations:
            recommendations.append("Monitor and log for further analysis")
        
        return recommendations
    
    async def train_ml_models(self, training_data: List[Dict[str, Any]]):
        """Train ML models with historical data"""
        if len(training_data) < 100:
            logger.warning("Insufficient training data for ML models", 
                          data_size=len(training_data))
            return
        
        try:
            # Extract features from training data
            features = [self._extract_features(data) for data in training_data]
            
            # Fit scaler
            self.scaler.fit(features)
            
            # Normalize features
            features_scaled = self.scaler.transform(features)
            
            # Train isolation forest
            self.isolation_forest.fit(features_scaled)
            self.model_trained = True
            
            logger.info("ML models trained successfully", 
                       training_samples=len(training_data))
        
        except Exception as e:
            logger.error("Failed to train ML models", error=str(e))
    
    async def load_threat_indicators(self, indicators: List[Dict[str, Any]]):
        """Load threat indicators from external feeds"""
        loaded_count = 0
        
        for indicator_data in indicators:
            try:
                indicator = ThreatIndicator(
                    indicator_type=indicator_data["type"],
                    value=indicator_data["value"],
                    threat_level=ThreatLevel(indicator_data["threat_level"]),
                    category=ThreatCategory(indicator_data["category"]),
                    confidence=indicator_data["confidence"],
                    source=indicator_data["source"],
                    first_seen=datetime.fromisoformat(indicator_data["first_seen"]),
                    last_seen=datetime.fromisoformat(indicator_data["last_seen"]),
                    description=indicator_data["description"]
                )
                
                key = f"{indicator.indicator_type}:{indicator.value}"
                self.indicators[key] = indicator
                loaded_count += 1
                
            except Exception as e:
                logger.error("Failed to load threat indicator", 
                           indicator=indicator_data, error=str(e))
        
        self.stats["indicators_loaded"] = loaded_count
        logger.info("Threat indicators loaded", count=loaded_count)
    
    def get_threat_statistics(self) -> Dict[str, Any]:
        """Get threat detection statistics"""
        return {
            "enabled": self.enabled,
            "threats_detected": self.stats["threats_detected"],
            "false_positives": self.stats["false_positives"],
            "indicators_loaded": self.stats["indicators_loaded"],
            "behavioral_anomalies": self.stats["behavioral_anomalies"],
            "behavioral_profiles": len(self.behavioral_profiles),
            "ml_model_trained": self.model_trained,
            "threat_patterns": len(self.threat_patterns)
        }
    
    async def update_threat_feeds(self):
        """Update threat intelligence feeds"""
        for feed_config in self.threat_feeds:
            try:
                # In production, implement actual feed updates
                logger.info("Updating threat feed", feed=feed_config["name"])
                
            except Exception as e:
                logger.error("Failed to update threat feed", 
                           feed=feed_config["name"], error=str(e))