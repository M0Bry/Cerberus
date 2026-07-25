"""
Attack Result Module - Data structures for attack findings
"""

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class SeverityLevel(Enum):
    """CVSS-based severity levels"""
    CRITICAL = "critical"      # CVSS 9.0-10.0
    HIGH = "high"              # CVSS 7.0-8.9
    MEDIUM = "medium"            # CVSS 4.0-6.9
    LOW = "low"                # CVSS 0.1-3.9
    INFO = "info"              # CVSS 0.0
    ERROR = "error"            # Execution error


class ConfidenceLevel(Enum):
    """Confidence in finding validity"""
    CERTAIN = "certain"        # 100% confirmed
    HIGH = "high"              # 80-99% likely
    MEDIUM = "medium"          # 50-79% likely
    LOW = "low"                # 20-49% likely
    TENTATIVE = "tentative"    # <20% likely


@dataclass
class AttackEvidence:
    """Evidence collected during attack"""
    type: str                                   # screenshot, request, response, file, etc.
    data: Any                                   # Actual evidence data
    timestamp: datetime = field(default_factory=datetime.now)
    description: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "timestamp": self.timestamp.isoformat(),
            "description": self.description,
            "metadata": self.metadata,
            "hash": self.calculate_hash()
        }

    def calculate_hash(self) -> str:
        """Calculate SHA256 hash of evidence"""
        data_str = json.dumps(self.data, sort_keys=True, default=str)
        return hashlib.sha256(data_str.encode()).hexdigest()


@dataclass
class AttackResult:
    """
    Represents a single finding from an attack module

    Attributes:
        attack_name: Name of the attack that found this vulnerability
        vulnerability_type: Type of vulnerability (CWE category)
        severity: Severity level of the finding
        confidence: Confidence level in the finding
        description: Detailed description of the vulnerability
        target: Affected target (URL, IP, etc.)
        evidence: List of evidence objects
        remediation: Recommended remediation steps
        references: CVE, CWE, or other references
        cvss_score: CVSS v3.1 score (0.0-10.0)
        cwe_id: CWE identifier
        cve_id: CVE identifier (if applicable)
        metadata: Additional attack-specific data
    """

    attack_name: str
    vulnerability_type: str
    severity: SeverityLevel
    description: str
    target: str
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH
    evidence: list[AttackEvidence] = field(default_factory=list)
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    cvss_score: float | None = None
    cwe_id: str | None = None
    cve_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    verified: bool = False                      # Whether finding was verified
    false_positive: bool = False                 # Marked as false positive

    def __post_init__(self):
        if self.cvss_score is None:
            self.cvss_score = self._severity_to_cvss()

    def _severity_to_cvss(self) -> float:
        """Convert severity to CVSS score range"""
        mapping = {
            SeverityLevel.CRITICAL: 9.5,
            SeverityLevel.HIGH: 7.5,
            SeverityLevel.MEDIUM: 5.5,
            SeverityLevel.LOW: 2.0,
            SeverityLevel.INFO: 0.0,
            SeverityLevel.ERROR: 0.0
        }
        return mapping.get(self.severity, 5.0)

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary"""
        return {
            "attack_name": self.attack_name,
            "vulnerability_type": self.vulnerability_type,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "description": self.description,
            "target": self.target,
            "evidence": [e.to_dict() for e in self.evidence],
            "remediation": self.remediation,
            "references": self.references,
            "cvss_score": self.cvss_score,
            "cwe_id": self.cwe_id,
            "cve_id": self.cve_id,
            "metadata": self.metadata,
            "timestamp": self.timestamp.isoformat(),
            "verified": self.verified,
            "false_positive": self.false_positive
        }

    def to_json(self) -> str:
        """Convert result to JSON string"""
        return json.dumps(self.to_dict(), indent=2)

    def add_evidence(self, evidence_type: str, data: Any, description: str = "", metadata: dict[str, Any] | None = None):
        """Add evidence to this result"""
        evidence = AttackEvidence(
            type=evidence_type,
            data=data,
            description=description,
            metadata=metadata or {}
        )
        self.evidence.append(evidence)

    def mark_verified(self):
        """Mark finding as verified"""
        self.verified = True

    def mark_false_positive(self):
        """Mark finding as false positive"""
        self.false_positive = True

    def calculate_risk_score(self) -> float:
        """
        Calculate risk score based on severity and confidence
        Returns score between 0-100
        """
        severity_weights = {
            SeverityLevel.CRITICAL: 10,
            SeverityLevel.HIGH: 7.5,
            SeverityLevel.MEDIUM: 5,
            SeverityLevel.LOW: 2.5,
            SeverityLevel.INFO: 0.5,
            SeverityLevel.ERROR: 0
        }

        confidence_weights = {
            ConfidenceLevel.CERTAIN: 1.0,
            ConfidenceLevel.HIGH: 0.9,
            ConfidenceLevel.MEDIUM: 0.7,
            ConfidenceLevel.LOW: 0.4,
            ConfidenceLevel.TENTATIVE: 0.2
        }

        sev_weight = severity_weights.get(self.severity, 5)
        conf_weight = confidence_weights.get(self.confidence, 0.5)

        return sev_weight * conf_weight * 10

    def is_critical(self) -> bool:
        """Check if finding is critical"""
        return self.severity == SeverityLevel.CRITICAL and not self.false_positive

    def __str__(self) -> str:
        return f"[{self.severity.value.upper()}] {self.vulnerability_type} on {self.target}"
