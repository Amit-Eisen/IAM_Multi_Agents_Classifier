"""
Enumerations for IAM Multi-Agent Security System.
Defines all categorical types used across the application.
"""
from enum import Enum


class RiskLevel(str, Enum):
    """Risk severity levels for security findings."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Verdict(str, Enum):
    """Final security verdict for IAM policy."""
    SECURE = "SECURE"
    NEEDS_IMPROVEMENT = "NEEDS_IMPROVEMENT"
    WEAK = "WEAK"
    CRITICAL_RISK = "CRITICAL_RISK"


class AgentType(str, Enum):
    """Types of security analysis agents."""
    LEAST_PRIVILEGE = "least_privilege"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXPOSURE = "data_exposure"
    COMPLIANCE = "compliance"
    JUDGE = "judge"


class PrivilegeLevel(str, Enum):
    """Privilege level classification for IAM policies."""
    NONE = "none"
    READ = "read"
    WRITE = "write"
    ADMINISTRATIVE = "administrative"


class ResourceScope(str, Enum):
    """Scope of resources in IAM policy."""
    SPECIFIC = "specific"  # Specific ARNs
    SERVICE = "service"    # All resources in a service
    ACCOUNT = "account"    # All resources in account
    ALL = "all"            # All resources (*)


class AgreementLevel(str, Enum):
    """Level of agreement between agents."""
    LOW = "low"           # Conflicting opinions
    MEDIUM = "medium"     # Partial agreement
    HIGH = "high"         # Strong consensus
