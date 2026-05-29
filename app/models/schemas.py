"""
Pydantic schemas for IAM Multi-Agent Security System.
Defines all data structures with validation.
"""
from typing import List, Dict, Optional, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field
from .enums import (
    RiskLevel, 
    Verdict, 
    AgentType, 
    PrivilegeLevel, 
    ResourceScope,
    AgreementLevel
)


# ============================================================================
# POLICY INPUT & PARSING
# ============================================================================

class PolicyInput(BaseModel):
    """Input schema for IAM policy analysis."""
    policy: Dict[str, Any] = Field(..., description="IAM policy JSON")
    policy_name: Optional[str] = Field(None, description="Optional policy identifier")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)


class WildcardDetection(BaseModel):
    """Detected wildcards in policy."""
    actions: List[str] = Field(default_factory=list, description="Wildcard actions")
    resources: List[str] = Field(default_factory=list, description="Wildcard resources")
    principals: List[str] = Field(default_factory=list, description="Wildcard principals")


class PolicyFeatures(BaseModel):
    """Extracted security-relevant features from IAM policy."""
    policy_id: str
    raw_policy: Dict[str, Any]
    
    # Wildcard detection
    uses_wildcards: WildcardDetection
    
    # Privilege classification
    privilege_level: PrivilegeLevel
    resource_scope: ResourceScope
    
    # Sensitive elements
    sensitive_actions: List[str] = Field(default_factory=list)
    dangerous_permissions: List[str] = Field(default_factory=list)
    
    # Policy structure
    num_statements: int
    has_conditions: bool
    principals: List[str] = Field(default_factory=list)
    
    # When this was parsed
    parsed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ============================================================================
# AGENT FINDINGS
# ============================================================================

class SecurityFinding(BaseModel):
    """Individual security finding from an agent."""
    issue: str = Field(..., description="Description of the security issue")
    severity: RiskLevel = Field(..., description="Severity level")
    location: str = Field(..., description="Location in policy (e.g., Statement[0].Action)")
    recommendation: str = Field(..., description="How to fix this issue")
    evidence: Optional[str] = Field(None, description="Supporting evidence or explanation")


class RiskBreakdown(BaseModel):
    """Dimensional risk breakdown for an agent."""
    dimensions: Dict[str, float] = Field(
        ..., 
        description="Risk scores for different dimensions (0-10 scale)"
    )
    
    def get_average(self) -> float:
        """Calculate average risk across all dimensions."""
        if not self.dimensions:
            return 0.0
        return sum(self.dimensions.values()) / len(self.dimensions)


class AgentAnalysis(BaseModel):
    """Analysis output from a single security agent."""
    model_config = {"protected_namespaces": ()}
    
    agent_name: AgentType
    risk_score: float = Field(..., ge=0, le=10, description="Overall risk score (0-10)")
    verdict: RiskLevel
    
    findings: List[SecurityFinding] = Field(default_factory=list)
    risk_breakdown: RiskBreakdown
    
    explanation: str = Field(..., description="Natural language explanation of analysis")
    
    # Metadata
    execution_time_sec: float = Field(..., description="Time taken for analysis")
    model_used: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ============================================================================
# JUDGE AGENT OUTPUT
# ============================================================================

class AgentConsensus(BaseModel):
    """Agreement analysis between agents."""
    agreement_level: AgreementLevel
    agreement_score: float = Field(..., ge=0, le=1, description="0-1 consensus metric")
    conflicting_agents: List[AgentType] = Field(default_factory=list)
    consensus_explanation: str


class PolicyRecommendation(BaseModel):
    """Specific recommendation for policy improvement."""
    priority: RiskLevel
    category: str  # e.g., "Least Privilege", "Conditions", "Resource Scope"
    recommendation: str
    impact: str  # What this fixes
    example: Optional[str] = Field(None, description="Example improved policy snippet")


class JudgeAnalysis(BaseModel):
    """Aggregated analysis from Judge agent."""
    final_verdict: Verdict
    overall_risk_score: float = Field(..., ge=0, le=10)
    confidence: float = Field(..., ge=0, le=1, description="Confidence in verdict")
    
    # Risk breakdown by agent
    risk_breakdown: Dict[AgentType, float] = Field(
        ..., 
        description="Risk scores from each agent"
    )
    
    # Consensus analysis
    agent_consensus: AgentConsensus
    
    # Top findings
    key_findings: List[str] = Field(..., description="3-5 most critical findings")
    priority_recommendations: List[PolicyRecommendation]
    
    # Summary
    executive_summary: str = Field(
        ..., 
        description="Human-readable executive summary"
    )
    
    # Metadata
    total_execution_time_sec: float
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ============================================================================
# FINAL OUTPUT
# ============================================================================

class PolicyAnalysisResult(BaseModel):
    """Complete analysis result for an IAM policy."""
    # Input
    policy_id: str
    policy_name: Optional[str] = None
    original_policy: Dict[str, Any]
    
    # Parsed features
    features: PolicyFeatures
    
    # Agent analyses
    agent_analyses: List[AgentAnalysis]
    
    # Judge decision
    judge_analysis: JudgeAnalysis
    
    # Metadata
    analysis_id: str
    started_at: datetime
    completed_at: datetime
    total_execution_time_sec: float
    
    # Cost tracking
    total_cost_usd: float = Field(default=0.0, description="Estimated API cost in USD")
    total_tokens: int = Field(default=0, description="Total tokens used")


# ============================================================================
# API RESPONSES
# ============================================================================

class AnalysisResponse(BaseModel):
    """API response for policy analysis."""
    success: bool
    analysis: Optional[PolicyAnalysisResult] = None
    error: Optional[str] = None


class HealthCheckResponse(BaseModel):
    """Health check response."""
    status: str
    version: str
    environment: str
    available_providers: List[str]
