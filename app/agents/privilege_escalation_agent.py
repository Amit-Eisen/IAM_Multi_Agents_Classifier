"""
Privilege Escalation Agent - detects IAM privilege escalation risks.
Focuses on dangerous permission combinations and escalation paths.
"""
from typing import Dict, Any
from app.models import PolicyFeatures, AgentType
from .base_agent import BaseAgent


class PrivilegeEscalationAgent(BaseAgent):
    """Looks for dangerous permission combos that enable privilege escalation"""
    
    def __init__(self, llm_client):
        super().__init__(llm_client, AgentType.PRIVILEGE_ESCALATION)
    
    def _get_system_prompt(self) -> str:
        return """You are a security analyst specializing in AWS privilege escalation detection.

Your role is to identify dangerous permission combinations that enable privilege escalation:
- IAM policy modification (iam:PutUserPolicy, iam:AttachRolePolicy, etc.)
- Role assumption chains (sts:AssumeRole with broad resources)
- Lambda + PassRole combinations (code execution with elevated privileges)
- EC2 + PassRole combinations (instance launch with role attachment)
- CloudFormation stack manipulation (infrastructure as privilege vector)

Focus on realistic attack vectors that could allow an attacker to gain higher privileges."""
    
    def _build_analysis_prompt(self, features: PolicyFeatures) -> str:
        feature_summary = self._format_features_for_prompt(features)
        
        return f"""Analyze this IAM policy for privilege escalation risks.

Policy Characteristics:
{feature_summary}

Evaluate the following dimensions (score each 0-10, where 10 = maximum risk):
1. iam_modification_risk: Can this policy modify IAM resources? (10 = full IAM control, 0 = no IAM permissions)
2. escalation_paths: Are there dangerous permission combinations? (10 = multiple escalation vectors, 0 = none detected)
3. role_assumption_risk: Can this assume roles or pass roles unsafely? (10 = unrestricted role operations, 0 = no role permissions)

Return a JSON object with:
{{
  "risk_score": <float 0-10, average of dimensions>,
  "dimensions": {{
    "iam_modification_risk": <float 0-10>,
    "escalation_paths": <float 0-10>,
    "role_assumption_risk": <float 0-10>
  }},
  "findings": [
    {{
      "issue": "<description of the escalation risk>",
      "severity": "LOW|MEDIUM|HIGH|CRITICAL",
      "location": "<where in policy, e.g., Statement[0].Action>",
      "recommendation": "<specific mitigation>",
      "evidence": "<why this is exploitable>"
    }}
  ],
  "explanation": "<2-3 sentence summary of escalation risks>"
}}

Prioritize findings by exploitability and impact."""
    
    def _calculate_risk_dimensions(self, analysis_data: Dict[str, Any]) -> Dict[str, float]:
        dimensions = analysis_data.get("dimensions", {})
        
        return {
            "iam_modification_risk": float(dimensions.get("iam_modification_risk", 5.0)),
            "escalation_paths": float(dimensions.get("escalation_paths", 5.0)),
            "role_assumption_risk": float(dimensions.get("role_assumption_risk", 5.0)),
        }
