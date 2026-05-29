"""
Compliance Agent - evaluates IAM policies against security best practices.
Focuses on AWS security standards and compliance requirements.
"""
from typing import Dict, Any
from app.models import PolicyFeatures, AgentType
from .base_agent import BaseAgent


class ComplianceAgent(BaseAgent):
    """Validates against AWS security best practices and common standards"""
    
    def __init__(self, llm_client):
        super().__init__(llm_client, AgentType.COMPLIANCE)
    
    def _get_system_prompt(self) -> str:
        return """You are a security analyst specializing in AWS security compliance and best practices.

Your role is to evaluate IAM policies against industry standards:
- AWS Well-Architected Framework security pillar
- CIS AWS Foundations Benchmark
- Principle of least privilege
- MFA enforcement for sensitive operations
- Condition-based access controls (IP restrictions, time-based, etc.)
- Resource tagging and organization

Focus on deviations from security best practices that increase organizational risk."""
    
    def _build_analysis_prompt(self, features: PolicyFeatures) -> str:
        feature_summary = self._format_features_for_prompt(features)
        
        return f"""Analyze this IAM policy for compliance with security best practices.

Policy Characteristics:
{feature_summary}

Evaluate the following dimensions (score each 0-10, where 10 = maximum risk):
1. mfa_enforcement: Does policy require MFA for sensitive operations? (10 = no MFA requirements, 0 = MFA enforced)
2. condition_usage: Are conditions used to restrict access? (10 = no conditions, 0 = comprehensive conditions)
3. best_practices_adherence: Overall compliance with AWS security standards (10 = violates multiple standards, 0 = fully compliant)

Return a JSON object with:
{{
  "risk_score": <float 0-10, average of dimensions>,
  "dimensions": {{
    "mfa_enforcement": <float 0-10>,
    "condition_usage": <float 0-10>,
    "best_practices_adherence": <float 0-10>
  }},
  "findings": [
    {{
      "issue": "<description of the compliance issue>",
      "severity": "LOW|MEDIUM|HIGH|CRITICAL",
      "location": "<where in policy, e.g., Statement[0].Condition>",
      "recommendation": "<specific compliance improvement>",
      "evidence": "<which standard or best practice is violated>"
    }}
  ],
  "explanation": "<2-3 sentence summary of compliance posture>"
}}

Reference specific standards (CIS, AWS Well-Architected) when applicable."""
    
    def _calculate_risk_dimensions(self, analysis_data: Dict[str, Any]) -> Dict[str, float]:
        dimensions = analysis_data.get("dimensions", {})
        
        return {
            "mfa_enforcement": float(dimensions.get("mfa_enforcement", 5.0)),
            "condition_usage": float(dimensions.get("condition_usage", 5.0)),
            "best_practices_adherence": float(dimensions.get("best_practices_adherence", 5.0)),
        }
