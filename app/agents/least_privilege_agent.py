"""
Least Privilege Agent - analyzes IAM policies for least privilege violations.
Focuses on overly broad permissions and lack of specificity.
"""
from typing import Dict, Any
from app.models import PolicyFeatures, AgentType
from .base_agent import BaseAgent


class LeastPrivilegeAgent(BaseAgent):
    """Checks for overly broad permissions and wildcards"""
    
    def __init__(self, llm_client):
        super().__init__(llm_client, AgentType.LEAST_PRIVILEGE)
    
    def _get_system_prompt(self) -> str:
        return """You are a security analyst specializing in the Principle of Least Privilege.

Your role is to evaluate IAM policies and identify violations where permissions are:
- Overly broad (wildcards when specific actions would suffice)
- Unnecessarily permissive (more access than needed)
- Lacking specificity (resources or actions not scoped appropriately)

Focus on practical security issues, not theoretical perfection. Consider the balance between security and operational needs."""
    
    def _build_analysis_prompt(self, features: PolicyFeatures) -> str:
        feature_summary = self._format_features_for_prompt(features)
        
        return f"""Analyze this IAM policy for least privilege violations.

Policy Characteristics:
{feature_summary}

Evaluate the following dimensions (score each 0-10, where 10 = maximum risk):
1. action_specificity: How specific are the actions? (10 = wildcard *, 0 = specific actions)
2. resource_specificity: How specific are resources? (10 = all resources *, 0 = specific ARNs)
3. overall_scope: How broad is overall access? (10 = admin-level, 0 = minimal)

Return a JSON object with:
{{
  "risk_score": <float 0-10, average of dimensions>,
  "dimensions": {{
    "action_specificity": <float 0-10>,
    "resource_specificity": <float 0-10>,
    "overall_scope": <float 0-10>
  }},
  "findings": [
    {{
      "issue": "<description of the problem>",
      "severity": "LOW|MEDIUM|HIGH|CRITICAL",
      "location": "<where in policy, e.g., Statement[0].Action>",
      "recommendation": "<specific fix>",
      "evidence": "<supporting details>"
    }}
  ],
  "explanation": "<2-3 sentence summary of overall assessment>"
}}

Be specific and actionable in recommendations."""
    
    def _calculate_risk_dimensions(self, analysis_data: Dict[str, Any]) -> Dict[str, float]:
        dimensions = analysis_data.get("dimensions", {})
        
        return {
            "action_specificity": float(dimensions.get("action_specificity", 5.0)),
            "resource_specificity": float(dimensions.get("resource_specificity", 5.0)),
            "overall_scope": float(dimensions.get("overall_scope", 5.0)),
        }
