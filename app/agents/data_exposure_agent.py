"""
Data Exposure Agent - analyzes IAM policies for data leakage risks.
Focuses on S3, databases, secrets, and sensitive data access.
"""
from typing import Dict, Any
from app.models import PolicyFeatures, AgentType
from .base_agent import BaseAgent


class DataExposureAgent(BaseAgent):
    """Checks for S3, database, and secrets access that could leak data"""
    
    def __init__(self, llm_client):
        super().__init__(llm_client, AgentType.DATA_EXPOSURE)
    
    def _get_system_prompt(self) -> str:
        return """You are a security analyst specializing in data exposure and data loss prevention.

Your role is to identify permissions that could lead to unauthorized data access or leakage:
- S3 bucket access (GetObject, PutBucketPolicy, GetBucketAcl)
- Database access (RDS, DynamoDB read/write permissions)
- Secrets management (GetSecretValue, DescribeSecret)
- Data exfiltration vectors (permissions that enable data copying or export)
- Public exposure risks (bucket policies, ACL modifications)

Focus on risks that could expose sensitive organizational data to unauthorized parties."""
    
    def _build_analysis_prompt(self, features: PolicyFeatures) -> str:
        feature_summary = self._format_features_for_prompt(features)
        
        return f"""Analyze this IAM policy for data exposure risks.

Policy Characteristics:
{feature_summary}

Evaluate the following dimensions (score each 0-10, where 10 = maximum risk):
1. s3_exposure_risk: How much S3 access is granted? (10 = full S3 access including policy modification, 0 = no S3 access)
2. database_access_risk: What database permissions exist? (10 = full RDS/DynamoDB access, 0 = no database permissions)
3. secrets_access_risk: Can this access secrets or credentials? (10 = unrestricted secrets access, 0 = no secrets permissions)

Return a JSON object with:
{{
  "risk_score": <float 0-10, average of dimensions>,
  "dimensions": {{
    "s3_exposure_risk": <float 0-10>,
    "database_access_risk": <float 0-10>,
    "secrets_access_risk": <float 0-10>
  }},
  "findings": [
    {{
      "issue": "<description of the data exposure risk>",
      "severity": "LOW|MEDIUM|HIGH|CRITICAL",
      "location": "<where in policy, e.g., Statement[0].Action>",
      "recommendation": "<specific mitigation>",
      "evidence": "<what data could be exposed>"
    }}
  ],
  "explanation": "<2-3 sentence summary of data exposure risks>"
}}

Consider both direct data access and indirect exposure vectors."""
    
    def _calculate_risk_dimensions(self, analysis_data: Dict[str, Any]) -> Dict[str, float]:
        dimensions = analysis_data.get("dimensions", {})
        
        return {
            "s3_exposure_risk": float(dimensions.get("s3_exposure_risk", 5.0)),
            "database_access_risk": float(dimensions.get("database_access_risk", 5.0)),
            "secrets_access_risk": float(dimensions.get("secrets_access_risk", 5.0)),
        }
