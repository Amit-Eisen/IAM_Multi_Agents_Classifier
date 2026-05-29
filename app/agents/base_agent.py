"""
Base agent class for IAM security analysis.
Provides common functionality for all security agents.
"""

import time
import json
from abc import ABC, abstractmethod
from typing import Dict, Any
from app.models import (
    PolicyFeatures,
    AgentAnalysis,
    AgentType,
    RiskLevel,
    SecurityFinding,
    RiskBreakdown,
)
from app.llm import LLMInterface
from app.utils import extract_json_from_text, get_logger

logger = get_logger(__name__)

class BaseAgent(ABC):
    """Base class for security analysis agents"""

    def __init__(self, llm_client: LLMInterface, agent_type: AgentType):
        self.llm = llm_client
        self.agent_type = agent_type
        self.logger = logger

    async def analyze(self, features: PolicyFeatures) -> AgentAnalysis:
        """Main analysis entry point - calls LLM and parses response"""
        start_time = time.time()

        try:
            self.logger.info(
                "agent_analysis_start",
                agent=self.agent_type.value,
                policy_id=features.policy_id,
            )

            prompt = self._build_analysis_prompt(features)
            system_prompt = self._get_system_prompt()

            response = await self.llm.generate(
                prompt=prompt,
                system_prompt=system_prompt,
                json_mode=True,
            )

            analysis_data = self._parse_llm_response(response)

            result = self._build_agent_analysis(
                analysis_data=analysis_data,
                execution_time=time.time() - start_time,
            )

            self.logger.info(
                "agent_analysis_complete",
                agent=self.agent_type.value,
                risk_score=result.risk_score,
                findings_count=len(result.findings),
            )

            return result

        except Exception as e:
            self.logger.error(
                "agent_analysis_failed",
                agent=self.agent_type.value,
                error=str(e),
                exc_info=True,
            )
            raise

    @abstractmethod
    def _get_system_prompt(self) -> str:
        pass

    @abstractmethod
    def _build_analysis_prompt(self, features: PolicyFeatures) -> str:
        pass

    @abstractmethod
    def _calculate_risk_dimensions(self, analysis_data: Dict[str, Any]) -> Dict[str, float]:
        pass

    def _parse_llm_response(self, response: str) -> Dict[str, Any]:
        """Extract and validate JSON from LLM output"""
        parsed = extract_json_from_text(response)

        if not parsed:
            self.logger.warning(
                "llm_json_extraction_failed",
                response_preview=response[:200] if response else "empty",
            )
            raise ValueError("Couldn't extract JSON from LLM response")

        required = ["risk_score", "findings", "explanation"]
        missing = [f for f in required if f not in parsed]

        if missing:
            self.logger.warning(
                "llm_response_missing_fields",
                missing_fields=missing,
                response_preview=str(parsed)[:200],
            )
            raise ValueError(f"Missing fields in response: {missing}")

        return parsed

    def _build_agent_analysis(
        self, 
        analysis_data: Dict[str, Any],
        execution_time: float,
    ) -> AgentAnalysis:
        """Convert LLM JSON to typed AgentAnalysis object"""
        findings = []
        for finding_data in analysis_data.get("findings", []):
            findings.append(SecurityFinding(
                issue=finding_data.get("issue", "Unknown issue"),
                severity=RiskLevel(finding_data.get("severity", "MEDIUM")),
                location=finding_data.get("location", "Unknown"),
                recommendation=finding_data.get("recommendation", "Review policy"),
                evidence=finding_data.get("evidence"),
            ))

        dimensions = self._calculate_risk_dimensions(analysis_data)
        risk_breakdown = RiskBreakdown(dimensions=dimensions)

        risk_score = float(analysis_data["risk_score"])
        verdict = self._score_to_verdict(risk_score)

        return AgentAnalysis(
            agent_name=self.agent_type,
            risk_score=risk_score,
            verdict=verdict,
            findings=findings,
            risk_breakdown=risk_breakdown,
            explanation=analysis_data["explanation"],
            execution_time_sec=round(execution_time, 2),
            model_used=self.llm.model,
        )

    def _score_to_verdict(self, score: float) -> RiskLevel:
        if score >= 8.0:
            return RiskLevel.CRITICAL
        elif score >= 6.0:
            return RiskLevel.HIGH
        elif score >= 3.0:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW

    def _format_features_for_prompt(self, features: PolicyFeatures) -> str:
        """Make features readable for the LLM"""

        parts = [
            f"Privilege Level: {features.privilege_level.value}",
            f"Resource Scope: {features.resource_scope.value}",
            f"Number of Statements: {features.num_statements}",
            f"Has Conditions: {features.has_conditions}",
        ]

        if features.uses_wildcards.actions:
            parts.append(f"Wildcard Actions: {', '.join(features.uses_wildcards.actions[:5])}")

        if features.uses_wildcards.resources:
            parts.append(f"Wildcard Resources: {', '.join(features.uses_wildcards.resources[:5])}")

        if features.sensitive_actions:
            parts.append(f"Sensitive Actions: {', '.join(features.sensitive_actions[:5])}")

        if features.dangerous_permissions:
            parts.append(f"Dangerous Patterns: {', '.join(features.dangerous_permissions)}")

        return "\n".join(parts)
