"""
Judge Agent - aggregates and evaluates findings from all security agents.
Makes final security verdict with explainable reasoning.
"""
import json
from typing import List, Dict, Any
from statistics import mean, stdev
from app.models import (
    AgentAnalysis,
    JudgeAnalysis,
    AgentType,
    Verdict,
    RiskLevel,
    AgreementLevel,
    AgentConsensus,
    PolicyRecommendation,
)
from app.llm import LLMInterface
from app.utils import extract_json_from_text, get_logger
import time

logger = get_logger(__name__)


class JudgeAgent:
    """Aggregates all agent findings and makes final verdict"""
    
    # Weight different agents by criticality - privilege escalation is most important
    # TODO: maybe make these configurable?
    AGENT_WEIGHTS = {
        AgentType.PRIVILEGE_ESCALATION: 1.5,
        AgentType.DATA_EXPOSURE: 1.3,
        AgentType.LEAST_PRIVILEGE: 1.0,
        AgentType.COMPLIANCE: 0.8,
    }
    
    def __init__(self, llm_client: LLMInterface):
        self.llm = llm_client
        self.logger = logger
    
    async def judge(self, agent_analyses: List[AgentAnalysis]) -> JudgeAnalysis:
        """Main judging logic - combines all agent outputs into final verdict"""
        start_time = time.time()
        
        self.logger.info(
            "judge_analysis_start",
            num_agents=len(agent_analyses),
        )
        
        consensus = self._calculate_consensus(agent_analyses)
        weighted_score = consensus["weighted_risk"]
        
        self.logger.info(
            "weighted_risk_calculated",
            weighted_score=weighted_score,
            simple_avg=consensus["avg_risk"],
        )
        
        try:
            prompt = self._build_judge_prompt(agent_analyses, consensus)
            system_prompt = self._get_system_prompt()
            
            response = await self.llm.generate(
                prompt=prompt,
                system_prompt=system_prompt,
                json_mode=True,
            )
            
            judge_data = extract_json_from_text(response)
            if not judge_data:
                raise ValueError("Couldn't extract JSON from Judge response")
            
            result = self._build_judge_analysis(
                judge_data=judge_data,
                agent_analyses=agent_analyses,
                consensus=consensus,
                execution_time=time.time() - start_time,
            )
            
            self.logger.info(
                "judge_analysis_complete",
                final_verdict=result.final_verdict.value,
                overall_risk=result.overall_risk_score,
                confidence=result.confidence,
            )
            
            return result
            
        except Exception as e:
            # Fallback to deterministic scoring if LLM fails
            self.logger.warning(
                "judge_llm_failed_using_fallback",
                error=str(e),
                weighted_score=weighted_score,
            )
            
            return self._build_fallback_analysis(
                agent_analyses=agent_analyses,
                consensus=consensus,
                execution_time=time.time() - start_time,
            )
    
    def _get_system_prompt(self) -> str:
        """System prompt defining Judge's role."""
        return """You are the Chief Security Officer responsible for making final security decisions.

Your role is to:
1. Review analyses from 4 specialized security agents
2. Weigh the importance of different risk types (privilege escalation is most critical)
3. Resolve conflicts when agents disagree
4. Make a final security verdict with clear reasoning
5. Provide actionable recommendations prioritized by risk

Consider:
- Privilege escalation risks are MOST critical (can lead to full compromise)
- Data exposure risks are highly important (sensitive data leakage)
- Least privilege violations are important (but may be necessary for operations)
- Compliance issues are important (but lower priority than active threats)

Be practical and balanced - not all findings are equally critical."""
    
    def _build_judge_prompt(
        self, 
        agent_analyses: List[AgentAnalysis],
        consensus: Dict[str, Any],
    ) -> str:
        """Build comprehensive prompt for Judge LLM."""
        
        # Summarize agent scores
        agent_summary = []
        for analysis in agent_analyses:
            agent_summary.append(
                f"- {analysis.agent_name.value}: {analysis.risk_score}/10 ({analysis.verdict.value})"
            )
        
        # Collect all findings by severity
        critical_findings = []
        high_findings = []
        medium_findings = []
        
        for analysis in agent_analyses:
            for finding in analysis.findings:
                finding_text = f"[{analysis.agent_name.value}] {finding.issue}"
                if finding.severity == RiskLevel.CRITICAL:
                    critical_findings.append(finding_text)
                elif finding.severity == RiskLevel.HIGH:
                    high_findings.append(finding_text)
                elif finding.severity == RiskLevel.MEDIUM:
                    medium_findings.append(finding_text)
        
        # Collect agent explanations
        explanations = []
        for analysis in agent_analyses:
            explanations.append(
                f"**{analysis.agent_name.value}**: {analysis.explanation}"
            )
        
        return f"""Review these security agent analyses and make a final verdict:

AGENT RISK SCORES:
{chr(10).join(agent_summary)}

CONSENSUS METRICS:
- Simple Average: {consensus['avg_risk']:.1f}/10
- Weighted Average: {consensus['weighted_risk']:.1f}/10 (accounts for agent importance)
- Score Spread: {consensus['std_dev']:.1f}
- Agreement Level: {consensus['agreement_level']}

NOTE: Weighted average gives more weight to Privilege Escalation (1.5x) and Data Exposure (1.3x).

CRITICAL FINDINGS ({len(critical_findings)}):
{chr(10).join(critical_findings[:5]) if critical_findings else "None"}

HIGH FINDINGS ({len(high_findings)}):
{chr(10).join(high_findings[:5]) if high_findings else "None"}

MEDIUM FINDINGS ({len(medium_findings)}):
{chr(10).join(medium_findings[:3]) if medium_findings else "None"}

AGENT EXPLANATIONS:
{chr(10).join(explanations)}

Provide a final security verdict in JSON format:
{{
  "final_verdict": "SECURE|NEEDS_IMPROVEMENT|WEAK|CRITICAL_RISK",
  "overall_risk_score": <float 0-10, weighted average considering agent importance>,
  "confidence": <float 0-1, based on agent agreement>,
  "key_findings": [
    "<3-5 most critical findings across all agents>"
  ],
  "priority_recommendations": [
    {{
      "priority": "CRITICAL|HIGH|MEDIUM|LOW",
      "category": "<e.g., Privilege Escalation, Least Privilege>",
      "recommendation": "<specific action to take>",
      "impact": "<what this fixes>"
    }}
  ],
  "executive_summary": "<2-3 paragraph summary explaining the verdict, key risks, and why this decision was made>"
}}

Remember:
- Privilege escalation findings are MOST critical
- Consider both severity AND exploitability
- Be specific and actionable in recommendations
- Explain reasoning clearly for stakeholders"""
    
    def _calculate_consensus(self, agent_analyses: List[AgentAnalysis]) -> Dict[str, Any]:
        """Calculate agreement metrics and weighted risk score."""
        scores = [a.risk_score for a in agent_analyses]
        
        avg_risk = mean(scores)
        std_dev = stdev(scores) if len(scores) > 1 else 0.0
        
        # Calculate weighted average based on agent importance
        weighted_score = self._calculate_weighted_risk(agent_analyses)
        
        # Determine agreement level based on standard deviation
        if std_dev < 1.5:
            agreement_level = AgreementLevel.HIGH
        elif std_dev < 3.0:
            agreement_level = AgreementLevel.MEDIUM
        else:
            agreement_level = AgreementLevel.LOW
        
        # Find conflicting agents (scores >3 points apart from mean)
        conflicting = []
        for analysis in agent_analyses:
            if abs(analysis.risk_score - avg_risk) > 3.0:
                conflicting.append(analysis.agent_name)
        
        return {
            "avg_risk": avg_risk,
            "weighted_risk": weighted_score,
            "std_dev": std_dev,
            "agreement_level": agreement_level,
            "conflicting_agents": conflicting,
        }
    
    def _calculate_weighted_risk(self, agent_analyses: List[AgentAnalysis]) -> float:
        """Calculate weighted risk score based on agent importance."""
        total_weight = 0.0
        weighted_sum = 0.0
        
        for analysis in agent_analyses:
            weight = self.AGENT_WEIGHTS.get(analysis.agent_name, 1.0)
            weighted_sum += analysis.risk_score * weight
            total_weight += weight
        
        if total_weight == 0:
            return 5.0  # fallback to medium risk
        
        return round(weighted_sum / total_weight, 1)
    
    def _get_fallback_verdict(self, weighted_score: float) -> Verdict:
        """Deterministic verdict based on weighted score - used as fallback."""
        if weighted_score >= 8.0:
            return Verdict.CRITICAL_RISK
        elif weighted_score >= 6.0:
            return Verdict.WEAK
        elif weighted_score >= 3.0:
            return Verdict.NEEDS_IMPROVEMENT
        else:
            return Verdict.SECURE
    
    def _build_judge_analysis(
        self,
        judge_data: Dict[str, Any],
        agent_analyses: List[AgentAnalysis],
        consensus: Dict[str, Any],
        execution_time: float,
    ) -> JudgeAnalysis:
        """Build final JudgeAnalysis from LLM output."""
        
        # Parse recommendations
        recommendations = []
        for rec_data in judge_data.get("priority_recommendations", []):
            recommendations.append(PolicyRecommendation(
                priority=RiskLevel(rec_data.get("priority", "MEDIUM")),
                category=rec_data.get("category", "General"),
                recommendation=rec_data.get("recommendation", "Review policy"),
                impact=rec_data.get("impact", "Improves security posture"),
                example=rec_data.get("example"),
            ))
        
        # Build risk breakdown by agent
        risk_breakdown = {
            analysis.agent_name: analysis.risk_score
            for analysis in agent_analyses
        }
        
        # Build consensus object
        agent_consensus = AgentConsensus(
            agreement_level=consensus["agreement_level"],
            agreement_score=1.0 - (consensus["std_dev"] / 10.0),  # Convert std_dev to 0-1 score
            conflicting_agents=consensus["conflicting_agents"],
            consensus_explanation=self._explain_consensus(consensus, agent_analyses),
        )
        
        return JudgeAnalysis(
            final_verdict=Verdict(judge_data.get("final_verdict", "WEAK")),
            overall_risk_score=float(judge_data.get("overall_risk_score", consensus["avg_risk"])),
            confidence=float(judge_data.get("confidence", 0.8)),
            risk_breakdown=risk_breakdown,
            agent_consensus=agent_consensus,
            key_findings=judge_data.get("key_findings", []),
            priority_recommendations=recommendations,
            executive_summary=judge_data.get("executive_summary", "Security assessment completed."),
            total_execution_time_sec=round(execution_time, 2),
        )
    
    def _explain_consensus(
        self, 
        consensus: Dict[str, Any], 
        agent_analyses: List[AgentAnalysis]
    ) -> str:
        """Generate explanation of agent consensus."""
        
        level = consensus["agreement_level"].value
        avg = consensus["avg_risk"]
        conflicting = consensus["conflicting_agents"]
        
        if level == "high":
            return f"All agents are in strong agreement with an average risk score of {avg:.1f}/10."
        elif level == "medium":
            if conflicting:
                agents = ", ".join([a.value for a in conflicting])
                return f"Most agents agree (avg {avg:.1f}/10), but {agents} identified different risk levels."
            return f"Agents show moderate agreement with an average risk score of {avg:.1f}/10."
        else:
            agents = ", ".join([a.value for a in conflicting])
            return f"Significant disagreement between agents (avg {avg:.1f}/10). {agents} identified notably different risks."
    
    def _build_fallback_analysis(
        self,
        agent_analyses: List[AgentAnalysis],
        consensus: Dict[str, Any],
        execution_time: float,
    ) -> JudgeAnalysis:
        """Build analysis using deterministic scoring when LLM fails."""
        
        weighted_score = consensus["weighted_risk"]
        fallback_verdict = self._get_fallback_verdict(weighted_score)
        
        # Collect top findings from all agents
        all_findings = []
        for analysis in agent_analyses:
            for finding in analysis.findings:
                all_findings.append({
                    "agent": analysis.agent_name.value,
                    "issue": finding.issue,
                    "severity": finding.severity,
                })
        
        # Sort by severity and take top 5
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        all_findings.sort(key=lambda x: severity_order.get(x["severity"].value, 3))
        key_findings = [f["issue"] for f in all_findings[:5]]
        
        # Build basic recommendations from findings
        recommendations = []
        for finding in all_findings[:3]:
            recommendations.append(PolicyRecommendation(
                priority=finding["severity"],
                category=finding["agent"].replace("_", " ").title(),
                recommendation=f"Address: {finding['issue']}",
                impact="Reduces overall policy risk",
            ))
        
        # Build risk breakdown by agent
        risk_breakdown = {
            analysis.agent_name: analysis.risk_score
            for analysis in agent_analyses
        }
        
        # Build consensus
        agent_consensus = AgentConsensus(
            agreement_level=consensus["agreement_level"],
            agreement_score=1.0 - (consensus["std_dev"] / 10.0),
            conflicting_agents=consensus["conflicting_agents"],
            consensus_explanation=self._explain_consensus(consensus, agent_analyses),
        )
        
        self.logger.info(
            "fallback_analysis_built",
            verdict=fallback_verdict.value,
            weighted_score=weighted_score,
        )
        
        return JudgeAnalysis(
            final_verdict=fallback_verdict,
            overall_risk_score=weighted_score,
            confidence=0.7,  # lower confidence for fallback
            risk_breakdown=risk_breakdown,
            agent_consensus=agent_consensus,
            key_findings=key_findings if key_findings else ["Review policy for security issues"],
            priority_recommendations=recommendations,
            executive_summary=f"Analysis completed using weighted scoring (LLM unavailable). "
                             f"The policy received a weighted risk score of {weighted_score}/10 "
                             f"based on {len(agent_analyses)} security agents. "
                             f"Verdict: {fallback_verdict.value}. Please review the individual agent findings for details.",
            total_execution_time_sec=round(execution_time, 2),
        )
