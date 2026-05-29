"""
Analysis Orchestrator - coordinates the complete IAM policy analysis pipeline.
Manages parser, agents, and judge to produce final security assessment.
"""
import asyncio
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from uuid import uuid4

from app.parser import parse_policy, extract_features
from app.agents import (
    LeastPrivilegeAgent,
    PrivilegeEscalationAgent,
    DataExposureAgent,
    ComplianceAgent,
    JudgeAgent,
)
from app.llm import LLMFactory
from app.models import PolicyAnalysisResult
from app.utils import get_logger

logger = get_logger(__name__)


class AnalysisOrchestrator:
    """Coordinates the full analysis pipeline from parsing to final verdict"""
    
    def __init__(
        self,
        llm_provider: Optional[str] = None,
        llm_model: Optional[str] = None,
    ):
        self.llm = LLMFactory.create(provider=llm_provider, model=llm_model)
        self.logger = logger
        
        # Initialize all 4 security agents + judge
        self.security_agents = [
            LeastPrivilegeAgent(self.llm),
            PrivilegeEscalationAgent(self.llm),
            DataExposureAgent(self.llm),
            ComplianceAgent(self.llm),
        ]
        
        self.judge = JudgeAgent(self.llm)
    
    async def analyze_policy(
        self,
        policy: Dict[str, Any],
        policy_name: Optional[str] = None,
    ) -> PolicyAnalysisResult:
        """Run full analysis: parse -> 4 agents (parallel) -> judge -> result"""
        analysis_id = str(uuid4())
        start_time = datetime.now(timezone.utc)
        
        try:
            self.logger.info(
                "analysis_pipeline_start",
                analysis_id=analysis_id,
                policy_name=policy_name,
            )
            
            # Parse policy and extract security features
            self.logger.info("step_1_parsing", analysis_id=analysis_id)
            parsed = parse_policy(policy)
            features = extract_features(parsed)
            
            self.logger.info(
                "parsing_complete",
                policy_id=features.policy_id,
                privilege_level=features.privilege_level.value,
                dangerous_patterns=features.dangerous_permissions,
            )
            
            # Run all 4 security agents in parallel
            self.logger.info("step_2_agents", analysis_id=analysis_id, num_agents=len(self.security_agents))
            
            agent_tasks = [
                agent.analyze(features)
                for agent in self.security_agents
            ]
            
            agent_analyses = await asyncio.gather(*agent_tasks, return_exceptions=True)
            
            # Check which agents succeeded (some might fail but we continue if at least 1 works)
            successful_analyses = []
            for i, result in enumerate(agent_analyses):
                if isinstance(result, Exception):
                    agent_name = self.security_agents[i].agent_type.value
                    self.logger.error(
                        "agent_failed",
                        agent=agent_name,
                        error=str(result),
                    )
                else:
                    successful_analyses.append(result)
            
            if len(successful_analyses) == 0:
                raise RuntimeError("All agents failed - can't continue")
            
            self.logger.info(
                "agents_complete",
                successful=len(successful_analyses),
                failed=len(agent_analyses) - len(successful_analyses),
            )
            
            # Judge combines all agent findings into final verdict
            self.logger.info("step_3_judge", analysis_id=analysis_id)
            judge_analysis = await self.judge.judge(successful_analyses)
            
            end_time = datetime.now(timezone.utc)
            total_time = (end_time - start_time).total_seconds()
            
            # Collect cost stats from LLM
            total_cost = self.llm.total_cost_usd
            total_tokens = self.llm.total_input_tokens + self.llm.total_output_tokens
            
            result = PolicyAnalysisResult(
                analysis_id=analysis_id,
                policy_id=features.policy_id,
                policy_name=policy_name,
                original_policy=policy,
                features=features,
                agent_analyses=successful_analyses,
                judge_analysis=judge_analysis,
                started_at=start_time,
                completed_at=end_time,
                total_execution_time_sec=round(total_time, 2),
                total_cost_usd=round(total_cost, 5),
                total_tokens=total_tokens,
            )
            
            self.logger.info(
                "analysis_pipeline_complete",
                analysis_id=analysis_id,
                final_verdict=judge_analysis.final_verdict.value,
                risk_score=judge_analysis.overall_risk_score,
                total_time=total_time,
                total_cost_usd=total_cost,
                total_tokens=total_tokens,
            )
            
            return result
            
        except Exception as e:
            self.logger.error(
                "analysis_pipeline_failed",
                analysis_id=analysis_id,
                error=str(e),
                exc_info=True,
            )
            raise
    
    async def analyze_policies_batch(
        self,
        policies: Dict[str, Dict[str, Any]],
    ) -> Dict[str, PolicyAnalysisResult]:
        """
        Analyze multiple policies in parallel.
        
        Args:
            policies: Dict of policy_name -> policy_json
            
        Returns:
            Dict of policy_name -> analysis_result
        """
        self.logger.info("batch_analysis_start", num_policies=len(policies))
        
        tasks = {
            name: self.analyze_policy(policy, policy_name=name)
            for name, policy in policies.items()
        }
        
        # Run all in parallel
        results = await asyncio.gather(*tasks.values(), return_exceptions=True)
        
        # Map back to names
        analysis_results = {}
        for name, result in zip(tasks.keys(), results):
            if isinstance(result, Exception):
                self.logger.error("batch_policy_failed", policy_name=name, error=str(result))
            else:
                analysis_results[name] = result
        
        self.logger.info(
            "batch_analysis_complete",
            total=len(policies),
            successful=len(analysis_results),
            failed=len(policies) - len(analysis_results),
        )
        
        return analysis_results


# Convenience function for simple usage
async def analyze_iam_policy(
    policy: Dict[str, Any],
    policy_name: Optional[str] = None,
    llm_provider: Optional[str] = None,
) -> PolicyAnalysisResult:
    """
    Simple function to analyze a single IAM policy.
    
    Args:
        policy: IAM policy JSON
        policy_name: Optional policy name
        llm_provider: Optional LLM provider override
        
    Returns:
        Complete analysis result
        
    Example:
        >>> policy = {"Version": "2012-10-17", "Statement": [...]}
        >>> result = await analyze_iam_policy(policy, "my-policy")
        >>> print(result.judge_analysis.final_verdict)
    """
    orchestrator = AnalysisOrchestrator(llm_provider=llm_provider)
    return await orchestrator.analyze_policy(policy, policy_name)
