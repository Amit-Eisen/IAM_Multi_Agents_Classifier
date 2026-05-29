"""Test Judge Agent with real agent outputs."""
import asyncio
import json
from pathlib import Path
from app.parser import parse_policy, extract_features
from app.agents import (
    LeastPrivilegeAgent,
    PrivilegeEscalationAgent,
    DataExposureAgent,
    ComplianceAgent,
    JudgeAgent,
)
from app.llm import LLMFactory


async def test_full_pipeline(policy_file: Path):
    """Test complete pipeline: Parser → 4 Agents → Judge."""
    print(f"\n{'='*70}")
    print(f"FULL PIPELINE TEST: {policy_file.name}")
    print('='*70)
    
    # Load policy
    with open(policy_file) as f:
        policy = json.load(f)
    
    # Parse
    parsed = parse_policy(policy)
    features = extract_features(parsed)
    
    print(f"\n[POLICY] {policy_file.name}")
    print(f"  Privilege: {features.privilege_level.value}")
    print(f"  Dangerous Patterns: {features.dangerous_permissions}")
    
    # Create LLM and agents
    llm = LLMFactory.create()
    
    agents = [
        LeastPrivilegeAgent(llm),
        PrivilegeEscalationAgent(llm),
        DataExposureAgent(llm),
        ComplianceAgent(llm),
    ]
    
    # Run all 4 agents
    print(f"\n[AGENTS] Running 4 security agents...")
    agent_analyses = []
    
    for agent in agents:
        try:
            result = await agent.analyze(features)
            agent_analyses.append(result)
            print(f"  {result.agent_name.value:25s}: {result.risk_score:4.1f}/10")
        except Exception as e:
            print(f"  Agent failed: {e}")
    
    if len(agent_analyses) < 4:
        print("\n[ERROR] Not all agents completed successfully")
        return
    
    # Create Judge and get final verdict
    print(f"\n[JUDGE] Aggregating findings...")
    judge = JudgeAgent(llm)
    
    final_verdict = await judge.judge(agent_analyses)
    
    # Display results
    print(f"\n{'='*70}")
    print("FINAL VERDICT")
    print('='*70)
    
    print(f"\n  Verdict: {final_verdict.final_verdict.value}")
    print(f"  Overall Risk: {final_verdict.overall_risk_score:.1f}/10")
    print(f"  Confidence: {final_verdict.confidence:.0%}")
    
    print(f"\n  Agent Consensus: {final_verdict.agent_consensus.agreement_level.value.upper()}")
    print(f"  {final_verdict.agent_consensus.consensus_explanation}")
    
    print(f"\n  Risk Breakdown:")
    for agent_type, score in final_verdict.risk_breakdown.items():
        print(f"    {agent_type.value:25s}: {score:4.1f}/10")
    
    print(f"\n  Key Findings ({len(final_verdict.key_findings)}):")
    for i, finding in enumerate(final_verdict.key_findings, 1):
        print(f"    {i}. {finding}")
    
    print(f"\n  Priority Recommendations ({len(final_verdict.priority_recommendations)}):")
    for i, rec in enumerate(final_verdict.priority_recommendations[:5], 1):
        print(f"    {i}. [{rec.priority.value}] {rec.category}")
        print(f"       {rec.recommendation}")
        print(f"       Impact: {rec.impact}")
    
    print(f"\n  Executive Summary:")
    for line in final_verdict.executive_summary.split('. '):
        if line:
            print(f"    {line.strip()}.")
    
    print(f"\n  Total Execution Time: {final_verdict.total_execution_time_sec:.1f}s")
    
    return final_verdict


async def main():
    print("\n" + "="*70)
    print("MULTI-AGENT IAM SECURITY SYSTEM - FULL PIPELINE TEST")
    print("="*70)
    
    # Test with different policy types
    test_policies = [
        ("policy1.json", "Full wildcard - should be CRITICAL"),
        ("policy9.json", "Privilege escalation - should be HIGH"),
        ("policy12.json", "Secure with MFA - should be better"),
    ]
    
    for policy_name, description in test_policies:
        policy_file = Path("example_policies") / policy_name
        if policy_file.exists():
            print(f"\n\nTest: {description}")
            try:
                await test_full_pipeline(policy_file)
            except Exception as e:
                print(f"\n[ERROR] Pipeline failed: {e}")
                import traceback
                traceback.print_exc()
        else:
            print(f"\n[SKIP] {policy_name} not found")
    
    print(f"\n{'='*70}")
    print("Pipeline test complete!")
    print('='*70)


if __name__ == "__main__":
    asyncio.run(main())
