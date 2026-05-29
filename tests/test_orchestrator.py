"""Quick test of the full orchestrator"""
import asyncio
import json
from pathlib import Path
from app.orchestrator import analyze_iam_policy


async def main():
    print("="*70)
    print("ORCHESTRATOR TEST")
    print("="*70)
    
    policy_file = Path("example_policies/policy1.json")
    with open(policy_file) as f:
        policy = json.load(f)
    
    print(f"\nTesting with: {policy_file.name}")
    print("Running full pipeline...\n")
    
    # One function call does the whole thing
    result = await analyze_iam_policy(policy, policy_name="policy1")
    
    print(f"{'='*70}")
    print("RESULTS")
    print('='*70)
    
    print(f"\nVerdict: {result.judge_analysis.final_verdict.value}")
    print(f"Risk Score: {result.judge_analysis.overall_risk_score:.1f}/10")
    print(f"Confidence: {result.judge_analysis.confidence:.0%}")
    
    print(f"\nAgent Scores:")
    for analysis in result.agent_analyses:
        print(f"  {analysis.agent_name.value:25s}: {analysis.risk_score:4.1f}/10")
    
    print(f"\nKey Findings:")
    for i, finding in enumerate(result.judge_analysis.key_findings[:3], 1):
        print(f"  {i}. {finding}")
    
    print(f"\nTotal Time: {result.total_execution_time_sec:.1f}s")
    
    print(f"\n{'='*70}")
    print("✅ All working!")
    print('='*70)

if __name__ == "__main__":
    asyncio.run(main())
