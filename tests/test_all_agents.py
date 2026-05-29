"""Test all 4 security agents with different policies."""
import asyncio
import json
from pathlib import Path
from app.parser import parse_policy, extract_features
from app.agents import (
    LeastPrivilegeAgent,
    PrivilegeEscalationAgent,
    DataExposureAgent,
    ComplianceAgent,
)
from app.llm import LLMFactory


async def test_policy_with_all_agents(policy_file: Path):
    """Run all 4 agents on a single policy."""
    print(f"\n{'='*70}")
    print(f"TESTING: {policy_file.name}")
    print('='*70)
    
    # Load and parse policy
    with open(policy_file) as f:
        policy = json.load(f)
    
    parsed = parse_policy(policy)
    features = extract_features(parsed)
    
    print(f"\n[PARSER] Policy Features:")
    print(f"  Privilege Level: {features.privilege_level.value}")
    print(f"  Resource Scope: {features.resource_scope.value}")
    print(f"  Dangerous Patterns: {features.dangerous_permissions}")
    print(f"  Has Conditions: {features.has_conditions}")
    
    # Create LLM client
    llm = LLMFactory.create()
    print(f"\n[LLM] Using: {llm.model}")
    
    # Create all 4 agents
    agents = [
        ("Least Privilege", LeastPrivilegeAgent(llm)),
        ("Privilege Escalation", PrivilegeEscalationAgent(llm)),
        ("Data Exposure", DataExposureAgent(llm)),
        ("Compliance", ComplianceAgent(llm)),
    ]
    
    results = []
    
    # Run each agent
    for agent_name, agent in agents:
        print(f"\n[{agent_name.upper()}] Analyzing...")
        try:
            result = await agent.analyze(features)
            results.append((agent_name, result))
            
            print(f"  Risk Score: {result.risk_score}/10")
            print(f"  Verdict: {result.verdict.value}")
            print(f"  Findings: {len(result.findings)}")
            print(f"  Time: {result.execution_time_sec}s")
            
        except Exception as e:
            print(f"  ERROR: {e}")
            results.append((agent_name, None))
    
    # Summary
    print(f"\n{'='*70}")
    print("SUMMARY")
    print('='*70)
    
    successful = [r for r in results if r[1] is not None]
    
    if successful:
        avg_risk = sum(r[1].risk_score for r in successful) / len(successful)
        print(f"\nAgents Completed: {len(successful)}/4")
        print(f"Average Risk Score: {avg_risk:.1f}/10")
        
        print(f"\nAgent Breakdown:")
        for agent_name, result in results:
            if result:
                print(f"  {agent_name:25s}: {result.risk_score:4.1f}/10  ({result.verdict.value})")
            else:
                print(f"  {agent_name:25s}: FAILED")
        
        print(f"\nTop Findings:")
        finding_count = 0
        for agent_name, result in results:
            if result and result.findings:
                for finding in result.findings[:2]:  # Top 2 per agent
                    finding_count += 1
                    print(f"  {finding_count}. [{finding.severity.value}] {finding.issue}")
                    print(f"     Agent: {agent_name}")
    else:
        print("\nAll agents failed!")
    
    return results


async def main():
    print("\n" + "="*70)
    print("MULTI-AGENT IAM SECURITY ANALYSIS - COMPREHENSIVE TEST")
    print("="*70)
    
    # Test with 3 diverse policies
    test_policies = [
        "policy1.json",   # Full wildcard - should trigger all agents
        "policy9.json",   # Privilege escalation - should hit PrivEsc agent hard
        "policy10.json",  # Data exposure - should hit DataExposure agent
        "policy12.json",  # Secure with MFA - should score well
    ]
    
    all_results = {}
    
    for policy_name in test_policies:
        policy_file = Path("example_policies") / policy_name
        if policy_file.exists():
            try:
                results = await test_policy_with_all_agents(policy_file)
                all_results[policy_name] = results
            except Exception as e:
                print(f"\n[ERROR] Failed to process {policy_name}: {e}")
                import traceback
                traceback.print_exc()
        else:
            print(f"\n[SKIP] {policy_name} not found")
    
    # Final summary
    print(f"\n{'='*70}")
    print("FINAL SUMMARY - ALL POLICIES")
    print('='*70)
    
    for policy_name, results in all_results.items():
        successful = [r for r in results if r[1] is not None]
        if successful:
            avg_risk = sum(r[1].risk_score for r in successful) / len(successful)
            print(f"\n{policy_name:20s}: Avg Risk {avg_risk:4.1f}/10  ({len(successful)}/4 agents)")
        else:
            print(f"\n{policy_name:20s}: FAILED")
    
    print(f"\n{'='*70}")
    print("Test Complete!")
    print('='*70)


if __name__ == "__main__":
    asyncio.run(main())
