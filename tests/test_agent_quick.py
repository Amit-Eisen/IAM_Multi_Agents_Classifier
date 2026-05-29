"""Quick test for agent - verifies it works end-to-end."""
import asyncio
import json
from pathlib import Path
from app.parser import parse_policy, extract_features
from app.agents import LeastPrivilegeAgent
from app.llm import LLMFactory

async def test_agent_with_policy(policy_file: Path):
    """Test agent with a single policy."""
    print(f"\n{'='*60}")
    print(f"Testing: {policy_file.name}")
    print('='*60)

    # Load policy
    with open(policy_file) as f:
        policy = json.load(f)

    # Parse and extract features
    parsed = parse_policy(policy)
    features = extract_features(parsed)

    print(f"\n[Parser] Features extracted:")
    print(f"  Privilege: {features.privilege_level.value}")
    print(f"  Resource Scope: {features.resource_scope.value}")
    print(f"  Dangerous Patterns: {features.dangerous_permissions}")

    # Create agent
    llm = LLMFactory.create()
    agent = LeastPrivilegeAgent(llm)

    print(f"\n[Agent] Analyzing with {llm.model}...")

    # Analyze
    result = await agent.analyze(features)

    print(f"\n[Results]")
    print(f"  Risk Score: {result.risk_score}/10")
    print(f"  Verdict: {result.verdict.value}")
    print(f"  Execution Time: {result.execution_time_sec}s")
    print(f"\n  Risk Breakdown:")
    for dim, score in result.risk_breakdown.dimensions.items():
        print(f"    {dim}: {score}/10")

    print(f"\n  Findings ({len(result.findings)}):")
    for i, finding in enumerate(result.findings, 1):
        print(f"    {i}. [{finding.severity.value}] {finding.issue}")
        print(f"       Location: {finding.location}")
        print(f"       Fix: {finding.recommendation}")

    print(f"\n  Explanation:")
    print(f"    {result.explanation}")

async def main():
    print("\nTesting Least Privilege Agent")

    # Test with a few key policies
    test_policies = [
        "policy1.json",   # Full wildcard - should be CRITICAL
        "policy9.json",   # Privilege escalation - should be HIGH
        "policy12.json",  # Secure with MFA - should be LOW
    ]

    for policy_name in test_policies:
        policy_file = Path("example_policies") / policy_name
        if policy_file.exists():
            try:
                await test_agent_with_policy(policy_file)
            except Exception as e:
                print(f"\n[ERROR] {e}")
                import traceback
                traceback.print_exc()
        else:
            print(f"\n[SKIP] {policy_name} not found")
    
    print(f"\n{'='*60}")
    print("Agent test complete!")
    print('='*60)

if __name__ == "__main__":
    asyncio.run(main())
