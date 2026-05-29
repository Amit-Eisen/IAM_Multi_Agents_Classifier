"""Quick test for parser - verifies it works with example policies."""
import json
from pathlib import Path
from app.parser import parse_policy, extract_features


def test_policy(policy_file: Path):
    """Test parser with a policy file."""
    print(f"\n{'='*60}")
    print(f"Testing: {policy_file.name}")
    print('='*60)
    
    with open(policy_file) as f:
        policy = json.load(f)
    
    # Parse
    parsed = parse_policy(policy)
    print(f"[OK] Parsed successfully")
    print(f"  Statements: {parsed['statement_count']}")
    
    # Extract features
    features = extract_features(parsed)
    print(f"[OK] Features extracted")
    print(f"  Privilege Level: {features.privilege_level.value}")
    print(f"  Resource Scope: {features.resource_scope.value}")
    print(f"  Wildcard Actions: {len(features.uses_wildcards.actions)}")
    print(f"  Wildcard Resources: {len(features.uses_wildcards.resources)}")
    print(f"  Sensitive Actions: {len(features.sensitive_actions)}")
    print(f"  Dangerous Patterns: {features.dangerous_permissions}")
    print(f"  Has Conditions: {features.has_conditions}")


def main():
    policy_dir = Path("example_policies")
    policies = sorted(policy_dir.glob("*.json"))
    
    print(f"\nTesting Parser with {len(policies)} policies")
    
    for policy_file in policies:
        try:
            test_policy(policy_file)
        except Exception as e:
            print(f"[ERROR] {e}")
            import traceback
            traceback.print_exc()
    
    print(f"\n{'='*60}")
    print("Parser test complete!")
    print('='*60)


if __name__ == "__main__":
    main()
