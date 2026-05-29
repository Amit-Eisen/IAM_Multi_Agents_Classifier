"""
IAM Policy Parser - validates and normalizes AWS IAM policy JSON.
Handles edge cases like single statements, missing fields, malformed structure.
"""
import json
from typing import Dict, Any, List, Optional
from uuid import uuid4


class PolicyParserError(Exception):
    pass


class PolicyParser:
    """Validates and normalizes IAM policy JSON"""
    
    def __init__(self, policy: Dict[str, Any]):
        self.raw_policy = policy
        self.policy_id = str(uuid4())
        
    def parse(self) -> Dict[str, Any]:
        """Parse and normalize the policy structure"""
        self._validate_basic_structure()
        statements = self._normalize_statements()
        
        return {
            "policy_id": self.policy_id,
            "raw_policy": self.raw_policy,
            "version": self.raw_policy.get("Version", "2012-10-17"),
            "statements": statements,
            "statement_count": len(statements),
        }
    
    def _validate_basic_structure(self):
        """Ensure policy has required fields."""
        if not isinstance(self.raw_policy, dict):
            raise PolicyParserError("Policy must be a dictionary")
        
        if "Statement" not in self.raw_policy:
            raise PolicyParserError("Policy missing 'Statement' field")
        
        statements = self.raw_policy["Statement"]
        if not statements:
            raise PolicyParserError("Policy has empty Statement array")
    
    def _normalize_statements(self) -> List[Dict[str, Any]]:
        """
        Normalize statements to consistent format.
        Handles single statement (dict) vs array of statements.
        """
        statements = self.raw_policy["Statement"]
        
        # Convert single statement to array
        if isinstance(statements, dict):
            statements = [statements]
        
        normalized = []
        for idx, stmt in enumerate(statements):
            normalized.append(self._normalize_statement(stmt, idx))
        
        return normalized
    
    def _normalize_statement(self, stmt: Dict[str, Any], index: int) -> Dict[str, Any]:
        """Normalize a single statement."""
        
        # Extract core fields
        effect = stmt.get("Effect", "Allow")
        actions = self._normalize_to_list(stmt.get("Action", []))
        resources = self._normalize_to_list(stmt.get("Resource", []))
        principals = self._extract_principals(stmt.get("Principal"))
        conditions = stmt.get("Condition", {})
        
        return {
            "index": index,
            "sid": stmt.get("Sid", f"Statement{index}"),
            "effect": effect,
            "actions": actions,
            "resources": resources,
            "principals": principals,
            "conditions": conditions,
            "has_conditions": bool(conditions),
        }
    
    def _normalize_to_list(self, value: Any) -> List[str]:
        """Convert string or list to list of strings."""
        if isinstance(value, str):
            return [value]
        elif isinstance(value, list):
            return [str(v) for v in value]
        return []
    
    def _extract_principals(self, principal: Any) -> List[str]:
        """Extract principals from various formats."""
        if not principal:
            return []
        
        if principal == "*":
            return ["*"]
        
        if isinstance(principal, str):
            return [principal]
        
        if isinstance(principal, dict):
            principals = []
            for key, value in principal.items():
                if isinstance(value, list):
                    principals.extend(value)
                else:
                    principals.append(str(value))
            return principals
        
        return []


def parse_policy(policy_json: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parse IAM policy JSON.
    
    Args:
        policy_json: Raw IAM policy dictionary
        
    Returns:
        Normalized policy structure
        
    Raises:
        PolicyParserError: If policy is invalid
    """
    parser = PolicyParser(policy_json)
    return parser.parse()
