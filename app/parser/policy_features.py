"""
Policy Feature Extraction - analyzes IAM policies for security characteristics.
Extracts wildcards, privilege levels, sensitive actions, and dangerous patterns.
"""
from typing import Dict, Any, List, Set
from datetime import datetime, timezone
from app.models import (
    PolicyFeatures,
    WildcardDetection,
    PrivilegeLevel,
    ResourceScope,
)

# Sensitive AWS actions that indicate high privilege
SENSITIVE_ACTIONS = {
    # IAM - identity modification
    "iam:createaccesskey", "iam:createuser", "iam:createrole",
    "iam:putuserpolicy", "iam:putrolepolicy", "iam:attachuserpolicy",
    "iam:attachrolepolicy", "iam:updateassumerolepolicy",
    
    # STS - role assumption
    "sts:assumerole", "sts:assumerolewithaml",
    
    # Security services
    "kms:decrypt", "kms:createkey", "secretsmanager:getsecretvalue",
    
    # Privilege escalation vectors
    "lambda:createfunction", "lambda:updatefunctioncode",
    "ec2:runinstances", "cloudformation:createstack",
    "cloudformation:updatestack",
}

# Actions indicating administrative control
ADMIN_ACTIONS = {
    "*", "iam:*", "s3:*", "ec2:*", "rds:*", "dynamodb:*",
}

# Read-only action patterns
READ_PATTERNS = ["get", "list", "describe", "view", "read"]

# Write action patterns  
WRITE_PATTERNS = ["put", "create", "delete", "update", "modify", "write"]

class FeatureExtractor:
    """Extracts security-relevant features from parsed IAM policy."""
    
    def __init__(self, parsed_policy: Dict[str, Any]):
        self.policy = parsed_policy
        self.statements = parsed_policy["statements"]
        
    def extract(self) -> PolicyFeatures:
        """Extract all security features."""
        
        all_actions = self._collect_all_actions()
        all_resources = self._collect_all_resources()
        all_principals = self._collect_all_principals()
        
        return PolicyFeatures(
            policy_id=self.policy["policy_id"],
            raw_policy=self.policy["raw_policy"],
            uses_wildcards=self._detect_wildcards(all_actions, all_resources, all_principals),
            privilege_level=self._classify_privilege_level(all_actions),
            resource_scope=self._calculate_resource_scope(all_resources),
            sensitive_actions=self._find_sensitive_actions(all_actions),
            dangerous_permissions=self._find_dangerous_patterns(all_actions),
            num_statements=self.policy["statement_count"],
            has_conditions=any(stmt["has_conditions"] for stmt in self.statements),
            principals=all_principals,
            parsed_at=datetime.now(timezone.utc),
        )
    
    def _collect_all_actions(self) -> List[str]:
        """Gather all actions from all statements."""
        actions = []
        for stmt in self.statements:
            if stmt["effect"] == "Allow":
                actions.extend(stmt["actions"])
        return actions
    
    def _collect_all_resources(self) -> List[str]:
        """Gather all resources from all statements."""
        resources = []
        for stmt in self.statements:
            resources.extend(stmt["resources"])
        return resources
    
    def _collect_all_principals(self) -> List[str]:
        """Gather all principals from all statements."""
        principals = []
        for stmt in self.statements:
            principals.extend(stmt["principals"])
        return list(set(principals))
    
    def _detect_wildcards(
        self, 
        actions: List[str], 
        resources: List[str],
        principals: List[str]
    ) -> WildcardDetection:
        """Detect wildcard usage in policy."""
        
        wildcard_actions = [a for a in actions if "*" in a]
        wildcard_resources = [r for r in resources if "*" in r]
        wildcard_principals = [p for p in principals if "*" in p]
        
        return WildcardDetection(
            actions=wildcard_actions,
            resources=wildcard_resources,
            principals=wildcard_principals,
        )
    
    def _classify_privilege_level(self, actions: List[str]) -> PrivilegeLevel:
        """Determine privilege level based on actions."""
        
        actions_lower = [a.lower() for a in actions]
        
        # Check for admin
        if any(a in ADMIN_ACTIONS for a in actions_lower):
            return PrivilegeLevel.ADMINISTRATIVE
        
        if "*" in actions:
            return PrivilegeLevel.ADMINISTRATIVE
        
        # Check for write
        has_write = any(
            any(pattern in action for pattern in WRITE_PATTERNS)
            for action in actions_lower
        )
        
        # Check for read
        has_read = any(
            any(pattern in action for pattern in READ_PATTERNS)
            for action in actions_lower
        )
        
        if has_write:
            return PrivilegeLevel.WRITE
        elif has_read:
            return PrivilegeLevel.READ
        
        return PrivilegeLevel.NONE

    def _calculate_resource_scope(self, resources: List[str]) -> ResourceScope:
        """Determine how broad the resource access is."""
        
        if not resources:
            return ResourceScope.SPECIFIC
        
        # Check for full wildcard
        if "*" in resources:
            return ResourceScope.ALL
        
        # Check for account-wide (arn:aws:service::account:*)
        account_wide = any(
            r.startswith("arn:aws:") and r.endswith("*") 
            for r in resources
        )
        if account_wide and any("::" in r for r in resources):
            return ResourceScope.ACCOUNT
        
        # Check for service-wide (service:*)
        service_wide = any(
            "*" in r and not r.startswith("arn:aws:")
            for r in resources
        )
        if service_wide:
            return ResourceScope.SERVICE
        
        # Check for wildcards in ARNs (service-level)
        if any("*" in r for r in resources):
            return ResourceScope.SERVICE
        
        return ResourceScope.SPECIFIC

    def _find_sensitive_actions(self, actions: List[str]) -> List[str]:
        """Find actions that are security-sensitive."""
        
        actions_lower = [a.lower() for a in actions]
        sensitive = []
        
        for action in actions_lower:
            if action in SENSITIVE_ACTIONS:
                sensitive.append(action)
        
        return sensitive

    def _find_dangerous_patterns(self, actions: List[str]) -> List[str]:
        """Identify dangerous permission combinations."""
        
        actions_set = set(a.lower() for a in actions)
        dangerous = []
        
        # Pattern 1: Lambda + PassRole (privilege escalation)
        if "lambda:createfunction" in actions_set and "iam:passrole" in actions_set:
            dangerous.append("lambda_privilege_escalation")

        # Pattern 2: EC2 + PassRole (privilege escalation)
        if "ec2:runinstances" in actions_set and "iam:passrole" in actions_set:
            dangerous.append("ec2_privilege_escalation")

        # Pattern 3: IAM modification permissions
        iam_modify = any("iam:put" in a or "iam:create" in a or "iam:attach" in a 
                        for a in actions_set)
        if iam_modify:
            dangerous.append("iam_modification")

        # Pattern 4: Full admin
        if "*" in actions_set:
            dangerous.append("full_admin_wildcard")

        # Pattern 5: CloudFormation stack manipulation
        cf_stack = "cloudformation:createstack" in actions_set or \
                   "cloudformation:updatestack" in actions_set
        if cf_stack:
            dangerous.append("cloudformation_stack_control")

        return dangerous

def extract_features(parsed_policy: Dict[str, Any]) -> PolicyFeatures:
    """
    Extract security features from parsed policy.

    Args:
        parsed_policy: Output from policy_parser.parse()

    Returns:
        PolicyFeatures object with all extracted characteristics
    """
    extractor = FeatureExtractor(parsed_policy)
    return extractor.extract()
