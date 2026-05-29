"""IAM Policy parser package."""
from .policy_parser import parse_policy, PolicyParserError
from .policy_features import extract_features

__all__ = ["parse_policy", "extract_features", "PolicyParserError"]
