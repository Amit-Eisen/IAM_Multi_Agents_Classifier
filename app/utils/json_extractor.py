"""
Robust JSON extraction from LLM responses.
Handles cases where LLMs return JSON wrapped in markdown, text, or malformed.
"""
import json
import re
from typing import Dict, Any, Optional


def extract_json_from_text(text: str) -> Optional[Dict[str, Any]]:
    """
    Extract JSON from LLM responses that might have markdown formatting or extra text.
    Tries direct parse, then markdown blocks, then brace matching.
    """
    if not text or not text.strip():
        return None
    
    text = text.strip()
    
    # Try direct parse first
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    
    markdown_patterns = [
        r'```json\s*\n(.*?)\n```',
        r'```\s*\n(.*?)\n```',
        r'`(.*?)`'
    ]

    for pattern in markdown_patterns:
        matches = re.findall(pattern, text, re.DOTALL)
        for match in matches:
            try:
                return json.loads(match.strip())
            except json.JSONDecodeError:
                continue

    json_obj = _extract_with_brace_matching(text)
    if json_obj:
        return json_obj
    
    cleaned = _clean_json_string(text)
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass
    
    return None


def _extract_with_brace_matching(text: str) -> Optional[Dict[str, Any]]:
    """Extract JSON using brace matching."""
    brace_stack = []
    start_idx = None
    
    for idx, char in enumerate(text):
        if char == '{':
            if not brace_stack:
                start_idx = idx
            brace_stack.append('{')
        elif char == '}':
            if brace_stack:
                brace_stack.pop()
                if not brace_stack and start_idx is not None:
                    candidate = text[start_idx:idx + 1]
                    try:
                        return json.loads(candidate)
                    except json.JSONDecodeError:
                        continue
    
    return None


def _clean_json_string(text: str) -> str:
    """Clean common JSON formatting issues."""
    text = text.strip()
    
    # Remove commo prefixes
    prefixes = ["Here's the JSON:", "JSON:", "Output:", "Result:"]
    for prefix in prefixes:
        if text.startswith(prefix):
            text = text[len(prefix):].strip()

    if '"' not in text and "'" in text:
        text = text.replace("'", '"')
    
    text = re.sub(r',\s*}', '}', text)
    text = re.sub(r',\s*]', ']', text)

    text = text.encode('utf-8', errors='ignore').decode('utf-8', errors='ignore')

    return text

def validate_agent_response(response: Dict[str, Any], required_fields: list) -> bool:
    """
    Returns True if response has all required fields, False otherwise
    """

    if not isinstance(response, dict):
        return False

    return all(field in response for field in required_fields)
