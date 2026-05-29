# Architecture

## System Overview
```
┌──────────────┐     ┌─────────────────┐     ┌─────────────────────────────────┐     ┌─────────────┐
│              │     │                 │     │      Security Agents            │     │             │
│  Policy      │────▶│  Parser +       │────▶│      (run in parallel)          │────▶│   Judge     │
│  JSON        │     │  Feature        │     │                                 │     │   Agent     │
│              │     │  Extraction     │     │  ┌──────────┐  ┌──────────┐    │     │             │
└──────────────┘     └─────────────────┘     │  │ Least    │  │ Priv     │    │     │  Weighted   │
                            │                │  │ Privilege│  │ Escalat. │    │     │  Scoring    │
                            ▼                │  └──────────┘  └──────────┘    │     │      +      │
                     ┌─────────────────┐     │  ┌──────────┐  ┌──────────┐    │     │  LLM Final  │
                     │ Extracts:       │     │  │ Data     │  │Compliance│    │     │  Decision   │
                     │ - Wildcards     │     │  │ Exposure │  │          │    │     │      │      │
                     │ - Privilege lvl │     │  └──────────┘  └──────────┘    │     │      ▼      │
                     │ - Sensitive ops │     └─────────────────────────────────┘     │  Fallback   │
                     │ - Danger combos │                                             │  if needed  │
                     └─────────────────┘                                             └──────┬──────┘
                                                                                           │
                                                                                           ▼
                                                                                    ┌─────────────┐
                                                                                    │   Final     │
                                                                                    │   Report    │
                                                                                    └─────────────┘
```

## Component Details

### Parser Layer
- **Policy Parser**: Validates IAM JSON, normalizes structure, handles edge cases
- **Feature Extractor**: Pulls out wildcards, privilege levels, sensitive actions, dangerous patterns

### Agent Layer
Each agent runs independently with its own LLM call:

| Agent | Focus Area | Key Checks |
|-------|------------|------------|
| Least Privilege | Overly broad permissions | Action wildcards, resource scope, specificity |
| Privilege Escalation | Dangerous combos | IAM modification, role assumption, pass-role patterns |
| Data Exposure | Data leak risks | S3 access, database permissions, secrets access |
| Compliance | Best practices | MFA conditions, policy structure, AWS guidelines |

### Judge Layer
Combines agent outputs:
1. Calculates weighted average (PE: 1.5x, DE: 1.3x, LP: 1.0x, CO: 0.8x)
2. Asks LLM for final verdict with full context
3. Falls back to deterministic scoring if LLM fails

## Data Flow

```python
# Simplified flow
parsed = parse_policy(raw_json)
features = extract_features(parsed)

# Parallel execution
tasks = [agent.analyze(features) for agent in agents]
results = await asyncio.gather(*tasks)

# Aggregation
verdict = await judge.evaluate(results)
```

## Error Handling

- LLM calls retry 3x with exponential backoff
- JSON extraction tries multiple parsing strategies  
- Judge has deterministic fallback
- Pipeline continues even if some agents fail
