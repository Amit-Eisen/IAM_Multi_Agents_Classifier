# IAM Policy Security Analyzer

Automated security review for AWS IAM policies. Uses multiple specialized LLM agents running in parallel to catch risks that manual review often misses.

## Why This Exists

IAM misconfigurations are behind most AWS breaches. Reviewing policies manually is slow, inconsistent, and doesn't scale. This tool runs 4 focused security checks simultaneously, then aggregates findings into a single verdict with prioritized recommendations.

Think of it as having 4 security engineers review every policy in ~20 seconds instead of 20 minutes.

<!-- TODO: Add architecture diagram image -->
<!-- ![Architecture](docs/architecture.png) -->

## Demo

<!-- TODO: Add screenshot/gif of the dashboard -->
<!-- ![Dashboard Demo](docs/demo.png) -->

*Upload a policy JSON → get a risk score, findings breakdown, and fix recommendations*

## How It Works

```
Policy JSON → Parser → 4 Security Agents (parallel) → Judge Agent → Final Report
                              ↓
                       Each agent focuses on:
                       - Least Privilege violations
                       - Privilege Escalation paths  
                       - Data Exposure risks
                       - Compliance gaps
```

The parser extracts features (wildcards, privilege levels, sensitive actions). Each agent scores the policy 0-10 from their perspective. The Judge combines scores with weighted averaging (privilege escalation weighted highest since it's the most dangerous) and produces a final verdict.

If the LLM fails for any reason, there's fallback logic using deterministic scoring so you still get results.

## Quick Start

```bash
# Clone and setup
git clone https://github.com/YOUR_USERNAME/iam-policy-analyzer.git
cd iam-policy-analyzer

python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

# Configure
cp .env.example .env
# Edit .env → add your OPENAI_API_KEY

# Run the dashboard
python main.py ui

# Or from command line
python main.py analyze example_policies/policy1.json
```

### Docker (recommended)

```bash
docker compose up
# Open http://localhost:8501
```

## Example Output

```
Analyzing: admin-policy.json

Verdict: CRITICAL_RISK
Risk Score: 9.2/10
Confidence: 94%

Agent Scores:
  Least Privilege      : 9.5/10
  Privilege Escalation : 10.0/10  ← weighted 1.5x
  Data Exposure        : 8.5/10
  Compliance           : 8.7/10

Top Findings:
  1. Full admin wildcard (*:*) - can do anything
  2. No MFA condition on sensitive actions
  3. Can assume any role (sts:AssumeRole on *)

Execution: 18.3s | Cost: ~$0.004
```

## Project Structure

```
├── app/
│   ├── agents/          # 4 security agents + judge
│   ├── parser/          # Policy parsing, feature extraction
│   ├── orchestrator/    # Pipeline coordination  
│   ├── llm/             # OpenAI/Ollama clients
│   ├── ui/              # Streamlit dashboard
│   └── models/          # Pydantic schemas
├── example_policies/    # Test policies (various risk levels)
├── tests/               # Unit & integration tests
└── docs/                # Architecture diagrams, screenshots
```

## Evaluation Results

Tested on 12 policies ranging from secure to extremely dangerous:

| Verdict | Count | % |
|---------|-------|---|
| CRITICAL_RISK | 7 | 58% |
| NEEDS_IMPROVEMENT | 5 | 42% |

- Average risk score: 7.2/10
- Agent agreement: 87%
- Avg execution time: ~20s per policy

## Configuration

Key settings in `.env`:

```bash
LLM_PROVIDER=openai          # or "ollama" for local
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-4o-mini     # good balance of cost/quality
TEMPERATURE=0.0              # deterministic outputs
```

See `.env.example` for all options.

## Agent Weights

The Judge uses weighted scoring because not all risks are equal:

| Agent | Weight | Rationale |
|-------|--------|-----------|
| Privilege Escalation | 1.5x | Can lead to full account compromise |
| Data Exposure | 1.3x | Direct data breach risk |
| Least Privilege | 1.0x | Important but sometimes intentional |
| Compliance | 0.8x | Best practices, lower immediate risk |

## Limitations

- LLM-based analysis can occasionally miss edge cases or hallucinate findings
- Not a replacement for AWS IAM Access Analyzer or formal policy analysis
- Tested primarily on gpt-4o-mini; other models may vary
- Token costs add up on large policy batches (~$0.002-0.005 per policy)

## Tech Stack

- Python 3.10+
- OpenAI GPT-4o-mini (or Ollama for local dev)
- Streamlit for the UI
- Pydantic for data validation
- asyncio for parallel agent execution

## License

MIT

---

**Author:** Amit Eisen | [LinkedIn](your-linkedin-url) | [Email](eisenamit96@gmail.com)
