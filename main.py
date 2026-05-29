"""
IAM Security Analysis - Main Entry Point
Run analysis from command line or start the UI.
"""
import sys
import json
import asyncio
from pathlib import Path

def run_ui():
    """Start the Streamlit UI"""
    import subprocess
    subprocess.run([sys.executable, "-m", "streamlit", "run", "app/ui/streamlit_app.py"])

def run_analysis(policy_path: str, output_path: str = None):
    """Run analysis on a single policy file"""
    from app.orchestrator import analyze_iam_policy
    
    policy_file = Path(policy_path)
    if not policy_file.exists():
        print(f"Error: Policy file not found: {policy_path}")
        sys.exit(1)
    
    print(f"Loading policy: {policy_file.name}")
    with open(policy_file) as f:
        policy = json.load(f)
    
    print("Running analysis...")
    print("  - Parsing policy")
    print("  - Running 4 security agents in parallel")
    print("  - Aggregating with Judge agent")
    print()
    
    result = asyncio.run(analyze_iam_policy(policy, policy_name=policy_file.stem))
    
    # Display results
    print("=" * 60)
    print("ANALYSIS RESULTS")
    print("=" * 60)
    print(f"\nVerdict: {result.judge_analysis.final_verdict.value}")
    print(f"Risk Score: {result.judge_analysis.overall_risk_score}/10")
    print(f"Confidence: {result.judge_analysis.confidence:.0%}")
    
    print("\nAgent Scores:")
    for analysis in result.agent_analyses:
        print(f"  {analysis.agent_name.value:25s}: {analysis.risk_score:.1f}/10")
    
    print("\nKey Findings:")
    for i, finding in enumerate(result.judge_analysis.key_findings[:5], 1):
        print(f"  {i}. {finding}")
    
    print(f"\nExecution Time: {result.total_execution_time_sec:.1f}s")
    if result.total_cost_usd > 0:
        print(f"Estimated Cost: ${result.total_cost_usd:.4f}")
    if result.total_tokens > 0:
        print(f"Tokens Used: {result.total_tokens:,}")
    
    # Save to file if requested
    if output_path:
        output = {
            "analysis_id": result.analysis_id,
            "policy_name": policy_file.stem,
            "verdict": result.judge_analysis.final_verdict.value,
            "risk_score": result.judge_analysis.overall_risk_score,
            "key_findings": result.judge_analysis.key_findings,
        }
        with open(output_path, 'w') as f:
            json.dump(output, f, indent=2)
        print(f"\nResults saved to: {output_path}")
    
    print("=" * 60)

def run_batch(policy_dir: str):
    """Run analysis on all policies in a directory"""
    from app.orchestrator import AnalysisOrchestrator
    
    policy_path = Path(policy_dir)
    if not policy_path.exists() or not policy_path.is_dir():
        print(f"Error: Directory not found: {policy_dir}")
        sys.exit(1)
    
    policy_files = list(policy_path.glob("*.json"))
    if not policy_files:
        print(f"No JSON files found in {policy_dir}")
        sys.exit(1)
    
    print(f"Found {len(policy_files)} policies to analyze")
    
    # Load all policies
    policies = {}
    for pf in policy_files:
        with open(pf) as f:
            policies[pf.stem] = json.load(f)
    
    orchestrator = AnalysisOrchestrator()
    results = asyncio.run(orchestrator.analyze_policies_batch(policies))
    
    print("\n" + "=" * 60)
    print("BATCH RESULTS")
    print("=" * 60)
    
    for name, result in results.items():
        verdict = result.judge_analysis.final_verdict.value
        score = result.judge_analysis.overall_risk_score
        print(f"  {name:20s}: {verdict:20s} ({score:.1f}/10)")
    
    print("=" * 60)
    print(f"Analyzed {len(results)}/{len(policies)} policies successfully")

def run_eval():
    """Run evaluation on all example policies"""
    from evaluate import run_evaluation
    run_evaluation()

def generate_presentation():
    """Generate presentation materials (charts, stats)"""
    from generate_presentation_materials import main
    main()

def run_generate():
    """Generate synthetic test policies"""
    from generate_policies import main as gen_main
    gen_main()

def print_help():
    print("""
IAM Policy Security Analyzer
============================

Usage:
  python main.py ui                     Start web dashboard
  python main.py analyze <policy.json>  Analyze single policy
  python main.py analyze <policy.json> -o results.json  Save to file
  python main.py batch <directory>      Analyze all JSON files in folder
  python main.py eval                   Run eval on example_policies/
  python main.py generate               Create synthetic test policies
  python main.py help                   Show this

Examples:
  python main.py ui
  python main.py analyze example_policies/policy1.json
  python main.py batch generated_policies
""")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print_help()
        sys.exit(0)
    
    command = sys.argv[1].lower()
    
    if command == "ui":
        run_ui()
    
    elif command == "analyze":
        if len(sys.argv) < 3:
            print("Error: Please specify a policy file")
            print("Usage: python main.py analyze <policy.json>")
            sys.exit(1)
        
        output = None
        if "-o" in sys.argv:
            idx = sys.argv.index("-o")
            if idx + 1 < len(sys.argv):
                output = sys.argv[idx + 1]
        
        run_analysis(sys.argv[2], output)
    
    elif command == "batch":
        if len(sys.argv) < 3:
            print("Error: Please specify a directory")
            print("Usage: python main.py batch <directory>")
            sys.exit(1)
        run_batch(sys.argv[2])
    
    elif command == "eval":
        run_eval()
    
    elif command == "presentation" or command == "pres":
        generate_presentation()
    
    elif command == "generate" or command == "gen":
        run_generate()
    
    elif command == "help" or command == "--help" or command == "-h":
        print_help()
    
    else:
        print(f"Unknown command: {command}")
        print_help()
        sys.exit(1)
