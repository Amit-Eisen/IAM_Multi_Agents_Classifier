"""
Run evaluation on all example policies and show results summary.
Useful for understanding system behavior and agent agreement patterns.
"""
import asyncio
import json
from pathlib import Path
from datetime import datetime
from app.orchestrator import AnalysisOrchestrator

def run_evaluation():
    """Evaluate all example policies and generate summary report."""
    
    policy_dir = Path("example_policies")
    policy_files = sorted(policy_dir.glob("*.json"))
    
    print("=" * 80)
    print("IAM SECURITY ANALYSIS - EVALUATION REPORT")
    print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print("=" * 80)
    print(f"\nAnalyzing {len(policy_files)} policies...\n")
    
    # Load policies
    policies = {}
    for pf in policy_files:
        with open(pf) as f:
            policies[pf.stem] = json.load(f)
    
    # Run analysis
    orchestrator = AnalysisOrchestrator()
    results = asyncio.run(orchestrator.analyze_policies_batch(policies))
    
    # Results table
    print("\n" + "=" * 80)
    print("RESULTS SUMMARY")
    print("=" * 80)
    print(f"\n{'Policy':<12} {'Verdict':<18} {'Score':>6} {'LP':>5} {'PE':>5} {'DE':>5} {'CO':>5} {'Agree':>6}")
    print("-" * 80)
    
    verdicts = {"SECURE": 0, "NEEDS_IMPROVEMENT": 0, "WEAK": 0, "CRITICAL_RISK": 0}
    all_scores = []
    agreement_scores = []
    
    for name in sorted(results.keys(), key=lambda x: int(x.replace('policy', ''))):
        r = results[name]
        j = r.judge_analysis
        
        # Get individual agent scores
        agent_scores = {a.agent_name.value: a.risk_score for a in r.agent_analyses}
        lp = agent_scores.get("least_privilege", 0)
        pe = agent_scores.get("privilege_escalation", 0)
        de = agent_scores.get("data_exposure", 0)
        co = agent_scores.get("compliance", 0)
        
        agree = j.agent_consensus.agreement_level.value[:3].upper()
        
        print(f"{name:<12} {j.final_verdict.value:<18} {j.overall_risk_score:>5.1f} {lp:>5.1f} {pe:>5.1f} {de:>5.1f} {co:>5.1f} {agree:>6}")
        
        verdicts[j.final_verdict.value] = verdicts.get(j.final_verdict.value, 0) + 1
        all_scores.append(j.overall_risk_score)
        agreement_scores.append(j.agent_consensus.agreement_score)
    
    # Summary stats
    print("-" * 80)
    print(f"\nLegend: LP=Least Privilege, PE=Privilege Escalation, DE=Data Exposure, CO=Compliance")
    
    print("\n" + "=" * 80)
    print("STATISTICS")
    print("=" * 80)
    
    print(f"\nVerdict Distribution:")
    for v, count in verdicts.items():
        if count > 0:
            pct = count / len(results) * 100
            bar = "█" * int(pct / 5)
            print(f"  {v:<18}: {count:>2} ({pct:>5.1f}%) {bar}")
    
    avg_score = sum(all_scores) / len(all_scores)
    avg_agreement = sum(agreement_scores) / len(agreement_scores)
    
    print(f"\nRisk Scores:")
    print(f"  Average: {avg_score:.1f}/10")
    print(f"  Min: {min(all_scores):.1f}/10")
    print(f"  Max: {max(all_scores):.1f}/10")
    
    print(f"\nAgent Agreement:")
    print(f"  Average: {avg_agreement:.0%}")
    
    # High risk policies
    high_risk = [(n, r.judge_analysis.overall_risk_score) for n, r in results.items() 
                 if r.judge_analysis.overall_risk_score >= 8]
    if high_risk:
        print(f"\nHigh Risk Policies (≥8.0):")
        for name, score in sorted(high_risk, key=lambda x: -x[1]):
            print(f"  - {name}: {score:.1f}/10")
    
    # Save detailed results
    output_file = Path("results/evaluation_report.json")
    output_file.parent.mkdir(exist_ok=True)
    
    report = {
        "timestamp": datetime.now().isoformat(),
        "total_policies": len(results),
        "verdict_distribution": verdicts,
        "average_risk_score": round(avg_score, 2),
        "average_agreement": round(avg_agreement, 2),
        "policies": {}
    }
    
    for name, r in results.items():
        report["policies"][name] = {
            "verdict": r.judge_analysis.final_verdict.value,
            "risk_score": r.judge_analysis.overall_risk_score,
            "agent_scores": {a.agent_name.value: a.risk_score for a in r.agent_analyses},
            "key_findings": r.judge_analysis.key_findings[:3],
        }
    
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n" + "=" * 80)
    print(f"Full report saved to: {output_file}")
    print("=" * 80)

if __name__ == "__main__":
    run_evaluation()
