"""
Generate presentation materials - stats, visualizations, summary data.
Run this to create files you can use in your presentation.
"""
import json
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from pathlib import Path
from collections import Counter

def load_evaluation_results():
    """Load the evaluation report"""
    report_path = Path("results/evaluation_report.json")
    if not report_path.exists():
        print("Error: Run 'python main.py eval' first to generate evaluation report")
        return None
    with open(report_path) as f:
        return json.load(f)

def create_verdict_distribution_chart():
    """Create pie chart of verdict distribution"""
    report = load_evaluation_results()
    if not report:
        return
    
    verdicts = report["verdict_distribution"]
    labels = [v for v, count in verdicts.items() if count > 0]
    sizes = [count for v, count in verdicts.items() if count > 0]
    colors = {
        "SECURE": "#2ecc71",
        "NEEDS_IMPROVEMENT": "#f39c12", 
        "WEAK": "#e74c3c",
        "CRITICAL_RISK": "#c0392b"
    }
    
    fig, ax = plt.subplots(figsize=(8, 8))
    wedges, texts, autotexts = ax.pie(
        sizes, 
        labels=labels,
        autopct='%1.1f%%',
        colors=[colors.get(l, "#95a5a6") for l in labels],
        startangle=90
    )
    
    plt.setp(autotexts, size=12, weight="bold", color="white")
    plt.setp(texts, size=11, weight="bold")
    
    ax.set_title("Verdict Distribution Across 12 Test Policies", 
                 fontsize=16, fontweight="bold", pad=20)
    
    plt.tight_layout()
    plt.savefig("presentation/verdict_distribution.png", dpi=300, bbox_inches='tight')
    print("[OK] Created: presentation/verdict_distribution.png")
    plt.close()

def create_risk_score_distribution():
    """Create histogram of risk scores"""
    report = load_evaluation_results()
    if not report:
        return
    
    scores = []
    for policy_data in report["policies"].values():
        scores.append(policy_data["risk_score"])
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    n, bins, patches = ax.hist(scores, bins=10, range=(0, 10), 
                               edgecolor='black', linewidth=1.2)
    
    # Color bars by risk level
    for i, patch in enumerate(patches):
        if bins[i] < 3:
            patch.set_facecolor('#2ecc71')  # green
        elif bins[i] < 6:
            patch.set_facecolor('#f39c12')  # orange
        elif bins[i] < 8:
            patch.set_facecolor('#e74c3c')  # red
        else:
            patch.set_facecolor('#c0392b')  # dark red
    
    ax.set_xlabel("Risk Score (0-10)", fontsize=12, fontweight="bold")
    ax.set_ylabel("Number of Policies", fontsize=12, fontweight="bold")
    ax.set_title("Risk Score Distribution", fontsize=14, fontweight="bold")
    ax.set_xlim(0, 10)
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    
    # Add average line
    avg_score = report["average_risk_score"]
    ax.axvline(avg_score, color='blue', linestyle='--', linewidth=2, 
               label=f'Average: {avg_score:.1f}')
    ax.legend()
    
    plt.tight_layout()
    plt.savefig("presentation/risk_score_distribution.png", dpi=300, bbox_inches='tight')
    print("[OK] Created: presentation/risk_score_distribution.png")
    plt.close()

def create_agent_comparison():
    """Create bar chart comparing agent scores"""
    report = load_evaluation_results()
    if not report:
        return
    
    agent_totals = {
        "Least Privilege": 0,
        "Privilege Escalation": 0,
        "Data Exposure": 0,
        "Compliance": 0
    }
    
    count = 0
    for policy_data in report["policies"].values():
        agent_scores = policy_data["agent_scores"]
        agent_totals["Least Privilege"] += agent_scores.get("least_privilege", 0)
        agent_totals["Privilege Escalation"] += agent_scores.get("privilege_escalation", 0)
        agent_totals["Data Exposure"] += agent_scores.get("data_exposure", 0)
        agent_totals["Compliance"] += agent_scores.get("compliance", 0)
        count += 1
    
    # Calculate averages
    agent_avgs = {k: v / count for k, v in agent_totals.items()}
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    agents = list(agent_avgs.keys())
    scores = list(agent_avgs.values())
    colors = ['#3498db', '#e74c3c', '#9b59b6', '#f39c12']
    
    bars = ax.bar(agents, scores, color=colors, edgecolor='black', linewidth=1.5)
    
    # Add value labels on bars
    for bar, score in zip(bars, scores):
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                f'{score:.1f}',
                ha='center', va='bottom', fontsize=11, fontweight='bold')
    
    ax.set_ylabel("Average Risk Score", fontsize=12, fontweight="bold")
    ax.set_title("Average Risk Scores by Agent Type", fontsize=14, fontweight="bold")
    ax.set_ylim(0, 10)
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    plt.xticks(rotation=15, ha='right')
    
    plt.tight_layout()
    plt.savefig("presentation/agent_comparison.png", dpi=300, bbox_inches='tight')
    print("[OK] Created: presentation/agent_comparison.png")
    plt.close()

def create_architecture_diagram():
    """Create simple architecture flow diagram"""
    fig, ax = plt.subplots(figsize=(14, 6))
    ax.axis('off')
    
    # Boxes
    boxes = [
        ("Policy\nJSON", 1, 0.5, '#3498db'),
        ("Parser\n+ Features", 3, 0.5, '#2ecc71'),
        ("4 Agents\n(Parallel)", 6, 0.5, '#e74c3c'),
        ("Judge\n+ Weighted\nScoring", 9, 0.5, '#f39c12'),
        ("Final\nReport", 11.5, 0.5, '#9b59b6'),
    ]
    
    for label, x, y, color in boxes:
        box = mpatches.FancyBboxPatch(
            (x-0.6, y-0.3), 1.2, 0.6,
            boxstyle="round,pad=0.1",
            facecolor=color,
            edgecolor='black',
            linewidth=2
        )
        ax.add_patch(box)
        ax.text(x, y, label, ha='center', va='center', 
                fontsize=10, fontweight='bold', color='white')
    
    # Arrows
    for i in range(len(boxes) - 1):
        ax.annotate('', xy=(boxes[i+1][1]-0.6, boxes[i+1][2]), 
                   xytext=(boxes[i][1]+0.6, boxes[i][2]),
                   arrowprops=dict(arrowstyle='->', lw=2, color='black'))
    
    ax.set_xlim(0, 13)
    ax.set_ylim(0, 1)
    ax.set_title("System Architecture Flow", fontsize=16, fontweight="bold", pad=20)
    
    plt.tight_layout()
    plt.savefig("presentation/architecture_diagram.png", dpi=300, bbox_inches='tight')
    print("[OK] Created: presentation/architecture_diagram.png")
    plt.close()

def create_summary_stats():
    """Create text file with key statistics"""
    report = load_evaluation_results()
    if not report:
        return
    
    output = []
    output.append("=" * 60)
    output.append("IAM SECURITY ANALYSIS - KEY STATISTICS")
    output.append("=" * 60)
    output.append("")
    output.append(f"Total Policies Analyzed: {report['total_policies']}")
    output.append(f"Average Risk Score: {report['average_risk_score']:.2f}/10")
    output.append(f"Average Agent Agreement: {report['average_agreement']:.0%}")
    output.append("")
    output.append("Verdict Distribution:")
    for verdict, count in report['verdict_distribution'].items():
        if count > 0:
            pct = count / report['total_policies'] * 100
            output.append(f"  {verdict:20s}: {count:2d} ({pct:5.1f}%)")
    output.append("")
    output.append("High Risk Policies (>=8.0):")
    high_risk = [(name, data['risk_score']) 
                 for name, data in report['policies'].items() 
                 if data['risk_score'] >= 8.0]
    high_risk.sort(key=lambda x: -x[1])
    for name, score in high_risk:
        output.append(f"  {name}: {score:.1f}/10")
    output.append("")
    output.append("=" * 60)
    
    Path("presentation").mkdir(exist_ok=True)
    with open("presentation/key_statistics.txt", 'w', encoding='utf-8') as f:
        f.write('\n'.join(output))
    
    print("[OK] Created: presentation/key_statistics.txt")
    print('\n'.join(output))

def main():
    """Generate all presentation materials"""
    Path("presentation").mkdir(exist_ok=True)
    
    print("Generating presentation materials...\n")
    
    create_summary_stats()
    print()
    
    try:
        create_verdict_distribution_chart()
        create_risk_score_distribution()
        create_agent_comparison()
        create_architecture_diagram()
    except ImportError:
        print("\n[WARNING] matplotlib not installed. Install with: pip install matplotlib")
        print("   Charts not generated, but text stats are available.")
    except Exception as e:
        print(f"\n[WARNING] Error generating charts: {e}")
        print("   Text stats are still available.")
    
    print("\n" + "=" * 60)
    print("[SUCCESS] Presentation materials generated in 'presentation/' folder")
    print("=" * 60)

if __name__ == "__main__":
    main()
