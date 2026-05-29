"""
Streamlit UI for IAM Multi-Agent Security Analysis System.
Simple, interactive interface for policy analysis.
"""
import streamlit as st
import json
import asyncio
from pathlib import Path
import plotly.graph_objects as go
import pandas as pd
from datetime import datetime

from app.orchestrator import analyze_iam_policy
from app.models import Verdict, RiskLevel

# Page config
st.set_page_config(
    page_title="IAM Security Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


def load_example_policies():
    """Load all example policies from the examples folder"""
    policy_dir = Path("example_policies")
    policies = {}
    
    if policy_dir.exists():
        for policy_file in sorted(policy_dir.glob("*.json")):
            with open(policy_file) as f:
                policies[policy_file.stem] = json.load(f)
    
    return policies


def create_risk_gauge(risk_score):
    """Build the risk score gauge chart"""
    color = "red" if risk_score >= 8 else "orange" if risk_score >= 6 else "yellow" if risk_score >= 3 else "green"
    
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=risk_score,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': "Overall Risk Score"},
        gauge={
            'axis': {'range': [None, 10]},
            'bar': {'color': color},
            'steps': [
                {'range': [0, 3], 'color': "lightgreen"},
                {'range': [3, 6], 'color': "lightyellow"},
                {'range': [6, 8], 'color': "orange"},
                {'range': [8, 10], 'color': "lightcoral"}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': 9
            }
        }
    ))
    
    fig.update_layout(height=300)
    return fig

def create_agent_comparison_chart(agent_analyses):
    """Create bar chart comparing agent risk scores."""
    agent_names = [a.agent_name.value.replace('_', ' ').title() for a in agent_analyses]
    scores = [a.risk_score for a in agent_analyses]
    colors = ['red' if s >= 8 else 'orange' if s >= 6 else 'yellow' if s >= 3 else 'green' for s in scores]

    fig = go.Figure(data=[
        go.Bar(
            x=agent_names,
            y=scores,
            marker_color=colors,
            text=[f"{s:.1f}/10" for s in scores],
            textposition='outside',
        )
    ])

    fig.update_layout(
        title="Agent Risk Assessments",
        yaxis_title="Risk Score (0-10)",
        yaxis_range=[0, 10],
        height=400,
    )

    return fig

def get_verdict_color(verdict):
    """Get color for verdict badge."""
    colors = {
        Verdict.SECURE: "green",
        Verdict.NEEDS_IMPROVEMENT: "orange",
        Verdict.WEAK: "orange",
        Verdict.CRITICAL_RISK: "red",
    }
    return colors.get(verdict, "gray")

def get_severity_color(severity):
    """Get color for severity badge."""
    colors = {
        RiskLevel.LOW: "green",
        RiskLevel.MEDIUM: "orange",
        RiskLevel.HIGH: "red",
        RiskLevel.CRITICAL: "darkred",
    }
    return colors.get(severity, "gray")

def main():
    """Main Streamlit app."""
    
    # Header
    st.title("🛡️ IAM Multi-Agent Security Analyzer")
    st.markdown("*Comprehensive security analysis using specialized AI agents*")
    
    # Sidebar
    with st.sidebar:
        st.header("⚙️ Configuration")
        
        llm_provider = st.selectbox(
            "LLM Provider",
            ["openai", "ollama"],
            help="Select which LLM to use for analysis"
        )

        st.markdown("---")
        st.markdown("### About")
        st.markdown("""
        This system uses 4 specialized security agents:
        - 🔒 Least Privilege
        - 🚨 Privilege Escalation
        - 📊 Data Exposure
        - ✅ Compliance

        A Judge agent aggregates findings into a final verdict.
        """)

        st.markdown("---")
        st.markdown("*Built with GPT-4 & Multi-Agent Architecture*")

    # Main content tabs
    tab1, tab2 = st.tabs(["📝 Analyze Policy", "📚 Example Policies"])

    with tab1:
        st.header("Policy Input")

        col1, col2 = st.columns([2, 1])

        with col1:
            policy_input = st.text_area(
                "Paste IAM Policy JSON",
                height=300,
                placeholder='{\n  "Version": "2012-10-17",\n  "Statement": [\n    {\n      "Effect": "Allow",\n      "Action": "*",\n      "Resource": "*"\n    }\n  ]\n}'
            )

        with col2:
            st.markdown("**Or upload a file:**")
            uploaded_file = st.file_uploader("Choose JSON file", type=['json'])

            if uploaded_file is not None:
                policy_input = uploaded_file.read().decode('utf-8')
                st.success("File loaded!")

        policy_name = st.text_input("Policy Name (optional)", placeholder="my-iam-policy")

        analyze_button = st.button("🔍 Analyze Policy", type="primary", use_container_width=True)

        if analyze_button:
            if not policy_input:
                st.error("Please provide a policy to analyze!")
            else:
                try:
                    # Parse JSON
                    policy = json.loads(policy_input)
                    
                    # Run analysis
                    with st.spinner("🤖 Running multi-agent analysis... This may take 20-30 seconds..."):
                        result = asyncio.run(
                            analyze_iam_policy(
                                policy, 
                                policy_name=policy_name or "uploaded-policy",
                                llm_provider=llm_provider
                            )
                        )

                    # Display results
                    st.success("✅ Analysis Complete!")

                    # Store in session state for persistence
                    st.session_state['last_result'] = result

                except json.JSONDecodeError:
                    st.error("Invalid JSON format. Please check your policy syntax.")
                except Exception as e:
                    st.error(f"Analysis failed: {str(e)}")
                    st.exception(e)

    with tab2:
        st.header("Example Policies")

        examples = load_example_policies()

        if examples:
            example_name = st.selectbox(
                "Select an example policy",
                list(examples.keys())
            )

            if example_name:
                col1, col2 = st.columns([2, 1])

                with col1:
                    st.json(examples[example_name])

                with col2:
                    if st.button("🔍 Analyze This Example", use_container_width=True):
                        with st.spinner("🤖 Running multi-agent analysis..."):
                            result = asyncio.run(
                                analyze_iam_policy(
                                    examples[example_name],
                                    policy_name=example_name,
                                    llm_provider=llm_provider
                                )
                            )

                        st.success("✅ Analysis Complete!")
                        st.session_state['last_result'] = result
        else:
            st.warning("No example policies found in example_policies/ directory")

    # Display results if available
    if 'last_result' in st.session_state:
        result = st.session_state['last_result']

        st.markdown("---")
        st.header("📊 Analysis Results")

        # Top-level metrics
        col1, col2, col3, col4 = st.columns(4)

        with col1:
            verdict_color = get_verdict_color(result.judge_analysis.final_verdict)
            st.markdown(f"### Verdict")
            st.markdown(f"<h2 style='color: {verdict_color};'>{result.judge_analysis.final_verdict.value}</h2>", unsafe_allow_html=True)

        with col2:
            st.metric("Risk Score", f"{result.judge_analysis.overall_risk_score:.1f}/10")

        with col3:
            st.metric("Confidence", f"{result.judge_analysis.confidence:.0%}")

        with col4:
            st.metric("Execution Time", f"{result.total_execution_time_sec:.1f}s")
        
        # Cost info row (if available)
        if hasattr(result, 'total_cost_usd') and result.total_cost_usd > 0:
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Est. Cost", f"${result.total_cost_usd:.4f}")
            with col2:
                if hasattr(result, 'total_tokens'):
                    st.metric("Tokens", f"{result.total_tokens:,}")

        # Risk gauge and agent comparison
        col1, col2 = st.columns(2)

        with col1:
            st.plotly_chart(
                create_risk_gauge(result.judge_analysis.overall_risk_score),
                use_container_width=True
            )

        with col2:
            st.plotly_chart(
                create_agent_comparison_chart(result.agent_analyses),
                use_container_width=True
            )

        # Agent consensus
        st.markdown("### 🤝 Agent Consensus")
        consensus = result.judge_analysis.agent_consensus

        col1, col2 = st.columns([1, 3])
        with col1:
            agreement_color = "green" if consensus.agreement_level.value == "high" else "orange" if consensus.agreement_level.value == "medium" else "red"
            st.markdown(f"**Agreement Level:** <span style='color: {agreement_color};'>{consensus.agreement_level.value.upper()}</span>", unsafe_allow_html=True)

        with col2:
            st.markdown(f"*{consensus.consensus_explanation}*")

        # Key findings
        st.markdown("### 🔍 Key Findings")
        for i, finding in enumerate(result.judge_analysis.key_findings, 1):
            st.markdown(f"{i}. {finding}")

        # Agent details (tabs)
        st.markdown("### 📋 Detailed Agent Reports")

        agent_tabs = st.tabs([
            f"{a.agent_name.value.replace('_', ' ').title()}" 
            for a in result.agent_analyses
        ])

        for tab, analysis in zip(agent_tabs, result.agent_analyses):
            with tab:
                col1, col2 = st.columns([2, 1])

                with col1:
                    st.markdown(f"**Risk Score:** {analysis.risk_score:.1f}/10")
                    st.markdown(f"**Verdict:** {analysis.verdict.value}")

                with col2:
                    st.markdown(f"**Execution Time:** {analysis.execution_time_sec:.1f}s")
                    st.markdown(f"**Model:** {analysis.model_used}")

                st.markdown("**Explanation:**")
                st.info(analysis.explanation)

                if analysis.findings:
                    st.markdown("**Findings:**")
                    for finding in analysis.findings:
                        severity_color = get_severity_color(finding.severity)
                        with st.expander(f"[{finding.severity.value}] {finding.issue}"):
                            st.markdown(f"**Location:** `{finding.location}`")
                            st.markdown(f"**Recommendation:** {finding.recommendation}")
                            if finding.evidence:
                                st.markdown(f"**Evidence:** {finding.evidence}")

                # Risk dimensions
                if analysis.risk_breakdown.dimensions:
                    st.markdown("**Risk Breakdown:**")
                    dims_df = pd.DataFrame([
                        {"Dimension": k, "Score": f"{v:.1f}/10"}
                        for k, v in analysis.risk_breakdown.dimensions.items()
                    ])
                    st.table(dims_df)

        # Recommendations
        st.markdown("### 💡 Priority Recommendations")

        for i, rec in enumerate(result.judge_analysis.priority_recommendations, 1):
            priority_color = get_severity_color(rec.priority)

            with st.expander(f"[{rec.priority.value}] {rec.category}", expanded=(i <= 3)):
                st.markdown(f"**Recommendation:** {rec.recommendation}")
                st.markdown(f"**Impact:** {rec.impact}")
                if rec.example:
                    st.code(rec.example, language="json")

        # Executive Summary
        st.markdown("### 📄 Executive Summary")
        st.markdown(result.judge_analysis.executive_summary)

        # Export options
        st.markdown("---")
        col1, col2 = st.columns(2)

        with col1:
            # Export as JSON
            export_data = {
                "analysis_id": result.analysis_id,
                "policy_name": result.policy_name,
                "timestamp": result.completed_at.isoformat(),
                "verdict": result.judge_analysis.final_verdict.value,
                "risk_score": result.judge_analysis.overall_risk_score,
                "key_findings": result.judge_analysis.key_findings,
            }

            st.download_button(
                "📥 Download Results (JSON)",
                data=json.dumps(export_data, indent=2),
                file_name=f"analysis_{result.analysis_id[:8]}.json",
                mime="application/json",
            )

        with col2:
            st.markdown(f"*Analysis ID: `{result.analysis_id}`*")

if __name__ == "__main__":
    main()
