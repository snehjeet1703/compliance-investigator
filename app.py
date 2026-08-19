import streamlit as st
import os
import tempfile
from investigator import build_investigation_context
from normalizer import load_logs, normalize_all
from linux_normalizer import load_linux_logs, normalize_all_linux
from app_normalizer import load_app_logs, normalize_all_app
from timeline import build_timeline, group_into_sessions, summarize_session
from detector import run_detection, detect_attack_chains
from compliance import load_all_frameworks, map_findings_to_compliance
from correlator import correlate_sources

st.set_page_config(page_title="Compliance Investigator", layout="wide")

st.title("AI-Powered Compliance Investigation Platform")
st.caption("Upload security logs. Get an investigation report.")

# File upload
uploaded_files = st.file_uploader(
    "Upload log files",
    type=["json", "log"],
    accept_multiple_files=True
)

if uploaded_files:
    if st.button("Run Investigation", type="primary"):
        
        # Load and normalize each file
        all_events = []
        
        progress = st.progress(0, text="Loading log files...")
        
        for i, uploaded_file in enumerate(uploaded_files):
            filename = uploaded_file.name
            content = uploaded_file.read().decode("utf-8")
            
            # Save to temp file
            temp_path = os.path.join(tempfile.gettempdir(), filename)
            with open(temp_path, "w") as f:
                f.write(content)
            
            if filename.endswith(".json"):
                raw = load_logs(temp_path)
                events = normalize_all(raw)
            elif "auth" in filename:
                lines = load_linux_logs(temp_path)
                events = normalize_all_linux(lines)
            else:
                lines = load_app_logs(temp_path)
                events = normalize_all_app(lines)
            
            st.sidebar.write(f"**{filename}:** {len(events)} events")
            all_events.extend(events)
            progress.progress((i + 1) / len(uploaded_files), text=f"Loaded {filename}")
        
        # Run pipeline
        progress.progress(0.3, text="Building timeline...")
        events = build_timeline(all_events)
        sessions = group_into_sessions(events)
        
        progress.progress(0.5, text="Running detection...")
        findings = run_detection(events)
        chains = detect_attack_chains(findings, sessions)
        
        progress.progress(0.7, text="Mapping compliance...")
        frameworks = load_all_frameworks()
        compliance_results = map_findings_to_compliance(findings, frameworks)
        
        progress.progress(1.0, text="Done!")
        
        # Summary metrics
        st.divider()
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Events", len(events))
        col2.metric("Findings", len(findings))
        col3.metric("Attack Chains", len(chains))
        col4.metric("Controls Failed", sum(r["total_failed"] for r in compliance_results))
        
        # Findings
        st.divider()
        st.subheader("Findings")
        
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            severity_findings = [f for f in findings if f["severity"] == severity]
            if not severity_findings:
                continue
            
            colors = {"CRITICAL": "red", "HIGH": "orange", "MEDIUM": "blue", "LOW": "gray"}
            
            with st.expander(f":{colors[severity]}[{severity}] — {len(severity_findings)} findings"):
                for f in severity_findings:
                    t = f["event"]["timestamp"].strftime("%H:%M:%S")
                    st.write(f"**[{t}] {f['rule']}** — {f['description']}")
        
        # Attack Chains
        st.divider()
        st.subheader("Attack Chains")
        
        if not chains:
            st.info("No attack chains detected.")
        
        for i, chain in enumerate(chains, 1):
            with st.expander(f"Chain {i}: {chain['chain_type']} [{chain['severity']}] — {chain['primary_actor']}"):
                st.write(f"**Description:** {chain['description']}")
                if chain["secondary_actor"]:
                    st.write(f"**Secondary Actor:** {chain['secondary_actor']}")
                
                st.write("**Indicators:**")
                for ind in chain["indicators"]:
                    st.write(f"- {ind}")
                
                st.write("**Event Sequence:**")
                sorted_findings = sorted(chain["findings"], key=lambda f: f["event"]["timestamp"])
                for f in sorted_findings:
                    t = f["event"]["timestamp"].strftime("%H:%M:%S")
                    st.write(f"`[{t}]` {f['severity']} | {f['rule']} | {f['event']['actor']}")
        
        # Compliance
        st.divider()
        st.subheader("Compliance Impact")
        
        for result in compliance_results:
            with st.expander(f"{result['framework']} — {result['total_failed']} controls failed"):
                for control_id, details in result["failed_controls"].items():
                    st.write(f"**{control_id} — {details['title']}**")
                    st.write(f"*Requirement:* {details['requirement'][:200]}...")
                    for failure in details["failures"]:
                        st.write(f"- {failure}")
                    st.write("")
        
        # Timeline
        st.divider()
        st.subheader("Full Timeline")
        
        timeline_data = []
        for e in events:
            timeline_data.append({
                "Time": e["timestamp"].strftime("%H:%M:%S"),
                "Actor": e["actor"],
                "Action": e["action"],
                "Target": e["target"][:60],
                "Source IP": e["source_ip"],
                "Source": e.get("source_file", "unknown")
            })
        
        st.dataframe(timeline_data, use_container_width=True)
        
        # Cross-source correlation
        if len(uploaded_files) > 1:
            st.divider()
            st.subheader("Cross-Source Correlation")
            
            correlations = correlate_sources(events)
            for corr in correlations:
                with st.expander(f"{corr['actor']}"):
                    for source, info in corr["sources"].items():
                        st.write(f"**[{source}]** — {info['event_count']} events")
                        st.write(f"Actions: {', '.join(info['actions'])}")
                    
                    if corr["unique_actions"]:
                        st.write("**Unique to each source:**")
                        for source, actions in corr["unique_actions"].items():
                            st.write(f"- Only in {source}: {', '.join(actions)}")

        # Store results in session state for chat
        st.session_state["context"] = build_investigation_context(
            events, sessions, findings, chains, compliance_results
        )
        st.session_state["ready"] = True

# Chat interface — only show after investigation has run
if st.session_state.get("ready"):
    st.divider()
    st.subheader("Investigation Chat")
    st.caption("Ask questions about the investigation findings.")
    
    # Initialize chat history
    if "messages" not in st.session_state:
        st.session_state["messages"] = []
    
    # Display chat history
    for message in st.session_state["messages"]:
        with st.chat_message(message["role"]):
            st.write(message["content"])
    
    # Chat input
    question = st.chat_input("Ask about the investigation...")
    
    if question:
        # Show user message
        st.session_state["messages"].append({"role": "user", "content": question})
        with st.chat_message("user"):
            st.write(question)
        
        # Get AI response
        from ai_engine import ask_ai
        
        system_prompt = f"""You are a senior security investigator conducting an interactive investigation.
You have access to the complete investigation data below. Use it to answer questions accurately.

RULES:
- Only state facts supported by the investigation data
- If something is an inference, say so
- Reference specific events, timestamps, and actors
- Be concise and direct
- Keep responses under 300 words

{st.session_state['context']}"""
        
        with st.chat_message("assistant"):
            with st.spinner("Analyzing..."):
                response = ask_ai(question, system_prompt)
            st.write(response)
        
        st.session_state["messages"].append({"role": "assistant", "content": response})