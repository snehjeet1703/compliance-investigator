import requests
import json

def ask_ai(prompt, system_prompt=None):
    """Send a prompt to the local AI model and return the response"""
    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})

    try:
        response = requests.post(
            "http://localhost:11434/api/chat",
            json={
                "model": "llama3.2",
                "messages": messages,
                "stream": False
            }
        )
        data = response.json()
        return data["message"]["content"]
    except Exception as e:
        return f"AI Error: {str(e)}"

def ai_root_cause(chain):
    """Generate root cause analysis for an attack chain"""
    sorted_findings = sorted(chain["findings"], key=lambda f: f["event"]["timestamp"])

    chain_text = f"Attack Chain: {chain['chain_type']}\n"
    chain_text += f"Primary Actor: {chain['primary_actor']}\n"
    if chain["secondary_actor"]:
        chain_text += f"Secondary Actor: {chain['secondary_actor']}\n"
    chain_text += f"\nIndicators:\n"
    for ind in chain["indicators"]:
        chain_text += f"- {ind}\n"
    chain_text += f"\nEvent sequence:\n"
    for f in sorted_findings:
        t = f["event"]["timestamp"].strftime("%H:%M:%S")
        chain_text += f"[{t}] {f['severity']} | {f['rule']} | {f['event']['actor']} | {f['event']['action']} | {f['event']['target']}\n"

    system_prompt = """You are a senior security investigator performing root cause analysis.
You are given a confirmed attack chain detected by an automated system.
Do NOT question whether this is suspicious — it is a confirmed attack.

Perform root cause analysis by asking 'why' repeatedly until you reach the organizational or technical root cause. Then provide:
1. Root cause (technical and organizational)
2. Business impact assessment
3. Three corrective actions (immediate)
4. Three preventive actions (long-term)

Be specific. Reference actual events and actors from the data.
Keep your response under 400 words."""

    return ask_ai(chain_text, system_prompt)

def ai_executive_summary(findings_count, chains, compliance_results):
    """Generate an executive summary of the investigation"""
    summary_text = f"Total findings: {findings_count}\n"
    summary_text += f"Attack chains detected: {len(chains)}\n\n"

    for chain in chains:
        summary_text += f"Chain: {chain['chain_type']} [{chain['severity']}]\n"
        summary_text += f"  Primary actor: {chain['primary_actor']}\n"
        if chain["secondary_actor"]:
            summary_text += f"  Secondary actor: {chain['secondary_actor']}\n"
        summary_text += f"  Indicators: {', '.join(chain['indicators'])}\n\n"

    summary_text += "Compliance Impact:\n"
    for result in compliance_results:
        summary_text += f"  {result['framework']}: {result['total_failed']} controls failed\n"

    system_prompt = """You are writing an executive summary for a CISO who has 2 minutes to read it.
This is a confirmed security incident investigation report.

Write a brief executive summary covering:
1. What happened (2-3 sentences)
2. Business impact (1-2 sentences)
3. Compliance impact (1-2 sentences)
4. Immediate action required (2-3 bullet points)

Use direct, clear language. No hedging. Under 200 words."""

    return ask_ai(summary_text, system_prompt)