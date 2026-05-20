import os
import json
import getpass
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

INDEXER = "https://localhost:9200"

def read_lastest_alert(user: str, pwd: str) -> dict:

    query = {
        "size": 1,
        "sort": [{"timestamp": {"order": "desc"}}],
        "_source": [
            "timestamp",
            "rule.id", "rule.level", "rule.description", "rule.groups",
            "agent.id", "agent.name",
            "manager.name"
        ]
    }

    url = f"{INDEXER}/wazuh-alerts-*/_search"
    r = requests.get(url, auth=(user, pwd), verify=False, json=query, timeout=20)
    r.raise_for_status()

    hits = r.json().get("hits", {}).get("hits", [])
    return hits[0].get("_source", {}) if hits else {}

def build_prompt(alert: dict) -> str:
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    ts = alert.get("timestamp", "unknown")

    desc = rule.get("description", "unknown")
    level = rule.get("level", "unknown")
    groups = rule.get("groups", [])
    agent_name = agent.get("name", "unknown")

    return f"""
You are a SOC security analyst.

Analyze the following security alert and classify the risk.

Alert details:

-Timestamp: {ts}
-Description: {desc}
-Severity level (Wazuh): {level}
-Rule groups: {", ".join(groups) if groups else "none"}
-Agent: {agent_name}
-Frequency: single event

Task:
Classify the alert as LOW, MEDIUM, or HIGH risk.
Explain briefly your reasoning.
Return exactly in this format:
RISK: <LOW|MEDIUM|HIGH>
Reason: <one short paragraph>
"""

def ask_gemini(prompt: str) -> str:
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise SystemExit("No encontre GEMINI_API_KEY. Ejecuta: export Gemini_API_KEY='TU_KEY'")

    from google import genai

    client = genai.Client(api_key=api_key)
    resp = client.models.generate_content(
        model="models/gemini-2.5-flash",
        contents=prompt
    )
    return resp.text.strip()

def main():
    user = input("Usuario del indexer: ").strip()
    pwd = getpass.getpass("Password del indexer: " )

    alert = read_lastest_alert(user, pwd)
    if not alert:
        print("No encontre alertas en wazuh-alerts-*.")
        return

    prompt = build_prompt(alert)
    print("\n=== Enviando a Gemini esta alerta ===")
    print(f"- Description: {alert.get('rule', {}).get('description')}")
    print(f"- Level: {alert.get('rule', {}).get('level')}")
    print(f"- Groups: {alert.get('rule', {}).get('groups')}")
    print(f"- Timestamp: {alert.get('timestamp')}\n")

    answer = ask_gemini(prompt)
    print("=== Respuesta Gemini ===")
    print(answer)

if __name__ == "__main__":
    main()
