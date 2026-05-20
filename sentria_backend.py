import requests
import google.generativeai as genai
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# CONFIGURACIÓN
WAZUH_URL = "https://localhost:9200"
INDEXER_USER = "admin"
INDEXER_PASS = "U30tI8IT09iKOJbFFX.j.LwnX0HG2ZU4"
INDEX_NAME = "wazuh-alerts-*"

GEMINI_API_KEY = "AIzaSyCdaSekFv9RjZG1PIjOU8xuqGZLBzVGMic"

genai.configure(api_key=GEMINI_API_KEY)
model = genai.GenerativeModel("gemini-2.5-flash")

def get_latest_alerts():
    url = f"{WAZUH_URL}/{INDEX_NAME}/_search"

    query = {
        "size": 1,
        "sort": [
            {
                "@timestamp": {
                    "order": "desc"
                }
            }
        ],
        "_source": [
            "rule.description",
            "rule.level",
            "rule.groups",
            "@timestamp"
        ]
    }

    response = requests.get(
        url,
        auth=(INDEXER_USER, INDEXER_PASS),
        json=query,
        verify=False
    )

    data = response.json()
    hits = data.get("hits", {}).get("hits", [])

    alerts = []
    for hit in hits:
        source = hit.get("_source", {})

        description = source.get("rule", {}).get("description", "N/A")
        level = source.get("rule", {}).get("level", "N/A")
        groups = source.get("rule", {}).get("groups", [])
        timestamp = source.get("@timestamp", "N/A")

        alerts.append({
            "description": description,
            "level": level,
            "groups": ", ".join(groups) if isinstance(groups, list) else str(groups),
            "timestamp": timestamp
        })

    return alerts

def analyze_with_gemini(alert):
    prompt = f"""
    Analyze this cybersecurity alert and respond in this exact format:

    RISK: <LOW, MEDIUM, HIGH, CRITICAL>
    REASON: <short explanation>

    Alert:
    Description: {alert['description']}
    Level: {alert['level']}
    Groups: {alert['groups']}
    Timestamp: {alert['timestamp']}
    """

    try:
        response = model.generate_content(prompt)
        text = response.text.strip()

        risk = "UNKNOWN"
        reason = text

        lines = text.splitlines()
        for line in lines:
            if line.upper().startswith("RISK:"):
                risk = line.split(":", 1)[1].strip()
            elif line.upper().startswith("REASON:"):
                reason = line.split(":", 1)[1].strip()

        return {
            "risk": risk,
            "reason": reason
        }

    except Exception as e:
        return {
            "risk": "PENDING",
            "reason": f"Gemini unavailable: {str(e)}"
        }

def get_analyzed_alerts():
    raw_alerts = get_latest_alerts()
    final_alerts = []

    for alert in raw_alerts:
        analysis = analyze_with_gemini(alert)

        final_alerts.append({
            "description": alert["description"],
            "level": alert["level"],
            "groups": alert["groups"],
            "timestamp": alert["timestamp"],
            "risk": analysis["risk"],
            "reason": analysis["reason"]
        })

    return final_alerts
