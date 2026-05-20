import getpass
import requests
import urllib3
from pprint import pprint


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

INDEXER = "https://localhost:9200"

user = input("Usuario del indexer: ").strip()
pwd = getpass.getpass("Password: ")

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
print("HTTP:", r.status_code)

r.raise_for_status()

data = r.json()
hits = data.get("hits", {}).get("hits", [])

if not hits:
    print("No encontre alertas en wazuh-alerts-*.")
else:
    print("\n=== ULTIMA ALERTA ===")
    pprint(hits[0].get("_source", {}))
