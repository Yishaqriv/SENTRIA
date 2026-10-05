"""
Puente entre Wazuh y SENTRIA.

- get_latest_alerts(): consulta el indexador Wazuh (proyecta también rule.id).
- anonimizar_texto():  se re-exporta desde dashboard.ia.anonimizacion.
- analyze_with_gemini() / get_analyzed_alerts(): SHIM legacy DEGRADADO. Desde el
  Sprint 2B ningún flujo operativo lo usa (la ingesta va por dashboard.ia.ingesta,
  que exige contexto de activo y aplica la política + el contrato estricto). Se
  conserva solo para que los prototipos legacy (root views.py, sentria_web.py)
  no rompan al importarse; devuelve un resultado "no disponible", nunca un
  veredicto.

Este módulo NO crea ningún cliente de red al importarse.
"""
import os
import sys

import requests
import urllib3
from dotenv import load_dotenv

# Carga del .env con la misma precedencia que settings.py: $SENTRIA_ENV_FILE
# (obligatorio que exista y tenga permisos <=600) y si no el .env local. Esto
# permite ejecutar este módulo desde un worktree distinto al del .env canónico.
# `override=True` mantiene la prioridad del .env sobre variables sueltas del
# shell, pero sobre el archivo CORRECTO (no una búsqueda ciega desde el cwd).
_REPO_DIR = os.path.dirname(os.path.abspath(__file__))
if _REPO_DIR not in sys.path:
    sys.path.append(_REPO_DIR)
try:
    from sentria_project.env_utils import EnvFileError, localizar_env_file

    _ENV_FILE = localizar_env_file(_REPO_DIR)
    if _ENV_FILE is not None:
        load_dotenv(_ENV_FILE, override=True)
except EnvFileError:
    raise
except Exception:
    load_dotenv(override=True)  # último recurso: búsqueda estándar de python-dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

WAZUH_URL = os.environ.get("WAZUH_URL", "https://localhost:9200")
INDEXER_USER = os.environ.get("INDEXER_USER", "")
INDEXER_PASS = os.environ.get("INDEXER_PASS", "")
INDEX_NAME = os.environ.get("WAZUH_INDEX_NAME", "wazuh-alerts-*")

GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "models/gemini-3.5-flash")

# Compatibilidad: anonimizar_texto y auxiliares viven en dashboard.ia.
from dashboard.ia.anonimizacion import (  # noqa: E402,F401
    anonimizar_texto,
    _enmascarar_ips_privadas,
    _enmascarar_por_etiqueta,
)


def get_latest_alerts(size=1, agent_id=None, min_level=None):
    """
    Consulta de SOLO LECTURA al indexador Wazuh. `GET .../_search`.
    - `agent_id`:  filtra por `agent.id` (la ingesta controlada procesa un
      único agente). `agent.id` es capa privada (P).
    - `min_level`: pre-filtra por `rule.level >= min_level` en el propio
      OpenSearch (optimización; la política vuelve a comprobar el nivel).
    """
    url = f"{WAZUH_URL}/{INDEX_NAME}/_search"

    query = {
        "size": size,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "_source": _SOURCE_FIELDS,
    }
    filtros = []
    if agent_id is not None:
        filtros.append({"term": {"agent.id": str(agent_id)}})
    if min_level is not None:
        filtros.append({"range": {"rule.level": {"gte": int(min_level)}}})
    if filtros:
        query["query"] = {"bool": {"filter": filtros}}

    response = requests.get(
        url, auth=(INDEXER_USER, INDEXER_PASS), json=query, verify=False, timeout=15
    )

    data = response.json()
    hits = data.get("hits", {}).get("hits", [])
    return [_normalizar_hit(h) for h in hits]


# agent.id / syscheck.* son CAPA PRIVADA (P) / evidencia cruda: se proyectan
# aquí, pero `dashboard.ia.evidencia`/`prompt` los convierten a valores
# categóricos seguros antes de que nada llegue al prompt / snapshot / dashboard.
_SOURCE_FIELDS = [
    "rule.description", "rule.level", "rule.groups", "rule.id", "rule.firedtimes",
    "agent.id", "@timestamp", "decoder.name",
    "syscheck.path", "syscheck.event", "syscheck.mode",
    "syscheck.size_before", "syscheck.size_after",
    "syscheck.sha1_after", "syscheck.sha256_after", "syscheck.md5_after",
    "syscheck.uid_after", "syscheck.gid_after", "syscheck.uname_after", "syscheck.gname_after",
    "syscheck.perm_after", "syscheck.audit.process.name",
]


def _normalizar_hit(hit):
    source = hit.get("_source", {}) or {}
    rule = source.get("rule", {}) or {}
    agent = source.get("agent", {}) or {}
    sc = source.get("syscheck", {}) or {}
    audit = (sc.get("audit", {}) or {})
    proc = (audit.get("process", {}) or {})
    groups = rule.get("groups", [])
    return {
        "opensearch_id": hit.get("_id"),
        "description": rule.get("description", "N/A"),
        "level": rule.get("level", "N/A"),
        "groups": ", ".join(groups) if isinstance(groups, list) else str(groups),
        "rule_id": rule.get("id"),
        "rule_firedtimes": rule.get("firedtimes"),
        "agent_id": agent.get("id"),   # capa P: sólo para el resolver de activos
        "timestamp": source.get("@timestamp", "N/A"),
        "decoder_name": (source.get("decoder", {}) or {}).get("name"),
        # syscheck (FIM) — evidencia CRUDA; se categoriza/anonimiza en evidencia.py
        "syscheck_path": sc.get("path"),
        "syscheck_event": sc.get("event"),
        "syscheck_mode": sc.get("mode"),
        "syscheck_size_before": sc.get("size_before"),
        "syscheck_size_after": sc.get("size_after"),
        "syscheck_hash_present": bool(sc.get("sha256_after") or sc.get("sha1_after") or sc.get("md5_after")),
        "syscheck_uid_after": sc.get("uid_after"),
        "syscheck_uname_after": sc.get("uname_after"),
        "syscheck_perm_after": sc.get("perm_after"),
        "syscheck_process_name": proc.get("name"),
    }


def get_alert_by_id(opensearch_id):
    """Lectura de UN documento de Wazuh por su `_id` (para reintentar un análisis)."""
    query = {"size": 1, "_source": _SOURCE_FIELDS,
             "query": {"ids": {"values": [str(opensearch_id)]}}}
    response = requests.get(
        f"{WAZUH_URL}/{INDEX_NAME}/_search",
        auth=(INDEXER_USER, INDEXER_PASS), json=query, verify=False, timeout=15,
    )
    hits = response.json().get("hits", {}).get("hits", [])
    return _normalizar_hit(hits[0]) if hits else None


# --- SHIM legacy degradado. No lo use ningún flujo nuevo. ---
def analyze_with_gemini(alert):
    return {
        "risk": "PENDING",
        "reason": "Ruta legacy sin contexto de activo; el análisis va por dashboard.ia.ingesta (Sprint 2B).",
    }


def get_analyzed_alerts():
    final = []
    for alert in get_latest_alerts():
        a = analyze_with_gemini(alert)
        final.append({**alert, "risk": a["risk"], "reason": a["reason"]})
    return final
