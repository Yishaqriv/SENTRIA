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
    # Entrada 1.1 (3F.8): SCA y cuentas. Capa P/cruda: evidencia.py solo emite categorías.
    "data.sca.type", "data.sca.policy", "data.sca.check.id", "data.sca.check.result",
    "data.sca.check.previous_result", "data.sca.check.compliance.cis",
    "data.sca.check.compliance.mitre_tactics",
    "data.uid", "data.gid", "data.shell",
    "data.win.system.eventID", "data.win.system.channel", "data.win.eventdata",
]

# Atributos de cuenta que informan los eventos 4720/4738 (documentación de Microsoft de ambos eventos).
# En el formato «delta» un atributo no cambiado vale "-" (Wazuh lo omite); en cuentas locales (SAM) el 4738
# trae el valor ACTUAL de todos los atributos, y Microsoft advierte que entonces no puede saberse cuál cambió.
_WIN_ATRIBUTOS_CUENTA = ("samAccountName", "displayName", "userPrincipalName", "homeDirectory", "homePath",
                         "scriptPath", "profilePath", "userWorkstations", "passwordLastSet", "accountExpires",
                         "primaryGroupId", "allowedToDelegateTo", "userParameters", "sidHistory", "logonHours")


def _win_formato_atributos(informados):
    """'valores_completos' (cuenta local: samAccountName siempre informado junto a otros) o 'delta'."""
    return "valores_completos" if ("samAccountName" in informados and len(informados) >= 3) else "delta"


def _sca_crudo(data):
    sca = (data or {}).get("sca") or {}
    if sca.get("type") != "check":
        return None
    chk = sca.get("check") or {}
    comp = chk.get("compliance") or {}
    return {"policy": sca.get("policy"), "id": chk.get("id"), "result": chk.get("result"),
            "previous_result": chk.get("previous_result"), "cis": comp.get("cis"),
            "mitre_tactics": comp.get("mitre_tactics")}


def _win_crudo(data):
    """Capa P: SIDs, NOMBRES de los atributos informados, formato del evento y valores UAC (hex).
    El nombre de usuario NO se propaga (solo si termina en `$`, es decir, cuenta de equipo); de los
    atributos solo se usa si están informados, nunca su valor."""
    win = (data or {}).get("win") or {}
    sysw = win.get("system") or {}
    if not sysw.get("eventID"):
        return None
    ed = win.get("eventdata") or {}
    informados = sorted(k for k in _WIN_ATRIBUTOS_CUENTA if str(ed.get(k, "")).strip() not in ("", "-"))
    return {"event_id": str(sysw.get("eventID")), "channel": sysw.get("channel"),
            "target_sid": ed.get("targetSid"), "subject_sid": ed.get("subjectUserSid"),
            "member_sid": ed.get("memberSid"),
            "target_es_equipo": str(ed.get("targetUserName") or "").endswith("$"),
            "atributos_informados": informados,
            "formato_atributos": _win_formato_atributos(informados),
            "uac_anterior": ed.get("oldUacValue"), "uac_nuevo": ed.get("newUacValue")}


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
        # Entrada 1.1 — crudo (capa P); se categoriza en dashboard.ia.evidencia
        "sca": _sca_crudo(source.get("data")),
        "cuenta_linux": ({k: (source.get("data") or {}).get(k) for k in ("uid", "gid", "shell")}
                         if any((source.get("data") or {}).get(k) not in (None, "") for k in ("uid", "gid", "shell"))
                         else None),
        "win": _win_crudo(source.get("data")),
    }


def _get_search(query, timeout=15):
    """Único `GET .../_search` para lecturas por `_id` (solo lectura)."""
    return requests.get(
        f"{WAZUH_URL}/{INDEX_NAME}/_search",
        auth=(INDEXER_USER, INDEXER_PASS), json=query, verify=False, timeout=timeout,
    )


def _query_por_ids(opensearch_ids, agent_id=None):
    """Consulta por `_id`; con `agent_id`, el indexador filtra también por `agent.id`."""
    ids = {"ids": {"values": [str(i) for i in opensearch_ids]}}
    if agent_id is None:
        consulta = ids
    else:
        consulta = {"bool": {"filter": [ids, {"term": {"agent.id": str(agent_id)}}]}}
    return {"size": len(opensearch_ids), "_source": _SOURCE_FIELDS, "query": consulta}


def get_alert_by_id(opensearch_id, agent_id=None):
    """Lectura de UN documento de Wazuh por su `_id` (para reintentar un análisis)."""
    response = _get_search(_query_por_ids([opensearch_id], agent_id))
    hits = response.json().get("hits", {}).get("hits", [])
    return _normalizar_hit(hits[0]) if hits else None


def get_alerts_by_ids(opensearch_ids, agent_id=None):
    """Lectura en lote por `_id` -> {opensearch_id: alerta normalizada}. Falla ante HTTP != 2xx."""
    opensearch_ids = list(opensearch_ids)
    if not opensearch_ids:
        return {}
    response = _get_search(_query_por_ids(opensearch_ids, agent_id), timeout=20)
    response.raise_for_status()
    return {h.get("_id"): _normalizar_hit(h) for h in response.json().get("hits", {}).get("hits", [])}


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
