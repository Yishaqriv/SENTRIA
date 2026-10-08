"""
Entrada del modelo ajustado: contrato `exp-entrada-1` + plantilla v1 (aprobados para el piloto, ruta A).

Funciones puras, trasladadas sin cambios de criterio desde el materializador del piloto:
- T-NORM-v1: estructura uniforme por familia (bloques `fim`, `sca`, `account`, `windows_event`,
  `windows_audit_policy`, `windows_device`) con `no_aplica` / `no_determinado` / `no_registrado` explícitos;
- T-NEUTRO-v1 (solo la parte de la ENTRADA): tablas cerradas que retiran la procedencia de laboratorio.

Parte de la entrada del dataset (`dashboard.dataset.construir_entrada`), nunca de la salida esperada.
Si la evidencia trae una clave sin destino en el contrato, la entrada NO es representable y se rechaza:
no se inventan campos ni transformaciones.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

from .contrato import CVSS_CLAVES

CONTRATO_ENTRADA = "exp-entrada-1"
TRANSFORMACIONES = ("T-NORM-v1", "T-NEUTRO-v1")
PLANTILLA_VERSION = "PLANTILLA_ENTRADA_v1"
PLANTILLA_SHA256 = "1d29f7962dc0751ee581c5c2d87f984c1e2df7933c17f12a07b918a369bd1a9a"
MARCADOR = "{ENTRADA_EXPORT_JSON}"

FIM = (("event_type", "fim_event_type"), ("path_category", "path_category"), ("file_extension", "file_extension"),
       ("hash_present", "hash_present"), ("size_info", "size_info"), ("user_role_category", "user_role_category"),
       ("process_category", "process_category"))
SCA = (("benchmark", "sca_benchmark"), ("check_id", "sca_id_comprobacion"), ("cis_control", "sca_control_cis"),
       ("control_category", "sca_categoria_control"), ("result", "sca_resultado"),
       ("previous_result", "sca_resultado_anterior"), ("mitre_tactics", "sca_tacticas_mitre"))
CUENTA = tuple((k, k) for k in ("cuenta_operacion", "cuenta_tipo", "cuenta_actor", "cuenta_inicio_sesion_interactivo",
                                "cuenta_atributos_cambiados", "cuenta_grupo", "cuenta_cambio_privilegios", "cuenta_estado"))
WIN_EVT = tuple((k, k) for k in ("win_canal", "win_proveedor_categoria", "win_id_evento"))
WIN_AUD = (("audit_subcategory", "win_auditoria_subcategoria"), ("audit_change", "win_auditoria_cambio"))
WIN_DEV = (("device_class", "win_dispositivo_clase"),)
VERSION_BLOQUE = {"sca": "1.1", "account": "1.1", "windows_event": "1.2", "windows_audit_policy": "1.4",
                  "windows_device": "1.4"}
# Claves de evidencia que el contrato representa fuera de los bloques o retira por redundancia con la alerta.
# `win_proveedor` NO tiene destino en el contrato aprobado: una entrada que lo trae se rechaza (no se retira en silencio).
_CLAVES_SIN_BLOQUE = {"telemetry_source", "correlated_events", "rule_id", "rule_groups"}

# T-NEUTRO-v1 (entrada): correspondencias cerradas aprobadas.
NEUTRO_VALORES = {("evidence.fim.path_category", "laboratorio_controlado"): "directorio_aislado_designado",
                  ("maintenance_scope", "archivos_laboratorio"): "archivos_directorio_aislado"}
NEUTRO_CONTEXTO = (
    ("Estación pública Windows que representa un puesto cliente de café internet dentro de un laboratorio controlado.",
     "Estación pública Windows de un puesto cliente de café internet."),
    ("directorio aislado de laboratorio", "directorio aislado designado"),
)


class EntradaNoRepresentable(ValueError):
    """La entrada no cabe en `exp-entrada-1` sin inventar campos ni transformaciones."""


def _v(s):
    return tuple(int(x) for x in str(s).split("."))


def aplica(bloque, e):
    g, rid = set(e.get("wazuh_rule_groups") or []), str(e.get("wazuh_rule_id") or "")
    ev = e.get("evidencia_tecnica") or {}
    if bloque == "fim":
        return ev.get("fim_event_type") not in (None, "no_aplica")
    if bloque == "sca":
        return "sca" in g
    if bloque == "account":
        return bool(g & {"adduser", "account_changed", "group_changed"})
    if bloque == "windows_event":
        return bool(g & {"windows_application", "windows_system"})
    if bloque == "windows_audit_policy":
        return rid == "60112"
    if bloque == "windows_device":
        return rid == "60227"
    return False


def _bloque(nombre, pares, e):
    ev = e.get("evidencia_tecnica") or {}
    if not aplica(nombre, e):
        return "no_aplica"
    previo = _v(e["schema_version"]) < _v(VERSION_BLOQUE.get(nombre, "1.0"))
    out = {}
    for nuevo, viejo in pares:
        if viejo in ev:
            val = ev[viejo]
            if nuevo == "hash_present":
                val = "si" if val else "no"
            out[nuevo] = val
        else:
            out[nuevo] = "no_registrado" if previo else "no_determinado"
    return out


def normalizar(e):
    """T-NORM-v1: entrada del dataset -> entrada `exp-entrada-1`. Lanza EntradaNoRepresentable si hay pérdidas."""
    ev = e.get("evidencia_tecnica") or {}
    conocidas = {k for _, k in FIM + SCA + CUENTA + WIN_EVT + WIN_AUD + WIN_DEV} | _CLAVES_SIN_BLOQUE
    sin_destino = sorted(k for k in ev if k not in conocidas)
    if sin_destino:
        raise EntradaNoRepresentable(f"clave de evidencia sin destino en {CONTRATO_ENTRADA}: {sin_destino}")
    if ev.get("rule_id") not in (None, e.get("wazuh_rule_id"), "no_determinado") or \
            ev.get("rule_groups") not in (None, e.get("wazuh_rule_groups")):
        raise EntradaNoRepresentable("evidencia_tecnica.rule_id/rule_groups difieren de los de la alerta")
    faltan = [k for k in ("schema_version", "alert_description_es", "wazuh_level", "wazuh_rule_groups", "asset_type",
                          "asset_criticality", "asset_os_family", "asset_os_role", "authorized_context_es",
                          "operational_window", "maintenance_window") if k not in e]
    if faltan:
        raise EntradaNoRepresentable(f"faltan claves de la entrada: {faltan}")
    win = e.get("maintenance_window")
    if "maintenance_scope" in e:
        scope, match = e["maintenance_scope"], e["maintenance_scope_match"]
    else:  # entradas < 1.3: mismas reglas que alcance.py
        scope = "no_aplica" if win == "sin_ventana_declarada" else (
            "no_declarado" if win == "dentro_ventana_declarada" else "no_determinado")
        match = "no_aplica" if win == "sin_ventana_declarada" else "no_determinado"
    return {
        "alert_description_es": e["alert_description_es"], "wazuh_level": e["wazuh_level"],
        "wazuh_rule_id": e.get("wazuh_rule_id") or "no_determinado", "wazuh_rule_groups": e["wazuh_rule_groups"],
        "asset_type": e["asset_type"], "asset_criticality": e["asset_criticality"],
        "asset_os_family": e["asset_os_family"], "asset_os_role": e["asset_os_role"],
        "authorized_context_es": e["authorized_context_es"], "operational_window": e["operational_window"],
        "maintenance_window": win, "maintenance_category": e.get("maintenance_category") or "no_aplica",
        "maintenance_scope": scope, "maintenance_scope_match": match,
        "evidence": {
            "telemetry_channel": ev.get("telemetry_source", "no_determinado"),
            "correlated_events": "no_determinado",
            "fim": _bloque("fim", FIM, e), "sca": _bloque("sca", SCA, e),
            "account": _bloque("account", CUENTA, e), "windows_event": _bloque("windows_event", WIN_EVT, e),
            "windows_audit_policy": _bloque("windows_audit_policy", WIN_AUD, e),
            "windows_device": _bloque("windows_device", WIN_DEV, e),
        },
        "observed_cvss_factors": {k: (e.get("observed_cvss_factors") or {}).get(k, "no_determinado") for k in CVSS_CLAVES},
    }


def neutro_entrada(x):
    """T-NEUTRO-v1 (entrada): sustituciones cerradas de procedencia; no cambia operaciones ni condiciones."""
    x = copy.deepcopy(x)
    fim = x["evidence"]["fim"]
    if isinstance(fim, dict) and fim.get("path_category") == "laboratorio_controlado":
        fim["path_category"] = NEUTRO_VALORES[("evidence.fim.path_category", "laboratorio_controlado")]
    if x["maintenance_scope"] == "archivos_laboratorio":
        x["maintenance_scope"] = NEUTRO_VALORES[("maintenance_scope", "archivos_laboratorio")]
    ctx = x["authorized_context_es"]
    for a, b in NEUTRO_CONTEXTO:
        ctx = ctx.replace(a, b)
    x["authorized_context_es"] = ctx
    return x


def plantilla_v1():
    texto = (Path(__file__).parent / "plantillas" / "entrada_v1.txt").read_text(encoding="utf-8")
    if hashlib.sha256(texto.encode("utf-8")).hexdigest() != PLANTILLA_SHA256 or texto.count(MARCADOR) != 1:
        raise RuntimeError("la plantilla v1 no coincide con la aprobada")
    return texto


def entrada_exportada(entrada_dataset):
    """Entrada del dataset -> entrada exportada (`exp-entrada-1` + T-NEUTRO-v1)."""
    return neutro_entrada(normalizar(entrada_dataset))


def texto_usuario(entrada_dataset):
    """-> (texto del turno user, entrada exportada). Mismo formato que el JSONL del piloto."""
    x = entrada_exportada(entrada_dataset)
    return plantilla_v1().replace(MARCADOR, json.dumps(x, ensure_ascii=False, indent=1)), x
