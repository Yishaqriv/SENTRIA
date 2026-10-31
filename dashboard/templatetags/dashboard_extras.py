"""Filtros de presentación del dashboard (Sprint 2E)."""
import datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from django import template

register = template.Library()

_ZONA_POR_DEFECTO = "America/Bogota"


@register.filter(name="en_zona")
def en_zona(dt, zona):
    """Formatea un ``datetime`` aware en la zona horaria IANA indicada.

    Devuelve ``'YYYY-MM-DD HH:MM'``. Los instantes se guardan aware en UTC
    (``USE_TZ=True``); esto es SÓLO presentación y no altera el instante.
    Un ``datetime`` naive se asume en UTC. Zona inválida -> se cae a UTC.
    """
    if dt is None:
        return ""
    if getattr(dt, "tzinfo", None) is None or dt.utcoffset() is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    try:
        tz = ZoneInfo(str(zona or _ZONA_POR_DEFECTO))
    except (ZoneInfoNotFoundError, ValueError, OSError):
        tz = datetime.timezone.utc
    return dt.astimezone(tz).strftime("%Y-%m-%d %H:%M")

# Etiquetas en español para las 8 claves del contrato CVSS v3 (que en el JSON
# viajan como identificadores técnicos en inglés). Los VALORES ya están en
# español en el contrato (`no_determinado`, `baja`, `alta`, `ninguno`, ...).
_CVSS_ES = {
    "attack_vector": "Vector de ataque",
    "attack_complexity": "Complejidad del ataque",
    "privileges_required": "Privilegios requeridos",
    "user_interaction": "Interacción del usuario",
    "scope": "Alcance",
    "confidentiality_impact": "Impacto en confidencialidad",
    "integrity_impact": "Impacto en integridad",
    "availability_impact": "Impacto en disponibilidad",
}


@register.filter(name="cvss_es")
def cvss_es(clave):
    """`attack_vector` -> `Vector de ataque`. Deja intacto lo que no reconozca."""
    return _CVSS_ES.get(str(clave), clave)


_MANT_ES = {
    "dentro_ventana_declarada": "Dentro de ventana autorizada",
    "sin_ventana_declarada": "Sin ventana declarada",
    "indeterminado": "No determinado",
    "no_determinado": "No determinado",   # compatibilidad con snapshots 2F
}


@register.filter(name="mant_es")
def mant_es(estado):
    """Estado de ventana de mantenimiento -> etiqueta legible en español."""
    return _MANT_ES.get(str(estado or ""), "Sin ventana declarada")


# ---------------------------------------------------------------------------
# Frontend liquid glass: SOLO presentación. Leen lo ya guardado en la alerta
# (snapshot congelado y datos de regla registrados); no consultan servicios,
# no recalculan contexto histórico con datos actuales ni inventan valores.
# ---------------------------------------------------------------------------

# Familia visual del evento -> (etiqueta, icono SVG del kit). El icono identifica
# el tipo de evento: NO representa riesgo, veredicto ni evidencia nueva.
_FAMILIAS_EVENTO = {
    "fim": ("Archivo (FIM)", "archivo"),
    "account": ("Cuenta", "cuenta"),
    "windows_audit_policy": ("Política de auditoría", "auditoria"),
    "windows_device": ("Dispositivo", "dispositivo"),
    "sca": ("Configuración (SCA)", "configuracion-sca"),
    "windows_event_application": ("Aplicación (Windows)", "aplicacion"),
    "windows_event_system": ("Sistema (Windows)", "sistema"),
    "authentication": ("Autenticación", "autenticacion"),
    "network": ("Red", "red"),
    "unknown": ("Familia no determinada", "evento-generico"),
}
_GRUPOS_FIM = {"syscheck", "syscheck_file", "syscheck_entry_added",
               "syscheck_entry_modified", "syscheck_entry_deleted", "syscheck_registry"}
_GRUPOS_CUENTA = {"adduser", "addgroup", "account_changed", "group_changed",
                  "group_created", "group_deleted", "userdel", "groupdel"}
_GRUPOS_AUTENTICACION = {"authentication_success", "authentication_failed",
                         "authentication_failures", "invalid_login"}
_GRUPOS_RED = {"firewall", "ids", "web", "suricata"}


def _snapshot(alerta):
    snap = getattr(alerta, "contexto_ia_snapshot", None)
    return snap if isinstance(snap, dict) else {}


def _evidencia(snap):
    ev = snap.get("evidencia_tecnica")
    return ev if isinstance(ev, dict) else {}


def _grupos(alerta, snap, ev):
    """Grupos de regla: los del snapshot si existe; si no, los registrados en la alerta."""
    for g in (snap.get("wazuh_rule_groups"), ev.get("rule_groups"), getattr(alerta, "wazuh_rule_groups", None)):
        if isinstance(g, (list, tuple)) and g:
            return {str(x).strip().lower() for x in g}
    return set()


def clave_familia_evento(alerta):
    """Clave de familia: primero evidencia normalizada específica, luego grupos de regla."""
    snap = _snapshot(alerta)
    ev = _evidencia(snap)
    if ev.get("fim_event_type") not in (None, "", "no_aplica"):
        return "fim"
    if "win_auditoria_subcategoria" in ev or "win_auditoria_cambio" in ev:
        return "windows_audit_policy"
    if "win_dispositivo_clase" in ev:
        return "windows_device"
    if any(k.startswith("sca_") for k in ev):
        return "sca"
    if any(k.startswith("cuenta_") for k in ev):
        return "account"
    if ev.get("win_canal") == "aplicacion":
        return "windows_event_application"
    if ev.get("win_canal") == "sistema":
        return "windows_event_system"
    grupos = _grupos(alerta, snap, ev)
    if grupos & _GRUPOS_FIM:
        return "fim"
    if "sca" in grupos:
        return "sca"
    if grupos & _GRUPOS_CUENTA:
        return "account"
    if grupos & _GRUPOS_AUTENTICACION:
        return "authentication"
    if grupos & _GRUPOS_RED:
        return "network"
    return "unknown"


@register.filter(name="familia_evento")
def familia_evento(alerta):
    clave = clave_familia_evento(alerta)
    etiqueta, icono = _FAMILIAS_EVENTO[clave]
    return {"clave": clave, "etiqueta": etiqueta, "icono": icono}


# Campos de evidencia que el detalle ya mostraba (rejilla principal).
EVIDENCIA_PRINCIPAL = (
    "fim_event_type", "path_category", "file_extension", "hash_present", "size_info",
    "user_role_category", "process_category", "correlated_events", "telemetry_source",
)
_BLOQUES_EVIDENCIA = (
    ("Regla de Wazuh", lambda k: k in ("rule_id", "rule_groups")),
    ("Configuración (SCA)", lambda k: k.startswith("sca_")),
    ("Cuenta", lambda k: k.startswith("cuenta_")),
    ("Política de auditoría de Windows", lambda k: k.startswith("win_auditoria_")),
    ("Dispositivo de Windows", lambda k: k.startswith("win_dispositivo_")),
    ("Evento de Windows", lambda k: k.startswith("win_")),
)


@register.filter(name="bloques_evidencia")
def bloques_evidencia(evidencia):
    """Agrupa los campos de `evidencia_tecnica` que no están en la rejilla principal.

    Devuelve ``[{"titulo": str, "campos": [(clave, valor), ...]}, ...]`` con las claves
    ORIGINALES y solo los campos presentes; lo que no encaje va a «Otros campos».
    """
    if not isinstance(evidencia, dict):
        return []
    restantes = [(k, v) for k, v in evidencia.items() if k not in EVIDENCIA_PRINCIPAL]
    bloques = []
    for titulo, pertenece in _BLOQUES_EVIDENCIA:
        campos = [(k, v) for k, v in restantes if pertenece(str(k))]
        if campos:
            bloques.append({"titulo": titulo, "campos": campos})
            restantes = [(k, v) for k, v in restantes if (k, v) not in campos]
    if restantes:
        bloques.append({"titulo": "Otros campos", "campos": restantes})
    return bloques


# Claves del snapshot que el detalle muestra en secciones propias.
_SNAPSHOT_MOSTRADAS = {
    "schema_version", "alert_description_es", "technical_evidence_es", "wazuh_level",
    "wazuh_rule_groups", "wazuh_rule_id", "asset_type", "asset_criticality", "asset_os_family",
    "asset_os_role", "operational_window", "maintenance_window", "maintenance_category",
    "maintenance_scope", "maintenance_scope_match", "authorized_context_es",
    "evidencia_tecnica", "observed_cvss_factors",
}


@register.filter(name="snapshot_restantes")
def snapshot_restantes(snap):
    """Claves del snapshot no mostradas en otra sección. Las internas (``_…``) no se muestran."""
    if not isinstance(snap, dict):
        return []
    return [(k, v) for k, v in snap.items()
            if k not in _SNAPSHOT_MOSTRADAS and not str(k).startswith("_")]


@register.filter(name="valor_campo")
def valor_campo(valor):
    """Valor guardado -> texto legible, sin reinterpretarlo."""
    if isinstance(valor, bool):
        return "sí" if valor else "no"
    if isinstance(valor, (list, tuple)):
        return ", ".join(str(v) for v in valor) if valor else "[]"
    if isinstance(valor, dict):
        return ", ".join(f"{k}: {valor_campo(v)}" for k, v in valor.items()) if valor else "{}"
    if valor is None:
        return "null"
    return valor


_CAMPOS_ACTIVO = {
    "asset_type": "tipo_activo",
    "asset_criticality": "criticidad",
    "asset_os_family": "os_family",
    "asset_os_role": "os_role",
}


@register.filter(name="etiqueta_activo")
def etiqueta_activo(valor, campo_snapshot):
    """Código congelado del activo (p. ej. ``equipo_personal``) -> etiqueta de las choices del modelo.

    Solo traduce el código; si no lo reconoce, devuelve el valor original.
    """
    from dashboard.models import ActivoLogico

    nombre = _CAMPOS_ACTIVO.get(str(campo_snapshot))
    if not nombre:
        return valor
    opciones = dict(ActivoLogico._meta.get_field(nombre).choices or [])
    return opciones.get(valor, valor)


@register.simple_tag
def filtros_adicionales_activos(analisis, motivo, estado, revision, severidad):
    """Filtros del grupo «Más filtros» que la vista está APLICANDO (mismos valores válidos
    que `_aplicar_filtros`; un valor no válido se ignora allí y no cuenta aquí).
    `sin_control` marca los que llegan por enlace y no tienen desplegable visible."""
    from dashboard.views import ANALISIS_VALIDOS, ESTADOS_VALIDOS, MOTIVOS_VALIDOS, REVISION_VALIDOS

    activos = []
    if analisis in ANALISIS_VALIDOS:
        activos.append({"campo": "Análisis", "valor": analisis, "sin_control": False})
    if motivo in MOTIVOS_VALIDOS:
        activos.append({"campo": "Motivo omisión", "valor": motivo, "sin_control": False})
    if estado in ESTADOS_VALIDOS:
        activos.append({"campo": "Estado triage", "valor": estado, "sin_control": False})
    if revision in REVISION_VALIDOS:
        activos.append({"campo": "Revisión", "valor": revision, "sin_control": True})
    if severidad in ("alta", "media", "baja"):
        activos.append({"campo": "Severidad", "valor": severidad, "sin_control": True})
    return activos


@register.filter(name="sin_control")
def sin_control(activos):
    """Subconjunto de `filtros_adicionales_activos` sin desplegable visible."""
    return [f for f in activos if f["sin_control"]]
