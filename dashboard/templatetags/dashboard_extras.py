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
