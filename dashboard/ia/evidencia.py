"""
Evidencia técnica de Wazuh — sanitizada y categorizada (Sprint 2F).

Toma los campos crudos de una alerta de Wazuh (sobre todo FIM / `syscheck`) y
produce SÓLO valores seguros y categóricos para la capa E (entra al prompt y
al `contexto_ia_snapshot`).

LISTA BLANCA de salida (nada fuera de esto llega al modelo):
  fim_event_type, path_category, file_extension, hash_present, size_info,
  process_category, user_role_category, telemetry_source, correlated_events,
  rule_id, rule_groups

NUNCA se emite: ruta literal, hostname, IP, agent.id, usuario real, correo,
`full_log`, secretos, ni ningún campo de capa P. Si un dato no existe -> "no_determinado".
"""
from __future__ import annotations

import posixpath

CATEGORIAS_RUTA = (
    "configuracion_sistema", "logs", "spool_impresion", "temporal",
    "ejecutable_sistema", "home_anonimizado", "laboratorio_controlado",
    "otra_no_determinada", "no_determinado",
)

# Directorio de laboratorio FIM aislado (checkpoint 2G.1). Categorización
# DETERMINISTA y ANÓNIMA: nunca se emite la ruta literal ni el nombre del
# archivo, sólo la etiqueta "laboratorio_controlado". Debe evaluarse ANTES que
# el prefijo genérico "/opt/".
_RUTA_LAB_CONTROLADO = "/opt/sentria_lab_fim/"

_PREFIJOS_RUTA = (
    (_RUTA_LAB_CONTROLADO, "laboratorio_controlado"),
    ("/etc/", "configuracion_sistema"),
    ("/usr/local/etc/", "configuracion_sistema"),
    ("/boot/", "configuracion_sistema"),
    ("/var/log/", "logs"),
    ("/var/spool/cups", "spool_impresion"),
    ("/var/spool/lpd", "spool_impresion"),
    ("/var/spool/", "spool_impresion"),
    ("/tmp/", "temporal"),
    ("/var/tmp/", "temporal"),
    ("/dev/shm/", "temporal"),
    ("/usr/bin/", "ejecutable_sistema"),
    ("/usr/sbin/", "ejecutable_sistema"),
    ("/usr/local/bin/", "ejecutable_sistema"),
    ("/bin/", "ejecutable_sistema"),
    ("/sbin/", "ejecutable_sistema"),
    ("/lib/", "ejecutable_sistema"),
    ("/usr/lib/", "ejecutable_sistema"),
    ("/home/", "home_anonimizado"),
    ("/root/", "home_anonimizado"),
    ("/srv/", "otra_no_determinada"),
    ("/opt/", "otra_no_determinada"),
    ("/var/www/", "otra_no_determinada"),
)


def clasificar_ruta(path):
    """Ruta absoluta -> categoría de la lista blanca. NO devuelve la ruta."""
    if not path or not isinstance(path, str):
        return "no_determinado"
    p = path.strip()
    if not p.startswith("/"):
        return "no_determinado"
    # normpath quita siempre la barra final; se re-añade para comparar por prefijo
    # de directorio de forma consistente (dé o no la ruta con "/" al final).
    p_norm = posixpath.normpath(p).lower() + "/"
    for prefijo, categoria in _PREFIJOS_RUTA:
        if p_norm.startswith(prefijo):
            return categoria
    return "otra_no_determinada"


def extension_archivo(path):
    """Extensión (sin punto) o 'sin_extension' / 'no_determinado'. No revela el nombre."""
    if not path or not isinstance(path, str):
        return "no_determinado"
    base = posixpath.basename(path.rstrip("/"))
    if not base:
        return "no_determinado"
    _, ext = posixpath.splitext(base)
    ext = ext.lstrip(".").lower()
    if not ext:
        return "sin_extension"
    # sólo se admite una extensión corta y alfanumérica (evita colar texto libre)
    return ext if (len(ext) <= 12 and ext.isalnum()) else "no_determinado"


def categoria_evento_fim(event):
    """`syscheck.event` -> added|modified|deleted|no_determinado."""
    e = str(event or "").strip().lower()
    return e if e in ("added", "modified", "deleted") else "no_determinado"


def categoria_usuario(uid, uname=None):
    """
    UID/uname -> rol ANONIMIZADO. Nunca el nombre real.
      0            -> root
      1..999       -> servicio_sistema
      >=1000       -> usuario_no_privilegiado
      desconocido  -> no_determinado
    """
    try:
        n = int(str(uid).strip())
    except (TypeError, ValueError):
        n = None
    if n is None:
        u = str(uname or "").strip().lower()
        if u == "root":
            return "root"
        return "no_determinado"
    if n == 0:
        return "root"
    if 1 <= n < 1000:
        return "servicio_sistema"
    return "usuario_no_privilegiado"


_PROCESOS_TECNICOS_SEGUROS = {
    "dpkg", "apt", "apt-get", "unattended-upgrade", "rm", "mv", "cp", "vi", "vim",
    "nano", "tee", "install", "systemctl", "systemd", "logrotate", "cron", "crond",
    "sh", "bash", "sudo", "cups", "cupsd", "gedit", "touch", "truncate", "ln",
    "sed", "gzip", "tar", "python3", "perl", "make", "dockerd", "containerd",
}


def categoria_proceso(nombre):
    """
    Nombre de proceso -> nombre técnico seguro o categoría. Nunca una ruta con
    home/usuario. Devuelve el nombre sólo si es un binario conocido y simple.
    """
    if not nombre or not isinstance(nombre, str):
        return "no_determinado"
    base = posixpath.basename(nombre.strip()).lower()
    if not base:
        return "no_determinado"
    if base in _PROCESOS_TECNICOS_SEGUROS:
        return base
    if base.replace("-", "").replace("_", "").isalnum() and len(base) <= 20:
        return "proceso_no_catalogado"
    return "no_determinado"


def resumen_tamano(size_before, size_after, event):
    """Categoría del tamaño / cambio de tamaño. Sin cifras exactas."""
    def _n(x):
        try:
            return int(str(x).strip())
        except (TypeError, ValueError):
            return None
    b, a = _n(size_before), _n(size_after)
    ev = categoria_evento_fim(event)
    if ev == "deleted":
        if a is not None:
            return "archivo_no_vacio" if a > 0 else "archivo_vacio"
        return "no_determinado"
    if ev == "added":
        if a is not None:
            return "nuevo_no_vacio" if a > 0 else "nuevo_vacio"
        return "no_determinado"
    if b is not None and a is not None:
        if a > b:
            return "aumento"
        if a < b:
            return "reduccion"
        return "sin_cambio_de_tamano"
    return "no_determinado"


def _int_o_no_determinado(x):
    try:
        return int(str(x).strip())
    except (TypeError, ValueError):
        return "no_determinado"


def construir_evidencia_tecnica(alert):
    """
    `alert`: dict de una alerta Wazuh (claves planas proyectadas por
    `get_latest_alerts`: syscheck_path, syscheck_event, syscheck_mode,
    syscheck_size_before/after, syscheck_hash_present, syscheck_uid_after,
    syscheck_uname_after, syscheck_process_name, rule_firedtimes, decoder_name).

    Devuelve SÓLO la lista blanca de valores seguros/categóricos.
    """
    a = alert or {}
    path = a.get("syscheck_path")
    grupos = a.get("groups")
    if isinstance(grupos, str):
        grupos = [g.strip() for g in grupos.replace(";", ",").split(",") if g.strip()]
    grupos = list(grupos or [])

    hay_fim = any(g in ("syscheck", "syscheck_file", "syscheck_entry_added",
                        "syscheck_entry_modified", "syscheck_entry_deleted")
                  for g in grupos) or bool(path)

    telemetry = "wazuh_syscheck" if hay_fim else "wazuh_agent"
    dec = str(a.get("decoder_name") or "")
    if "syscheck" in dec:
        telemetry = "wazuh_syscheck"

    return {
        "fim_event_type": categoria_evento_fim(a.get("syscheck_event")) if hay_fim else "no_aplica",
        "path_category": clasificar_ruta(path) if hay_fim else "no_aplica",
        "file_extension": extension_archivo(path) if hay_fim else "no_aplica",
        "hash_present": bool(a.get("syscheck_hash_present")) if hay_fim else False,
        "size_info": resumen_tamano(a.get("syscheck_size_before"), a.get("syscheck_size_after"),
                                    a.get("syscheck_event")) if hay_fim else "no_aplica",
        "process_category": categoria_proceso(a.get("syscheck_process_name")),
        "user_role_category": categoria_usuario(a.get("syscheck_uid_after"), a.get("syscheck_uname_after"))
                              if hay_fim else "no_determinado",
        "telemetry_source": telemetry,
        "correlated_events": _int_o_no_determinado(a.get("rule_firedtimes")),
        "rule_id": (str(a["rule_id"]) if a.get("rule_id") not in (None, "") else "no_determinado"),
        "rule_groups": grupos,
    }
