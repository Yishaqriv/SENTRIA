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

ENTRADA 1.1 (3F.8) — campos OPCIONALES, solo presentes cuando la telemetría los trae
(los eventos FIM y los snapshots 1.0 no cambian):
  SCA:     sca_resultado, sca_resultado_anterior, sca_id_comprobacion, sca_control_cis,
           sca_categoria_control, sca_benchmark, sca_tacticas_mitre
  Cuentas: cuenta_operacion, cuenta_tipo, cuenta_actor, cuenta_inicio_sesion_interactivo,
           cuenta_atributos_cambiados (lista o "no_determinado"), cuenta_grupo, cuenta_cambio_privilegios,
           cuenta_estado (deshabilitada/habilitada, solo con UAC nuevo válido)
Todos son categorías cerradas o identificadores técnicos validados por patrón; nunca
nombres de usuario/equipo, SIDs, rutas, comandos ni texto libre de la telemetría.

`correlated_events` se mantiene en el contrato pero hoy SIEMPRE es
"no_determinado": SENTRIA no calcula correlación entre eventos. `rule.firedtimes`
es sólo un contador de disparos de la regla (crece con cada evento, sin relación
causal) y NO se presenta como correlación.
"""
from __future__ import annotations

import ntpath
import posixpath
import re

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


# Laboratorio FIM aislado de Windows (Sprint 3E, LAPTOP-01). Misma idea que el de
# Linux: sólo se emite la etiqueta. Comparación sin distinguir mayúsculas
# (Wazuh suele informar las rutas Windows en minúsculas), con `\` o `/`, y tras
# resolver `.`/`..`. Se evalúa ANTES que las categorías genéricas de Windows.
_RUTA_LAB_CONTROLADO_WINDOWS = "c:\\sentria-lab\\"

# Prefijos genéricos de Windows (ya normalizados: minúsculas, `\`, con `\` final).
_PREFIJOS_RUTA_WINDOWS = (
    (_RUTA_LAB_CONTROLADO_WINDOWS, "laboratorio_controlado"),
    ("c:\\windows\\system32\\config\\", "configuracion_sistema"),
    ("c:\\windows\\system32\\spool\\", "spool_impresion"),
    ("c:\\windows\\logs\\", "logs"),
    ("c:\\windows\\temp\\", "temporal"),
    ("c:\\windows\\", "ejecutable_sistema"),
    ("c:\\program files\\", "ejecutable_sistema"),
    ("c:\\program files (x86)\\", "ejecutable_sistema"),
    ("c:\\users\\", "home_anonimizado"),
)

_RUTA_WINDOWS_ABSOLUTA = re.compile(r"^[A-Za-z]:[\\/]")


def _es_ruta_windows(p):
    """`C:\\...` o `C:/...` (absoluta con letra de unidad). UNC y relativas no."""
    return bool(_RUTA_WINDOWS_ABSOLUTA.match(p))


def _clasificar_ruta_windows(p):
    # ntpath.normpath acepta `/` y `\`, colapsa separadores y resuelve `.`/`..`
    # (un `..` que escape del laboratorio deja de estar bajo su raíz).
    p_norm = ntpath.normpath(p).lower().rstrip("\\") + "\\"
    for prefijo, categoria in _PREFIJOS_RUTA_WINDOWS:
        if p_norm.startswith(prefijo):
            return categoria
    return "otra_no_determinada"


def clasificar_ruta(path):
    """Ruta absoluta (Linux o Windows) -> categoría de la lista blanca. NO devuelve la ruta."""
    if not path or not isinstance(path, str):
        return "no_determinado"
    p = path.strip()
    if _es_ruta_windows(p):
        return _clasificar_ruta_windows(p)
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
    p = path.strip()
    if _es_ruta_windows(p):
        base = ntpath.basename(ntpath.normpath(p).rstrip("\\"))
    else:
        base = posixpath.basename(p.rstrip("/"))
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



# ---------------------------------------------------------------------------
# Entrada 1.1 — SCA
# ---------------------------------------------------------------------------
_RE_ID_SCA = re.compile(r"^\d{1,9}$")
_RE_CIS = re.compile(r"^\d{1,2}(\.\d{1,3}){0,5}$")
_RE_TACTICA = re.compile(r"^TA\d{4}$")
_SCA_RESULTADOS = {"failed": "fallida", "passed": "superada", "not applicable": "no_aplicable"}
_CIS_CATEGORIAS = {
    "cis_ubuntu": {"1": "configuracion_inicial", "2": "servicios", "3": "red", "4": "cortafuegos",
                   "5": "control_acceso", "6": "registro_auditoria", "7": "mantenimiento_sistema"},
    "cis_windows": {"1": "politicas_cuenta", "2": "politicas_locales", "5": "servicios_sistema",
                    "9": "cortafuegos", "17": "auditoria_avanzada", "18": "plantillas_admin_equipo",
                    "19": "plantillas_admin_usuario"},
}


def _benchmark(policy):
    p = str(policy or "").lower()
    if "ubuntu" in p or "linux" in p:
        return "cis_ubuntu" if "ubuntu" in p else "cis_linux"
    if "windows" in p:
        return "cis_windows"
    return "otro" if p else "no_determinado"


def evidencia_sca(sca):
    """Dict crudo de `sentria_backend._sca_crudo` -> campos categóricos SCA (o {})."""
    if not isinstance(sca, dict):
        return {}
    bench = _benchmark(sca.get("policy"))
    cis = str(sca.get("cis") or "").split(",")[0].strip()
    cis = cis if _RE_CIS.match(cis) else None
    seccion = cis.split(".")[0] if cis else None
    tacticas = sca.get("mitre_tactics") or []
    if isinstance(tacticas, str):
        tacticas = tacticas.split(",")
    tacticas = sorted({t.strip() for t in tacticas if _RE_TACTICA.match(str(t).strip())})[:5]
    ev = {
        "sca_resultado": _SCA_RESULTADOS.get(str(sca.get("result") or "").strip().lower(), "no_determinado"),
        "sca_id_comprobacion": str(sca.get("id")) if _RE_ID_SCA.match(str(sca.get("id") or "")) else "no_determinado",
        # Puntos -> guiones bajos: "1.3.1.3" parecería una IPv4 al validador de privacidad del dataset.
        "sca_control_cis": ("cis_" + cis.replace(".", "_")) if cis else "no_determinado",
        "sca_categoria_control": _CIS_CATEGORIAS.get(bench, {}).get(seccion, "no_determinado"),
        "sca_benchmark": bench,
        "sca_tacticas_mitre": tacticas,
    }
    prev = str(sca.get("previous_result") or "").strip().lower()
    if prev:
        ev["sca_resultado_anterior"] = _SCA_RESULTADOS.get(prev, "no_determinado")
    return ev


# ---------------------------------------------------------------------------
# Entrada 1.1 — Cuentas (Linux: reglas adduser; Windows: Security EventIDs)
# ---------------------------------------------------------------------------
_OPERACION_LINUX = {"5901": "crear_grupo", "5902": "crear_usuario", "5903": "eliminar_usuario_o_grupo",
                    "5904": "modificar_usuario"}
_OPERACION_WIN = {
    "4720": "crear_usuario", "4722": "habilitar_usuario", "4725": "deshabilitar_usuario",
    "4726": "eliminar_usuario", "4738": "modificar_usuario", "4781": "renombrar_usuario",
    "4723": "cambiar_contrasena", "4724": "restablecer_contrasena", "4740": "bloquear_cuenta",
    "4767": "desbloquear_cuenta", "4727": "crear_grupo", "4731": "crear_grupo", "4754": "crear_grupo",
    "4728": "anadir_miembro_grupo", "4732": "anadir_miembro_grupo", "4756": "anadir_miembro_grupo",
    "4729": "quitar_miembro_grupo", "4733": "quitar_miembro_grupo", "4757": "quitar_miembro_grupo",
}
_GRUPOS_WIN = {"544": "administradores", "545": "usuarios", "546": "invitados", "547": "usuarios_avanzados",
               "551": "operadores_copia", "555": "escritorio_remoto", "562": "dcom", "578": "admins_hyperv",
               "580": "administracion_remota"}
_GRUPOS_PRIVILEGIADOS = {"administradores", "usuarios_avanzados", "operadores_copia", "escritorio_remoto",
                         "dcom", "admins_hyperv", "administracion_remota"}
_ATRIBUTOS_WIN = {
    "displayName": "nombre_visible", "userPrincipalName": "nombre_principal", "samAccountName": "nombre_cuenta",
    "homeDirectory": "directorio_personal", "homePath": "directorio_personal", "scriptPath": "script_inicio",
    "profilePath": "perfil", "userWorkstations": "estaciones_permitidas", "passwordLastSet": "contrasena",
    "accountExpires": "expiracion", "primaryGroupId": "grupo_principal", "allowedToDelegateTo": "delegacion",
    "userParameters": "parametros", "sidHistory": "historial_sid", "logonHours": "horas_inicio_sesion",
}
# [MS-SAMR] USER_ACCOUNT codes: USER_ACCOUNT_DISABLED = 0x00000001 (Old/New UAC Value de 4720/4738).
_UAC_CUENTA_DESHABILITADA = 0x1
_RE_HEX = re.compile(r"^0x[0-9a-fA-F]+$")
_RE_SID_DOMINIO = re.compile(r"^S-1-5-21-\d+-\d+-\d+-(\d+)$")


def _tipo_sid(sid, es_equipo=False):
    if es_equipo:
        return "cuenta_equipo"
    s = str(sid or "")
    if s in ("S-1-5-18", "S-1-5-19", "S-1-5-20"):
        return "cuenta_servicio_sistema"
    m = _RE_SID_DOMINIO.match(s)
    if m:
        rid = int(m.group(1))
        return {500: "administrador_integrado", 501: "invitado_integrado", 503: "cuenta_predeterminada",
                504: "cuenta_wdag"}.get(rid, "usuario" if rid >= 1000 else "no_determinado")
    return "no_determinado"


def _grupo_sid(sid):
    m = re.match(r"^S-1-5-32-(\d+)$", str(sid or ""))
    return _GRUPOS_WIN.get(m.group(1), "grupo_integrado_otro") if m else ("grupo_local_o_dominio"
                                                                          if _RE_SID_DOMINIO.match(str(sid or "")) else "no_determinado")


def _num(x):
    try:
        return int(str(x).strip())
    except (TypeError, ValueError):
        return None


def _uac(valor):
    """Valor UAC hexadecimal válido ("0x15") -> int; cualquier otra cosa (ausente, "-", texto) -> None."""
    s = str(valor or "").strip()
    return int(s, 16) if _RE_HEX.match(s) else None


def _evidencia_cambio_usuario_win(win):
    """
    4738 (y compatibles): distingue cambio demostrado, atributo solo informado y dato no determinado.
    - Formato «delta» (lo no cambiado vale "-" y Wazuh lo omite): cada atributo informado es un cambio demostrado.
    - Formato de «valores completos» (cuentas locales): Microsoft documenta que no puede saberse qué
      atributo cambió -> `no_determinado`, nunca el valor completo como prueba de modificación.
    - Un 4738 sin atributos informados ni cambio UAC: cambió algo no listado (p. ej. la descripción) -> `no_determinado`.
    - control de cuenta: solo si los UAC anterior y nuevo son válidos y distintos; si falta alguno no se infiere nada.
    """
    ant, nue = _uac(win.get("uac_anterior")), _uac(win.get("uac_nuevo"))
    uac_cambio = ant is not None and nue is not None and ant != nue
    if win.get("formato_atributos") == "valores_completos":
        attrs = "no_determinado"
    else:
        cambiados = {_ATRIBUTOS_WIN[k] for k in (win.get("atributos_informados") or []) if k in _ATRIBUTOS_WIN}
        if uac_cambio:
            cambiados.add("control_cuenta")
        attrs = sorted(cambiados) or "no_determinado"
    return attrs, ("control_cuenta_modificado" if uac_cambio else "no_indicado")


def evidencia_cuenta(alert):
    """Campos categóricos de gestión de cuentas (o {} si el evento no es de cuentas)."""
    a = alert or {}
    rid = str(a.get("rule_id") or "")
    win = a.get("win") if isinstance(a.get("win"), dict) else None
    if rid in _OPERACION_LINUX:
        lx = a.get("cuenta_linux") if isinstance(a.get("cuenta_linux"), dict) else {}
        uid, gid = _num(lx.get("uid")), _num(lx.get("gid"))
        ev = {"cuenta_operacion": _OPERACION_LINUX[rid]}
        if rid == "5901":
            ev["cuenta_tipo"] = ("grupo_root" if gid == 0 else "grupo_sistema" if gid is not None and gid < 1000
                                 else "grupo_usuario" if gid is not None else "no_determinado")
        else:
            ev["cuenta_tipo"] = ("superusuario" if uid == 0 else "sistema" if uid is not None and (uid < 1000 or uid == 65534)
                                 else "usuario" if uid is not None else "no_determinado")
        # el decodificador puede dejar puntuación final ("nologin,"): solo se usa el nombre base limpio
        shell = posixpath.basename(str(lx.get("shell") or "").strip().strip(",;")).lower()
        if rid == "5902":
            ev["cuenta_inicio_sesion_interactivo"] = (False if shell in ("nologin", "false") else
                                                      True if shell in ("bash", "sh", "dash", "zsh", "fish", "ksh", "csh", "tcsh")
                                                      else "no_determinado")
        ev["cuenta_cambio_privilegios"] = "privilegios_root" if (uid == 0 or gid == 0) else "no_indicado"
        return ev
    if win and win.get("event_id") in _OPERACION_WIN and str(win.get("channel") or "").lower() == "security":
        op = _OPERACION_WIN[win["event_id"]]
        ev = {"cuenta_operacion": op, "cuenta_actor": _tipo_sid(win.get("subject_sid"))}
        if "miembro_grupo" in op:
            grupo = _grupo_sid(win.get("target_sid"))
            ev["cuenta_grupo"] = grupo
            ev["cuenta_tipo"] = _tipo_sid(win.get("member_sid"))
            priv = grupo in _GRUPOS_PRIVILEGIADOS
            ev["cuenta_cambio_privilegios"] = (("elevacion" if op.startswith("anadir") else "reduccion") if priv
                                               else "sin_cambio_privilegiado" if grupo != "no_determinado" else "no_indicado")
        else:
            ev["cuenta_tipo"] = _tipo_sid(win.get("target_sid"), bool(win.get("target_es_equipo")))
            nue = _uac(win.get("uac_nuevo"))
            if nue is not None and op in ("crear_usuario", "modificar_usuario"):
                ev["cuenta_estado"] = "deshabilitada" if nue & _UAC_CUENTA_DESHABILITADA else "habilitada"
            if op == "modificar_usuario":
                ev["cuenta_atributos_cambiados"], ev["cuenta_cambio_privilegios"] = _evidencia_cambio_usuario_win(win)
            else:
                ev["cuenta_cambio_privilegios"] = "no_indicado"
        return ev
    return {}


def construir_evidencia_tecnica(alert):
    """
    `alert`: dict de una alerta Wazuh (claves planas proyectadas por
    `get_latest_alerts`: syscheck_path, syscheck_event, syscheck_mode,
    syscheck_size_before/after, syscheck_hash_present, syscheck_uid_after,
    syscheck_uname_after, syscheck_process_name, decoder_name). `rule_firedtimes`
    se ignora a propósito: no es correlación.

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
        "correlated_events": "no_determinado",   # sin correlación calculada (ver cabecera)
        "rule_id": (str(a["rule_id"]) if a.get("rule_id") not in (None, "") else "no_determinado"),
        "rule_groups": grupos,
        # Entrada 1.1: SOLO si la telemetría los trae (FIM y snapshots 1.0 no cambian)
        **evidencia_sca(a.get("sca")),
        **evidencia_cuenta(a),
    }
