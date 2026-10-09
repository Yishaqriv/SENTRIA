"""
Construcción de la entrada (capa E) y del prompt para el proveedor de IA.

La capa E contiene SOLO información que un analista tendría normalmente:
- de Wazuh: descripción (anonimizada), nivel, grupos, rule.id;
- del ActivoLogico configurado: tipo, criticidad, familia/rol de SO, contexto
  autorizado, ventana operativa (calculada objetivamente contra la hora de la
  alerta);
- cálculo objetivo: resumen de evidencia técnica, `attack_vector` conservador.

Nunca se incluyen: agent.id, hostname, IP ni campos de las capas P/S.
Sin ActivoLogico NO se construye entrada para el prompt: la política de
elegibilidad marca la alerta OMITIDO_POLITICA (SIN_CONTEXTO_ACTIVO).
"""
from __future__ import annotations

import datetime

from .anonimizacion import anonimizar_texto
from .contrato import CVSS_CLAVES
from .alcance import alcance_en_entrada, coincidencia, operacion_observada
from .evidencia import construir_evidencia_tecnica

# Estados de ventana de mantenimiento (capa E).
#   dentro_ventana_declarada : hay un mantenimiento autorizado que cubre la alerta.
#   sin_ventana_declarada    : hay activo y hora, pero ninguna ventana coincide.
#   indeterminado            : falta activo o timestamp fiable.
# NUNCA se usa "fuera_ventana_declarada": no hay evidencia explícita para afirmarlo.
# Estar dentro de una ventana NO convierte la alerta en FALSO_POSITIVO.
VENTANA_MANT_ESTADOS = (
    "dentro_ventana_declarada", "sin_ventana_declarada", "indeterminado",
)


def _estado_ventana_mantenimiento(alert, activo=None, momento=None):
    """
    Devuelve (estado, categoria|None). `alert['maintenance_window']` explícito
    (pruebas / override) tiene prioridad; si no, se consulta el modelo.
    """
    v = str(alert.get("maintenance_window", "") or "").strip()
    if v in VENTANA_MANT_ESTADOS:
        return v, alert.get("maintenance_category")
    if "maintenance_window_declared" in alert:  # compatibilidad con el bool antiguo
        return ("dentro_ventana_declarada" if alert["maintenance_window_declared"]
                else "sin_ventana_declarada"), None
    try:
        from dashboard.mantenimiento import estado_para
        return estado_para(activo, momento)
    except Exception:
        return "indeterminado", None


def _alcance_mantenimiento(alert, activo, momento, estado):
    """Alcance declarado de la ventana que cubre el evento (misma ventana y misma hora que `estado`).
    `alert['maintenance_scope']` explícito (pruebas / override) tiene prioridad."""
    if estado != "dentro_ventana_declarada":
        return None
    v = str(alert.get("maintenance_scope", "") or "").strip()
    if v:
        return v
    try:
        from dashboard.mantenimiento import alcance_para
        return alcance_para(activo, momento)
    except Exception:
        return None


def _texto_evidencia(nivel, grupos, ev):
    partes = [f"Regla de Wazuh nivel {nivel if nivel is not None else 'no determinado'} "
              f"({', '.join(grupos) or 'sin grupos'})."]
    if ev.get("fim_event_type") not in (None, "no_determinado", "no_aplica"):
        partes.append(
            f"Evento FIM: {ev['fim_event_type']} sobre un archivo de categoría "
            f"'{ev['path_category']}' (extensión: {ev['file_extension']}). "
            f"Hash disponible: {'sí' if ev['hash_present'] else 'no'}. "
            f"Tamaño: {ev['size_info']}. Usuario (rol anonimizado): {ev['user_role_category']}. "
            f"Proceso: {ev['process_category']}. "
            f"Telemetría: {ev['telemetry_source']}."
        )
    else:
        partes.append(f"Telemetría: {ev.get('telemetry_source', 'no_determinado')}. "
                      "Sólo hay descripción, nivel y grupos de la regla; sin datos FIM estructurados.")
    extra = [k for k in ev if k.startswith(("sca_", "cuenta_", "win_"))]
    if extra:
        partes.append("Incluye evidencia estructurada adicional (categorías anonimizadas): " + ", ".join(extra) + ".")
    return " ".join(partes)

_OBS_CVSS_POR_DEFECTO = {k: "no_determinado" for k in CVSS_CLAVES}

# Grupos de Wazuh que permiten inferir el vector de ataque de forma conservadora.
_GRUPOS_VECTOR_RED = {"web", "ids", "firewall", "attack", "recon", "sshd",
                      "authentication_failed", "authentication_success", "invalid_login"}
_GRUPOS_VECTOR_LOCAL = {"syscheck", "syscheck_file", "syscheck_registry", "rootcheck",
                        "sudo", "adduser", "account_changed", "policy_changed"}


def _nivel_int(level):
    try:
        return int(float(level))
    except (TypeError, ValueError):
        return None


def _grupos_lista(groups):
    if isinstance(groups, (list, tuple)):
        return [str(g).strip() for g in groups if str(g).strip()]
    if not groups:
        return []
    return [g.strip() for g in str(groups).replace(";", ",").split(",") if g.strip()]


def _parsear_ts(ts):
    if isinstance(ts, datetime.datetime):
        return ts
    if not ts:
        return None
    s = str(ts).replace("Z", "+00:00")
    try:
        return datetime.datetime.fromisoformat(s)
    except ValueError:
        return None


def _ventana_operativa(ts, activo):
    """
    Cálculo OBJETIVO: compara la hora de la alerta con el horario de operación
    del activo. Devuelve 'dentro_horario_operativo' | 'fuera_horario_operativo'
    | 'no_determinado' (si no hay timestamp usable).
    Activo con `horario_sin_restriccion`: cualquier hora está dentro del horario,
    así que es 'dentro_horario_operativo' aunque falte la hora del evento.
    """
    if activo is None:
        return "no_determinado"
    if getattr(activo, "horario_sin_restriccion", False):
        return "dentro_horario_operativo"
    dt = _parsear_ts(ts)
    if dt is None:
        return "no_determinado"
    try:
        from zoneinfo import ZoneInfo
        tz = ZoneInfo(activo.zona_horaria or "America/Bogota")
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        hora = dt.astimezone(tz).time()
    except Exception:
        hora = dt.time()
    ini, fin = activo.hora_inicio_operacion, activo.hora_fin_operacion
    dentro = (ini <= hora <= fin) if ini <= fin else (hora >= ini or hora <= fin)
    return "dentro_horario_operativo" if dentro else "fuera_horario_operativo"


# Hora del EVENTO (horario y ventana) frente a hora de RECEPCIÓN (diagnóstico).
# - `timestamp` (= `@timestamp`: el pipeline de Filebeat de Wazuh lo copia de `timestamp`) es la hora en que el gestor
#   generó la alerta. Un agente Windows puede entregar eventos con horas o días de retraso.
# - Windows: `win.system.systemTime` = TimeCreated/SystemTime, hora UTC en que Windows registró el evento.
# Sin hora original válida en un evento Windows NO se usa la recepción: horario `no_determinado`, ventana `indeterminado`.
_TOLERANCIA_RELOJ = datetime.timedelta(minutes=5)
_ANIO_MINIMO_EVENTO = 2000          # FILETIME 0 = 1601: hora no inicializada


def _a_utc(dt):
    return dt.replace(tzinfo=datetime.timezone.utc) if dt.tzinfo is None else dt.astimezone(datetime.timezone.utc)


def _es_evento_windows(alert):
    """Evento del registro de eventos de Windows (eventchannel), aunque falte la capa `win`."""
    if isinstance(alert.get("win"), dict):
        return True
    return (str(alert.get("decoder_name") or "").lower() == "windows_eventchannel"
            or any(g.lower().startswith("windows") for g in _grupos_lista(alert.get("groups"))))


def hora_del_evento(alert):
    """
    -> (momento UTC | None, fuente, recepción UTC | None).
    fuente: 'recepcion_wazuh' (no Windows: única hora disponible, comportamiento anterior) ·
            'hora_original_windows' · 'hora_original_ausente' · 'hora_original_invalida' ·
            'hora_original_sin_zona' · 'hora_original_incoherente' (anterior a 2000 o posterior a la recepción
            en más de la tolerancia de reloj).
    """
    recepcion = _parsear_ts(alert.get("timestamp"))
    recepcion = _a_utc(recepcion) if recepcion is not None else None
    if not _es_evento_windows(alert):
        return recepcion, "recepcion_wazuh", recepcion
    win = alert.get("win") if isinstance(alert.get("win"), dict) else {}
    crudo = win.get("system_time")
    if crudo in (None, ""):
        return None, "hora_original_ausente", recepcion
    if not isinstance(crudo, str) or len(crudo) > 40:
        return None, "hora_original_invalida", recepcion
    original = _parsear_ts(crudo.strip())
    if original is None:
        return None, "hora_original_invalida", recepcion
    if original.tzinfo is None:
        return None, "hora_original_sin_zona", recepcion
    original = _a_utc(original)
    if original.year < _ANIO_MINIMO_EVENTO or (recepcion is not None and original > recepcion + _TOLERANCIA_RELOJ):
        return None, "hora_original_incoherente", recepcion
    return original, "hora_original_windows", recepcion


def diagnostico_tiempo(alert, activo=None):
    """Capa P (snapshot `_diagnostico_tiempo`, fuera de la entrada y de la huella): qué hora se usó y por qué."""
    momento, fuente, recepcion = hora_del_evento(alert)
    d = {"fuente": fuente,
         "hora_evento_utc": momento.isoformat() if momento else None,
         "recepcion_utc": recepcion.isoformat() if recepcion else None,
         "retraso_segundos": int((recepcion - momento).total_seconds()) if momento and recepcion else None}
    try:
        from dashboard.mantenimiento import ventana_declarada_despues
        d["ventana_registrada_despues_del_evento"] = ventana_declarada_despues(activo, momento)
    except Exception:
        d["ventana_registrada_despues_del_evento"] = None
    return d


def _attack_vector_conservador(grupos):
    g = set(grupos)
    if g & _GRUPOS_VECTOR_RED:
        return "red"
    if g & _GRUPOS_VECTOR_LOCAL:
        return "local"
    return "no_determinado"


def construir_entrada_e(alert, activo):
    """
    `alert`: dict con 'description'/'descripcion', 'level'/'severidad',
             'groups', 'rule_id', 'timestamp'.
    `activo`: instancia de ActivoLogico (obligatoria; sin activo la alerta
              no llega aquí — la omite la política).
    Devuelve el dict de la capa E, ya anonimizado. NO incluye datos del activo
    que puedan identificar (solo tipo/criticidad/SO/contexto/horario).
    """
    descripcion = alert.get("description", alert.get("descripcion", "")) or ""
    nivel = _nivel_int(alert.get("level", alert.get("severidad")))
    grupos = _grupos_lista(alert.get("groups"))

    obs_cvss = dict(_OBS_CVSS_POR_DEFECTO)
    obs_cvss["attack_vector"] = _attack_vector_conservador(grupos)

    # Evidencia técnica: SÓLO valores categóricos/anonimizados (lista blanca).
    evidencia_tecnica = construir_evidencia_tecnica({**alert, "groups": grupos})

    # Horario y ventana con la hora del EVENTO (en Windows, la original; nunca la recepción en su lugar).
    momento, _fuente, _recepcion = hora_del_evento(alert)
    mant_estado, mant_categoria = _estado_ventana_mantenimiento(alert, activo, momento)
    # Entrada 1.3: alcance de la autorización y correspondencia CONSERVADORA con la operación observada.
    mant_alcance = alcance_en_entrada(mant_estado, _alcance_mantenimiento(alert, activo, momento, mant_estado))
    mant_coincide = coincidencia(mant_estado, mant_alcance, operacion_observada(evidencia_tecnica, alert.get("rule_id")))

    return {
        # Entrada 1.1 (3F.8): añade campos OPCIONALES sca_* / cuenta_* en evidencia_tecnica.
        # Entrada 1.2: añade campos OPCIONALES win_* (solo eventos Windows Application/System) y, en eventos
        # Windows, calcula horario y ventana con la hora original del evento (`hora_del_evento`).
        # Entrada 1.3: añade `maintenance_scope` y `maintenance_scope_match` (alcance de la autorización).
        # Entrada 1.4: añade campos OPCIONALES de Security 4719 (subcategoría y acción de auditoría) y 6416 (clase del dispositivo).
        # Los snapshots 1.0–1.3 siguen siendo válidos y no se recalculan; la huella ignora la versión.
        "schema_version": "1.4",
        "alert_description_es": anonimizar_texto(descripcion),
        "wazuh_level": nivel,
        "wazuh_rule_groups": grupos,
        "wazuh_rule_id": (str(alert["rule_id"]) if alert.get("rule_id") not in (None, "") else None),
        "asset_type": activo.tipo_activo,
        "asset_criticality": activo.criticidad,
        "asset_os_family": activo.os_family,
        "asset_os_role": activo.os_role,
        "operational_window": _ventana_operativa(momento, activo),
        "maintenance_window": mant_estado,
        # SÓLO la categoría controlada llega al prompt; descripción/creador/auditoría NO.
        "maintenance_category": mant_categoria or "no_aplica",
        "maintenance_scope": mant_alcance,
        "maintenance_scope_match": mant_coincide,
        "authorized_context_es": activo.contexto_autorizado_es,
        "technical_evidence_es": _texto_evidencia(nivel, grupos, evidencia_tecnica),
        "evidencia_tecnica": evidencia_tecnica,
        "observed_cvss_factors": obs_cvss,
    }


_INSTRUCCIONES = """\
Eres un analista de seguridad. Analiza la alerta y responde ÚNICAMENTE con un
objeto JSON válido, sin texto adicional y sin markdown (nada de ```).

El objeto debe tener EXACTAMENTE estas claves:
  "schema_version": "1.0"
  "verdict": "FALSO_POSITIVO" | "REQUIERE_ATENCION"
  "risk": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
  "explanation_es": texto en español, 20 a 600 caracteres
  "cvss_factors": objeto con EXACTAMENTE estas 8 claves y estos valores:
     "attack_vector": "red"|"adyacente"|"local"|"fisico"|"no_determinado"
     "attack_complexity": "baja"|"alta"|"no_determinado"
     "privileges_required": "ninguno"|"bajos"|"altos"|"no_determinado"
     "user_interaction": "ninguna"|"requerida"|"no_determinado"
     "scope": "sin_cambio"|"cambiado"|"no_determinado"
     "confidentiality_impact": "ninguno"|"bajo"|"alto"|"no_determinado"
     "integrity_impact": "ninguno"|"bajo"|"alto"|"no_determinado"
     "availability_impact": "ninguno"|"bajo"|"alto"|"no_determinado"
  "cvss_reasoning_es": texto en español, 20 a 800 caracteres; indica qué
     factores quedaron "no_determinado" y por qué
  "recommendation_es": texto en español, 10 a 500 caracteres; una acción
     sugerida, nunca ejecutada automáticamente
  "missing_evidence": lista de 0 a 10 textos (cada uno de 3 a 120 caracteres)
     con la evidencia que faltó

Reglas:
- Un riesgo bajo (LOW) NO implica que sea FALSO_POSITIVO.
- Si falta evidencia, marca los factores como "no_determinado"; no inventes.
- No añadas ninguna clave extra ni comentarios.
- "verdict" debe ser EXACTAMENTE "FALSO_POSITIVO" o "REQUIERE_ATENCION"
  (mayúsculas, sin acentos, sin sinónimos).
- Ventana de mantenimiento:
    · "sin_ventana_declarada" = no hay ninguna ventana que cubra este momento
      (NO asumas que ocurrió "fuera de la ventana").
    · "indeterminado" = falta el activo o una hora fiable.
    · "dentro_ventana_declarada" = hay un mantenimiento AUTORIZADO que cubre este
      momento. Es contexto a favor de una explicación benigna, pero **NO** hace
      la alerta FALSO_POSITIVO por sí solo: pondera la evidencia técnica (qué se
      modificó, quién, correlación) y la categoría del mantenimiento.
- Alcance de la autorización (tipo de operación autorizada en la ventana):
    · "coincide" = la operación observada es del tipo autorizado. No prueba ausencia
      de privilegios ni de riesgo: sigue ponderando la evidencia técnica.
    · "no_coincide" = la operación observada es de otro tipo: la ventana no la autoriza.
    · "no_determinado" = no puede compararse (alcance no declarado, no tipificado u
      operación sin evidencia suficiente). "no_aplica" = no hay ventana.
"""


def construir_prompt(entrada_e):
    """entrada_e: dict devuelto por construir_entrada_e(). -> str prompt."""
    grupos = ", ".join(entrada_e["wazuh_rule_groups"]) or "(sin grupos)"
    ev = entrada_e.get("evidencia_tecnica", {}) or {}
    return (
        _INSTRUCCIONES
        + "\n--- ALERTA ---\n"
        + f"Descripción (anonimizada): {entrada_e['alert_description_es']}\n"
        + f"Nivel Wazuh: {entrada_e['wazuh_level']}\n"
        + f"Grupos de la regla: {grupos}\n"
        + f"ID de regla: {entrada_e['wazuh_rule_id'] or 'no disponible'}\n"
        + f"Tipo de activo: {entrada_e['asset_type']}\n"
        + f"Criticidad del activo: {entrada_e['asset_criticality']}\n"
        + f"Familia de SO: {entrada_e['asset_os_family']}\n"
        + f"Rol del activo: {entrada_e['asset_os_role']}\n"
        + f"Ventana operativa: {entrada_e['operational_window']}\n"
        + f"Ventana de mantenimiento: {entrada_e['maintenance_window']}\n"
        + f"Categoría del mantenimiento declarado: {entrada_e.get('maintenance_category', 'no_aplica')}\n"
        + f"Alcance autorizado del mantenimiento: {entrada_e.get('maintenance_scope', 'no_determinado')}\n"
        + f"Coincidencia de la operación con el alcance: {entrada_e.get('maintenance_scope_match', 'no_determinado')}\n"
        + f"Contexto autorizado: {entrada_e['authorized_context_es']}\n"
        + f"Evidencia técnica (categórica y anonimizada): {entrada_e['technical_evidence_es']}\n"
        + f"  · tipo de evento FIM: {ev.get('fim_event_type', 'no_determinado')}\n"
        + f"  · categoría de ruta: {ev.get('path_category', 'no_determinado')}\n"
        + f"  · extensión/tipo de archivo: {ev.get('file_extension', 'no_determinado')}\n"
        + f"  · hash disponible: {ev.get('hash_present', False)}\n"
        + f"  · tamaño: {ev.get('size_info', 'no_determinado')}\n"
        + f"  · rol del usuario (anonimizado): {ev.get('user_role_category', 'no_determinado')}\n"
        + f"  · proceso (anonimizado): {ev.get('process_category', 'no_determinado')}\n"
        + f"  · eventos correlacionados: {ev.get('correlated_events', 'no_determinado')}\n"
        + f"  · fuente de telemetría: {ev.get('telemetry_source', 'no_determinado')}\n"
        + _lineas_evidencia_extra(ev)
    )


_ETIQUETAS_EXTRA = {
    "sca_resultado": "resultado de la comprobación SCA", "sca_resultado_anterior": "resultado SCA anterior",
    "sca_id_comprobacion": "identificador de la comprobación SCA", "sca_control_cis": "control CIS",
    "sca_categoria_control": "categoría del control", "sca_benchmark": "benchmark",
    "sca_tacticas_mitre": "tácticas MITRE asociadas", "cuenta_operacion": "operación sobre la cuenta",
    "cuenta_tipo": "tipo de cuenta", "cuenta_actor": "tipo de actor que hizo el cambio",
    "cuenta_inicio_sesion_interactivo": "permite inicio de sesión interactivo",
    "cuenta_atributos_cambiados": "atributos cambiados", "cuenta_grupo": "grupo afectado",
    "cuenta_cambio_privilegios": "cambio de privilegios", "cuenta_estado": "estado de la cuenta",
    "win_canal": "canal del registro de eventos de Windows", "win_proveedor": "proveedor del evento",
    "win_proveedor_categoria": "categoría del proveedor", "win_id_evento": "ID de evento de Windows",
    "win_auditoria_subcategoria": "subcategoría de auditoría modificada", "win_auditoria_cambio": "cambio de auditoría",
    "win_dispositivo_clase": "clase del dispositivo",
}


def _lineas_evidencia_extra(ev):
    """Solo para campos 1.1/1.2 presentes; todos son categorías cerradas o identificadores validados (nunca texto libre)."""
    out = ""
    for k, etiqueta in _ETIQUETAS_EXTRA.items():
        if k in ev:
            v = ev[k]
            v = ", ".join(v) if isinstance(v, list) else v
            out += f"  · {etiqueta}: {v if v not in ('', None) else 'ninguno'}\n"
    return out
