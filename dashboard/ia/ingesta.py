"""
Ingesta completa (Sprint 2B).

Un único camino para toda la ingesta: dedup -> crear (siempre) -> resolver
activo lógico -> política de elegibilidad -> analizar con el contrato o marcar
OMITIDO_POLITICA. Nada de {"risk","reason"}; nada de contexto inventado.

Este módulo NO llama al indexador de Wazuh: recibe alertas ya crudas (dicts).
El proveedor de IA es inyectable (mockeable en pruebas).
"""
from __future__ import annotations

from django.db import transaction
from django.utils import timezone

from dashboard.models import Alert

from .analizador import analizar_alerta
from .persistencia import aplicar_omision, aplicar_resultado
from .politica import cargar_politica, evaluar_elegibilidad
from .prompt import _grupos_lista, _nivel_int
from .resolver import resolver_desde_alerta


def resolver_activo(alert, resolver=None):
    """
    Devuelve el ActivoLogico de una alerta, o None.
    `resolver`: callable(alert)->ActivoLogico|None (inyección para pruebas).
    Sin resolver: se usa `resolver_desde_alerta` (identificador lógico explícito
    o, si no, la asignación activa del `agent.id` — capa P). Nunca se usa
    `agent.id`/hostname/IP como dato del prompt.
    """
    if callable(resolver):
        return resolver(alert)
    return resolver_desde_alerta(alert)


def _alert_dict_desde_modelo(alerta):
    return {
        "description": alerta.descripcion,
        "level": alerta.severidad,
        "groups": alerta.wazuh_rule_groups or "",
        "rule_id": alerta.wazuh_rule_id,
        "timestamp": alerta.timestamp.isoformat() if alerta.timestamp else None,
        # capa P: sólo para re-resolver el activo; no llega al prompt/snapshot.
        "agent_id": alerta.wazuh_agent_id,
    }


def _enriquecer_procedencia(alerta, alert):
    """
    Completa ÚNICAMENTE los campos de PROCEDENCIA de Wazuh que estén vacíos en
    una alerta ya existente (dedup por opensearch_id): `wazuh_agent_id`,
    `wazuh_rule_id`, `wazuh_rule_groups`.

    NO toca `COMPLETED`. NO sobrescribe un valor ya presente. NO toca
    descripción, severidad, veredicto, riesgo, explicación ni correcciones
    humanas. Devuelve la lista de campos completados.
    """
    if alerta.estado_analisis == "COMPLETED":
        return []
    cambios = []
    if not alerta.wazuh_agent_id and alert.get("agent_id") not in (None, ""):
        alerta.wazuh_agent_id = str(alert["agent_id"])
        cambios.append("wazuh_agent_id")
    if not alerta.wazuh_rule_id and alert.get("rule_id") not in (None, ""):
        alerta.wazuh_rule_id = str(alert["rule_id"])
        cambios.append("wazuh_rule_id")
    if not alerta.wazuh_rule_groups:
        grupos = _grupos_lista(alert.get("groups"))
        if grupos:
            alerta.wazuh_rule_groups = grupos
            cambios.append("wazuh_rule_groups")
    if cambios:
        alerta.save(update_fields=cambios)
    return cambios


def ingestar_alerta(alert, *, resolver=None, politica=None, proveedor=None):
    """
    Procesa UNA alerta cruda. Devuelve (Alert, accion) con accion en
    {'duplicada','omitida','analizada','fallida'} para una alerta NUEVA, o
    'recuperada:<omitida|analizada|fallida>' cuando una alerta ya existente y
    no COMPLETED se reprocesa (dedup que NO impide la recuperación explícita).
    Aísla su propio fallo.
    """
    politica = politica or cargar_politica()
    opensearch_id = alert.get("opensearch_id")

    if opensearch_id:
        existente = Alert.objects.filter(opensearch_id=opensearch_id).first()
        if existente is not None:
            # COMPLETED (o con corrección humana) -> intocable: no-op.
            if existente.estado_analisis == "COMPLETED":
                return existente, "duplicada"
            # PENDING / OMITIDO_POLITICA / ANALISIS_FALLIDO / legacy:
            # el dedup por opensearch_id NO debe impedir recuperarla. Se
            # completan SÓLO los campos de procedencia que falten (sin tocar
            # datos históricos) y se re-evalúa con la política y las
            # asignaciones vigentes.
            _enriquecer_procedencia(existente, alert)
            accion = reanalizar_alerta(
                existente, politica=politica, proveedor=proveedor, resolver=resolver
            )
            return existente, f"recuperada:{accion}"

    activo = resolver_activo(alert, resolver)

    with transaction.atomic():
        obj = Alert.objects.create(
            opensearch_id=opensearch_id,
            timestamp=alert.get("timestamp"),
            titulo=(alert.get("description") or alert.get("descripcion") or "")[:255],
            descripcion=alert.get("description") or alert.get("descripcion") or "",
            severidad=_nivel_int(alert.get("level", alert.get("severidad"))),
            estado="Pendiente",
            estado_analisis="PENDING",
            fuente="Wazuh",
            activo_logico=activo,
            wazuh_rule_id=(str(alert["rule_id"]) if alert.get("rule_id") not in (None, "") else None),
            wazuh_rule_groups=_grupos_lista(alert.get("groups")) or None,
            wazuh_agent_id=(str(alert["agent_id"]) if alert.get("agent_id") not in (None, "") else None),
        )

    tiene_activo = bool(activo and getattr(activo, "activo", True))
    decision = evaluar_elegibilidad(alert, tiene_activo, politica)

    if not decision.elegible:
        with transaction.atomic():
            aplicar_omision(obj, decision.motivo_omision)
        return obj, "omitida"

    try:
        resultado = analizar_alerta(alert, activo, proveedor=proveedor)
        with transaction.atomic():
            aplicar_resultado(obj, resultado)
    except Exception as e:  # aísla el fallo de esta alerta
        with transaction.atomic():
            obj.refresh_from_db()
            if obj.estado_analisis != "COMPLETED":
                obj.estado_analisis = "ANALISIS_FALLIDO"
                obj.explicacion_ia = f"Error de ingesta: {type(e).__name__}: {e}"
                obj.analizado_en = timezone.now()
                obj.save()
        return obj, "fallida"

    return obj, ("analizada" if resultado["estado_analisis"] == "COMPLETED" else "fallida")


def ingestar_lote(alertas, *, resolver=None, politica=None, proveedor=None):
    """Procesa una lista de alertas crudas. El fallo de una NO detiene el resto."""
    politica = politica or cargar_politica()
    c = {"total": 0, "nuevas": 0, "duplicadas": 0, "recuperadas": 0,
         "omitidas": 0, "analizadas": 0, "fallidas": 0}
    _plural = {"analizada": "analizadas", "omitida": "omitidas", "fallida": "fallidas",
               "completed_sin_cambios": "duplicadas"}
    for alert in alertas:
        c["total"] += 1
        try:
            _obj, accion = ingestar_alerta(
                alert, resolver=resolver, politica=politica, proveedor=proveedor
            )
        except Exception:
            c["nuevas"] += 1
            c["fallidas"] += 1
            continue
        if accion == "duplicada":
            c["duplicadas"] += 1
        elif accion.startswith("recuperada:"):
            real = accion.split(":", 1)[1]
            if real == "completed_sin_cambios":
                c["duplicadas"] += 1
            else:
                c["recuperadas"] += 1
                c[_plural.get(real, "fallidas")] += 1
        else:
            c["nuevas"] += 1
            c[_plural.get(accion, "fallidas")] += 1
    return c


_CAMPOS_EVIDENCIA_OVERRIDE = (
    "description", "groups", "rule_id", "timestamp", "rule_firedtimes", "decoder_name",
    "syscheck_path", "syscheck_event", "syscheck_mode", "syscheck_size_before",
    "syscheck_size_after", "syscheck_hash_present", "syscheck_uid_after",
    "syscheck_uname_after", "syscheck_perm_after", "syscheck_process_name",
    "sca", "cuenta_linux", "win",          # entrada 1.1 (3F.8)
)


def reanalizar_alerta(alerta, *, politica=None, proveedor=None, resolver=None, alert_override=None):
    """
    Re-analiza una alerta EXISTENTE en ANALISIS_FALLIDO / PENDING /
    OMITIDO_POLITICA / sin estado (legacy).

    - NUNCA toca una alerta COMPLETED (-> 'completed_sin_cambios').
    - NUNCA sobrescribe la corrección humana ni, una vez COMPLETED, el
      veredicto original de la IA.
    - Vuelve a RESOLVER el activo con las asignaciones vigentes (capa P): si
      apareció una asignación válida para el `agent.id` de la alerta, deja de
      estar SIN_CONTEXTO_ACTIVO. Sólo afecta a alertas no COMPLETED — las
      históricas conservan su `activo_logico` y su snapshot.
    - Re-aplica la POLÍTICA vigente (`settings.IA_POLITICA`).
    - Un reintento nunca convierte un error en FALSO_POSITIVO
      (`resultado_fallido`/`aplicar_omision` fuerzan `veredicto_ia=None`).
    -> str acción {'completed_sin_cambios','omitida','analizada','fallida'}.
    """
    if alerta.estado_analisis == "COMPLETED":
        return "completed_sin_cambios"
    politica = politica or cargar_politica()

    alert_dict = _alert_dict_desde_modelo(alerta)
    if alert_override:
        for k in _CAMPOS_EVIDENCIA_OVERRIDE:
            if k in alert_override and alert_override[k] not in (None, ""):
                alert_dict[k] = alert_override[k]
    activo = resolver_activo(alert_dict, resolver)
    if activo is None and alerta.activo_logico_id and alerta.activo_logico and alerta.activo_logico.activo:
        activo = alerta.activo_logico
    if activo is not None and alerta.activo_logico_id != activo.id:
        alerta.activo_logico = activo
        alerta.save(update_fields=["activo_logico"])

    decision = evaluar_elegibilidad(alert_dict, bool(activo), politica)
    if not decision.elegible:
        aplicar_omision(alerta, decision.motivo_omision)
        return "omitida"

    resultado = analizar_alerta(alert_dict, activo, proveedor=proveedor)
    aplicar_resultado(alerta, resultado)
    return "analizada" if resultado["estado_analisis"] == "COMPLETED" else "fallida"
