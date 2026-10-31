"""
Diagnóstico de solo lectura del flujo legado (Sprint 3C/3D).

Todo aquí es GET contra el indexador Wazuh con las credenciales de solo
lectura configuradas, a través del acceso central de `sentria_backend` (no
abre su propio cliente HTTP ni su propia configuración TLS). Nunca llama a
Gemini, nunca escribe en `Alert`. Devuelve SIEMPRE conteos agregados — nunca
rutas, usuarios, IP, hostname, agent.id ni opensearch_id concretos.

"Recuperable" (el documento sigue en Wazuh) NO significa "apto para el
dataset": sólo lo recuperable Y elegible por la política vigente podría
completar el flujo real.
"""
from __future__ import annotations

from .politica import cargar_politica, evaluar_elegibilidad
from .resolver import agentes_bloqueados, resolver_activo_por_agente
from ..models import Alert


def _buscar_documentos(opensearch_ids, agent_id=None):
    """{opensearch_id: alerta normalizada} vía el acceso central al indexador."""
    from sentria_backend import get_alerts_by_ids
    return get_alerts_by_ids(opensearch_ids, agent_id=agent_id)


def _grupos(doc):
    grupos = doc.get("groups") or []
    if isinstance(grupos, str):
        grupos = [g.strip() for g in grupos.split(",")]
    return [g for g in grupos if g]


def diagnosticar_legado():
    """
    Para cada alerta legado (`estado_analisis` NULL) con `opensearch_id`,
    comprueba si el documento de Wazuh sigue existiendo y evalúa elegibilidad,
    asignación de activo y bloqueo. Devuelve SÓLO conteos agregados.
    """
    qs_legado = Alert.objects.filter(estado_analisis__isnull=True)
    legado_con_id = list(qs_legado.exclude(opensearch_id__isnull=True).exclude(opensearch_id=""))
    docs = _buscar_documentos([a.opensearch_id for a in legado_con_id])

    politica = cargar_politica()
    bloqueados = agentes_bloqueados()

    legado_total = qs_legado.count()
    resumen = {
        "legado_total": legado_total,
        "legado_con_opensearch_id": len(legado_con_id),
        "legado_sin_opensearch_id": legado_total - len(legado_con_id),
        "sin_documento": 0,
        "recuperables": 0,
        "agente_bloqueado": 0,
        "sin_activo_asignado": 0,
        "recuperable_y_elegible": 0,
        "recuperable_no_elegible": 0,
    }
    por_familia, por_familia_elegible, por_nivel, por_motivo = {}, {}, {}, {}
    por_agente = {}

    for a in legado_con_id:
        doc = docs.get(a.opensearch_id)
        if doc is None:
            resumen["sin_documento"] += 1
            continue
        resumen["recuperables"] += 1
        agent_id = str(doc.get("agent_id") or "").strip()
        nivel = doc.get("level")
        grupos = _grupos(doc)
        familia = grupos[0] if grupos else "sin_grupo"

        por_familia[familia] = por_familia.get(familia, 0) + 1
        por_nivel[nivel] = por_nivel.get(nivel, 0) + 1
        por_agente[agent_id] = por_agente.get(agent_id, 0) + 1   # agregado, nunca se muestra el id crudo fuera de este módulo

        if agent_id in bloqueados:
            resumen["agente_bloqueado"] += 1
            continue
        activo = resolver_activo_por_agente(agent_id)
        if activo is None:
            resumen["sin_activo_asignado"] += 1
            continue
        decision = evaluar_elegibilidad(
            {"level": nivel, "groups": grupos, "rule_id": doc.get("rule_id")},
            tiene_activo=True, politica=politica,
        )
        if decision.elegible:
            resumen["recuperable_y_elegible"] += 1
            por_familia_elegible[familia] = por_familia_elegible.get(familia, 0) + 1
        else:
            resumen["recuperable_no_elegible"] += 1
            motivo = decision.motivo_omision or "otro"
            por_motivo[motivo] = por_motivo.get(motivo, 0) + 1

    # Todo lo recuperable que NO es elegible (política, agente bloqueado o sin activo).
    resumen["no_elegible_total"] = resumen["recuperables"] - resumen["recuperable_y_elegible"]
    # Legado que no puede reconstruirse: sin opensearch_id o con el documento ya borrado.
    resumen["sin_documento_recuperable"] = resumen["legado_sin_opensearch_id"] + resumen["sin_documento"]
    resumen["por_familia"] = por_familia
    resumen["por_familia_elegible"] = por_familia_elegible
    resumen["por_nivel"] = por_nivel
    resumen["por_motivo_omision"] = por_motivo
    resumen["n_agentes_distintos"] = len(por_agente)
    return resumen
