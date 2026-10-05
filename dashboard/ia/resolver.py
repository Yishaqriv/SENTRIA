"""
Resolver real agente físico (Wazuh `agent.id`) -> `ActivoLogico` (Sprint 2C).

CAPA PRIVADA (P). El `agent.id` sólo se usa aquí para localizar la asignación
actual; el resultado devuelto es un `ActivoLogico` (configuración / capa E). El
`agent.id` NUNCA se propaga al prompt, al `contexto_ia_snapshot`, a la
explicación, al dashboard del analista, al CSV ni a la respuesta de la IA.

Persistencia (compatible con MySQL, MariaDB y SQLite):
- `AsignacionAgenteActivo` — asignación ACTUAL, una por `agent.id`
  (`UNIQUE(agent_id)` a nivel de BD, sin constraint condicional).
- `HistorialAsignacionAgente` — bitácora append-only de todos los cambios.
- El cambio de asignación es transaccional (`asignar_agente()`), con bloqueo de
  fila donde el motor lo soporta; la unicidad la impone la BD, no sólo Python.

`IA_AGENTES_BLOQUEADOS` (settings, opcional): `agent.id` que NO pueden asignarse
ni resolverse. AGENT-02 es una **etiqueta documental**: su `agent.id` real sigue
sin conocerse en este entorno, así que su protección efectiva hoy es que **no
existe ninguna asignación** para él. Cuando 1C.1/1D confirme su `agent.id`, debe
añadirse a `IA_AGENTES_BLOQUEADOS` antes de cualquier uso.
"""
from __future__ import annotations

from django.db import connection, transaction

from dashboard.models import (
    ActivoLogico,
    AsignacionAgenteActivo,
    HistorialAsignacionAgente,
)


def agentes_bloqueados():
    """`agent.id` que NO pueden asignarse ni resolverse. -> set[str]."""
    try:
        from django.conf import settings
        return {str(a).strip() for a in getattr(settings, "IA_AGENTES_BLOQUEADOS", ()) if str(a).strip()}
    except Exception:
        return set()


def _qs_con_bloqueo(qs):
    """Aplica SELECT ... FOR UPDATE sólo si el motor lo soporta (MySQL/MariaDB sí, SQLite no)."""
    if connection.features.has_select_for_update:
        return qs.select_for_update()
    return qs


def resolver_activo_por_agente(agent_id):
    """`agent.id` -> `ActivoLogico` de su asignación ACTUAL, o None. No lanza."""
    if agent_id in (None, ""):
        return None
    agent_id = str(agent_id).strip()
    if not agent_id or agent_id in agentes_bloqueados():
        return None
    asignacion = (
        AsignacionAgenteActivo.objects
        .filter(agent_id=agent_id, activo_logico__activo=True)
        .select_related("activo_logico")
        .first()
    )
    return asignacion.activo_logico if asignacion else None


def resolver_desde_alerta(alert):
    """
    Resolver por defecto de la ingesta. Orden de prioridad:
      0. Si el `agent.id` de la alerta está BLOQUEADO -> None de inmediato.
         Un `agent.id` bloqueado se rechaza ANTES de aceptar cualquier
         `activo_logico` explícito que venga en la propia alerta. Sólo una
         operación administrativa deliberada (retirarlo de IA_AGENTES_BLOQUEADOS)
         puede habilitarlo.
      1. identificador lógico EXPLÍCITO en `alert['activo_logico']` /
         `alert['activo_id']` (carga dirigida / pruebas / uso manual).
         Nunca es un `agent.id`/hostname/IP: es `EP-01`…/`SRV-01`.
      2. asignación ACTUAL para `alert['agent_id']` (capa P).
    Devuelve `ActivoLogico` o None. No lanza.
    """
    agent_id = alert.get("agent_id")
    if agent_id not in (None, "") and str(agent_id).strip() in agentes_bloqueados():
        return None

    ident = alert.get("activo_logico") or alert.get("activo_id")
    if isinstance(ident, ActivoLogico):
        return ident
    if ident not in (None, ""):
        return ActivoLogico.objects.filter(identificador=str(ident), activo=True).first()
    return resolver_activo_por_agente(agent_id)


# ---------------------------------------------------------------------------
# Alta / baja de asignaciones (transaccional y auditable). NO por migración.
# ---------------------------------------------------------------------------
def _registrar_historial(*, agent_id, activo, accion, etiqueta, nota, autor):
    HistorialAsignacionAgente.objects.create(
        agent_id=agent_id,
        activo_identificador=activo.identificador,
        activo_logico=activo,
        accion=accion,
        etiqueta_privada=etiqueta or "",
        nota=nota or "",
        autor=autor if getattr(autor, "pk", None) else None,
    )


def asignar_agente(agent_id, activo_identificador, *, etiqueta="", nota="", autor=None):
    """
    Fija la asignación ACTUAL de un agente y añade una entrada al historial, todo
    en una transacción. Si el agente ya tenía asignación, se actualiza la misma
    fila (`agent_id` sigue siendo único) y el cambio queda registrado como
    'reemplazada'.

    Un `agent_id` en `IA_AGENTES_BLOQUEADOS` -> `ValueError`.
    """
    agent_id = str(agent_id).strip()
    if not agent_id:
        raise ValueError("agent_id vacío")
    if agent_id in agentes_bloqueados():
        raise ValueError(
            f"agent.id '{agent_id}' está en IA_AGENTES_BLOQUEADOS. Para asignarlo, "
            f"retíralo primero de esa lista de forma deliberada y auditada."
        )
    activo = ActivoLogico.objects.filter(identificador=str(activo_identificador).strip()).first()
    if activo is None:
        raise ValueError(
            f"ActivoLogico '{activo_identificador}' no existe "
            f"(¿ejecutaste 'manage.py cargar_activos_cafe'?)."
        )
    autor_obj = autor if getattr(autor, "pk", None) else None

    with transaction.atomic():
        actual, creada = (
            _qs_con_bloqueo(AsignacionAgenteActivo.objects.all())
            .get_or_create(
                agent_id=agent_id,
                defaults=dict(
                    activo_logico=activo,
                    etiqueta_privada=etiqueta or "",
                    nota=nota or "",
                    creada_por=autor_obj,
                ),
            )
        )
        if not creada:
            actual.activo_logico = activo
            if etiqueta:
                actual.etiqueta_privada = etiqueta
            actual.nota = nota or ""
            actual.save(update_fields=["activo_logico", "etiqueta_privada", "nota", "actualizada_en"])
        _registrar_historial(
            agent_id=agent_id, activo=activo,
            accion="asignada" if creada else "reemplazada",
            etiqueta=actual.etiqueta_privada, nota=nota, autor=autor_obj,
        )
    return actual


def desactivar_asignacion(agent_id, *, autor=None, nota=""):
    """
    Quita la asignación ACTUAL de un agente (si la hay) y lo registra en el
    historial. -> nº de asignaciones retiradas (0 o 1). Transaccional.
    """
    agent_id = str(agent_id).strip()
    with transaction.atomic():
        actual = _qs_con_bloqueo(
            AsignacionAgenteActivo.objects.select_related("activo_logico")
        ).filter(agent_id=agent_id).first()
        if actual is None:
            return 0
        _registrar_historial(
            agent_id=agent_id, activo=actual.activo_logico, accion="desactivada",
            etiqueta=actual.etiqueta_privada, nota=nota, autor=autor,
        )
        actual.delete()
        return 1
