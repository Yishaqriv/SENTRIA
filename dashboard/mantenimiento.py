"""
Lógica de dominio de las ventanas de mantenimiento (Sprint 2G).

- `crear_ventana` / `cancelar_ventana`: alta y baja auditada (nunca borra).
- `estado_para`: contexto que se pasa a la IA (estado + categoría controlada).

Nada de esto expone `agent.id`, hostname, IP ni datos privados.
"""
from __future__ import annotations

from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from dashboard.ia.alcance import ALCANCES_VALIDOS, NO_DECLARADO
from dashboard.models import VentanaMantenimiento

_CATEGORIAS = dict(VentanaMantenimiento.CATEGORIA_CHOICES)


def _hay_solape_activo(activo, inicio, fin, excluir_id=None):
    qs = (VentanaMantenimiento.objects
          .filter(activo_logico=activo, estado="ACTIVA")
          .filter(Q(inicio__lt=fin) & Q(fin__gt=inicio)))
    if excluir_id:
        qs = qs.exclude(pk=excluir_id)
    return qs.exists()


def crear_ventana(*, activo, inicio, fin, categoria, descripcion="", autor=None, alcance_operacion=NO_DECLARADO):
    """Crea una ventana ACTIVA. Valida fin>inicio, categoría, alcance y no-solapamiento.
    `alcance_operacion`: categoría cerrada; `no_declarado` solo para llamadas internas antiguas (el formulario exige uno)."""
    if activo is None:
        raise ValidationError("Activo lógico obligatorio.")
    if inicio is None or fin is None:
        raise ValidationError("Inicio y fin son obligatorios.")
    if fin <= inicio:
        raise ValidationError("La fecha/hora de fin debe ser posterior a la de inicio.")
    if categoria not in _CATEGORIAS:
        raise ValidationError("Categoría de mantenimiento no válida.")
    if alcance_operacion not in ALCANCES_VALIDOS + (NO_DECLARADO,):
        raise ValidationError("Alcance de la operación no válido.")
    with transaction.atomic():
        if _hay_solape_activo(activo, inicio, fin):
            raise ValidationError(
                f"Ya existe una ventana ACTIVA que se solapa para {activo.identificador}."
            )
        return VentanaMantenimiento.objects.create(
            activo_logico=activo, inicio=inicio, fin=fin, categoria=categoria, alcance_operacion=alcance_operacion,
            descripcion=(descripcion or "").strip()[:280],
            creada_por=autor if getattr(autor, "pk", None) else None,
        )


def cancelar_ventana(ventana, *, autor=None):
    """Marca la ventana como CANCELADA conservando la fila (auditoría). -> bool."""
    if ventana.estado == "CANCELADA":
        return False
    ventana.estado = "CANCELADA"
    ventana.cancelada_en = timezone.now()
    ventana.cancelada_por = autor if getattr(autor, "pk", None) else None
    ventana.save(update_fields=["estado", "cancelada_en", "cancelada_por"])
    return True


def estado_para(activo, momento):
    """
    Contexto de mantenimiento de una alerta. Devuelve (estado, categoria|None):
      - ("dentro_ventana_declarada", <categoria>) si una ventana ACTIVA, registrada ANTES del evento
        (`creada_en <= momento`), cubre `momento`;
      - ("sin_ventana_declarada", None) si hay activo y hora pero ninguna coincide. Una ventana registrada
        después del evento no lo autoriza retroactivamente (ver `ventana_declarada_despues`);
      - ("indeterminado", None) si falta el activo o `momento` (p. ej., evento Windows sin hora original válida).
    `momento` es la hora del EVENTO (`prompt.hora_del_evento`), no la de recepción.
    NUNCA devuelve "fuera_ventana_declarada".
    """
    if activo is None or getattr(activo, "pk", None) is None or momento is None:
        return "indeterminado", None
    v = ventana_aplicable(activo, momento)
    if v is None:
        return "sin_ventana_declarada", None
    return "dentro_ventana_declarada", v.categoria


def ventana_aplicable(activo, momento):
    """La ventana ACTIVA, registrada antes del evento, que cubre `momento` (la misma que usa `estado_para`)."""
    if activo is None or getattr(activo, "pk", None) is None or momento is None:
        return None
    return _cubren(activo, momento).filter(creada_en__lte=momento).order_by("inicio").first()


def alcance_para(activo, momento):
    """Alcance declarado de la ventana aplicable (`no_declarado` en las anteriores a la 1.3) o None."""
    v = ventana_aplicable(activo, momento)
    return v.alcance_operacion if v is not None else None


def _cubren(activo, momento):
    return VentanaMantenimiento.objects.filter(activo_logico=activo, estado="ACTIVA",
                                               inicio__lte=momento, fin__gte=momento)


def ventana_declarada_despues(activo, momento):
    """Diagnóstico: ¿hay una ventana ACTIVA que cubre `momento` pero se registró después? (None si no aplica)."""
    if activo is None or getattr(activo, "pk", None) is None or momento is None:
        return None
    return _cubren(activo, momento).filter(creada_en__gt=momento).exists()
