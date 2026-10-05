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

from dashboard.models import VentanaMantenimiento

_CATEGORIAS = dict(VentanaMantenimiento.CATEGORIA_CHOICES)


def _hay_solape_activo(activo, inicio, fin, excluir_id=None):
    qs = (VentanaMantenimiento.objects
          .filter(activo_logico=activo, estado="ACTIVA")
          .filter(Q(inicio__lt=fin) & Q(fin__gt=inicio)))
    if excluir_id:
        qs = qs.exclude(pk=excluir_id)
    return qs.exists()


def crear_ventana(*, activo, inicio, fin, categoria, descripcion="", autor=None):
    """Crea una ventana ACTIVA. Valida fin>inicio, categoría y no-solapamiento."""
    if activo is None:
        raise ValidationError("Activo lógico obligatorio.")
    if inicio is None or fin is None:
        raise ValidationError("Inicio y fin son obligatorios.")
    if fin <= inicio:
        raise ValidationError("La fecha/hora de fin debe ser posterior a la de inicio.")
    if categoria not in _CATEGORIAS:
        raise ValidationError("Categoría de mantenimiento no válida.")
    with transaction.atomic():
        if _hay_solape_activo(activo, inicio, fin):
            raise ValidationError(
                f"Ya existe una ventana ACTIVA que se solapa para {activo.identificador}."
            )
        return VentanaMantenimiento.objects.create(
            activo_logico=activo, inicio=inicio, fin=fin, categoria=categoria,
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
      - ("dentro_ventana_declarada", <categoria>) si una ventana ACTIVA cubre `momento`;
      - ("sin_ventana_declarada", None) si hay activo y hora pero ninguna coincide;
      - ("indeterminado", None) si falta el activo o `momento`.
    NUNCA devuelve "fuera_ventana_declarada".
    """
    if activo is None or getattr(activo, "pk", None) is None or momento is None:
        return "indeterminado", None
    v = (VentanaMantenimiento.objects
         .filter(activo_logico=activo, estado="ACTIVA",
                 inicio__lte=momento, fin__gte=momento)
         .order_by("inicio").first())
    if v is None:
        return "sin_ventana_declarada", None
    return "dentro_ventana_declarada", v.categoria
