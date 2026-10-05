"""
Métricas de evaluación del clasificador (Sprint 3A).

Clase POSITIVA = REQUIERE_ATENCION.

Se calculan SÓLO sobre alertas con VERDAD DE TERRENO humana (revisión
CONFIRMADA o CORREGIDA) y un veredicto de IA COMPLETED. No se usa el campo
`estado` legacy. Las alertas sin revisión humana no cuentan.

  TP: IA=REQUIERE_ATENCION, humano=REQUIERE_ATENCION
  FP: IA=REQUIERE_ATENCION, humano=FALSO_POSITIVO
  TN: IA=FALSO_POSITIVO,    humano=FALSO_POSITIVO
  FN: IA=FALSO_POSITIVO,    humano=REQUIERE_ATENCION
"""
from __future__ import annotations

from .models import RevisionHumana

_VEREDICTOS = ("FALSO_POSITIVO", "REQUIERE_ATENCION")


def _ratio(num, den):
    return None if den == 0 else num / den


def matriz_confusion():
    tp = fp = tn = fn = 0
    sin_veredicto_ia = 0

    qs = (RevisionHumana.objects
          .filter(accion__in=["CONFIRMADA", "CORREGIDA"],
                  veredicto_verdad_terreno__in=_VEREDICTOS)
          .select_related("alerta"))

    for rev in qs:
        a = rev.alerta
        ia = a.veredicto_ia
        if a.estado_analisis != "COMPLETED" or ia not in _VEREDICTOS:
            sin_veredicto_ia += 1
            continue
        humano = rev.veredicto_verdad_terreno
        if ia == "REQUIERE_ATENCION" and humano == "REQUIERE_ATENCION":
            tp += 1
        elif ia == "REQUIERE_ATENCION" and humano == "FALSO_POSITIVO":
            fp += 1
        elif ia == "FALSO_POSITIVO" and humano == "FALSO_POSITIVO":
            tn += 1
        elif ia == "FALSO_POSITIVO" and humano == "REQUIERE_ATENCION":
            fn += 1

    total = tp + fp + tn + fn
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "total_etiquetado": total,
        "sin_veredicto_ia": sin_veredicto_ia,
        "fpr":       _ratio(fp, fp + tn), "fpr_den":       fp + tn,
        "fnr":       _ratio(fn, fn + tp), "fnr_den":       fn + tp,
        "precision": _ratio(tp, tp + fp), "precision_den": tp + fp,
        "recall":    _ratio(tp, tp + fn), "recall_den":    tp + fn,
        "accuracy":  _ratio(tp + tn, total), "accuracy_den": total,
    }


def resumen_revisiones():
    base = RevisionHumana.objects
    return {
        "total": base.count(),
        "confirmadas": base.filter(accion="CONFIRMADA").count(),
        "corregidas": base.filter(accion="CORREGIDA").count(),
        "excluidas": base.filter(accion="EXCLUIDA").count(),
    }
