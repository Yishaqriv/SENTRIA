"""
Revisión humana de alertas (Sprint 3A).

Tres acciones:
  - CONFIRMADA : el humano está de acuerdo con la IA.
  - CORREGIDA  : el humano está en desacuerdo -> nuevo veredicto de verdad de terreno.
  - EXCLUIDA   : evidencia insuficiente -> fuera del dataset, sin verdad de terreno.

NUNCA se sobrescriben los campos originales de la IA. El veredicto EFECTIVO y las
colas siguen leyendo `Alert.correccion_*`: sólo una CORRECCIÓN los toca.
"""
from __future__ import annotations

from django.db import transaction

from .models import Alert, RevisionHumana
from .ia.persistencia import registrar_correccion_humana

ACCIONES = ("CONFIRMADA", "CORREGIDA", "EXCLUIDA")
MOTIVOS = tuple(k for k, _ in RevisionHumana.MOTIVO_CHOICES)
RIESGOS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
VEREDICTOS = ("FALSO_POSITIVO", "REQUIERE_ATENCION")

_ETIQUETA_MOTIVO = dict(RevisionHumana.MOTIVO_CHOICES)


def registrar_revision(alerta, *, accion, motivo_categoria, autor,
                       veredicto_gt=None, riesgo_revisado=None, nota="",
                       tocar_correccion=True):
    """
    Crea o actualiza la `RevisionHumana` de `alerta`.

    - CONFIRMADA -> verdad de terreno = veredicto de la IA; riesgo revisado por
      defecto = riesgo de la IA.
    - CORREGIDA  -> `veredicto_gt` obligatorio y distinto (o igual) elegido por
      el humano; actualiza `Alert.correccion_*` (veredicto efectivo).
    - EXCLUIDA   -> sin verdad de terreno ni riesgo.

    `tocar_correccion=False` sólo para el backfill desde `correccion_*` ya
    existentes (no re-escribe fecha/motivo históricos).
    """
    if accion not in ACCIONES:
        raise ValueError(f"acción de revisión inválida: {accion!r}")
    if motivo_categoria not in MOTIVOS:
        raise ValueError(f"motivo_categoria inválido: {motivo_categoria!r}")
    if alerta.estado_analisis != "COMPLETED":
        raise ValueError("solo se revisan alertas con análisis COMPLETED")
    nota = (nota or "").strip()

    if accion == "EXCLUIDA":
        veredicto_gt = None
        riesgo_revisado = None
    elif accion == "CONFIRMADA":
        veredicto_gt = alerta.veredicto_ia
        riesgo_revisado = riesgo_revisado or alerta.riesgo_ia
    elif accion == "CORREGIDA":
        if veredicto_gt not in VEREDICTOS:
            raise ValueError("una corrección necesita un veredicto de verdad de terreno")

    if riesgo_revisado is not None and riesgo_revisado not in RIESGOS:
        raise ValueError(f"riesgo_revisado inválido: {riesgo_revisado!r}")

    with transaction.atomic():
        rev, _creada = RevisionHumana.objects.update_or_create(
            alerta=alerta,
            defaults=dict(
                accion=accion,
                veredicto_verdad_terreno=veredicto_gt,
                riesgo_revisado=riesgo_revisado,
                motivo_categoria=motivo_categoria,
                nota=nota,
                autor=autor if getattr(autor, "pk", None) else None,
            ),
        )

        if tocar_correccion:
            if accion == "CORREGIDA":
                texto = _ETIQUETA_MOTIVO.get(motivo_categoria, motivo_categoria)
                if nota:
                    texto = f"{texto} — {nota}"
                registrar_correccion_humana(
                    alerta, veredicto=veredicto_gt, autor=autor, motivo=texto,
                )
            elif accion in ("CONFIRMADA", "EXCLUIDA") and alerta.correccion_veredicto:
                # El humano ya no discrepa: se retira la corrección previa para
                # que el veredicto efectivo vuelva a ser el de la IA.
                alerta.correccion_veredicto = None
                alerta.correccion_autor = None
                alerta.correccion_fecha = None
                alerta.correccion_motivo = None
                alerta.save(update_fields=[
                    "correccion_veredicto", "correccion_autor",
                    "correccion_fecha", "correccion_motivo",
                ])

    from .dataset import sincronizar_candidato
    sincronizar_candidato(alerta)
    return rev


def sincronizar_revision_desde_correccion(alerta, *, motivo_categoria="otro"):
    """
    Backfill: crea una `RevisionHumana` CORREGIDA a partir de `correccion_*` ya
    presentes en la alerta (flujo antiguo), SIN tocar esos campos históricos.
    No hace nada si ya existe una revisión o si no hay corrección.
    """
    if getattr(alerta, "revision_humana", None) is not None:
        return None
    if not alerta.correccion_veredicto:
        return None
    if motivo_categoria not in MOTIVOS:
        motivo_categoria = "otro"
    return registrar_revision(
        alerta,
        accion="CORREGIDA",
        motivo_categoria=motivo_categoria,
        autor=alerta.correccion_autor,
        veredicto_gt=alerta.correccion_veredicto,
        riesgo_revisado=None,
        nota=(alerta.correccion_motivo or "").strip(),
        tocar_correccion=False,
    )
