"""
Escritura del resultado del análisis en el modelo Alert.

Garantías:
1. Un análisis COMPLETED nunca se sobrescribe (salvo forzar=True explícito).
2. La corrección humana vive en campos separados y NUNCA toca el veredicto
   original de la IA.
3. Una alerta OMITIDA por política no se envía al proveedor, no es
   ANALISIS_FALLIDO y nunca se marca FALSO_POSITIVO.
"""
from __future__ import annotations

from django.utils import timezone

from .contrato import VEREDICTOS

_CAMPOS_IA = (
    "estado_analisis", "veredicto_ia", "riesgo_ia", "explicacion_ia",
    "factores_cvss", "justificacion_cvss", "recomendacion_ia",
    "evidencia_faltante", "respuesta_ia_original", "proveedor_ia", "modelo_ia",
)


def aplicar_resultado(alerta, resultado, *, forzar=False):
    """
    Vuelca `resultado` (dict de analizador.analizar_alerta) en `alerta`.
    Devuelve True si escribió, False si lo omitió por inmutabilidad.
    """
    if alerta.estado_analisis == "COMPLETED" and not forzar:
        return False

    for campo in _CAMPOS_IA:
        setattr(alerta, campo, resultado[campo])
    alerta.contexto_ia_snapshot = resultado.get("contexto_ia_snapshot")
    alerta.motivo_omision = None  # este resultado vino del analizador, no de la política
    alerta.analizado_en = timezone.now()
    alerta.save()
    return True


def aplicar_omision(alerta, motivo):
    """
    Marca la alerta como OMITIDO_POLITICA con un motivo estructurado.
    No la envía al proveedor. No es ANALISIS_FALLIDO. No es FALSO_POSITIVO.
    No sobrescribe un análisis ya COMPLETED.
    """
    if alerta.estado_analisis == "COMPLETED":
        return False
    alerta.estado_analisis = "OMITIDO_POLITICA"
    alerta.motivo_omision = motivo
    alerta.veredicto_ia = None
    alerta.riesgo_ia = None
    alerta.analizado_en = timezone.now()
    alerta.save()
    return True


def registrar_correccion_humana(alerta, *, veredicto, autor, motivo):
    """
    Registra la corrección de un analista SIN alterar el veredicto de la IA.
    `veredicto` debe ser uno de contrato.VEREDICTOS. `motivo` es obligatorio.
    """
    if veredicto not in VEREDICTOS:
        raise ValueError(f"veredicto de corrección inválido: {veredicto!r}")
    if not (motivo or "").strip():
        raise ValueError("el motivo de la corrección es obligatorio")
    alerta.correccion_veredicto = veredicto
    alerta.correccion_autor = autor if getattr(autor, "pk", None) else None
    alerta.correccion_fecha = timezone.now()
    alerta.correccion_motivo = motivo.strip()
    alerta.save()
