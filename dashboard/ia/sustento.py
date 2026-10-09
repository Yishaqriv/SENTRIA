"""
Sustento de los impactos CVSS «ninguno» (proveedor `vertex_tuned`).

Un impacto nulo es una afirmación, no la ausencia de información. Solo se acepta si la ENTRADA lo trae como
factor deducido por una regla admitida (`observed_cvss_factors[factor] == "ninguno"`, contrato 1C §5.1).
La falta de información, un veredicto FALSO_POSITIVO o la ausencia de señales de ataque no cuentan.
Criterio estructurado: no se interpreta el texto del razonamiento. No modifica la respuesta.
"""
from __future__ import annotations

IMPACTOS_VIGILADOS = ("confidentiality_impact", "integrity_impact")


def impactos_nulos_sin_sustento(salida, entrada):
    """-> factores vigilados con valor «ninguno» en la salida que la entrada no sostiene (lista ordenada)."""
    observados = (entrada or {}).get("observed_cvss_factors") or {}
    factores = (salida or {}).get("cvss_factors") or {}
    if not isinstance(observados, dict) or not isinstance(factores, dict):
        return list(IMPACTOS_VIGILADOS)
    return [k for k in IMPACTOS_VIGILADOS if factores.get(k) == "ninguno" and observados.get(k) != "ninguno"]
