"""
Sustento de los factores CVSS de la respuesta (todos los proveedores).

Un factor distinto de «no_determinado» es una afirmación, no la ausencia de información. Solo se acepta si la
ENTRADA lo sostiene: `observed_cvss_factors[factor]` tiene ese mismo valor. Esos factores observados los calcula
SENTRIA antes de llamar al modelo, con reglas deterministas y documentadas (hoy solo `attack_vector`, a partir
de los grupos de Wazuh: `prompt._attack_vector_conservador`; el resto queda «no_determinado»). Para admitir una
inferencia nueva hay que añadir la regla a ese cálculo, con su justificación y pruebas: la deducción del modelo
nunca cuenta como sustento.

El criterio es SIMÉTRICO: se rechaza tanto el valor que minimiza (p. ej., un impacto «ninguno» no sostenido)
como el que exagera (p. ej., un impacto «alto» no sostenido). La falta de información, un veredicto
FALSO_POSITIVO o la ausencia de señales de ataque no sostienen nada. Criterio estructurado: no se interpreta
el texto del razonamiento, no se corrige ni se sustituye ningún valor de la respuesta y no se calcula ninguna
puntuación CVSS numérica.
"""
from __future__ import annotations

NO_DETERMINADO = "no_determinado"

# Orden de gravedad de cada factor (de menos a más grave), según la semántica de CVSS v3. Solo se usa para
# describir el SENTIDO de un factor sin sustento; la decisión de aceptar o rechazar no depende de él.
GRAVEDAD = {
    "attack_vector": ("fisico", "local", "adyacente", "red"),
    "attack_complexity": ("alta", "baja"),
    "privileges_required": ("altos", "bajos", "ninguno"),
    "user_interaction": ("requerida", "ninguna"),
    "scope": ("sin_cambio", "cambiado"),
    "confidentiality_impact": ("ninguno", "bajo", "alto"),
    "integrity_impact": ("ninguno", "bajo", "alto"),
    "availability_impact": ("ninguno", "bajo", "alto"),
}

# Subconjunto histórico (impactos «ninguno» de confidencialidad e integridad), conservado por compatibilidad.
IMPACTOS_VIGILADOS = ("confidentiality_impact", "integrity_impact")


def _sentido(factor, valor, sostenido):
    escala = GRAVEDAD[factor]
    if valor not in escala:
        return "valor_fuera_de_escala"
    if sostenido in escala:
        return "minimiza" if escala.index(valor) < escala.index(sostenido) else "exagera"
    i, medio = escala.index(valor), (len(escala) - 1) / 2
    return "minimiza" if i < medio else "exagera" if i > medio else "afirma_sin_sustento"


def factores_sin_sustento(salida, entrada):
    """
    -> lista ordenada de {"factor", "valor", "sostenido", "sentido"} con los factores de la salida que no son
    «no_determinado» ni coinciden con el valor observado de la entrada. Vacía si todo está sustentado.
    `sentido`: "minimiza" | "exagera" | "afirma_sin_sustento" (valor intermedio sin valor observado).
    Si la salida no trae un objeto de factores, se devuelve [] (eso lo rechaza antes el contrato). Si la entrada
    no trae factores observados válidos, nada está sostenido.
    """
    factores = (salida or {}).get("cvss_factors")
    if not isinstance(factores, dict):
        return []
    observados = (entrada or {}).get("observed_cvss_factors")
    if not isinstance(observados, dict):
        observados = {}
    out = []
    for factor in GRAVEDAD:
        valor = factores.get(factor, NO_DETERMINADO)
        sostenido = observados.get(factor, NO_DETERMINADO)
        if valor == NO_DETERMINADO or valor == sostenido:
            continue
        out.append({"factor": factor, "valor": valor, "sostenido": sostenido,
                    "sentido": _sentido(factor, valor, sostenido)})
    return out


def solo_impactos_nulos(sin_sustento):
    """True si todos los factores sin sustento son impactos C/I «ninguno» (categoría histórica)."""
    return bool(sin_sustento) and all(x["factor"] in IMPACTOS_VIGILADOS and x["valor"] == "ninguno"
                                      for x in sin_sustento)


def impactos_nulos_sin_sustento(salida, entrada):
    """Compatibilidad: factores C/I con valor «ninguno» que la entrada no sostiene (lista ordenada)."""
    observados = (entrada or {}).get("observed_cvss_factors") or {}
    factores = (salida or {}).get("cvss_factors") or {}
    if not isinstance(observados, dict) or not isinstance(factores, dict):
        return list(IMPACTOS_VIGILADOS)
    return [k for k in IMPACTOS_VIGILADOS if factores.get(k) == "ninguno" and observados.get(k) != "ninguno"]
