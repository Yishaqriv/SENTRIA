"""
Política de auditoría selectiva de falsos positivos de la IA (Sprint 3C/3D).

El analista no revisa todas las clasificaciones: un FALSO_POSITIVO original de
la IA sólo entra a la cola "Auditoría selectiva IA" si:

  - el nivel Wazuh es >= `UMBRAL_NIVEL_AUDITORIA`, o
  - el riesgo de la IA es HIGH o CRITICAL, o
  - cae en una MUESTRA ESTABLE del 10 % (determinista, versionada).

La muestra se calcula con SHA-256 sobre una SAL PÚBLICA, FIJA Y VERSIONADA
(`SAL_MUESTREO_POR_VERSION`) y el `opensearch_id` COMPLETO de la alerta (su
identificador estable en Wazuh, nunca la PK de la base): es determinista (no
cambia al recargar la página, nunca usa `ORDER BY RAND()`), no depende de
`SECRET_KEY` y da la misma decisión en cualquier instalación para el mismo
documento de Wazuh, aunque su PK sea distinta. Ni el identificador ni el hash
se muestran, registran ni persisten. Sin `opensearch_id` la alerta NO entra a
la muestra (no hay fallback a la PK); los criterios de nivel y riesgo siguen
aplicando. No inventa ni consume ningún
campo de "confianza" de Gemini: el contrato de salida no tiene ese campo.
"""
from __future__ import annotations

import hashlib

POLITICA_MUESTREO_VERSION = "1.0"
# Sal pública y fija por versión de la política. Cambiarla = nueva versión.
SAL_MUESTREO_POR_VERSION = {"1.0": "SENTRIA_AUDIT_SAMPLE_V1"}
UMBRAL_NIVEL_AUDITORIA = 10
RIESGOS_AUDITABLES = ("HIGH", "CRITICAL")
PROPORCION_MUESTRA = 0.10


def _hash_unitario(identificador, version):
    """`identificador` (el `opensearch_id` completo) -> float determinista en [0, 1)."""
    sal = SAL_MUESTREO_POR_VERSION.get(version, f"SENTRIA_AUDIT_SAMPLE_V{version}")
    semilla = f"{sal}:{str(identificador)}"
    digest = hashlib.sha256(semilla.encode("utf-8")).hexdigest()
    return int(digest[:8], 16) / 0x100000000


def en_muestra_selectiva(identificador, *, version=POLITICA_MUESTREO_VERSION,
                         proporcion=PROPORCION_MUESTRA):
    """
    Determinista: el mismo `identificador` (y la misma `version`) siempre
    produce el mismo resultado. Nunca usa aleatoriedad de la BD ni del proceso.
    Sin identificador (`None`, vacío o sólo espacios) devuelve False: nunca falla.
    """
    if identificador is None or str(identificador).strip() == "":
        return False
    return _hash_unitario(identificador, version) < proporcion


def requiere_auditoria_selectiva(alert, *, version=POLITICA_MUESTREO_VERSION):
    """
    `alert`: instancia de `Alert` con `estado_analisis == COMPLETED` y
    `veredicto_ia == FALSO_POSITIVO` (se asume ya filtrado por el llamador).

    Devuelve `(bool, motivo|None)`. `motivo` ∈
    {"nivel_alto", "riesgo_alto", "muestra_10pct", None}.
    """
    nivel = alert.severidad
    riesgo = alert.riesgo_ia
    if nivel is not None and nivel >= UMBRAL_NIVEL_AUDITORIA:
        return True, "nivel_alto"
    if riesgo in RIESGOS_AUDITABLES:
        return True, "riesgo_alto"
    if en_muestra_selectiva(getattr(alert, "opensearch_id", None), version=version):
        return True, "muestra_10pct"
    return False, None
