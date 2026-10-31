"""
Contrato de la salida del modelo (aprobado en el checkpoint 1C, sección 5).

`validar_salida_ia()` NO confía en que el modelo devuelva JSON correcto: valida
estructura, campos obligatorios, enums, tipos, longitudes y propiedades extra.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

SCHEMA_VERSION = "1.0"

VEREDICTOS = ("FALSO_POSITIVO", "REQUIERE_ATENCION")
RIESGOS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
ESTADOS_ANALISIS = ("PENDING", "COMPLETED", "ANALISIS_FALLIDO")

CVSS_ENUMS = {
    "attack_vector": ("red", "adyacente", "local", "fisico", "no_determinado"),
    "attack_complexity": ("baja", "alta", "no_determinado"),
    "privileges_required": ("ninguno", "bajos", "altos", "no_determinado"),
    "user_interaction": ("ninguna", "requerida", "no_determinado"),
    "scope": ("sin_cambio", "cambiado", "no_determinado"),
    "confidentiality_impact": ("ninguno", "bajo", "alto", "no_determinado"),
    "integrity_impact": ("ninguno", "bajo", "alto", "no_determinado"),
    "availability_impact": ("ninguno", "bajo", "alto", "no_determinado"),
}
CVSS_CLAVES = tuple(CVSS_ENUMS.keys())

CAMPOS_SALIDA = (
    "schema_version",
    "verdict",
    "risk",
    "explanation_es",
    "cvss_factors",
    "cvss_reasoning_es",
    "recommendation_es",
    "missing_evidence",
)

LONGITUDES = {
    "explanation_es": (20, 600),
    "cvss_reasoning_es": (20, 800),
    "recommendation_es": (10, 500),
}
MISSING_EVIDENCE_MAX = 10
MISSING_EVIDENCE_ITEM = (3, 120)


@dataclass
class ResultadoValidacion:
    ok: bool
    errores: list = field(default_factory=list)
    advertencias: list = field(default_factory=list)


def esquema_json_salida():
    """
    JSON Schema del contrato de salida, para la salida estructurada del SDK de
    Gemini (`response_json_schema`). Restringe `verdict`/`risk`/`cvss_factors` a
    sus enums exactos. La validación estricta de `validar_salida_ia()` SIGUE
    aplicándose después (el esquema del SDK reduce, no elimina, los fallos).
    """
    lo_ex, hi_ex = LONGITUDES["explanation_es"]
    lo_cr, hi_cr = LONGITUDES["cvss_reasoning_es"]
    lo_re, hi_re = LONGITUDES["recommendation_es"]
    lo_me, hi_me = MISSING_EVIDENCE_ITEM
    return {
        "type": "object",
        "additionalProperties": False,
        "required": list(CAMPOS_SALIDA),
        "properties": {
            "schema_version": {"type": "string", "enum": [SCHEMA_VERSION]},
            "verdict": {"type": "string", "enum": list(VEREDICTOS)},
            "risk": {"type": "string", "enum": list(RIESGOS)},
            "explanation_es": {"type": "string", "minLength": lo_ex, "maxLength": hi_ex},
            "cvss_factors": {
                "type": "object",
                "additionalProperties": False,
                "required": list(CVSS_CLAVES),
                "properties": {k: {"type": "string", "enum": list(v)}
                               for k, v in CVSS_ENUMS.items()},
            },
            "cvss_reasoning_es": {"type": "string", "minLength": lo_cr, "maxLength": hi_cr},
            "recommendation_es": {"type": "string", "minLength": lo_re, "maxLength": hi_re},
            "missing_evidence": {
                "type": "array", "maxItems": MISSING_EVIDENCE_MAX,
                "items": {"type": "string", "minLength": lo_me, "maxLength": hi_me},
            },
        },
    }


def parsear_json_estricto(texto):
    """
    Devuelve (dict, None) si `texto` es EXACTAMENTE un objeto JSON.
    Devuelve (None, motivo) en cualquier otro caso (vacío, markdown, lista,
    escalar, JSON malformado). No hace recuperación de vallas ```.
    """
    if texto is None:
        return None, "respuesta vacía"
    t = texto.strip()
    if not t:
        return None, "respuesta vacía"
    if t.startswith("```"):
        return None, "la respuesta viene envuelta en markdown/```"
    try:
        data = json.loads(t)
    except (ValueError, TypeError) as e:
        return None, f"JSON malformado: {e}"
    if not isinstance(data, dict):
        return None, f"la raíz no es un objeto JSON (es {type(data).__name__})"
    return data, None


def _validar_longitud(nombre, valor, errores):
    lo, hi = LONGITUDES[nombre]
    if not isinstance(valor, str):
        errores.append(f"{nombre}: debe ser texto")
        return
    n = len(valor)
    if n < lo or n > hi:
        errores.append(f"{nombre}: longitud {n} fuera de rango [{lo}, {hi}]")


def validar_salida_ia(data):
    """Valida `data` (dict ya parseado) contra el contrato. -> ResultadoValidacion."""
    errores = []
    advertencias = []

    if not isinstance(data, dict):
        return ResultadoValidacion(False, ["la salida no es un objeto"])

    # --- propiedades: ni de más ni de menos ---
    presentes = set(data.keys())
    esperadas = set(CAMPOS_SALIDA)
    faltan = esperadas - presentes
    sobran = presentes - esperadas
    if faltan:
        errores.append(f"faltan campos obligatorios: {sorted(faltan)}")
    if sobran:
        errores.append(f"propiedades adicionales no permitidas: {sorted(sobran)}")

    # --- schema_version ---
    if data.get("schema_version") != SCHEMA_VERSION:
        errores.append(f"schema_version debe ser '{SCHEMA_VERSION}'")

    # --- verdict / risk ---
    if data.get("verdict") not in VEREDICTOS:
        errores.append(f"verdict inválido: {data.get('verdict')!r} (esperado {VEREDICTOS})")
    if data.get("risk") not in RIESGOS:
        errores.append(f"risk inválido: {data.get('risk')!r} (esperado {RIESGOS})")

    # --- textos con longitud ---
    for nombre in ("explanation_es", "cvss_reasoning_es", "recommendation_es"):
        if nombre in data:
            _validar_longitud(nombre, data[nombre], errores)

    # --- cvss_factors ---
    cvss = data.get("cvss_factors")
    if not isinstance(cvss, dict):
        errores.append("cvss_factors: debe ser un objeto con las 8 claves")
    else:
        c_faltan = set(CVSS_CLAVES) - set(cvss.keys())
        c_sobran = set(cvss.keys()) - set(CVSS_CLAVES)
        if c_faltan:
            errores.append(f"cvss_factors: faltan {sorted(c_faltan)}")
        if c_sobran:
            errores.append(f"cvss_factors: claves no permitidas {sorted(c_sobran)}")
        for clave, permitidos in CVSS_ENUMS.items():
            if clave in cvss and cvss[clave] not in permitidos:
                errores.append(f"cvss_factors.{clave} inválido: {cvss[clave]!r}")

    # --- missing_evidence ---
    me = data.get("missing_evidence")
    if not isinstance(me, list):
        errores.append("missing_evidence: debe ser una lista (puede estar vacía)")
    else:
        if len(me) > MISSING_EVIDENCE_MAX:
            errores.append(f"missing_evidence: {len(me)} elementos (máx {MISSING_EVIDENCE_MAX})")
        lo, hi = MISSING_EVIDENCE_ITEM
        for i, item in enumerate(me):
            if not isinstance(item, str):
                errores.append(f"missing_evidence[{i}]: debe ser texto")
            elif not (lo <= len(item) <= hi):
                errores.append(f"missing_evidence[{i}]: longitud {len(item)} fuera de [{lo}, {hi}]")

    # --- coherencia (no bloquea; marca revisión humana) ---
    if not errores:
        no_det = [k for k in CVSS_CLAVES if cvss.get(k) == "no_determinado"]
        if no_det:
            texto_ref = (data.get("cvss_reasoning_es", "") + " " + " ".join(me)).lower()
            if not any(k.split("_")[0] in texto_ref or "no determinad" in texto_ref for k in no_det):
                advertencias.append(
                    "hay factores CVSS 'no_determinado' no justificados en cvss_reasoning_es ni en missing_evidence"
                )
        if data.get("risk") in ("HIGH", "CRITICAL") and data.get("verdict") == "FALSO_POSITIVO":
            advertencias.append("riesgo alto marcado como FALSO_POSITIVO: revisión humana recomendada")

    return ResultadoValidacion(ok=not errores, errores=errores, advertencias=advertencias)
