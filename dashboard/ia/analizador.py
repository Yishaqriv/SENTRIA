"""
Orquestación del análisis de una alerta.

`analizar_alerta()` es el único punto de entrada. Devuelve SIEMPRE un dict con
la misma forma (ver RESULTADO_CLAVES). Nunca lanza excepción por un fallo del
proveedor o del formato: en ese caso devuelve estado_analisis='ANALISIS_FALLIDO'
con veredicto_ia=None y la respuesta cruda conservada.
"""
from __future__ import annotations

import hashlib
from types import SimpleNamespace

from .anonimizacion import anonimizar_texto
from .contrato import parsear_json_estricto, validar_salida_ia
from .entrada_exportacion import (CONTRATO_ENTRADA, PLANTILLA_SHA256, PLANTILLA_VERSION, TRANSFORMACIONES,
                                  EntradaNoRepresentable, texto_usuario)
from .prompt import construir_entrada_e, construir_prompt, diagnostico_tiempo
from .sustento import impactos_nulos_sin_sustento
from .proveedores import ProveedorIA, nombre_proveedor_activo, obtener_proveedor

RESULTADO_CLAVES = (
    "estado_analisis",
    "veredicto_ia",
    "riesgo_ia",
    "explicacion_ia",
    "factores_cvss",
    "justificacion_cvss",
    "recomendacion_ia",
    "evidencia_faltante",
    "respuesta_ia_original",
    "proveedor_ia",
    "modelo_ia",
    "motivo_fallo",
    "advertencias",
    "contexto_ia_snapshot",
)

# Tamaño máximo de la respuesta cruda que se persiste (evita almacenar
# respuestas gigantes de un modelo que se desvía del formato).
RAW_MAX_CHARS = 20000


def _raw_seguro(texto):
    """Anonimiza (RNF-03) y trunca la respuesta cruda antes de persistirla."""
    if not texto:
        return "" if texto is None else texto
    t = anonimizar_texto(str(texto))
    if len(t) > RAW_MAX_CHARS:
        t = t[:RAW_MAX_CHARS] + f"\n...[truncado a {RAW_MAX_CHARS} caracteres]"
    return t


# Categorías sanitizadas de fallo (para diagnóstico; van al snapshot, nunca
# exponen contenido crudo).
CAT_FALLO = (
    "proveedor_no_disponible", "proveedor_excepcion", "timeout",
    "respuesta_vacia", "respuesta_truncada", "no_json", "markdown",
    "contrato_invalido", "bloqueo_privacidad", "bloqueo_seguridad_proveedor", "entrada_no_representable",
    "impacto_sin_sustento", "otra",
)


def _entrada_modelo_ajustado(entrada, prov):
    """
    Proveedores con `formato_entrada == exp-entrada-1`: texto = plantilla v1 + entrada exportada a partir de
    la ENTRADA del dataset (lista blanca de la capa E; nunca la salida esperada). Devuelve (texto, traza) para
    conservar en el snapshot qué se envió realmente. Lanza EntradaNoRepresentable.
    """
    from dashboard.dataset import construir_entrada    # import perezoso (modelos de Django)
    texto, exportada = texto_usuario(construir_entrada(SimpleNamespace(contexto_ia_snapshot=entrada)))
    traza = {"proveedor": prov.nombre, "recurso_modelo": getattr(prov, "_modelo", "desconocido"),
             "plantilla": PLANTILLA_VERSION, "plantilla_sha256": PLANTILLA_SHA256,
             "contrato_entrada": CONTRATO_ENTRADA, "transformaciones": list(TRANSFORMACIONES),
             "entrada_exportada": exportada, "texto_enviado_sha256": hashlib.sha256(texto.encode("utf-8")).hexdigest()}
    return texto, traza


def _categoria_fallo(motivo):
    m = (motivo or "").lower()
    if "anonimiz" in m or "privacidad" in m or "ip privada" in m or "agent.id" in m:
        return "bloqueo_privacidad"
    if "bloqueo de seguridad del proveedor" in m or "safety" in m or "prohibited" in m or "blocklist" in m:
        return "bloqueo_seguridad_proveedor"
    if "timeout" in m or "timed out" in m or "deadline" in m:
        return "timeout"
    if "truncad" in m or "max_tokens" in m:
        return "respuesta_truncada"
    if "markdown" in m or "```" in m:
        return "markdown"
    if "respuesta vacía" in m or "vacia" in m:
        return "respuesta_vacia"
    if "no es json" in m or "json malformado" in m or "raíz no es un objeto" in m:
        return "no_json"
    if "no cumple el contrato" in m:
        return "contrato_invalido"
    if "sin sustento estructurado" in m:
        return "impacto_sin_sustento"
    if "no representable" in m:
        return "entrada_no_representable"
    if "desconocido o no disponible" in m or "no devolvió un análisis" in m:
        return "proveedor_no_disponible"
    if "lanzó una excepción" in m:
        return "proveedor_excepcion"
    return "otra"


def resultado_fallido(*, raw, motivo, proveedor, modelo, snapshot=None, diag=None):
    """
    Construye un resultado ANALISIS_FALLIDO. Reglas no negociables:
    veredicto_ia=None y riesgo_ia=None; NUNCA 'FALSO_POSITIVO'; la respuesta
    cruda se conserva (anonimizada y truncada); la alerta permanece visible.

    El motivo (anonimizado) se guarda en `explicacion_ia` para que el dashboard
    pueda mostrarlo, y la categoría sanitizada + finish_reason + conteos de
    tokens + presencia de `parsed` se añaden al snapshot bajo `_diagnostico_fallo`
    (sin crear ningún campo/migración nuevo).
    """
    motivo_seguro = anonimizar_texto(str(motivo or ""))[:400]
    categoria = _categoria_fallo(motivo)
    snap = dict(snapshot) if isinstance(snapshot, dict) else snapshot
    if isinstance(snap, dict):
        d = {"categoria": categoria, "motivo": motivo_seguro}
        if isinstance(diag, dict):
            d.update({k: diag[k] for k in ("finish_reason", "usage", "parsed_present") if k in diag})
        snap["_diagnostico_fallo"] = d
    return {
        "estado_analisis": "ANALISIS_FALLIDO",
        "veredicto_ia": None,
        "riesgo_ia": None,
        "explicacion_ia": motivo_seguro or None,
        "factores_cvss": None,
        "justificacion_cvss": None,
        "recomendacion_ia": None,
        "evidencia_faltante": None,
        "respuesta_ia_original": _raw_seguro(raw),
        "proveedor_ia": proveedor,
        "modelo_ia": modelo,
        "motivo_fallo": motivo,
        "categoria_fallo": categoria,
        "advertencias": [],
        "contexto_ia_snapshot": snap,
    }


def analizar_alerta(alert, activo, proveedor=None):
    """
    `alert`:  dict con 'description'/'descripcion', 'level'/'severidad',
              'groups', 'rule_id', 'timestamp'.
    `activo`: instancia de ActivoLogico (o equivalente con los mismos atributos).
              Es obligatorio: una alerta sin activo NO llega aquí (la política
              la marca OMITIDO_POLITICA / SIN_CONTEXTO_ACTIVO).
    `proveedor`: None (usa IA_PROVIDER), un nombre str, o una instancia ProveedorIA.
    """
    entrada = construir_entrada_e(alert, activo)
    prompt = construir_prompt(entrada)
    # Capa P en el snapshot (no llega al prompt ni al candidato): hora del evento usada y recepción.
    entrada["_diagnostico_tiempo"] = diagnostico_tiempo(alert, activo)

    if isinstance(proveedor, ProveedorIA):
        prov = proveedor
    else:
        prov = obtener_proveedor(proveedor)

    if prov is None:
        nombre = proveedor if isinstance(proveedor, str) else nombre_proveedor_activo()
        return resultado_fallido(
            raw="",
            motivo=f"Proveedor de IA desconocido o no disponible: '{nombre}'",
            proveedor=str(nombre),
            modelo="desconocido",
            snapshot=entrada,
        )

    if getattr(prov, "formato_entrada", None) == CONTRATO_ENTRADA:
        try:
            prompt, traza = _entrada_modelo_ajustado(entrada, prov)
        except EntradaNoRepresentable as e:
            return resultado_fallido(
                raw="",
                motivo=f"Entrada no representable para el modelo ajustado: {e}",
                proveedor=prov.nombre,
                modelo=getattr(prov, "_modelo", "desconocido"),
                snapshot=entrada,
            )
        # Capa P en el snapshot: proveedor, recurso, plantilla, contrato y entrada realmente enviada.
        entrada["_entrada_modelo"] = traza

    try:
        respuesta = prov.analizar(prompt)
    except Exception as e:  # un proveedor no debería lanzar, pero por si acaso
        return resultado_fallido(
            raw="",
            motivo=f"El proveedor lanzó una excepción: {type(e).__name__}: {e}",
            proveedor=getattr(prov, "nombre", "?"),
            modelo="desconocido",
            snapshot=entrada,
        )
    modelo = respuesta.modelo
    diag = {
        "finish_reason": getattr(respuesta, "finish_reason", None),
        "usage": getattr(respuesta, "usage", None),
        "parsed_present": isinstance(getattr(respuesta, "parsed", None), dict),
    }

    if not respuesta.ok:
        return resultado_fallido(
            raw=respuesta.texto,
            motivo=f"El proveedor no devolvió un análisis: {respuesta.error}",
            proveedor=prov.nombre,
            modelo=modelo,
            snapshot=entrada,
            diag=diag,
        )

    # JSON: preferir el que ya deserializó el SDK (`response.parsed`); el texto
    # crudo es sólo la alternativa.
    parsed = getattr(respuesta, "parsed", None)
    if isinstance(parsed, dict):
        data, err = parsed, None
    else:
        data, err = parsear_json_estricto(respuesta.texto)
    raw = respuesta.texto
    if data is None:
        return resultado_fallido(
            raw=raw,
            motivo=f"La respuesta no es JSON estricto: {err}",
            proveedor=prov.nombre,
            modelo=modelo,
            snapshot=entrada,
            diag=diag,
        )

    validacion = validar_salida_ia(data)
    if not validacion.ok:
        return resultado_fallido(
            raw=raw,
            motivo="La respuesta no cumple el contrato: " + "; ".join(validacion.errores[:6]),
            proveedor=prov.nombre,
            modelo=modelo,
            snapshot=entrada,
            diag=diag,
        )

    if getattr(prov, "valida_privacidad_salida", False):
        from dashboard.dataset import validar_privacidad    # import perezoso (modelos de Django)
        privacidad_ok, hallazgos = validar_privacidad(data)
        if not privacidad_ok:
            return resultado_fallido(
                raw=raw,
                motivo=f"La respuesta no supera la validación de privacidad: {hallazgos}",
                proveedor=prov.nombre,
                modelo=modelo,
                snapshot=entrada,
                diag=diag,
            )

    if getattr(prov, "valida_sustento_impactos", False):
        sin_sustento = impactos_nulos_sin_sustento(data, entrada)
        if sin_sustento:
            # No se sustituyen factores: la respuesta se conserva íntegra para diagnóstico.
            return resultado_fallido(
                raw=raw,
                motivo=f"Impacto 'ninguno' sin sustento estructurado en la entrada: {sin_sustento}",
                proveedor=prov.nombre,
                modelo=modelo,
                snapshot=entrada,
                diag=diag,
            )

    return {
        "estado_analisis": "COMPLETED",
        "veredicto_ia": data["verdict"],
        "riesgo_ia": data["risk"],
        "explicacion_ia": data["explanation_es"],
        "factores_cvss": data["cvss_factors"],
        "justificacion_cvss": data["cvss_reasoning_es"],
        "recomendacion_ia": data["recommendation_es"],
        "evidencia_faltante": data["missing_evidence"],
        "respuesta_ia_original": _raw_seguro(raw),
        "proveedor_ia": prov.nombre,
        "modelo_ia": modelo,
        "motivo_fallo": None,
        "advertencias": validacion.advertencias,
        "contexto_ia_snapshot": entrada,
    }
