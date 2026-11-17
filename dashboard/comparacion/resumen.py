"""
«Resumen del conjunto»: agregados por proveedor/modelo sobre un conjunto congelado (solo lectura, sin IA ni red).

- Serie = proveedor + modelo INFORMADO (o «no informado» con el solicitado) + protocolo + equivalencia: versiones de
  modelo, protocolos o condiciones distintas nunca se juntan.
- Las ejecuciones se vinculan a los casos del conjunto por la clave del caso (huella), no por su nombre visible.
- Cobertura por casos (k de N) y, aparte, número de ejecuciones. Una repetición no es un caso nuevo.
- Tiempo: cada caso pesa igual (media de sus repeticiones medidas; luego media y mediana entre casos). Ausentes = faltantes,
  nunca 0. Tokens: total observado y promedio por ejecución medida, con cobertura; el razonamiento no se suma.
- Comparación: solo series «equivalente» y solo sobre los casos que TODAS cubren (mismos casos y condiciones).
"""
from __future__ import annotations

import hashlib
import statistics

from dashboard.models import EjecucionComparacion

from . import estadisticas as E

CAMPOS_TOKENS = ("tokens_entrada", "tokens_salida", "tokens_total")


def serie_resumen(e) -> tuple:
    modelo = e.modelo_informado or f"no informado (solicitado: {e.modelo_solicitado or 'no registrado'})"
    return (e.proveedor, modelo, E.protocolo(e)[0], e.equivalencia)


def id_serie(s) -> str:
    return hashlib.sha256("|".join(s).encode()).hexdigest()[:12]


def _media(v):
    return statistics.fmean(v) if v else None


def ejecuciones_del_conjunto(cj, *, repeticiones="todas", serie=None):
    claves = [m.caso.clave for m in cj.miembros.select_related("caso").order_by("orden")]
    qs = list(EjecucionComparacion.objects.select_related("caso").filter(caso__clave__in=claves)
              .order_by("inicio_utc", "registrado_en", "uuid"))
    if serie:
        qs = [e for e in qs if id_serie(serie_resumen(e)) == serie]
    if repeticiones == "primera":                        # primera ejecución por (serie, caso)
        vistos, sel = set(), []
        for e in qs:
            k = (serie_resumen(e), e.caso.clave)
            if k not in vistos:
                vistos.add(k)
                sel.append(e)
        qs = sel
    return claves, qs


def _por_caso(ejecs, campo):
    """{clave: media de las mediciones disponibles del caso} (solo casos con al menos una medición)."""
    acc = {}
    for e in ejecs:
        v = getattr(e, campo)
        if v is not None:
            acc.setdefault(e.caso.clave, []).append(v)
    return {k: statistics.fmean(v) for k, v in acc.items()}


def _bloque_serie(s, ejecs, n_casos_conjunto):
    casos = sorted({e.caso.clave for e in ejecs})
    lat_caso = _por_caso(ejecs, "latencia_proveedor_s")
    lat_medidas = [e.latencia_proveedor_s for e in ejecs if e.latencia_proveedor_s is not None]
    tok = {}
    for c in CAMPOS_TOKENS:
        vals = [getattr(e, c) for e in ejecs if getattr(e, c) is not None]
        tok[c] = {"total_observado": sum(vals) if vals else None, "promedio_por_ejecucion": _media(vals),
                  "n_medidas": len(vals), "n_faltantes": len(ejecs) - len(vals)}
    estados = {k: 0 for k in E.ESTADOS_UI}
    for e in ejecs:
        estados[E.estado_ui(e)] += 1
    return {"id": id_serie(s), "proveedor": s[0], "modelo": s[1], "protocolo": s[2], "equivalencia": s[3],
            "casos": casos, "n_casos": len(casos), "n_pendientes": n_casos_conjunto - len(casos),
            "n_ejecuciones": len(ejecs),
            "tiempo": {"media_por_caso": _media(list(lat_caso.values())),
                       "mediana_por_caso": statistics.median(lat_caso.values()) if lat_caso else None,
                       "n_casos_medidos": len(lat_caso), "n_medidas": len(lat_medidas),
                       "n_faltantes": len(ejecs) - len(lat_medidas)},
            "tokens": tok, "estados": estados, "por_caso_latencia": lat_caso,
            "por_caso_tokens": {c: _por_caso(ejecs, c) for c in CAMPOS_TOKENS}}


def calcular(cj, *, repeticiones="todas", serie=None) -> dict:
    claves, ejecs = ejecuciones_del_conjunto(cj, repeticiones=repeticiones, serie=serie)
    grupos = {}
    for e in ejecs:
        grupos.setdefault(serie_resumen(e), []).append(e)
    series = [_bloque_serie(s, es, len(claves)) for s, es in sorted(grupos.items())]
    comparables = [s for s in series if s["equivalencia"] == "equivalente"]
    comparacion = None
    if len(comparables) >= 2:
        comunes = sorted(set.intersection(*(set(s["casos"]) for s in comparables)))
        filas = []
        for s in comparables:
            es = [e for e in grupos[next(k for k in grupos if id_serie(k) == s["id"])] if e.caso.clave in comunes]
            lat = _por_caso(es, "latencia_proveedor_s")
            fila = {"id": s["id"], "proveedor": s["proveedor"], "modelo": s["modelo"],
                    "tiempo_media_por_caso": _media(list(lat.values())),
                    "tiempo_mediana_por_caso": statistics.median(lat.values()) if lat else None,
                    "casos_con_tiempo": len(lat), "casos_sin_tiempo": len(comunes) - len(lat)}
            for c in CAMPOS_TOKENS:
                pc = _por_caso(es, c)
                fila[c] = {"media_por_caso": _media(list(pc.values())), "casos_medidos": len(pc),
                           "casos_sin_dato": len(comunes) - len(pc)}
            filas.append(fila)
        comparacion = {"casos_comunes": comunes, "n_casos_comunes": len(comunes), "series": filas}
    return {"conjunto": cj, "n_casos": len(claves), "claves": claves, "repeticiones": repeticiones,
            "ejecuciones": ejecs, "series": series, "comparables": len(comparables),
            "series_no_comparables": len(series) - len(comparables), "comparacion": comparacion,
            "pendiente_otro_proveedor": len({s["proveedor"] for s in comparables}) < 2}
