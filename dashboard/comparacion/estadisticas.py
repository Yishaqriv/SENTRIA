"""
Filtros, agrupación y resúmenes de las ejecuciones guardadas (solo lectura; sin IA, sin red).

No se mezclan por defecto casos, protocolos ni equivalencias distintos: una gráfica se calcula sobre UN grupo
(caso + protocolo + equivalencia). Las cuatro equivalencias (equivalente / variante / incompatible / no_verificada)
forman grupos separados: «no_verificada» nunca se presenta como comparación controlada.
Protocolo = formato + esquema de REFERENCIA del caso + esquema EFECTIVO de la ejecución («no_declarado» si falta) +
TODOS los parámetros registrados (normalización explícita: solo se retira `esquema_salida_sha256`, que ya forma
parte de la identidad como esquema efectivo). Un parámetro de generación adicional de un adaptador cambia el
protocolo; no se descarta para afirmar equivalencia. Dentro del grupo, cada serie es proveedor + modelo INFORMADO (o «no informado»
junto al solicitado): versiones informadas distintas son series distintas. Lo no medido cuenta como «ausente»,
nunca como 0; no se suman campos faltantes ni se suman tokens de razonamiento a la salida o al total.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import re
import statistics

from dashboard.models import EjecucionComparacion

from . import normalizacion as N

MAX_FILAS = 5000
MAX_SERIES = 12
EQUIVALENCIAS_UI = {
    "equivalente": "equivalente (entrada y esquema comunes verificados)",
    "variante": "variante (entrada o esquema distintos): no comparable con las equivalentes",
    "incompatible": "incompatible (sin llamada)",
    "no_verificada": "no verificada: no es una comparación controlada",
}
ESTADOS_UI = {
    "completada": "Respondió y SENTRIA la aceptó",
    "rechazada": "Respondió; SENTRIA la rechazó (validación)",
    "respondida_sin_resultado": "Respondió; resultado final no registrado",
    "fallo_llamada": "Fallo de llamada",
    "sin_llamada": "Sin llamada (entrada no representable u otra causa)",
}
_FECHA = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def estado_ui(e) -> str:
    if e.estado_llamada == "sin_llamada":
        return "sin_llamada"
    if e.estado_llamada == "error":
        return "fallo_llamada"
    if e.estado_analisis == "COMPLETED":
        return "completada"
    if e.estado_analisis == "ANALISIS_FALLIDO":
        return "rechazada"
    return "respondida_sin_resultado"


def parametros_protocolo(p):
    """Todos los parámetros registrados salvo la huella del esquema (identidad aparte). None = no registrados."""
    if not isinstance(p, dict):
        return None
    return {k: v for k, v in p.items() if k != "esquema_salida_sha256"}


def protocolo(e) -> tuple[str, dict]:
    """-> (id corto, detalle). El detalle describe exactamente lo que identifica al protocolo."""
    detalle = {"formato": e.caso.formato_entrada, "esquema_referencia": e.caso.esquema_sha256 or "no_declarado",
               "esquema_efectivo": e.esquema_efectivo_sha256 or "no_declarado",
               "parametros": parametros_protocolo(e.parametros)}
    base = dict(detalle, parametros=detalle["parametros"] if detalle["parametros"] is not None else "no_registrados")
    return "P-" + hashlib.sha256(N.canonico(base)).hexdigest()[:8], detalle


def grupo_de(e) -> str:
    equiv = e.equivalencia if e.equivalencia in EQUIVALENCIAS_UI else "no_verificada"
    return hashlib.sha256(f"{e.caso.clave}|{protocolo(e)[0]}|{equiv}".encode()).hexdigest()[:16]


def serie_de(e) -> str:
    modelo = e.modelo_informado or f"no informado (solicitado: {e.modelo_solicitado or 'no registrado'})"
    return f"{e.proveedor} · {modelo}"


def leer_filtros(qd) -> dict:
    """Lista cerrada de filtros; lo que no valida se ignora (y no se muestra como aplicado)."""
    f = {}
    v = qd.get("caso", "")
    if re.match(r"^[0-9a-f]{64}$", v):
        f["caso"] = v
    for k in ("proveedor", "modelo"):
        v = qd.get(k, "")
        try:
            if v and N.etiqueta(v, k):
                f[k] = v
        except N.DatoInvalido:
            pass
    if qd.get("procedencia") in N.PROCEDENCIAS:
        f["procedencia"] = qd["procedencia"]
    if qd.get("origen") in N.ORIGENES:
        f["origen"] = qd["origen"]
    if qd.get("estado") in ESTADOS_UI:
        f["estado"] = qd["estado"]
    for k in ("desde", "hasta"):
        v = qd.get(k, "")
        if _FECHA.match(v):
            try:
                dt.date.fromisoformat(v)
                f[k] = v
            except ValueError:
                pass
    v = qd.get("repeticion", "")
    if v.isdigit() and 1 <= int(v) <= 10_000:
        f["repeticion"] = int(v)
    v = qd.get("grupo", "")
    if re.match(r"^[0-9a-f]{16}$", v):
        f["grupo"] = v
    return f


def consulta(filtros: dict):
    qs = EjecucionComparacion.objects.select_related("caso").order_by("-inicio_utc", "uuid")
    if "caso" in filtros:
        qs = qs.filter(caso__clave=filtros["caso"])
    if "proveedor" in filtros:
        qs = qs.filter(proveedor=filtros["proveedor"])
    if "modelo" in filtros:
        from django.db.models import Q
        qs = qs.filter(Q(modelo_informado=filtros["modelo"]) | Q(modelo_solicitado=filtros["modelo"]))
    if "procedencia" in filtros:
        qs = qs.filter(caso__procedencia=filtros["procedencia"])
    if "origen" in filtros:
        qs = qs.filter(origen_medicion=filtros["origen"])
    if "desde" in filtros:
        qs = qs.filter(inicio_utc__date__gte=filtros["desde"])
    if "hasta" in filtros:
        qs = qs.filter(inicio_utc__date__lte=filtros["hasta"])
    if "repeticion" in filtros:
        qs = qs.filter(repeticion=filtros["repeticion"])
    filas = list(qs[:MAX_FILAS + 1])
    truncado = len(filas) > MAX_FILAS
    filas = filas[:MAX_FILAS]
    if "estado" in filtros:
        filas = [e for e in filas if estado_ui(e) == filtros["estado"]]
    return filas, truncado


def grupos(filas) -> list[dict]:
    out = {}
    for e in filas:
        g = grupo_de(e)
        pid, det = protocolo(e)
        d = out.setdefault(g, {"id": g, "caso": e.caso, "protocolo": pid, "detalle": det,
                               "equivalencia": e.equivalencia,
                               "equivalencia_ui": EQUIVALENCIAS_UI.get(e.equivalencia, e.equivalencia),
                               "n": 0, "series": set()})
        d["n"] += 1
        d["series"].add(serie_de(e))
    res = sorted(out.values(), key=lambda d: (d["caso"].codigo, d["protocolo"], -d["n"]))
    for d in res:
        d["n_series"] = len(d["series"])
        d["series"] = sorted(d["series"])
    return res


def _resumen(valores):
    medidos = [v for v in valores if v is not None]
    return {"valores": medidos, "n_medido": len(medidos), "n_ausente": len(valores) - len(medidos),
            "mediana": statistics.median(medidos) if medidos else None}


def datos_grupo(filas, grupo_id) -> dict | None:
    """Datos de las tres gráficas para UN grupo. None si el grupo no está en las filas filtradas."""
    sel = [e for e in filas if grupo_de(e) == grupo_id]
    if not sel:
        return None
    series = {}
    for e in sel:
        series.setdefault(serie_de(e), []).append(e)
    nombres = sorted(series)[:MAX_SERIES]
    lat, tok, est = [], [], []
    for s in nombres:
        es = series[s]
        lat.append({"serie": s, **_resumen([e.latencia_proveedor_s for e in es])})
        tok.append({"serie": s, "entrada": _resumen([e.tokens_entrada for e in es]),
                    "salida": _resumen([e.tokens_salida for e in es]),
                    "total": _resumen([e.tokens_total for e in es]),
                    "razonamiento": _resumen([e.tokens_razonamiento for e in es])})
        cuenta = {k: 0 for k in ESTADOS_UI}
        for e in es:
            cuenta[estado_ui(e)] += 1
        est.append({"serie": s, "n": len(es), **cuenta})
    prim = sel[0]
    origenes = sorted({e.get_origen_medicion_display() for e in sel})
    pid, det = protocolo(prim)
    return {"grupo": grupo_id, "caso": prim.caso, "protocolo": pid, "detalle": det,
            "equivalencia": prim.equivalencia,
            "equivalencia_ui": EQUIVALENCIAS_UI.get(prim.equivalencia, prim.equivalencia),
            "ejecuciones": [e for e in sel if serie_de(e) in nombres], "series_omitidas": max(0, len(series) - MAX_SERIES),
            "latencia": lat, "tokens": tok, "estados": est, "origenes": origenes,
            "un_solo_proveedor": len({e.proveedor for e in sel}) <= 1, "n": len(sel)}
