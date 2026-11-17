"""
Apartado «Comparación de IA»: EXCLUSIVO del superusuario real (usuario autenticado, activo e `is_superuser`).
El rol ADMIN de SENTRIA o `is_staff` NO bastan. Todas las vistas (página, detalle, gráficas, CSV/JSON, importación)
pasan por `solo_superusuario`: anónimo -> login; autenticado sin permiso -> 403 sin datos.
Ninguna vista llama a la IA, al indexador ni lee credenciales. Los GET solo leen; lo que escribe es POST con CSRF.
"""
from __future__ import annotations

import csv
import datetime as dt
import hashlib
import io
import json
from functools import wraps

from django.contrib import messages
from django.contrib.auth.views import redirect_to_login
from django.core.exceptions import PermissionDenied
from django.core.paginator import Paginator
from django.http import Http404, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_GET, require_POST

from dashboard.models import CasoComparacion, ConjuntoComparacion, EjecucionComparacion, LoteImportacionComparacion

from . import estadisticas as E
from . import graficas as G
from . import intercambio as I
from . import local as L
from . import normalizacion as N
from . import conjuntos as CJ
from . import resumen as RS
from . import textos as T

SESION_IMPORTACION = "comparacion_importacion_pendiente"


def es_superusuario_real(user) -> bool:
    return bool(getattr(user, "is_authenticated", False) and user.is_active and user.is_superuser)


def solo_superusuario(vista):
    @wraps(vista)
    def envoltura(request, *args, **kwargs):
        if not getattr(request.user, "is_authenticated", False):
            return redirect_to_login(request.get_full_path())
        if not es_superusuario_real(request.user):
            raise PermissionDenied("Apartado reservado al superusuario.")
        return vista(request, *args, **kwargs)
    return envoltura


# ------------------------------------------------------------------------------------------------- utilidades
def _celda_csv(v):
    if v is None:
        return "No disponible"
    if isinstance(v, bool):
        return "sí" if v else "no"
    if isinstance(v, (int, float)):
        return str(v)
    t = str(v).replace("\r", " ").replace("\n", " ")
    return "'" + t if t[:1] in ("=", "+", "-", "@", "\t") else t


def _csv(cabecera, filas) -> bytes:
    out = io.StringIO(newline="")
    w = csv.writer(out, delimiter=";", lineterminator="\r\n")
    w.writerow(cabecera)
    for f in filas:
        w.writerow([_celda_csv(x) for x in f])
    return b"\xef\xbb\xbf" + out.getvalue().encode("utf-8")


def _adjunto(contenido, tipo, nombre):
    r = HttpResponse(contenido, content_type=tipo)
    r["Content-Disposition"] = f'attachment; filename="{nombre}"'
    r["Cache-Control"] = "no-store"
    return r


COLUMNAS_TABLA = [
    ("uuid", "UUID"), ("caso", "Caso"), ("caso_clave", "Clave del caso"), ("procedencia", "Procedencia"),
    ("protocolo", "Protocolo"), ("repeticion", "Repetición"), ("origen", "Origen de la medición"),
    ("proveedor", "Proveedor"), ("modelo_solicitado", "Modelo solicitado"), ("modelo_informado", "Modelo informado"),
    ("inicio_utc", "Inicio UTC"), ("definicion_tiempo", "Definición del tiempo"),
    ("latencia_proveedor_s", "Latencia del proveedor (s)"), ("duracion_analisis_s", "Duración del análisis (s)"),
    ("duracion_ejecucion_s", "Duración de la ejecución (s)"), ("tokens_entrada", "Tokens entrada"),
    ("tokens_salida", "Tokens salida"), ("tokens_razonamiento", "Tokens razonamiento"),
    ("tokens_total", "Tokens total informado"), ("estado", "Estado"), ("estado_llamada", "Estado de la llamada"),
    ("estado_analisis", "Estado del análisis"), ("categoria_error", "Categoría de error"),
    ("finish_reason", "Finalización"), ("codigo_http", "HTTP"), ("equivalencia", "Equivalencia"),
    ("esquema_efectivo", "Esquema efectivo"), ("identidad", "Identidad de la ejecución"),
    ("entrada_sha256", "SHA-256 de entrada"), ("huella_contenido", "Huella de contenido"),
]


def _fila(e):
    return {"uuid": str(e.uuid), "caso": e.caso.codigo, "caso_clave": e.caso.clave,
            "procedencia": e.caso.get_procedencia_display(), "protocolo": E.protocolo(e)[0],
            "repeticion": e.repeticion, "origen": e.get_origen_medicion_display(), "proveedor": e.proveedor,
            "modelo_solicitado": e.modelo_solicitado, "modelo_informado": e.modelo_informado,
            "inicio_utc": N.fecha_iso(e.inicio_utc), "definicion_tiempo": e.definicion_tiempo or None,
            "latencia_proveedor_s": e.latencia_proveedor_s, "duracion_analisis_s": e.duracion_analisis_s,
            "duracion_ejecucion_s": e.duracion_ejecucion_s, "tokens_entrada": e.tokens_entrada,
            "tokens_salida": e.tokens_salida, "tokens_razonamiento": e.tokens_razonamiento,
            "tokens_total": e.tokens_total, "estado": E.ESTADOS_UI[E.estado_ui(e)],
            "estado_llamada": e.get_estado_llamada_display(), "estado_analisis": e.estado_analisis,
            "categoria_error": e.categoria_error, "finish_reason": e.finish_reason, "codigo_http": e.codigo_http,
            "equivalencia": e.equivalencia, "entrada_sha256": e.caso.entrada_sha256,
            "esquema_efectivo": e.esquema_efectivo_sha256 or "no declarado",
            "identidad": "derivada (formato v1)" if e.identidad_derivada else "UUID propio",
            "huella_contenido": e.huella_contenido}


def _filtros_query(filtros):
    from urllib.parse import urlencode
    return urlencode({k: v for k, v in filtros.items()})


# ------------------------------------------------------------------------------------------------- páginas
def _resumen_series(datos):
    """Filas sencillas por serie para la tabla bajo las gráficas (sin huellas)."""
    filas = []
    for lat, tok, est in zip(datos["latencia"], datos["tokens"], datos["estados"]):
        prov, _, modelo = lat["serie"].partition(" · ")
        partes = [T.plural(est["completada"], "aceptada", "aceptadas"),
                  T.plural(est["rechazada"], "rechazada por SENTRIA", "rechazadas por SENTRIA"),
                  T.plural(est["respondida_sin_resultado"], "sin resultado final", "sin resultado final"),
                  T.plural(est["fallo_llamada"], "fallo de llamada", "fallos de llamada"),
                  T.plural(est["sin_llamada"], "sin llamada", "sin llamada")]
        filas.append({"proveedor": prov, "modelo": modelo, "latencia": lat["mediana"], "n_medido": lat["n_medido"],
                      "n_ausente": lat["n_ausente"], "tokens_total": tok["total"]["mediana"],
                      "resultado": ", ".join(p for p in partes if not p.startswith("0 ")) or "No disponible"})
    return filas


def _proveedores_de(series):
    return len({s.partition(" · ")[0] for s in series})


# --------------------------------------------------------------------------------------- resumen del conjunto
def _resumen_desde(qd):
    """-> (conjunto | None, resumen | None, parámetros normalizados). Lista cerrada de parámetros."""
    import re as _re
    conjuntos = list(ConjuntoComparacion.objects.order_by("-creado_en", "-id"))
    if not conjuntos:
        return None, None, {}
    cid = qd.get("conjunto", "")
    cj = next((c for c in conjuntos if CJ.identificador(c) == cid), conjuntos[0])
    rep = qd.get("rep") if qd.get("rep") in ("todas", "primera") else "todas"
    serie = qd.get("serie") if _re.match(r"^[0-9a-f]{12}$", qd.get("serie", "")) else None
    return cj, RS.calcular(cj, repeticiones=rep, serie=serie), {"conjunto": CJ.identificador(cj), "rep": rep,
                                                                **({"serie": serie} if serie else {})}


def _filas_resumen(r):
    filas = []
    for s in r["series"]:
        t, k = s["tiempo"], s["tokens"]
        res = s["estados"]
        filas.append({
            "id": s["id"], "proveedor": s["proveedor"], "modelo": s["modelo"],
            "comparable": s["equivalencia"] == "equivalente",
            "condiciones": T.EQUIVALENCIA.get(s["equivalencia"], s["equivalencia"]),
            "cobertura": f"{s['n_casos']} de {r['n_casos']} casos", "pendientes": s["n_pendientes"],
            "ejecuciones": s["n_ejecuciones"], "tiempo_media": t["media_por_caso"], "tiempo_mediana": t["mediana_por_caso"],
            "tiempo_cobertura": f"{t['n_medidas']} con dato" + (f" · {t['n_faltantes']} sin dato" if t["n_faltantes"] else ""),
            "tokens": [(n, k[c]["promedio_por_ejecucion"], k[c]["total_observado"], k[c]["n_medidas"], s["n_ejecuciones"])
                       for n, c in (("Entrada", "tokens_entrada"), ("Salida", "tokens_salida"), ("Total", "tokens_total"))],
            "resultados": ", ".join(p for p in (T.plural(res["completada"], "aceptada", "aceptadas"),
                                                T.plural(res["rechazada"], "rechazada", "rechazadas"),
                                                T.plural(res["respondida_sin_resultado"], "sin resultado", "sin resultado"),
                                                T.plural(res["fallo_llamada"], "fallo de llamada", "fallos de llamada"),
                                                T.plural(res["sin_llamada"], "sin llamada", "sin llamada"))
                                    if not p.startswith("0 ")) or "No disponible",
            "protocolo": s["protocolo"], "equivalencia": s["equivalencia"]})
    return filas


def _csv_resumen(r):
    cj = r["conjunto"]
    cab = ["Conjunto", "Versión", "Huella del manifiesto", "Caso", "Clave del caso", "Serie", "Proveedor",
           "Modelo solicitado", "Modelo informado", "Protocolo", "Equivalencia", "Comparable", "UUID", "Repetición",
           "Identidad derivada", "Origen", "Inicio UTC", "Latencia del proveedor (s)", "Tokens entrada",
           "Tokens salida", "Tokens razonamiento (no sumados)", "Tokens total informado", "Resultado"]
    codigos = {c["clave"]: c["codigo"] for c in cj.casos_manifiesto}
    filas = []
    for e in r["ejecuciones"]:
        s = RS.serie_resumen(e)
        filas.append([cj.codigo, cj.version, cj.manifiesto_sha256, codigos.get(e.caso.clave, e.caso.codigo),
                      e.caso.clave, RS.id_serie(s), e.proveedor, e.modelo_solicitado, e.modelo_informado, s[2],
                      e.equivalencia, "sí" if e.equivalencia == "equivalente" else "no", str(e.uuid), e.repeticion,
                      "sí" if e.identidad_derivada else "no", e.get_origen_medicion_display(), N.fecha_iso(e.inicio_utc),
                      e.latencia_proveedor_s, e.tokens_entrada, e.tokens_salida, e.tokens_razonamiento, e.tokens_total,
                      E.ESTADOS_UI[E.estado_ui(e)]])
    for s in r["series"]:                                 # cobertura: casos pendientes de cada serie
        for clave in r["claves"]:
            if clave not in s["casos"]:
                filas.append([cj.codigo, cj.version, cj.manifiesto_sha256, codigos.get(clave), clave, s["id"],
                              s["proveedor"], None, s["modelo"], s["protocolo"], s["equivalencia"],
                              "sí" if s["equivalencia"] == "equivalente" else "no", None, None, None, None, None,
                              None, None, None, None, None, "Pendiente (sin ejecución en esta serie)"])
    return _csv(cab, filas)


def _ficha_resumen(r, params, contenido_csv):
    cj = r["conjunto"]
    def limpio(s):
        return {k: v for k, v in s.items() if k not in ("casos",)} | {"casos_con_ejecucion": s["casos"]}
    return {
        "vista": "resumen_del_conjunto", "parametros": params,
        "conjunto": {"codigo": cj.codigo, "version": cj.version, "manifiesto_sha256": cj.manifiesto_sha256,
                     "descripcion": cj.descripcion, "reglas": cj.reglas, "casos": cj.casos_manifiesto},
        "regla_de_agregacion": CJ.REGLA_AGREGACION, "n_casos": r["n_casos"], "repeticiones": r["repeticiones"],
        "series": [limpio(s) for s in r["series"]], "comparacion": r["comparacion"],
        "pendiente_otro_proveedor": r["pendiente_otro_proveedor"],
        "ejecuciones": [{"uuid": str(e.uuid), "huella_contenido": e.huella_contenido, "caso_clave": e.caso.clave,
                         "serie": RS.id_serie(RS.serie_resumen(e))} for e in r["ejecuciones"]],
        "datos_csv_sha256": hashlib.sha256(contenido_csv).hexdigest(),
        "fecha_corte_utc": N.fecha_iso(timezone.now()),
        "renderizador": {"version": G.VERSION_RENDERIZADOR, "matplotlib": G.version_matplotlib(), "backend": "Agg",
                         "png_ppp": G.DPI_DOCUMENTO},
        "aviso": "Piloto comparativo, no representativo. Sin exactitud, FP/FN ni costes. Tokens según cada proveedor."}


@solo_superusuario
@require_GET
def comparacion_resumen_grafica(request, tipo, formato):
    if tipo not in G.TIPOS_RESUMEN or formato not in G.FORMATOS:
        raise Http404("Tipo o formato no admitido.")
    cj, r, params = _resumen_desde(request.GET)
    if cj is None:
        raise Http404("No hay un conjunto congelado.")
    if not G.disponible():
        return HttpResponse("Gráficas no disponibles: falta la dependencia de graficación en este entorno.",
                            status=503, content_type="text/plain; charset=utf-8")
    vista = request.GET.get("vista") == "1" and formato == "png"
    try:
        contenido = G.renderizar_resumen(tipo, formato, r, vista=vista)
    except G.Ocupado:
        return HttpResponse("Hay otra figura en curso; reintenta en unos segundos.", status=503,
                            content_type="text/plain; charset=utf-8")
    if vista:
        resp = HttpResponse(contenido, content_type=G.FORMATOS[formato])
        resp["Cache-Control"] = "no-store"
        return resp
    return _adjunto(contenido, G.FORMATOS[formato], f"sentria_resumen_{tipo}_{params['conjunto']}.{formato}")


@solo_superusuario
@require_GET
def comparacion_resumen_datos(request):
    cj, r, params = _resumen_desde(request.GET)
    if cj is None:
        raise Http404("No hay un conjunto congelado.")
    return _adjunto(_csv_resumen(r), "text/csv; charset=utf-8", f"sentria_resumen_{params['conjunto']}_datos.csv")


@solo_superusuario
@require_GET
def comparacion_resumen_ficha(request):
    cj, r, params = _resumen_desde(request.GET)
    if cj is None:
        raise Http404("No hay un conjunto congelado.")
    ficha = _ficha_resumen(r, params, _csv_resumen(r))
    return _adjunto(json.dumps(ficha, ensure_ascii=False, indent=1, default=str).encode("utf-8"), "application/json",
                    f"sentria_resumen_{params['conjunto']}_ficha_tecnica.json")


@solo_superusuario
@require_GET
def comparacion(request):
    filtros = E.leer_filtros(request.GET)
    filas, truncado = E.consulta(filtros)
    grupos = E.grupos(filas)
    gid = filtros.get("grupo") or (grupos[0]["id"] if len(grupos) == 1 else None)
    datos = E.datos_grupo(filas, gid) if gid else None
    for g in grupos:
        g["equivalencia_texto"] = T.EQUIVALENCIA.get(g["equivalencia"], g["equivalencia"])
        g["n_proveedores"] = _proveedores_de(g["series"])
        g["parametros_texto"] = T.parametros_legibles(g["detalle"]["parametros"])
    if datos:
        datos["equivalencia_texto"] = T.EQUIVALENCIA.get(datos["equivalencia"], datos["equivalencia"])
        datos["resumen_series"] = _resumen_series(datos)
    cj_sel, resumen, params_resumen = _resumen_desde(request.GET)
    pagina = Paginator(filas, 50).get_page(request.GET.get("pagina"))
    filtros_sin_grupo = {k: v for k, v in filtros.items() if k != "grupo"}
    ctx = {
        "filtros": filtros, "q": _filtros_query(filtros), "q_sin_grupo": _filtros_query(filtros_sin_grupo),
        "pagina": pagina, "filas": [(_fila(e), e) for e in pagina.object_list], "truncado": truncado,
        "n_total": len(filas), "n_casos": len({e.caso_id for e in filas}),
        "n_proveedores": len({e.proveedor for e in filas}),
        "n_importadas": sum(1 for e in filas if e.origen_medicion != "observada_local"),
        "grupos": grupos, "grupo": datos, "pendientes_locales": L.pendientes(),
        "graficas_disponibles": G.disponible(), "tipos_grafica": G.TIPOS,
        "casos": [(c.clave, f"{c.codigo} · {c.get_procedencia_display()}")
                  for c in CasoComparacion.objects.order_by("codigo")[:500]],
        "ayuda": T.AYUDA_MEDIDAS,
        "proveedores": sorted(set(EjecucionComparacion.objects.values_list("proveedor", flat=True))),
        "procedencias": CasoComparacion.PROCEDENCIA_CHOICES, "origenes": EjecucionComparacion.ORIGEN_CHOICES,
        "estados": list(E.ESTADOS_UI.items()),
        "lotes": [{"fecha": l.importado_en, "formato": T.FORMATO_ARCHIVO.get(l.formato, l.formato),
                   "nombre": l.archivo_nombre, "recuento": T.lista_recuento(l.resumen.get("recuento"))}
                  for l in LoteImportacionComparacion.objects.order_by("-importado_en")[:5]],
        "pendiente_importacion": request.session.get(SESION_IMPORTACION, {}).get("resumen"),
        "max_kib": I.MAX_BYTES // 1024,
        "conjunto": cj_sel, "conjunto_id": params_resumen.get("conjunto"), "resumen": resumen,
        "q_resumen": _filtros_query(params_resumen),
        "filas_resumen": _filas_resumen(resumen) if resumen else [],
        "conjuntos": [(CJ.identificador(c), f"{c.codigo} v{c.version}") for c in ConjuntoComparacion.objects.order_by("-creado_en", "-id")],
        "regla_agregacion": CJ.REGLA_AGREGACION, "tipos_resumen": G.TIPOS_RESUMEN,
    }
    return render(request, "dashboard/comparacion/comparacion.html", ctx)


@solo_superusuario
@require_GET
def comparacion_detalle(request, uuid):
    e = get_object_or_404(EjecucionComparacion.objects.select_related("caso", "lote"), uuid=uuid)
    return render(request, "dashboard/comparacion/detalle.html", {
        "e": e, "f": _fila(e), "protocolo": E.protocolo(e), "estado": E.ESTADOS_UI[E.estado_ui(e)],
        "equivalencia_texto": T.EQUIVALENCIA.get(e.equivalencia, e.equivalencia),
        "analisis_texto": T.ESTADO_ANALISIS.get(e.estado_analisis, "No disponible"),
        "veredicto_texto": T.VEREDICTO.get(e.veredicto, e.veredicto),
        "riesgo_texto": T.RIESGO.get(e.riesgo, e.riesgo),
        "tokens_fuente_texto": T.TOKENS_FUENTE.get(e.tokens_fuente, e.tokens_fuente or "No disponible"),
        "parametros": json.dumps(e.parametros, ensure_ascii=False, indent=1, sort_keys=True) if e.parametros else None,
        "vinculada_localmente": e.alerta_local_id is not None,
        "procedencias": CasoComparacion.PROCEDENCIA_CHOICES})


# ------------------------------------------------------------------------------------------------- gráficas
def _datos_grafica(request):
    filtros = E.leer_filtros(request.GET)
    if "grupo" not in filtros:
        raise Http404("Elige un grupo (caso y protocolo) para la figura.")
    filas, _ = E.consulta(filtros)
    datos = E.datos_grupo(filas, filtros["grupo"])
    if datos is None:
        raise Http404("El grupo no tiene ejecuciones con estos filtros.")
    return filtros, datos


def _filas_figura(tipo, datos):
    proto = datos["protocolo"]
    cab = ["UUID", "Caso", "Clave del caso", "Protocolo", "Equivalencia", "Esquema efectivo", "Serie", "Proveedor",
           "Modelo solicitado", "Modelo informado", "Origen", "Inicio UTC"]
    if tipo == "latencia":
        cab += ["Latencia del proveedor (s)", "Definición del tiempo"]
    elif tipo == "tokens":
        cab += ["Tokens entrada", "Tokens salida", "Tokens total informado", "Tokens razonamiento (no sumados)",
                "Fuente de tokens"]
    else:
        cab += ["Estado", "Estado de la llamada", "Estado del análisis", "Categoría de error"]
    filas = []
    for e in sorted(datos["ejecuciones"], key=lambda x: (E.serie_de(x), str(x.uuid))):
        base = [str(e.uuid), e.caso.codigo, e.caso.clave, proto, e.equivalencia,
                e.esquema_efectivo_sha256 or "no declarado", E.serie_de(e), e.proveedor, e.modelo_solicitado,
                e.modelo_informado, e.get_origen_medicion_display(), N.fecha_iso(e.inicio_utc)]
        if tipo == "latencia":
            base += [e.latencia_proveedor_s, e.definicion_tiempo or None]
        elif tipo == "tokens":
            base += [e.tokens_entrada, e.tokens_salida, e.tokens_total, e.tokens_razonamiento, e.tokens_fuente]
        else:
            base += [E.ESTADOS_UI[E.estado_ui(e)], e.estado_llamada, e.estado_analisis, e.categoria_error]
        filas.append(base)
    return cab, filas


@solo_superusuario
@require_GET
def comparacion_grafica(request, tipo, formato):
    if tipo not in G.TIPOS or formato not in G.FORMATOS:
        raise Http404("Tipo o formato no admitido.")
    if not G.disponible():
        return HttpResponse("Gráficas no disponibles: falta la dependencia de graficación en este entorno.",
                            status=503, content_type="text/plain; charset=utf-8")
    _, datos = _datos_grafica(request)
    vista = request.GET.get("vista") == "1" and formato == "png"
    try:
        contenido = G.renderizar(tipo, formato, datos, vista=vista)
    except G.Ocupado:
        return HttpResponse("Hay otra figura en curso; reintenta en unos segundos.", status=503,
                            content_type="text/plain; charset=utf-8")
    nombre = f"sentria_{tipo}_{datos['grupo']}.{formato}"
    if vista:
        r = HttpResponse(contenido, content_type=G.FORMATOS[formato])
        r["Cache-Control"] = "no-store"
        return r
    return _adjunto(contenido, G.FORMATOS[formato], nombre)


@solo_superusuario
@require_GET
def comparacion_grafica_datos(request, tipo):
    if tipo not in G.TIPOS:
        raise Http404("Tipo no admitido.")
    _, datos = _datos_grafica(request)
    cab, filas = _filas_figura(tipo, datos)
    return _adjunto(_csv(cab, filas), "text/csv; charset=utf-8", f"sentria_{tipo}_{datos['grupo']}_datos.csv")


@solo_superusuario
@require_GET
def comparacion_grafica_manifiesto(request, tipo):
    if tipo not in G.TIPOS:
        raise Http404("Tipo no admitido.")
    filtros, datos = _datos_grafica(request)
    cab, filas = _filas_figura(tipo, datos)
    caso = datos["caso"]
    man = {
        "figura": tipo, "filtros": filtros, "grupo": datos["grupo"],
        "caso": {"codigo": caso.codigo, "clave": caso.clave, "entrada_sha256": caso.entrada_sha256,
                 "esquema_sha256": caso.esquema_sha256, "formato_entrada": caso.formato_entrada,
                 "procedencia": caso.procedencia},
        "protocolo": {"id": datos["protocolo"], **datos["detalle"]},
        "equivalencia": datos["equivalencia"], "equivalencia_descripcion": datos["equivalencia_ui"],
        "ejecuciones": [{"uuid": str(e.uuid), "huella_contenido": e.huella_contenido, "serie": E.serie_de(e),
                         "origen_medicion": e.origen_medicion, "equivalencia": e.equivalencia,
                         "esquema_efectivo_sha256": e.esquema_efectivo_sha256,
                         "identidad_derivada": e.identidad_derivada}
                        for e in sorted(datos["ejecuciones"], key=lambda x: str(x.uuid))],
        "fecha_corte_utc": N.fecha_iso(timezone.now()),
        "renderizador": {"version": G.VERSION_RENDERIZADOR, "matplotlib": G.version_matplotlib(), "backend": "Agg",
                         "png_ppp": G.DPI_DOCUMENTO, "formatos": sorted(G.FORMATOS)},
        "datos_csv_sha256": hashlib.sha256(_csv(cab, filas)).hexdigest(),
        "definiciones": {
            "latencia": "tiempo medido alrededor de la llamada al proveedor (ver definicion_tiempo de cada fila)",
            "mediana": "mediana de las mediciones disponibles; los ausentes no cuentan como 0",
            "tokens": "valores informados por el proveedor; total = el informado, no una suma; razonamiento no "
                      "sumado",
            "estados": "respuesta del proveedor y aceptación por SENTRIA por separado; no es exactitud"},
        "aviso": "Las huellas comprueban integridad; no autentican al proveedor. Sin llamadas a la IA.",
    }
    return _adjunto(json.dumps(man, ensure_ascii=False, indent=1).encode("utf-8"), "application/json",
                    f"sentria_{tipo}_{datos['grupo']}_ficha_tecnica.json")


# ------------------------------------------------------------------------------------------- exportaciones
@solo_superusuario
@require_GET
def comparacion_exportar_csv(request):
    filtros = E.leer_filtros(request.GET)
    filas, _ = E.consulta(filtros)
    cab = [t for _, t in COLUMNAS_TABLA]
    datos = [[_fila(e)[k] for k, _ in COLUMNAS_TABLA] for e in filas]
    marca = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return _adjunto(_csv(cab, datos), "text/csv; charset=utf-8", f"sentria_comparacion_{marca}.csv")


@solo_superusuario
@require_GET
def comparacion_exportar_json(request):
    filtros = E.leer_filtros(request.GET)
    cj = None
    if request.GET.get("conjunto"):
        cj = next((c for c in ConjuntoComparacion.objects.all() if CJ.identificador(c) == request.GET["conjunto"]), None)
        if cj is None:
            raise Http404("Conjunto no encontrado.")
        claves = [c["clave"] for c in cj.casos_manifiesto]
        ids = list(EjecucionComparacion.objects.filter(caso__clave__in=claves).values_list("pk", flat=True))
        filtros = {"conjunto": CJ.identificador(cj)}
    else:
        filas, _ = E.consulta(filtros)
        ids = [e.pk for e in filas]
    doc = I.exportar(EjecucionComparacion.objects.filter(pk__in=ids), filtros=filtros, conjunto=cj)
    marca = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return _adjunto(json.dumps(doc, ensure_ascii=False, indent=1).encode("utf-8"), "application/json",
                    f"sentria_comparacion_{marca}.json")


# ------------------------------------------------------------------------------------------- escrituras (POST)
@solo_superusuario
@require_POST
def comparacion_registrar_locales(request):
    r = L.registrar(request.user, incluir_ambiguas=request.POST.get("incluir_ambiguas") == "1")
    messages.success(request, f"Mediciones locales registradas: {r['registradas']} (repeticiones con la misma "
                              f"respuesta que otra ejecución: {r['repeticiones_con_misma_respuesta']}) · ambiguas no "
                              f"registradas: {r['ambiguas_no_registradas']} · no registrables: {r['no_registrables']} · "
                              f"casos nuevos: {r['casos_nuevos']}. No se llamó a la IA ni se modificaron alertas.")
    if r["ambiguas_no_registradas"]:
        messages.warning(request, "Ambigua: misma respuesta que una referencia sin identidad propia (formato v1); no se "
                                  "puede demostrar si es la misma ejecución. No se fusionó. Para guardarla como "
                                  "ejecución separada, marca «incluir ambiguas» y vuelve a registrar.")
    for motivo, n in list(r["motivos"].items())[:5]:
        messages.warning(request, f"{n} × {motivo}")
    return redirect("comparacion")


@solo_superusuario
@require_POST
def comparacion_importar(request):
    archivo = request.FILES.get("archivo")
    if archivo is None:
        messages.error(request, "Selecciona un archivo JSON o JSONL.")
        return redirect("comparacion")
    if archivo.size > I.MAX_BYTES:
        messages.error(request, f"El archivo supera {I.MAX_BYTES // 1024} KiB.")
        return redirect("comparacion")
    contenido = archivo.read(I.MAX_BYTES + 1)
    try:
        participante = N.participante(request.POST.get("participante", "").strip())
    except N.DatoInvalido:
        messages.error(request, "Participante: usa una etiqueta neutral (letras, números, espacios, - o _).")
        return redirect("comparacion")
    try:
        analisis = I.analizar(contenido)
    except I.ArchivoInvalido as e:
        messages.error(request, f"Archivo rechazado: {e}.")
        return redirect("comparacion")
    resumen = I.resumen_publico(analisis)
    resumen["filas"] = resumen["filas"][:500]
    vista = {"formato": T.FORMATO_ARCHIVO.get(resumen["formato"], resumen["formato"]),
             "recuento": T.lista_recuento(resumen["recuento"]),
             "filas": [dict(f, resultado_texto=T.RESULTADO_IMPORTACION.get(f["resultado"], f["resultado"]))
                       for f in resumen["filas"]]}
    request.session[SESION_IMPORTACION] = {
        "sha256": hashlib.sha256(contenido).hexdigest(), "nombre": I._nombre_seguro(archivo.name),
        "contenido": contenido.decode("utf-8"), "participante": participante, "resumen": resumen}
    return render(request, "dashboard/comparacion/importar_previa.html", {
        "resumen": resumen, "vista": vista, "sha256": hashlib.sha256(contenido).hexdigest(),
        "nombre": I._nombre_seguro(archivo.name), "participante": participante})


@solo_superusuario
@require_POST
def comparacion_importar_confirmar(request):
    pend = request.session.get(SESION_IMPORTACION)
    if not pend or request.POST.get("sha256") != pend.get("sha256"):
        messages.error(request, "No hay una vista previa vigente para ese archivo: vuelve a cargarlo.")
        return redirect("comparacion")
    if request.POST.get("accion") == "cancelar":
        request.session.pop(SESION_IMPORTACION, None)
        messages.info(request, "Importación cancelada: no se escribió nada.")
        return redirect("comparacion")
    contenido = pend["contenido"].encode("utf-8")          # mismos bytes que la vista previa (BOM incluido)
    if hashlib.sha256(contenido).hexdigest() != pend["sha256"]:
        request.session.pop(SESION_IMPORTACION, None)
        messages.error(request, "La vista previa guardada no coincide con el archivo: vuelve a cargarlo.")
        return redirect("comparacion")
    try:
        lote = I.confirmar(contenido, nombre=pend["nombre"], usuario=request.user,
                           participante=pend.get("participante", ""),
                           registrar_casos_nuevos=request.POST.get("registrar_casos_nuevos") == "1",
                           importar_ambiguas=request.POST.get("importar_ambiguas") == "1")
    except I.ArchivoInvalido as e:
        messages.error(request, f"Archivo rechazado: {e}.")
        return redirect("comparacion")
    finally:
        request.session.pop(SESION_IMPORTACION, None)
    rc = T.lista_recuento(lote.resumen.get("recuento", {}))
    messages.success(request, "Importación registrada: " + ", ".join(f"{t}: {n}" for t, n in rc)
                     + ". Lo que ya existía no se modificó.")
    return redirect("comparacion")


@solo_superusuario
@require_POST
def comparacion_procedencia(request, clave):
    caso = get_object_or_404(CasoComparacion, clave=clave)
    valor = request.POST.get("procedencia")
    if valor not in N.PROCEDENCIAS:
        messages.error(request, "Procedencia no admitida.")
    else:
        CasoComparacion.objects.filter(pk=caso.pk).update(
            procedencia=valor, procedencia_asignada_por=request.user, procedencia_asignada_en=timezone.now())
        messages.success(request, f"Procedencia del caso {caso.codigo} asignada.")
    return redirect(request.POST.get("volver") if (request.POST.get("volver") or "").startswith("/comparacion/")
                    else "comparacion")
