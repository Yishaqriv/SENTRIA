"""
Figuras para el documento (Matplotlib, backend Agg; sin TeX, sin pyplot global, sin red ni CDN).

- Formatos por lista cerrada: PNG (300 ppp; la previsualización usa 110 ppp), SVG y PDF vectoriales.
- Fondo blanco, etiquetas legibles en papel. El texto que viene de los datos (proveedor, modelo, código de caso)
  se limita y se escapa: sin mathtext (`$`) y sin saltos; el SVG dibuja el texto como trazos.
- Una figura por GRUPO (mismo caso, protocolo y equivalencia). Cada figura lleva título, unidades, leyenda cuando
  hay más de una serie de color, caso y protocolo, n medido / n ausente, origen de los datos y notas.
- Sin ceros inventados: una serie sin mediciones aparece como «sin medición», no como barra 0. Con una sola
  medición no se dibuja dispersión. No hay ranking ni «ganador».
- Un semáforo limita a un renderizado a la vez (no compite con el indexador ni con el trabajador); las figuras
  se cierran siempre.
"""
from __future__ import annotations

import io
import statistics
import re
import threading

FORMATOS = {"png": "image/png", "svg": "image/svg+xml", "pdf": "application/pdf"}
TIPOS = ("latencia", "tokens", "estados")
DPI_DOCUMENTO = 300
DPI_VISTA = 110
_SEMAFORO = threading.BoundedSemaphore(1)
VERSION_RENDERIZADOR = "comparacion_graficas_v1"

# Paleta de referencia (validada como par adyacente): azul y naranja para series; colores de estado SIEMPRE con
# etiqueta de texto; tinta neutra para texto, ejes y medianas.
AZUL, NARANJA = "#2a78d6", "#eb6834"
TINTA, TINTA_2, REJILLA = "#0b0b0b", "#52514e", "#e4e3df"
ESTADO_COLOR = {"completada": "#0ca30c", "rechazada": "#ec835a", "respondida_sin_resultado": "#fab219",
                "fallo_llamada": "#d03b3b", "sin_llamada": "#9a9993"}


class Ocupado(RuntimeError):
    pass


class DependenciaAusente(RuntimeError):
    pass


def disponible() -> bool:
    try:
        import matplotlib  # noqa: F401
        return True
    except ImportError:
        return False


def version_matplotlib():
    try:
        import matplotlib
        return matplotlib.__version__
    except ImportError:
        return None


def texto_seguro(t, maximo=60) -> str:
    t = re.sub(r"[\x00-\x1f\x7f]", " ", str(t))
    t = t if len(t) <= maximo else t[: maximo - 1] + "…"
    return t.replace("\\", "/").replace("$", r"\$")


def _figura(ancho=7.0, alto=4.2):
    try:
        import matplotlib
        matplotlib.use("Agg", force=True)
        from matplotlib.backends.backend_agg import FigureCanvasAgg
        from matplotlib.figure import Figure
    except ImportError:
        raise DependenciaAusente("matplotlib no está instalado en este entorno") from None
    fig = Figure(figsize=(ancho, alto), facecolor="white")
    FigureCanvasAgg(fig)
    return fig


def _ejes(ax, unidad):
    ax.set_facecolor("white")
    for lado in ("top", "right"):
        ax.spines[lado].set_visible(False)
    for lado in ("left", "bottom"):
        ax.spines[lado].set_color(TINTA_2)
        ax.spines[lado].set_linewidth(0.8)
    ax.tick_params(colors=TINTA_2, labelsize=8)
    ax.yaxis.grid(True, color=REJILLA, linewidth=0.6)
    ax.set_axisbelow(True)
    ax.set_ylabel(unidad, color=TINTA, fontsize=9)


def _pie(fig, datos, extra=""):
    caso = datos["caso"]
    origen = ", ".join(datos["origenes"])
    from .textos import EQUIVALENCIA
    efectivo = datos["detalle"]["esquema_efectivo"]
    notas = (f"Caso {texto_seguro(caso.codigo, 40)} ({texto_seguro(caso.get_procedencia_display(), 40)}) · "
             f"{EQUIVALENCIA.get(datos['equivalencia'], datos['equivalencia']).lower()}"
             f"{' · formato de salida no declarado' if efectivo == 'no_declarado' else ''} · "
             f"{datos['n']} ejecucion{'es' if datos['n'] != 1 else ''} · origen: {texto_seguro(origen, 120).lower()} · "
             f"identificadores y huellas: ficha técnica (JSON)")
    avisos = []
    if datos["equivalencia"] != "equivalente":
        avisos.append("Condiciones no verificadas como iguales: no es una comparación controlada")
    if datos["un_solo_proveedor"]:
        avisos.append("Muestra inicial de un solo proveedor: no es una comparación ni un ranking")
    if datos["series_omitidas"]:
        avisos.append(f"{datos['series_omitidas']} serie(s) adicionales no mostradas")
    if extra:
        avisos.append(extra)
    import textwrap
    lineas = textwrap.wrap(notas, 135) + (textwrap.wrap(" · ".join(avisos), 135) if avisos else [])
    fig.text(0.01, 0.01, "\n".join(lineas), fontsize=6.5, color=TINTA_2, ha="left", va="bottom")


def etiqueta_serie(serie: str) -> str:
    """«proveedor · modelo» en dos líneas cortas (sin rotar ni recortar por la izquierda)."""
    import textwrap
    prov, _, modelo = serie.partition(" · ")
    lineas = [texto_seguro(prov, 30)] + textwrap.wrap(texto_seguro(modelo, 48), 24)[:2]
    return "\n".join(lineas)


def _etiquetas_series(ax, nombres):
    ax.set_xticks(range(len(nombres)))
    ax.set_xticklabels([etiqueta_serie(n) for n in nombres], fontsize=7.5 if len(nombres) <= 4 else 6.5,
                       color=TINTA)


def _puntos(ax, x, resumen, color, etiqueta=None, desplaz=0.0):
    vals = resumen["valores"]
    if vals:
        n = len(vals)
        xs = [x + desplaz + (0.06 * (i - (n - 1) / 2) / max(1, n - 1) * 2 if n > 1 else 0) for i in range(n)]
        ax.scatter(xs, vals, s=22, color=color, edgecolor="white", linewidth=0.8, zorder=3, label=etiqueta)
        med = resumen["mediana"]
        ax.hlines(med, x + desplaz - 0.16, x + desplaz + 0.16, color=TINTA, linewidth=1.6, zorder=4)
    elif etiqueta:
        ax.scatter([], [], s=22, color=color, label=etiqueta)


def _anotar_n(ax, x, resumen, y0):
    n = resumen["n_medido"]
    txt = "No disponible" if n == 0 else ("1 medición\n(sin dispersión)" if n == 1 else f"{n} mediciones")
    if resumen["n_ausente"]:
        txt += f"\n{resumen['n_ausente']} sin dato"
    ax.annotate(txt, (x, y0), xytext=(0, 4), textcoords="offset points", ha="center", va="bottom",
                fontsize=6.5, color=TINTA_2)


def _latencia(datos):
    fig = _figura()
    ax = fig.add_axes([0.10, 0.27, 0.86, 0.57])
    _ejes(ax, "Latencia del proveedor (s)")
    nombres = [d["serie"] for d in datos["latencia"]]
    for i, d in enumerate(datos["latencia"]):
        _puntos(ax, i, d, AZUL)
    ymax = max([v for d in datos["latencia"] for v in d["valores"]] or [1.0])
    ax.set_ylim(0, ymax * 1.30)
    for i, d in enumerate(datos["latencia"]):
        _anotar_n(ax, i, d, ymax * 1.05)
    ax.set_xlim(-0.6, len(nombres) - 0.4)
    _etiquetas_series(ax, nombres)
    fig.suptitle("Tiempo de respuesta del proveedor (mismo caso, mismas condiciones)",
                 fontsize=10, color=TINTA, x=0.01, ha="left")
    fig.text(0.01, 0.935, "Cada punto es una medición; la línea negra es la mediana.\nLatencia: segundos desde que "
             "SENTRIA envía el caso hasta que el proveedor responde.", fontsize=7, color=TINTA_2, va="top")
    _pie(fig, datos)
    return fig


def _tokens(datos):
    fig = _figura(7.0, 6.4)
    ax1 = fig.add_axes([0.10, 0.56, 0.86, 0.31])
    ax2 = fig.add_axes([0.10, 0.17, 0.86, 0.25])
    _ejes(ax1, "Tokens (entrada y salida)")
    _ejes(ax2, "Tokens totales")
    nombres = [d["serie"] for d in datos["tokens"]]
    for i, d in enumerate(datos["tokens"]):
        _puntos(ax1, i, d["entrada"], AZUL, "Entrada" if i == 0 else None, -0.18)
        _puntos(ax1, i, d["salida"], NARANJA, "Salida" if i == 0 else None, 0.18)
        _puntos(ax2, i, d["total"], TINTA_2)
    for ax, claves in ((ax1, ("entrada", "salida")), (ax2, ("total",))):
        vals = [v for d in datos["tokens"] for k in claves for v in d[k]["valores"]]
        top = max(vals or [1])
        ax.set_ylim(0, top * 1.45)
        for i, d in enumerate(datos["tokens"]):
            r = {"n_medido": min(d[k]["n_medido"] for k in claves), "n_ausente": max(d[k]["n_ausente"] for k in claves)}
            _anotar_n(ax, i, r, top * 1.08)
        ax.set_xlim(-0.6, len(nombres) - 0.4)
        _etiquetas_series(ax, nombres)
    ax1.tick_params(labelbottom=False)
    ax1.legend(loc="lower left", bbox_to_anchor=(0, 1.0), ncol=2, fontsize=7.5, frameon=False)
    fig.suptitle("Tokens informados por el proveedor (mismo caso, mismas condiciones)", fontsize=10, color=TINTA,
                 x=0.01, y=0.985, ha="left", va="top")
    fig.text(0.10, 0.935, "Entrada: texto enviado · salida: texto generado. Cada punto es una medición; la línea "
             "negra es la mediana.", fontsize=7, color=TINTA_2)
    fig.text(0.10, 0.445, "Total: el que informa el proveedor; no es una suma de los otros valores",
             fontsize=7, color=TINTA_2)
    _pie(fig, datos, "Los tokens de razonamiento no se suman (ver el detalle) · cada proveedor cuenta los tokens "
                     "a su manera")
    return fig


def _estados(datos):
    from .estadisticas import ESTADOS_UI
    n = len(datos["estados"])
    sup, alto_barras, inf = 1.25, 0.45 * n + 0.3, 1.25            # pulgadas: título+leyenda, barras, eje+notas
    alto = sup + alto_barras + inf
    fig = _figura(7.0, alto)
    ax = fig.add_axes([0.34, inf / alto, 0.62, alto_barras / alto])
    ax.set_facecolor("white")
    for lado in ("top", "right"):
        ax.spines[lado].set_visible(False)
    ax.tick_params(colors=TINTA_2, labelsize=8)
    nombres = [d["serie"] for d in datos["estados"]]
    usados = [k for k in ESTADOS_UI if any(d[k] for d in datos["estados"])]
    for i, d in enumerate(datos["estados"]):
        izq = 0
        for k in usados:
            v = d[k]
            if v:
                ax.barh(i, v, left=izq, height=0.6, color=ESTADO_COLOR[k], edgecolor="white", linewidth=2)
                ax.text(izq + v / 2, i, str(v), ha="center", va="center", fontsize=8, color=TINTA)
                izq += v
    ax.set_ylim(n - 0.5, -0.5)
    ax.set_yticks(range(n))
    ax.set_yticklabels([etiqueta_serie(x) for x in nombres], fontsize=7.5, color=TINTA)
    ax.set_xlabel("Número de ejecuciones", fontsize=9, color=TINTA)
    ax.xaxis.get_major_locator().set_params(integer=True)
    from matplotlib.patches import Patch
    fig.legend(handles=[Patch(facecolor=ESTADO_COLOR[k], label=ESTADOS_UI[k]) for k in usados],
               loc="upper left", bbox_to_anchor=(0.01, 1 - 0.55 / alto), ncol=2, fontsize=7, frameon=False)
    fig.suptitle("Resultado de cada ejecución (mismo caso, mismas condiciones)", fontsize=10, color=TINTA, x=0.01,
                 y=1 - 0.12 / alto, ha="left", va="top")
    _pie(fig, datos, "Que el proveedor responda no significa que SENTRIA acepte la respuesta · no mide aciertos "
                     "ni falsos positivos")
    return fig


TIPOS_RESUMEN = ("tiempo", "tokens")


def _pie_resumen(fig, r, comps):
    import textwrap
    cj = r["conjunto"]
    texto = (f"Conjunto {texto_seguro(cj.codigo, 40)} v{cj.version}: {r['n_casos']} casos (piloto comparativo, no "
             f"representativo) · repeticiones: {r['repeticiones']} · solo condiciones verificadas · cada caso pesa "
             f"igual (media de sus repeticiones) · identificadores, cobertura y huellas: ficha técnica (JSON)")
    avisos = []
    if r["pendiente_otro_proveedor"]:
        avisos.append("Pendiente de resultados de otro proveedor: describe los datos disponibles, no compara")
    if r["series_no_comparables"]:
        avisos.append(f"{r['series_no_comparables']} serie(s) sin condiciones verificadas no se muestran")
    lineas = textwrap.wrap(texto, 135) + (textwrap.wrap(" · ".join(avisos), 135) if avisos else [])
    fig.text(0.01, 0.01, "\n".join(lineas), fontsize=6.5, color=TINTA_2, ha="left", va="bottom")


def _resumen_tiempo(r):
    comps = [s for s in r["series"] if s["equivalencia"] == "equivalente"][:MAX_SERIES_RESUMEN]
    fig = _figura()
    ax = fig.add_axes([0.10, 0.27, 0.86, 0.57])
    _ejes(ax, "Tiempo medio por caso (s)")
    ymax = 1.0
    for i, s in enumerate(comps):
        vals = list(s["por_caso_latencia"].values())
        _puntos(ax, i, {"valores": vals, "mediana": s["tiempo"]["mediana_por_caso"]}, AZUL)
        if s["tiempo"]["media_por_caso"] is not None:
            ax.scatter([i + 0.22], [s["tiempo"]["media_por_caso"]], marker="D", s=26, color=NARANJA, zorder=5)
        ymax = max([ymax] + vals)
    ax.set_ylim(0, ymax * 1.30)
    for i, s in enumerate(comps):
        t = s["tiempo"]
        txt = (f"{t['n_casos_medidos']} de {r['n_casos']} casos con dato" if t["n_casos_medidos"] else "No disponible")
        if t["n_faltantes"]:
            txt += "\n" + (f"{t['n_faltantes']} ejecución sin dato" if t["n_faltantes"] == 1 else
                           f"{t['n_faltantes']} ejecuciones sin dato")
        ax.annotate(txt, (i, ymax * 1.05), xytext=(0, 4), textcoords="offset points", ha="center", va="bottom",
                    fontsize=6.5, color=TINTA_2)
    ax.set_xlim(-0.6, max(1, len(comps)) - 0.4)
    _etiquetas_series(ax, [f"{s['proveedor']} · {s['modelo']}" for s in comps])
    fig.suptitle("Tiempo de respuesta por caso del conjunto", fontsize=10, color=TINTA, x=0.01, ha="left")
    fig.text(0.01, 0.935, "Cada punto es un caso (media de sus repeticiones); línea negra: mediana entre casos; "
             "rombo: media entre casos.\nLatencia: segundos desde que se envía el caso hasta que el proveedor "
             "responde.", fontsize=7, color=TINTA_2, va="top")
    _pie_resumen(fig, r, comps)
    return fig


def _resumen_tokens(r):
    comps = [s for s in r["series"] if s["equivalencia"] == "equivalente"][:MAX_SERIES_RESUMEN]
    fig = _figura(7.0, 6.4)
    ax1 = fig.add_axes([0.10, 0.56, 0.86, 0.31])
    ax2 = fig.add_axes([0.10, 0.17, 0.86, 0.25])
    _ejes(ax1, "Tokens por caso (entrada y salida)")
    _ejes(ax2, "Tokens totales por caso")
    nombres = [f"{s['proveedor']} · {s['modelo']}" for s in comps]
    for i, s in enumerate(comps):
        for ax, campo, color, etq, d in ((ax1, "tokens_entrada", AZUL, "Entrada", -0.18),
                                        (ax1, "tokens_salida", NARANJA, "Salida", 0.18),
                                        (ax2, "tokens_total", TINTA_2, None, 0.0)):
            vals = list(s["por_caso_tokens"][campo].values())
            _puntos(ax, i, {"valores": vals, "mediana": statistics.median(vals) if vals else None}, color,
                    etq if i == 0 else None, d)
    for ax, campos in ((ax1, ("tokens_entrada", "tokens_salida")), (ax2, ("tokens_total",))):
        vals = [v for s in comps for c in campos for v in s["por_caso_tokens"][c].values()]
        top = max(vals or [1])
        ax.set_ylim(0, top * 1.45)
        for i, s in enumerate(comps):
            n = min(len(s["por_caso_tokens"][c]) for c in campos)
            falt = max(s["tokens"][c]["n_faltantes"] for c in campos)
            txt = (f"{n} de {r['n_casos']} casos con dato" if n else "No disponible")
            if falt:
                txt += "\n" + (f"{falt} ejecución sin dato" if falt == 1 else f"{falt} ejecuciones sin dato")
            ax.annotate(txt, (i, top * 1.08), xytext=(0, 4), textcoords="offset points", ha="center",
                        va="bottom", fontsize=6.5, color=TINTA_2)
        ax.set_xlim(-0.6, max(1, len(comps)) - 0.4)
        _etiquetas_series(ax, nombres)
    ax1.tick_params(labelbottom=False)
    if comps:
        ax1.legend(loc="lower left", bbox_to_anchor=(0, 1.0), ncol=2, fontsize=7.5, frameon=False)
    fig.suptitle("Tokens informados por caso del conjunto", fontsize=10, color=TINTA, x=0.01, y=0.985, ha="left",
                 va="top")
    fig.text(0.10, 0.955, "Cada punto es un caso (media de sus repeticiones medidas); línea negra: mediana entre casos."
             "\nCada proveedor cuenta los tokens a su manera.", fontsize=7, color=TINTA_2, va="top")
    fig.text(0.10, 0.445, "Total: el que informa el proveedor; no es una suma de los otros valores",
             fontsize=7, color=TINTA_2)
    _pie_resumen(fig, r, comps)
    return fig


MAX_SERIES_RESUMEN = 8


def renderizar_resumen(tipo: str, formato: str, r: dict, *, vista=False) -> bytes:
    if tipo not in TIPOS_RESUMEN or formato not in FORMATOS:
        raise ValueError("tipo o formato no admitido")
    return _renderizar_con(lambda: {"tiempo": _resumen_tiempo, "tokens": _resumen_tokens}[tipo](r), formato, vista)


def renderizar(tipo: str, formato: str, datos: dict, *, vista=False) -> bytes:
    if tipo not in TIPOS or formato not in FORMATOS:
        raise ValueError("tipo o formato no admitido")
    return _renderizar_con(lambda: {"latencia": _latencia, "tokens": _tokens, "estados": _estados}[tipo](datos),
                           formato, vista)


def _renderizar_con(construir, formato, vista):
    if not _SEMAFORO.acquire(timeout=15):
        raise Ocupado("hay otra figura renderizándose")
    fig = None
    try:
        fig = construir()
        buf = io.BytesIO()
        meta = {"png": {"Software": None}, "svg": {"Date": None, "Creator": None},
                "pdf": {"CreationDate": None, "Creator": None, "Producer": None}}[formato]
        kw = {"format": formato, "facecolor": "white", "metadata": meta}
        if formato == "png":
            kw["dpi"] = DPI_VISTA if vista else DPI_DOCUMENTO
        if formato == "svg":
            import matplotlib
            with matplotlib.rc_context({"svg.hashsalt": "sentria-comparacion", "svg.fonttype": "path"}):
                fig.savefig(buf, **kw)
        else:
            fig.savefig(buf, **kw)
        return buf.getvalue()
    finally:
        if fig is not None:
            fig.clear()
        _SEMAFORO.release()
