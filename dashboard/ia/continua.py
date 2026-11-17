"""
Ingesta continua ACOTADA de un único agente (trabajador periódico).

Reutiliza la política (`politica`), la normalización (`sentria_backend`), el resolver de activos, el camino de
persistencia (`ingesta.ingestar_alerta`), la medición `medicion_v2` y el envoltorio con tope y guarda de
anonimización de `ingestar_alertas` (`_ProveedorContado`). No cambia el contrato de la IA.

Reglas:
- Solo alertas NUEVAS para SENTRIA: un `opensearch_id` presente en MySQL (en cualquier estado) o ya intentado por
  este trabajador nunca se vuelve a enviar. No hay reintentos automáticos ni proveedor de respaldo.
- Más antiguas primero: `@timestamp` asc, desempate `id` (identificador de alerta de Wazuh, keyword) y `_index`,
  paginado con `search_after` (comprobado contra el indexador real).
- Web: solo `mode=live` confirmado (procedencia `en_vivo`). `historical_replay` y procedencia desconocida no se
  automatizan. Los avisos del agente (202/203) no se excluyen: se clasifican aparte (`agente_wazuh`).
- Límites conjuntos y persistentes de INVOCACIONES al proveedor (no son un presupuesto de dinero ni de tokens):
  por ejecución, en cualquier ventana móvil de 60 min y por día calendario de America/Bogota. Instantes en UTC.
  Cada intento consume en su INSTANTE EFECTIVO: el de invocación registrada si existe; si no (reservado, incierto
  sin marca), el de reserva, como respaldo conservador. La hora móvil y el día de Bogotá se calculan desde ese
  instante; el cupo se revalida justo antes de invocar, sin cobrar dos veces la propia reserva.
- Cada intento se RESERVA de forma duradera antes de llamar y se marca `invocado` justo antes de la llamada
  (`antes_de_llamar`). Tras una caída, lo reservado o invocado sin cierre queda `incierto`: cuenta en el cupo, se
  señala para revisión y nunca se reintenta. No se promete una única entrega HTTP.
- Exclusión común por alerta con el dashboard y la ingesta manual (`exclusion`): si otra vía analiza el mismo
  documento, el intento queda `sin_llamada` (`analisis_en_curso_otra_via`) sin consumir cupo.
- Lecturas: una respuesta con `timed_out`, shards fallidos o incompletos, total inconsistente o claves `sort`
  ausentes/no progresivas se rechaza ANTES de seleccionar o llamar (`LecturaIncompletaError`), sin avanzar marcas.
- Cobertura: límite inicial EXPLÍCITO (`desde`, lo fija el lanzador privado) y marca de agua persistente
  `completa_hasta_utc` (todo lo anterior está leído y clasificado). La reconciliación de 48 h y la pendiente más
  antigua solo pueden ADELANTAR el inicio de lectura; tras una parada larga se reanuda desde la marca de agua.
  Límite residual: documentos con `@timestamp` anterior a la marca de agua menos el solape que se indexen tarde, y
  documentos ya eliminados por la retención del indexador, no se recuperan.
- Corte hasta el siguiente día de presupuesto tras 3 análisis fallidos consecutivos con invocación, o un 429
  REAL (`RespuestaProveedor.codigo_http`). Un error de lectura del indexador no gasta cupo y no cuenta como fallo.
- Estado privado (0600, directorio 0700), escrituras atómicas (tmp + fsync + replace) y un único trabajador por
  `flock` (se libera al morir el proceso).
"""
from __future__ import annotations

import datetime as dt
import errno
import fcntl
import json
import os
import tempfile
import uuid
from contextlib import contextmanager
from zoneinfo import ZoneInfo

ZONA_DIA = ZoneInfo("America/Bogota")
ESTADO_VERSION = 2
VERSIONES_RECONOCIDAS = (1, 2)
LIMITES = {"por_ejecucion": 2, "por_hora_movil": 6, "por_dia": 30}
INTERVALO_MIN = 15
PAGINA = 200
MAX_PAGINAS = 5
SOLAPE = dt.timedelta(minutes=30)          # margen para llegadas tardías al reanudar desde la marca
VENTANA_RECONCILIACION = dt.timedelta(hours=48)
ESTADOS_SIN_CUPO = {"sin_llamada"}         # el resto (reservado, invocado, completado, fallido, incierto) consume cupo
ORDEN = [{"@timestamp": "asc"}, {"id": {"order": "asc", "missing": "_last"}}, {"_index": "asc"}]
CAMPOS_EXTRA = ["id", "agent.name", "data.sentria_source", "data.sentria_web.mode"]


class EstadoError(RuntimeError):
    """Estado privado ausente, inseguro o inconsistente."""


class OcupadoError(RuntimeError):
    """Otra ejecución del trabajador tiene el bloqueo."""


class InicioError(RuntimeError):
    """Falta el límite inicial explícito o no coincide con el persistido."""


class LecturaIncompletaError(RuntimeError):
    """Respuesta parcial o no verificable del indexador. `tipo` es una etiqueta sin datos privados."""

    def __init__(self, tipo):
        super().__init__(tipo)
        self.tipo = tipo


# --------------------------------------------------------------------------- tiempo y cupos
def _utc(x):
    return x.astimezone(dt.timezone.utc) if x.tzinfo else x.replace(tzinfo=dt.timezone.utc)


def _iso(x):
    return _utc(x).isoformat(timespec="milliseconds") if x else None


def _desde_iso(s):
    return _utc(dt.datetime.fromisoformat(str(s).replace("Z", "+00:00"))) if s else None


def dia_bogota(instante):
    return _utc(instante).astimezone(ZONA_DIA).date().isoformat()


def inicio_dia_siguiente_utc(instante):
    """Medianoche de America/Bogota del día siguiente al de `instante`, en UTC (inicio del siguiente presupuesto)."""
    local = _utc(instante).astimezone(ZONA_DIA)
    siguiente = dt.datetime.combine(local.date() + dt.timedelta(days=1), dt.time(0, 0), tzinfo=ZONA_DIA)
    return siguiente.astimezone(dt.timezone.utc)


def instante_consumo(intento):
    """Instante en que un intento consume cupo: la invocación registrada; si no consta (reservado, o incierto tras
    una caída antes de marcarla), la reserva como respaldo conservador."""
    return _desde_iso(intento.get("invocado_utc") or intento["reservado_utc"])


def cupo(intentos, ahora, usados_en_ejecucion=0, limites=LIMITES):
    """-> dict con usados/restantes por ejecución, ventana móvil de 60 min y día de Bogotá, y el mínimo conjunto.
    Hora y día se calculan desde el instante efectivo de cada intento (`instante_consumo`), nunca desde la
    etiqueta de día guardada en la reserva. Un instante posterior a `ahora` (reloj atrasado) cuenta en la hora."""
    ahora = _utc(ahora)
    instantes = [instante_consumo(i) for i in intentos if i.get("estado") not in ESTADOS_SIN_CUPO]
    hoy = dia_bogota(ahora)
    hora = sum(1 for t in instantes if t > ahora - dt.timedelta(minutes=60))
    dia = sum(1 for t in instantes if dia_bogota(t) == hoy)
    r = {"ejecucion": {"usados": usados_en_ejecucion, "limite": limites["por_ejecucion"]},
         "hora_movil": {"usados": hora, "limite": limites["por_hora_movil"]},
         "dia_bogota": {"usados": dia, "limite": limites["por_dia"], "dia": dia_bogota(ahora)}}
    for v in r.values():
        v["restantes"] = max(0, v["limite"] - v["usados"])
    r["disponibles"] = min(v["restantes"] for v in (r["ejecucion"], r["hora_movil"], r["dia_bogota"]))
    return r


# --------------------------------------------------------------------------- estado privado
def _cobertura_vacia():
    return {"inicio_utc": None, "completa_hasta_utc": None, "actualizada_utc": None}


def _estado_inicial(agente, ahora):
    return {"version": ESTADO_VERSION, "agente": agente, "creado_utc": _iso(ahora), "intentos": [],
            "fallos_consecutivos": 0, "pausa": None, "marca": None, "ultima_ejecucion": None,
            "ultimo_completado": None, "errores": [], "cobertura": _cobertura_vacia()}


def _migrar(e):
    """Versión 1 -> 2 en memoria (se persiste en la siguiente ejecución confirmada). Conserva TODOS los intentos
    (siguen fuera de la selección y siguen contando en el cupo con la regla vigente), la pausa, los fallos y la marca
    de pendientes. La v1 no tenía límite inicial ni marca de agua: quedan vacíos y el lanzador debe aportar `desde`."""
    if e.get("version") == 1:
        e = dict(e)
        e["version"], e["migrado_de_version"] = 2, 1
        e.setdefault("cobertura", _cobertura_vacia())
    return e


def _comprobar_privado(ruta, es_dir=False):
    st = os.lstat(ruta)
    import stat as _st
    tipo_ok = _st.S_ISDIR(st.st_mode) if es_dir else _st.S_ISREG(st.st_mode)
    if _st.S_ISLNK(st.st_mode) or not tipo_ok or st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise EstadoError(f"{os.path.basename(ruta)} debe ser {'un directorio' if es_dir else 'un archivo'} "
                          f"del dueño, sin enlaces y sin permisos para grupo u otros")


class Almacen:
    """Estado JSON privado del trabajador en `directorio` (0700) con escritura atómica."""

    def __init__(self, directorio, agente):
        self.dir = os.path.abspath(directorio)
        self.ruta = os.path.join(self.dir, "estado.json")
        self.ruta_bloqueo = os.path.join(self.dir, "trabajador.lock")
        self.agente = agente

    def preparar(self):
        if not os.path.exists(self.dir):
            os.makedirs(self.dir, mode=0o700)
        _comprobar_privado(self.dir, es_dir=True)

    def leer(self, ahora):
        if not os.path.exists(self.ruta):
            return _estado_inicial(self.agente, ahora)
        _comprobar_privado(self.ruta)
        with open(self.ruta, encoding="utf-8") as f:
            e = json.load(f)
        if e.get("version") not in VERSIONES_RECONOCIDAS or e.get("agente") != self.agente \
                or not isinstance(e.get("intentos"), list):
            raise EstadoError("el estado no corresponde a una versión reconocida o a este agente")
        return _migrar(e)

    def guardar(self, estado):
        fd, tmp = tempfile.mkstemp(prefix=".estado.", dir=self.dir)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(estado, f, ensure_ascii=False, sort_keys=True)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.ruta)
            dfd = os.open(self.dir, os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise

    @contextmanager
    def bloqueo(self):
        fd = os.open(self.ruta_bloqueo, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as e:
                if e.errno in (errno.EAGAIN, errno.EACCES):
                    raise OcupadoError("otra ejecución del trabajador está en curso") from None
                raise
            yield
        finally:
            os.close(fd)        # cierra y libera el flock (también lo libera el SO si el proceso muere)


# --------------------------------------------------------------------------- selección
def consulta(agente, nombre_agente, nivel_minimo, desde, hasta, search_after=None, pagina=PAGINA, campos=()):
    q = {"size": pagina, "track_total_hits": True, "sort": ORDEN, "_source": list(campos) + CAMPOS_EXTRA,
         "query": {"bool": {"filter": [
             {"term": {"agent.id": agente}}, {"term": {"agent.name": nombre_agente}},
             {"range": {"rule.level": {"gte": int(nivel_minimo)}}},
             {"range": {"@timestamp": {"gte": _iso(desde), "lte": _iso(hasta)}}}]}}}
    if search_after is not None:
        q["search_after"] = search_after
    return q


def validar_respuesta(r):
    """-> (hits, total, relacion). Rechaza (LecturaIncompletaError) toda respuesta que no permita afirmar que la
    página está completa: `timed_out` distinto de False, `_shards` ausente, con fallos o con shards sin responder,
    o `hits` mal formado. `relacion` es 'eq' (total exacto) o 'gte' (cota inferior)."""
    if not isinstance(r, dict):
        raise LecturaIncompletaError("respuesta_no_valida")
    if r.get("timed_out") is not False:
        raise LecturaIncompletaError("timed_out" if r.get("timed_out") else "timed_out_ausente")
    sh = r.get("_shards")
    if not isinstance(sh, dict):
        raise LecturaIncompletaError("shards_ausente")
    total_sh, ok_sh, skip_sh, fallo_sh = (sh.get(k) for k in ("total", "successful", "skipped", "failed"))
    if not all(isinstance(x, int) and not isinstance(x, bool) for x in (total_sh, ok_sh, fallo_sh)):
        raise LecturaIncompletaError("shards_ausente")
    if fallo_sh != 0:
        raise LecturaIncompletaError("shards_fallidos")
    if ok_sh + (skip_sh if isinstance(skip_sh, int) else 0) < total_sh:
        raise LecturaIncompletaError("shards_incompletos")
    h = r.get("hits")
    if not isinstance(h, dict) or not isinstance(h.get("hits"), list):
        raise LecturaIncompletaError("hits_no_validos")
    t = h.get("total")
    if not isinstance(t, dict) or not isinstance(t.get("value"), int) or t.get("relation") not in ("eq", "gte"):
        raise LecturaIncompletaError("total_no_valido")
    return h["hits"], t["value"], t["relation"]


def _clave_sort(s):
    """Orden comparable de un `sort` [epoch_ms, id|None (missing _last), _index]."""
    return (s[0], (1, "") if s[1] is None else (0, str(s[1])), str(s[2]))


def validar_cursor(nuevo, previo):
    """El cursor de continuación debe existir, tener una clave por criterio de ORDEN y avanzar estrictamente."""
    if not isinstance(nuevo, list) or len(nuevo) != len(ORDEN) or not isinstance(nuevo[0], (int, float)) \
            or isinstance(nuevo[0], bool) or not isinstance(nuevo[2], str):
        raise LecturaIncompletaError("sort_ausente")
    if previo is not None and _clave_sort(nuevo) <= _clave_sort(previo):
        raise LecturaIncompletaError("sort_no_progresa")


def categoria_evento(alert, fuente):
    grupos = [g.strip() for g in str(alert.get("groups") or "").split(",") if g.strip()]
    if (fuente.get("data") or {}).get("sentria_source") == "web_access":
        return "web"
    if str(alert.get("decoder_name") or "") == "windows_eventchannel" or any(g.startswith("windows") for g in grupos):
        return "windows"
    if "agent_flooding" in grupos or str(alert.get("rule_id")) in ("202", "203", "204"):
        return "agente_wazuh"
    if any(g.startswith("syscheck") for g in grupos):
        return "fim"
    return "otro"


def procedencia_web(fuente, alert):
    """-> (automatizable: bool, motivo). Solo `mode=live` confirmado y normalizado es automatizable."""
    modo = ((fuente.get("data") or {}).get("sentria_web") or {}).get("mode")
    if modo == "historical_replay":
        return False, "replay_historico"
    web = alert.get("web")
    if not isinstance(web, dict) or web.get("procedencia") != "en_vivo":
        return False, "procedencia_web_no_confirmada"
    return True, None


def metadatos_seguros(alert, categoria, ts):
    return {"opensearch_id": alert.get("opensearch_id"), "timestamp_utc": ts, "regla": str(alert.get("rule_id") or ""),
            "nivel": alert.get("level"), "categoria": categoria}


# --------------------------------------------------------------------------- trabajador
class Trabajador:
    """
    Dependencias inyectables (pruebas): `buscar(query)->dict` (respuesta JSON del indexador), `normalizar(hit)`,
    `existentes(ids)->set`, `activo()->ActivoLogico|None`, `proveedor()->ProveedorIA`, `ingestar(raw, **kw)`,
    `reloj()->datetime UTC`.
    """

    def __init__(self, almacen, *, agente, nombre_agente, identificador_activo, buscar, normalizar, existentes,
                 activo, proveedor, ingestar, politica, reloj, excluidos=(), limites=LIMITES, pagina=PAGINA,
                 max_paginas=MAX_PAGINAS, campos=(), log=lambda s: None, desde=None):
        self.a, self.agente, self.nombre_agente, self.id_activo = almacen, agente, nombre_agente, identificador_activo
        self.buscar, self.normalizar, self.existentes, self.activo = buscar, normalizar, existentes, activo
        self.proveedor, self.ingestar, self.politica, self.reloj = proveedor, ingestar, politica, reloj
        self.excluidos, self.limites, self.pagina, self.max_paginas = set(excluidos), limites, pagina, max_paginas
        self.campos, self.log = tuple(campos), log
        self.desde = _utc(desde) if desde is not None else None

    # ---- lectura y clasificación (no escribe nada)
    def _inicio(self, estado, ahora):
        """Límite inicial efectivo: el persistido; si no hay, el `desde` explícito del lanzador. Nunca se deduce."""
        persistido = _desde_iso(((estado.get("cobertura") or {}).get("inicio_utc")))
        if persistido is not None:
            if self.desde is not None and self.desde != persistido:
                raise InicioError("desde_distinto_del_persistido")
            return persistido
        if self.desde is None:
            raise InicioError("falta_desde")
        if self.desde > ahora:
            raise InicioError("desde_futuro")
        return self.desde

    def _ventana(self, estado, ahora, inicio):
        """-> (desde, hasta, search_after, origen). Sin marca de agua (primer arranque) se lee desde `inicio`. Con
        ella, desde la marca de agua menos el solape; la reconciliación de 48 h y la pendiente más antigua (con
        solape) solo ADELANTAN ese punto. Nunca antes de `inicio`. Si la lectura anterior se cortó por paginación y no
        quedaban pendientes, se continúa EXACTAMENTE donde se cortó (search_after)."""
        marca = estado.get("marca") or {}
        pend, cont = marca.get("pendiente_mas_antigua_utc"), marca.get("continuar")
        agua = _desde_iso((estado.get("cobertura") or {}).get("completa_hasta_utc"))
        if cont and not pend:
            return max(inicio, _desde_iso(cont["desde_utc"])), ahora, cont["search_after"], "continuacion"
        candidatos = {"reconciliacion_48h": ahora - VENTANA_RECONCILIACION}
        candidatos["marca_de_agua" if agua else "inicio_explicito"] = (agua - SOLAPE) if agua else inicio
        if pend:
            candidatos["pendiente_mas_antigua"] = _desde_iso(pend) - SOLAPE
        origen, desde = min(candidatos.items(), key=lambda kv: kv[1])
        if desde < inicio:
            origen, desde = "inicio_explicito", inicio
        return desde, ahora, None, origen

    def clasificar(self, estado, ahora, inicio=None):
        """-> dict con pendientes (orden de procesamiento), descartes por motivo y cobertura. Solo lee.
        Lanza LecturaIncompletaError ante una respuesta parcial o no verificable (nada se selecciona)."""
        from dashboard.ia.politica import evaluar_elegibilidad
        inicio = inicio if inicio is not None else self._inicio(estado, ahora)
        desde, hasta, sa, origen = self._ventana(estado, ahora, inicio)
        continuacion = sa is not None
        intentados = {i["opensearch_id"] for i in estado.get("intentos", [])}
        pendientes, descartes, por_cat = [], {}, {}
        total, relacion, leidos, truncada, ultimo_ts = None, None, 0, False, None
        for n in range(self.max_paginas):
            r = self.buscar(consulta(self.agente, self.nombre_agente, self.politica.nivel_minimo, desde, hasta,
                                     sa, self.pagina, self.campos))
            hits, tot, rel = validar_respuesta(r)
            if total is None:
                total, relacion = tot, rel
            if not hits:
                break
            en_bd = self.existentes([h.get("_id") for h in hits])
            for h in hits:
                leidos += 1
                fuente = h.get("_source") or {}
                alert = self.normalizar(h)
                ts = fuente.get("@timestamp")
                ultimo_ts = ts
                cat = categoria_evento(alert, fuente)
                osid = h.get("_id")
                motivo = None
                if osid in en_bd:
                    motivo = "ya_registrada"
                elif osid in intentados:
                    motivo = "ya_intentada"
                elif osid in self.excluidos:
                    motivo = "excluida"
                elif str((fuente.get("agent") or {}).get("name")) != self.nombre_agente or \
                        str(alert.get("agent_id")) != self.agente:
                    motivo = "otro_agente"
                elif cat == "web":
                    ok, m = procedencia_web(fuente, alert)
                    motivo = None if ok else m
                if motivo is None:
                    d = evaluar_elegibilidad(alert, True, self.politica)
                    if not d.elegible:
                        motivo = f"no_elegible:{d.motivo_omision}"
                if motivo:
                    descartes[motivo] = descartes.get(motivo, 0) + 1
                    continue
                por_cat[cat] = por_cat.get(cat, 0) + 1
                pendientes.append({"alert": alert, "meta": metadatos_seguros(alert, cat, ts)})
            if len(hits) > self.pagina:
                raise LecturaIncompletaError("pagina_excede_tamano")
            if len(hits) < self.pagina:
                break
            # Página llena: hace falta continuar (otra página o cursor persistido). El cursor debe ser válido y avanzar.
            nuevo = hits[-1].get("sort")
            validar_cursor(nuevo, sa)
            sa = nuevo
            if n == self.max_paginas - 1:
                truncada = True
        if not truncada and not continuacion and relacion == "eq" and leidos < total:
            raise LecturaIncompletaError("total_inconsistente")     # final natural sin haber leído todo el total
        completa = not truncada
        mas_antigua = pendientes[0]["meta"]["timestamp_utc"] if pendientes else None
        return {"ventana": {"desde_utc": _iso(desde), "hasta_utc": _iso(hasta), "continuacion": continuacion,
                            "origen_desde": origen, "inicio_utc": _iso(inicio)},
                "total_en_ventana": total if relacion == "eq" else None,
                "total_relacion": relacion, "total_minimo": total if relacion == "gte" else None,
                "leidos": leidos, "cobertura": "completa" if completa else "incompleta",
                "ultimo_leido_utc": ultimo_ts, "ultimo_sort": sa if truncada else None,
                "pendientes": pendientes, "pendientes_por_categoria": por_cat, "descartes": descartes,
                "pendiente_mas_antigua_utc": mas_antigua,
                "antiguedad_pendiente_mas_antigua_s": int((ahora - _desde_iso(mas_antigua)).total_seconds())
                if mas_antigua else None,
                "nota_cobertura": None if completa else
                "lectura limitada por paginación: el total de pendientes es un mínimo, no exhaustivo"}

    # ---- ejecución
    def _cerrar_inciertos(self, estado, ahora):
        n = 0
        for i in estado["intentos"]:
            if i.get("estado") in ("reservado", "invocado"):
                i["estado_previo"], i["estado"], i["revisar"], i["cerrado_utc"] = i["estado"], "incierto", True, _iso(ahora)
                n += 1
        return n

    def resumen_estado(self, estado, ahora):
        intentos = estado.get("intentos", [])
        c = cupo(intentos, ahora, 0, self.limites)
        inciertos = [i["opensearch_id"] for i in intentos if i.get("estado") == "incierto"]
        por_entrada = {}
        for i in intentos:                       # entradas idénticas: eventos distintos, agrupables al comparar
            h = i.get("entrada_sha256")
            if h:
                por_entrada.setdefault(h, []).append(i["opensearch_id"])
        marca = estado.get("marca") or {}
        return {"agente": self.agente, "version_estado": estado.get("version"),
                "migrado_de_version": estado.get("migrado_de_version"),
                "pausa": estado.get("pausa"), "fallos_consecutivos": estado.get("fallos_consecutivos"),
                "cupo": {k: c[k] for k in ("hora_movil", "dia_bogota")}, "limites": dict(self.limites),
                "cobertura": estado.get("cobertura"),
                "pendiente_mas_antigua_utc": marca.get("pendiente_mas_antigua_utc"),
                "lectura_cortada_pendiente_de_continuar": bool(marca.get("continuar")),
                "ultima_ejecucion": estado.get("ultima_ejecucion"), "ultimo_completado": estado.get("ultimo_completado"),
                "intentos_totales": len(intentos), "inciertos_para_revisar": inciertos,
                "llamadas_sin_cerrar": _llamadas_sin_cerrar(),
                "entradas_identicas": [{"entrada_sha256": h, "opensearch_ids": ids}
                                       for h, ids in sorted(por_entrada.items()) if len(ids) > 1],
                "errores_recientes": (estado.get("errores") or [])[-5:]}

    def ejecutar(self, *, ensayo=False):
        """Una ejecución. En ensayo: no llama al proveedor, no escribe filas ni el estado, no consume cupo."""
        ahora = _utc(self.reloj())
        if ensayo:
            return self._una(self.a.leer(ahora), ahora, ensayo=True)
        self.a.preparar()
        with self.a.bloqueo():
            estado = self.a.leer(ahora)
            return self._una(estado, ahora, ensayo=False)

    def _registrar(self, estado, resultado, ensayo):
        if not ensayo:
            estado["ultima_ejecucion"] = {k: v for k, v in resultado.items() if k != "seleccion"}
            self.a.guardar(estado)
        return resultado

    @staticmethod
    def _error(estado, ahora, tipo):
        estado.setdefault("errores", []).append({"utc": _iso(ahora), "tipo": tipo})
        estado["errores"] = estado["errores"][-50:]

    @staticmethod
    def _agua_tras_lectura(cobertura, sel):
        """Marca de agua tras una lectura VALIDADA y contigua con lo ya cubierto: el final de la ventana si la
        cobertura es completa; si la lectura se cortó por paginación, el instante del último documento leído (todo lo
        anterior en el orden ascendente está leído). Nunca retrocede."""
        previa = _desde_iso((cobertura or {}).get("completa_hasta_utc"))
        nueva = _desde_iso(sel["ventana"]["hasta_utc"] if sel["cobertura"] == "completa" else sel["ultimo_leido_utc"])
        if previa is not None and (nueva is None or nueva < previa):
            nueva = previa
        return _iso(nueva)

    def _una(self, estado, ahora, *, ensayo):
        res = {"ejecucion_id": uuid.uuid4().hex, "inicio_utc": _iso(ahora), "modo": "ensayo" if ensayo else "confirmar",
               "llamadas": 0,
               "completados": 0, "fallidos": 0, "sin_llamada": 0, "inciertos_cerrados": 0, "resultado": None}
        if not ensayo:
            res["inciertos_cerrados"] = self._cerrar_inciertos(estado, ahora)
        pausa = estado.get("pausa")
        en_pausa = bool(pausa and (pausa.get("hasta_utc") is None or ahora < _desde_iso(pausa["hasta_utc"])))
        if en_pausa:
            res["pausa"] = pausa
            if not ensayo:
                res["resultado"] = "en_pausa"
                return self._registrar(estado, res, ensayo)
        elif pausa and not ensayo:
            estado["pausa"] = None               # vencida: empieza el nuevo día de presupuesto, sin reintentar nada
            estado["fallos_consecutivos"] = 0
        act = self.activo()
        if act is None or getattr(act, "identificador", None) != self.id_activo or not getattr(act, "activo", False):
            res["resultado"] = "contexto_no_verificado"
            self._error(estado, ahora, "contexto_no_verificado")
            return self._registrar(estado, res, ensayo)
        try:
            inicio = self._inicio(estado, ahora)
        except InicioError as e:                 # sin límite inicial explícito no se lee ni se llama
            res["resultado"], res["error"] = "inicio_no_valido", e.args[0]
            self._error(estado, ahora, f"inicio:{e.args[0]}")
            return self._registrar(estado, res, ensayo)
        cobertura = estado.setdefault("cobertura", _cobertura_vacia())
        if not ensayo and not cobertura.get("inicio_utc"):
            cobertura["inicio_utc"] = _iso(inicio)
        try:
            sel = self.clasificar(estado, ahora, inicio)
        except Exception as e:                   # lectura (VPN/indexador o respuesta parcial): sin cupo, sin avance
            res["resultado"] = "error_lectura"
            res["error"] = _motivo_lectura(e)
            self._error(estado, ahora, f"lectura:{res['error']}")
            return self._registrar(estado, res, ensayo)
        res.update({k: v for k, v in sel.items() if k not in ("pendientes", "ultimo_sort")})
        res["pendientes"] = len(sel["pendientes"])
        res["marca_de_agua_previa_utc"] = cobertura.get("completa_hasta_utc")
        res["marca_de_agua_resultante_utc"] = self._agua_tras_lectura(cobertura, sel)
        c = cupo(estado["intentos"], ahora, 0, self.limites)
        res["cupo_inicial"] = {k: c[k] for k in ("hora_movil", "dia_bogota")}
        if ensayo:
            seleccion = [] if en_pausa else sel["pendientes"][:c["disponibles"]]
            res["seleccion"] = [p["meta"] for p in seleccion]
            res["pendientes_meta"] = [p["meta"] for p in sel["pendientes"]]
            res["resultado"] = "ensayo_en_pausa" if en_pausa else "ensayo"
            res["quedarian_pendientes"] = len(sel["pendientes"]) - len(seleccion)
            return res
        if sel["pendientes"] and c["disponibles"] > 0:
            from dashboard.ia import exclusion
            try:
                exclusion.comprobar()
            except exclusion.ExclusionError:     # sin exclusión común utilizable no se llama ni se marca nada
                res["resultado"] = "exclusion_no_disponible"
                self._error(estado, ahora, "exclusion_no_disponible")
                return self._registrar(estado, res, False)
        usados = 0
        for p in sel["pendientes"]:
            if cupo(estado["intentos"], _utc(self.reloj()), usados, self.limites)["disponibles"] <= 0:
                break
            pausa_activada, consumio = self._procesar(estado, p, res["ejecucion_id"], usados)
            usados += 1 if consumio else 0
            if pausa_activada:
                break
        procesados = {i["opensearch_id"] for i in estado["intentos"]}
        restantes = [p for p in sel["pendientes"] if p["meta"]["opensearch_id"] not in procesados]
        estado["marca"] = {"pendiente_mas_antigua_utc": restantes[0]["meta"]["timestamp_utc"] if restantes else None,
                           "continuar": {"desde_utc": sel["ventana"]["desde_utc"], "search_after": sel["ultimo_sort"]}
                           if sel["cobertura"] == "incompleta" else None}
        cobertura["completa_hasta_utc"] = res["marca_de_agua_resultante_utc"]
        cobertura["actualizada_utc"] = _iso(ahora)
        res["seleccion"] = [i["meta"] for i in estado["intentos"] if i.get("ejecucion_id") == res["ejecucion_id"]]
        for i in estado["intentos"]:
            if i.get("ejecucion_id") == res["ejecucion_id"]:
                res["llamadas"] += 1 if i.get("invocado_utc") else 0
                key = {"completado": "completados", "fallido": "fallidos", "sin_llamada": "sin_llamada"}.get(i["estado"])
                if key:
                    res[key] += 1
        res["pendientes_tras_ejecucion"] = len(restantes)
        res["resultado"] = "pausa_activada" if estado.get("pausa") else "ok"
        return self._registrar(estado, res, False)

    def _procesar(self, estado, p, ejecucion_id, usados_en_ejecucion=0):
        """Reserva duradera -> comprobación de ausencia -> ingesta con exclusión común y `solo_nueva` -> marca
        `invocado` justo antes de llamar, tras revalidar el cupo. -> (pausa_activada, consumio_cupo)."""
        from dashboard.ia import piloto as piloto_mod
        from dashboard.ia.exclusion import AnalisisEnCursoError, AnalisisInciertoError
        from dashboard.ia.ingesta import YA_EXISTENTE
        from dashboard.management.commands.ingestar_alertas import _ProveedorContado
        alert, meta = p["alert"], p["meta"]
        ahora = _utc(self.reloj())
        intento = {"opensearch_id": meta["opensearch_id"], "reservado_utc": _iso(ahora), "dia_bogota": dia_bogota(ahora),
                   "ejecucion_id": ejecucion_id, "estado": "reservado", "meta": meta, "invocado_utc": None}
        estado["intentos"].append(intento)
        self.a.guardar(estado)                   # RESERVA duradera antes de cualquier llamada

        if self.existentes([meta["opensearch_id"]]):
            intento.update(estado="sin_llamada", motivo="colision_fila_existente", cerrado_utc=_iso(self.reloj()))
            self.a.guardar(estado)
            return False, False

        def marcar_invocado(texto_sha256):
            t = _utc(self.reloj())
            otros = [i for i in estado["intentos"] if i is not intento]      # la propia reserva no se cobra dos veces
            if cupo(otros, t, usados_en_ejecucion, self.limites)["disponibles"] < 1:
                intento["motivo"] = "cupo_agotado_al_invocar"
                raise piloto_mod.RegistroPilotoError("cupo agotado al invocar; no se llama")
            previo = dict(intento)
            intento.update(estado="invocado", invocado_utc=_iso(t), entrada_sha256=texto_sha256)
            try:
                self.a.guardar(estado)
            except Exception:
                intento.clear()
                intento.update(previo)           # en memoria = en disco: sin invocación registrada, no se llama
                raise piloto_mod.RegistroPilotoError("no se pudo registrar la invocación; no se llama") from None

        inner = self.proveedor()
        respuestas = []

        class _Captura:
            """Conserva el código HTTP real y el estado de la respuesta (nunca su texto)."""
            def __init__(self, prov):
                self._p = prov
                for a in ("nombre", "formato_entrada", "valida_privacidad_salida", "valida_sustento_impactos", "_modelo",
                          "parametros_medicion"):
                    if hasattr(prov, a):
                        setattr(self, a, getattr(prov, a))

            def analizar(self, prompt):
                r = self._p.analizar(prompt)
                respuestas.append({"ok": bool(getattr(r, "ok", False)), "codigo_http": getattr(r, "codigo_http", None)})
                return r

        prov = _ProveedorContado(_Captura(inner), tope=1, agent_id=self.agente, antes_de_llamar=marcar_invocado)
        try:
            obj, accion = self.ingestar(alert, resolver=lambda a: self.activo() if str(a.get("agent_id")) == self.agente
                                        and a.get("opensearch_id") == meta["opensearch_id"] else None,
                                        politica=self.politica, proveedor=prov, solo_nueva=True)
        except Exception as e:
            from django.db import IntegrityError
            invocado = intento.get("invocado_utc") is not None
            if isinstance(e, AnalisisEnCursoError):
                motivo = "analisis_en_curso_otra_via"
            elif isinstance(e, AnalisisInciertoError):
                motivo = "requiere_revision_llamada_sin_cerrar"
            elif isinstance(e, IntegrityError):
                motivo = "colision_fila_existente"
            else:
                motivo = f"excepcion:{type(e).__name__}"
            intento.update(estado="incierto" if invocado else "sin_llamada", revisar=invocado, motivo=motivo,
                           cerrado_utc=_iso(self.reloj()))
            self.a.guardar(estado)
            return False, invocado
        if accion == YA_EXISTENTE:               # creada por otra vía entre la comprobación y la exclusión
            intento.update(estado="sin_llamada", motivo="colision_fila_existente", cerrado_utc=_iso(self.reloj()))
            self.a.guardar(estado)
            return False, False
        obj.refresh_from_db()
        med = (obj.contexto_ia_snapshot or {}).get("_medicion") or {}
        codigo = respuestas[-1]["codigo_http"] if respuestas else None
        invocado = intento.get("invocado_utc") is not None
        if not invocado:
            estado_i = "sin_llamada"
        else:
            estado_i = "completado" if obj.estado_analisis == "COMPLETED" else "fallido"
        intento.update(estado=estado_i, alert_id=obj.id, accion=accion, estado_analisis=obj.estado_analisis,
                       codigo_http=codigo if isinstance(codigo, int) else None, cerrado_utc=_iso(self.reloj()),
                       medicion={k: med.get(k) for k in (
                           "version", "proveedor", "modelo_configurado", "modelo_respuesta", "entrada_sha256",
                           "parametros", "inicio_llamada_utc", "duracion_llamada_s", "duracion_analisis_s",
                           "estado_llamada", "categoria_error_llamada", "codigo_http_llamada", "estado_analisis",
                           "categoria_fallo_analisis", "finish_reason", "tokens", "tokens_fuente",
                           "invocaciones_analizador", "reintentos_configurados", "intentos_http_observados",
                           "extension_web")})
        pausa = False
        if estado_i == "completado":
            estado["fallos_consecutivos"] = 0
            estado["ultimo_completado"] = {"utc": intento["cerrado_utc"], "alert_id": obj.id, **meta}
        elif estado_i == "fallido":
            estado["fallos_consecutivos"] = int(estado.get("fallos_consecutivos") or 0) + 1
        hasta = _iso(inicio_dia_siguiente_utc(self.reloj()))
        if invocado and intento["codigo_http"] == 429:
            estado["pausa"] = {"motivo": "http_429", "desde_utc": intento["cerrado_utc"], "hasta_utc": hasta}
            pausa = True
        elif estado["fallos_consecutivos"] >= 3:
            estado["pausa"] = {"motivo": "3_fallos_consecutivos", "desde_utc": intento["cerrado_utc"], "hasta_utc": hasta}
            pausa = True
        self.a.guardar(estado)
        return pausa, estado_i != "sin_llamada"


def _llamadas_sin_cerrar():
    """Marcas persistentes de llamada sin cerrar (todas las vías), solo lectura. Nunca impide ver el estado."""
    from dashboard.ia import exclusion
    try:
        return [{k: m.get(k) for k in ("clave", "via", "alert_id", "desde_utc")} for m in exclusion.listar_inciertos()]
    except exclusion.ExclusionError:
        return "directorio_de_exclusion_no_utilizable"


def _motivo_lectura(exc):
    """Tipo de error de lectura sanitizado (nunca el mensaje, que podría incluir URL o credenciales)."""
    from sentria_backend import IndexadorTLSError
    if isinstance(exc, LecturaIncompletaError):
        return f"incompleta:{exc.tipo}"
    return "tls_indexador" if isinstance(exc, IndexadorTLSError) else type(exc).__name__


def pausar(almacen, ahora):
    almacen.preparar()
    with almacen.bloqueo():
        e = almacen.leer(ahora)
        e["pausa"] = {"motivo": "manual", "desde_utc": _iso(ahora), "hasta_utc": None}
        almacen.guardar(e)
        return e["pausa"]


def reanudar(almacen, ahora):
    """Quita la pausa (manual, 429 o fallos) y pone a cero los fallos consecutivos. No reintenta nada anterior:
    los eventos ya intentados siguen fuera de la selección automática."""
    almacen.preparar()
    with almacen.bloqueo():
        e = almacen.leer(ahora)
        anterior = e.get("pausa")
        e["pausa"], e["fallos_consecutivos"] = None, 0
        almacen.guardar(e)
        return anterior
