"""
Ingesta continua acotada (dashboard/ia/continua.py y el comando ingesta_continua).

Sin red, sin IA real y sin MySQL: indexador y proveedores simulados, BD de pruebas aislada y estado en directorios
temporales. Límites probados: 2 por ejecución, 6 en ventana móvil de 60 min, 30 por día de America/Bogota.
"""
import datetime as dt
import hashlib
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import urllib.error
from types import SimpleNamespace
from unittest import mock

from django.contrib.auth.models import User
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import connection
from django.test import TestCase, TransactionTestCase
from django.urls import reverse

import sentria_backend
from dashboard.ia import continua, exclusion, proveedores
from dashboard.ia.ingesta import ingestar_alerta, reanalizar_alerta
from dashboard.ia.politica import POLITICA_POR_DEFECTO
from dashboard.models import ActivoLogico, Alert

UTC = dt.timezone.utc
T0 = dt.datetime(2026, 11, 13, 15, 0, tzinfo=UTC)          # 10:00 en Bogotá
POL5 = POLITICA_POR_DEFECTO.con_overrides({"nivel_minimo": 5})
SALIDA = {
    "schema_version": "1.0", "verdict": "REQUIERE_ATENCION", "risk": "LOW",
    "explanation_es": "Evento que requiere revisión humana con la evidencia disponible en la entrada.",
    "cvss_factors": {k: "no_determinado" for k in ("attack_vector", "attack_complexity", "privileges_required",
                     "user_interaction", "scope", "confidentiality_impact", "integrity_impact", "availability_impact")},
    "cvss_reasoning_es": "Factores no determinados: la entrada no trae factores observados que los sostengan.",
    "recommendation_es": "Revisar el evento en el servidor afectado.",
    "missing_evidence": ["Contexto adicional del evento"],
}
SECRETO = "tok_SECRETO_987"


class Caida(BaseException):
    """Simula la muerte del proceso (no la captura ningún `except Exception`)."""


def _ts(x):
    return x.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def doc(n, cuando, *, tipo="windows", level=5, mode="live", wid=None, indice="wazuh-alerts-4.x-2026.11.13",
        nombre="AGENTE-PRUEBA", agente="003"):
    src = {"agent": {"id": agente, "name": nombre}, "@timestamp": _ts(cuando), "id": wid or f"{int(cuando.timestamp())}.{n:06d}"}
    if tipo == "windows":
        src.update(rule={"description": "Servicio terminó con error", "level": level, "id": "61102",
                         "groups": ["windows", "windows_system", "system_error"]},
                   decoder={"name": "windows_eventchannel"},
                   data={"win": {"system": {"eventID": "7023", "channel": "System",
                                            "providerName": "Service Control Manager", "systemTime": _ts(cuando)}}})
    elif tipo == "web":
        web = {"schema_version": 1, "kind": "http_access", "service": "domjudge", "http_method": "POST",
               "http_status": 401, "response_bytes": 10, "route_class": "authentication_route", "has_query": False,
               "source_time_utc": _ts(cuando)}
        if mode is not None:
            web["mode"] = mode
        src.update(rule={"description": "Acceso HTTP 401", "level": level, "id": "119602",
                         "groups": ["sentria_web", "web", "accesslog"]}, decoder={"name": "json"},
                   data={"sentria_source": "web_access", "sentria_web": web})
    elif tipo == "flooding":
        src.update(rule={"description": "Agent event queue is flooded.", "level": 7, "id": "202",
                         "groups": ["agent_flooding", "wazuh"]}, decoder={"name": "wazuh"})
    return {"_id": f"d{n:03d}", "_index": indice, "_source": src}


class Indexador:
    """Interpreta las consultas del trabajador: filtros term/range, orden, search_after y size."""

    def __init__(self, docs=()):
        self.docs, self.consultas, self.fallo, self.alterar = list(docs), 0, None, None

    def buscar(self, q):
        self.consultas += 1
        if self.fallo is not None:
            raise self.fallo
        out = []
        for d in self.docs:
            s = d["_source"]
            ok = True
            for f in q["query"]["bool"]["filter"]:
                if "term" in f:
                    (campo, v), = f["term"].items()
                    ok &= {"agent.id": s["agent"]["id"], "agent.name": s["agent"]["name"]}[campo] == v
                else:
                    (campo, r), = f["range"].items()
                    if campo == "rule.level":
                        ok &= s["rule"]["level"] >= r["gte"]
                    else:
                        t = dt.datetime.fromisoformat(s["@timestamp"].replace("Z", "+00:00"))
                        ok &= continua._desde_iso(r["gte"]) <= t <= continua._desde_iso(r["lte"])
            if ok:
                t = int(dt.datetime.fromisoformat(s["@timestamp"].replace("Z", "+00:00")).timestamp() * 1000)
                out.append(dict(d, sort=[t, s.get("id") or "￿", d["_index"]]))
        out.sort(key=lambda h: tuple(h["sort"]))
        total = len(out)
        if q.get("search_after"):           # como OpenSearch: el total es el de la consulta, no el del tramo
            out = [h for h in out if tuple(h["sort"]) > tuple(q["search_after"])]
        r = {"took": 1, "timed_out": False, "_shards": {"total": 2, "successful": 2, "skipped": 0, "failed": 0},
             "hits": {"total": {"value": total, "relation": "eq"},
                      "hits": [dict(h, _source={k: v for k, v in h["_source"].items()}) for h in out[:q["size"]]]}}
        return self.alterar(q, r) if self.alterar else r


class Prov(proveedores.ProveedorIA):
    nombre = "gemini_developer"

    def __init__(self, respuestas=None, caida=False, durante=None):
        self.n, self.prompts, self._r, self._caida, self._durante = 0, [], list(respuestas or []), caida, durante

    def parametros_medicion(self):
        return {"temperature": 0.1, "reintentos_configurados": 0}

    def analizar(self, prompt):
        self.n += 1
        self.prompts.append(prompt)
        if self._durante is not None:       # otra vía actúa MIENTRAS esta llamada está en curso
            self._durante()
        if self._caida:
            raise Caida()
        r = self._r.pop(0) if self._r else {}
        return proveedores.RespuestaProveedor(
            ok=r.get("ok", True), texto=r.get("texto", json.dumps(SALIDA)), modelo="fake-m", error=r.get("error"),
            finish_reason="STOP", usage={"prompt": 100, "candidates": 20, "thoughts": None, "total": 120},
            modelo_respuesta="fake-m-001", codigo_http=r.get("codigo_http"))


class Reloj:
    def __init__(self, t=T0):
        self.t = t

    def __call__(self):
        return self.t

    def avanzar(self, **kw):
        self.t = self.t + dt.timedelta(**kw)


DESDE = T0 - dt.timedelta(days=7)            # límite inicial explícito de las pruebas (lo aporta el lanzador)


class _Comun:
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = os.path.join(self.tmp.name, "estado")
        self.excl = os.path.join(self.tmp.name, "exclusion")
        self._env = mock.patch.dict(os.environ, {exclusion.VARIABLE_DIR: self.excl})
        self._env.start()
        self.activo = ActivoLogico.objects.create(
            identificador="SRV-PRUEBA-01", nombre_visible="Servidor", tipo_activo="servidor_interno", criticidad="media",
            os_family="windows", os_role="servidor", hora_inicio_operacion=dt.time(0, 0),
            hora_fin_operacion=dt.time(23, 59), horario_sin_restriccion=True,
            contexto_autorizado_es="Servidor con servicios web y administración.")
        self.idx, self.reloj, self.prov = Indexador(), Reloj(), Prov()

    def tearDown(self):
        self._env.stop()
        self.tmp.cleanup()

    def trabajador(self, **kw):
        base = dict(agente="003", nombre_agente="AGENTE-PRUEBA", identificador_activo="SRV-PRUEBA-01", desde=DESDE,
                    buscar=self.idx.buscar, normalizar=sentria_backend._normalizar_hit,
                    existentes=lambda ids: set(Alert.objects.filter(opensearch_id__in=[i for i in ids if i])
                                               .values_list("opensearch_id", flat=True)),
                    activo=lambda: self.activo, proveedor=lambda: self.prov, ingestar=ingestar_alerta,
                    politica=POL5, reloj=self.reloj, campos=sentria_backend._SOURCE_FIELDS)
        base.update(kw)
        return continua.Trabajador(continua.Almacen(self.dir, "003"), **base)

    def poblar(self, n, *, desde=None, paso=dt.timedelta(minutes=1), **kw):
        desde = desde or (T0 - dt.timedelta(hours=3))
        self.idx.docs += [doc(len(self.idx.docs) + i, desde + i * paso, **kw) for i in range(n)]

    def estado(self):
        return continua.Almacen(self.dir, "003").leer(self.reloj())


class Base(_Comun, TestCase):
    pass


class BaseTx(_Comun, TransactionTestCase):
    """Con hilos: cada hilo usa su propia conexión, como el dashboard y el trabajador en procesos distintos."""


class LimitesTests(Base):
    def test_dos_por_ejecucion_y_estado_persistido(self):
        self.poblar(5)
        r = self.trabajador().ejecutar()
        self.assertEqual((r["llamadas"], r["completados"], r["pendientes_tras_ejecucion"], self.prov.n), (2, 2, 3, 2))
        self.assertEqual(len(self.estado()["intentos"]), 2)

    def test_ventana_movil_de_60_min(self):
        self.poblar(20)
        llamadas = []
        for _ in range(5):
            llamadas.append(self.trabajador().ejecutar()["llamadas"])
            self.reloj.avanzar(minutes=15)
        self.assertEqual(llamadas, [2, 2, 2, 0, 2])        # 4.ª: 6 en la última hora; 5.ª: las de t0 ya salen

    def test_treinta_por_dia_bogota_y_cruce_de_medianoche(self):
        self.reloj.t = dt.datetime(2026, 11, 14, 4, 50, tzinfo=UTC)        # 23:50 del 13 en Bogotá
        a = continua.Almacen(self.dir, "003"); a.preparar()
        e = continua._estado_inicial("003", self.reloj())
        for i in range(30):                                                # 30 del 13 de Bogotá, fuera de la hora móvil
            t = dt.datetime(2026, 11, 13, 6, 0, tzinfo=UTC) + dt.timedelta(minutes=30 * i)
            e["intentos"].append({"opensearch_id": f"x{i}", "reservado_utc": continua._iso(t),
                                  "dia_bogota": continua.dia_bogota(t), "estado": "completado"})
        a.guardar(e)
        self.poblar(5, desde=self.reloj.t - dt.timedelta(hours=1))
        self.assertEqual(self.trabajador().ejecutar()["llamadas"], 0)
        self.assertEqual(continua.cupo(self.estado()["intentos"], self.reloj())["dia_bogota"]["restantes"], 0)
        self.reloj.t = dt.datetime(2026, 11, 14, 5, 10, tzinfo=UTC)        # 00:10 del 14 en Bogotá
        self.assertEqual(self.trabajador().ejecutar()["llamadas"], 2)
        self.assertEqual(continua.dia_bogota(dt.datetime(2026, 11, 14, 4, 59, tzinfo=UTC)), "2026-11-13")

    def test_limites_conjuntos(self):
        c = continua.cupo([{"reservado_utc": continua._iso(T0 - dt.timedelta(minutes=10)),
                            "dia_bogota": continua.dia_bogota(T0), "estado": "completado"}] * 5, T0, 0)
        self.assertEqual((c["hora_movil"]["restantes"], c["disponibles"]), (1, 1))
        c = continua.cupo([], T0, 2)
        self.assertEqual(c["disponibles"], 0)
        sin = [{"reservado_utc": continua._iso(T0), "dia_bogota": continua.dia_bogota(T0), "estado": "sin_llamada"}] * 9
        self.assertEqual(continua.cupo(sin, T0, 0)["disponibles"], 2)

    def test_reinicio_conserva_cupo(self):
        self.poblar(20)
        for _ in range(3):
            self.trabajador().ejecutar()
            self.reloj.avanzar(minutes=1)
        nuevo = self.trabajador()                    # otro proceso: solo comparte el estado en disco
        self.assertEqual(nuevo.ejecutar()["llamadas"], 0)
        self.assertEqual(continua.cupo(self.estado()["intentos"], self.reloj())["hora_movil"]["usados"], 6)


class ConcurrenciaYCaidasTests(Base):
    def test_ejecucion_concurrente_se_rechaza(self):
        self.poblar(3)
        a = continua.Almacen(self.dir, "003"); a.preparar()
        with a.bloqueo():
            with self.assertRaises(continua.OcupadoError):
                self.trabajador().ejecutar()
        self.assertEqual(self.prov.n, 0)
        self.assertEqual(self.trabajador().ejecutar()["llamadas"], 2)

    def test_caida_antes_de_reservar(self):
        self.poblar(3)
        self.idx.fallo = Caida()
        with self.assertRaises(Caida):
            self.trabajador().ejecutar()
        self.idx.fallo = None
        self.assertEqual(self.estado()["intentos"], [])
        self.assertEqual(self.trabajador().ejecutar()["llamadas"], 2)

    def test_caida_tras_reservar_antes_de_llamar(self):
        self.poblar(3)
        def ingestar(*a, **kw):
            raise Caida()
        with self.assertRaises(Caida):
            self.trabajador(ingestar=ingestar).ejecutar()
        self.assertEqual([i["estado"] for i in self.estado()["intentos"]], ["reservado"])
        r = self.trabajador().ejecutar()
        e = self.estado()
        self.assertEqual(r["inciertos_cerrados"], 1)
        self.assertEqual(e["intentos"][0]["estado"], "incierto")
        self.assertEqual(sum(1 for i in e["intentos"] if i["opensearch_id"] == "d000"), 1)    # nunca se reintenta
        self.assertEqual(r["llamadas"], 2)           # d001 y d002; d000 (incierto) no se reintenta
        self.assertEqual([i["opensearch_id"] for i in e["intentos"][1:]], ["d001", "d002"])
        self.assertEqual(continua.cupo(e["intentos"], self.reloj())["hora_movil"]["usados"], 3)   # el incierto cuenta

    def test_caida_tras_llamar_antes_de_guardar(self):
        self.poblar(2)
        self.prov = Prov(caida=True)
        with self.assertRaises(Caida):
            self.trabajador().ejecutar()
        self.assertEqual((self.prov.n, self.estado()["intentos"][0]["estado"]), (1, "invocado"))
        fila = Alert.objects.get(opensearch_id="d000")
        self.assertNotEqual(fila.estado_analisis, "COMPLETED")
        self.prov = Prov()
        r = self.trabajador().ejecutar()
        e = self.estado()
        self.assertEqual(e["intentos"][0]["estado"], "incierto")
        self.assertTrue(e["intentos"][0]["revisar"])
        self.assertNotIn("d000", [p["opensearch_id"] for p in r["seleccion"]])
        self.assertEqual(len(self.prov.prompts), 1)  # solo d001: d000 no se vuelve a enviar
        self.assertEqual(self.trabajador().resumen_estado(e, self.reloj())["inciertos_para_revisar"], ["d000"])

    def test_colision_con_ingesta_manual_sin_llamada_ni_cupo(self):
        self.poblar(1)
        llamadas_existentes = {"n": 0}
        real = lambda ids: set(Alert.objects.filter(opensearch_id__in=ids).values_list("opensearch_id", flat=True))
        def existentes(ids):
            llamadas_existentes["n"] += 1
            if llamadas_existentes["n"] == 2:        # entre clasificar y llamar, otra vía crea la fila
                Alert.objects.create(opensearch_id="d000", titulo="t", descripcion="d", estado_analisis="PENDING")
            return real(ids)
        r = self.trabajador(existentes=existentes).ejecutar()
        i = self.estado()["intentos"][0]
        self.assertEqual((i["estado"], i["motivo"], self.prov.n, r["llamadas"]), ("sin_llamada", "colision_fila_existente", 0, 0))
        self.assertEqual(continua.cupo(self.estado()["intentos"], self.reloj())["hora_movil"]["usados"], 0)


    def test_fila_creada_tras_la_comprobacion_previa_no_se_reanaliza(self):
        # La fila aparece (en fallo) DESPUÉS de la comprobación previa del trabajador y antes de su exclusión: la
        # comprobación dentro de la exclusión (`solo_nueva`) la deja intacta, sin recuperación ni llamada.
        self.poblar(1)
        n = {"c": 0}
        def existentes(ids):
            n["c"] += 1
            r = set(Alert.objects.filter(opensearch_id__in=ids).values_list("opensearch_id", flat=True))
            if n["c"] == 2:
                Alert.objects.create(opensearch_id="d000", titulo="t", descripcion="d", severidad=5,
                                     estado_analisis="ANALISIS_FALLIDO", wazuh_agent_id="003", activo_logico=self.activo)
            return r
        r = self.trabajador(existentes=existentes).ejecutar()
        i = self.estado()["intentos"][0]
        fila = Alert.objects.get(opensearch_id="d000")
        self.assertEqual((i["estado"], i["motivo"], self.prov.n, r["llamadas"]), ("sin_llamada", "colision_fila_existente", 0, 0))
        self.assertEqual((fila.estado_analisis, fila.contexto_ia_snapshot), ("ANALISIS_FALLIDO", None))


class SeleccionTests(Base):
    def test_filas_existentes_en_cualquier_estado(self):
        self.poblar(4)
        for n, est in zip(("d000", "d001", "d002", "d003"), ("PENDING", "ANALISIS_FALLIDO", "COMPLETED", "OMITIDO_POLITICA")):
            Alert.objects.create(opensearch_id=n, titulo="t", descripcion="d", estado_analisis=est)
        r = self.trabajador().ejecutar()
        self.assertEqual((r["llamadas"], r["descartes"]), (0, {"ya_registrada": 4}))

    def test_replays_procedencia_y_excluidos(self):
        self.idx.docs = [doc(0, T0 - dt.timedelta(hours=2), tipo="web", mode="historical_replay"),
                         doc(1, T0 - dt.timedelta(hours=2, minutes=-1), tipo="web", mode=None),
                         doc(2, T0 - dt.timedelta(hours=2, minutes=-2), tipo="web", mode="inventado"),
                         doc(3, T0 - dt.timedelta(hours=2, minutes=-3), tipo="web", mode="live"),
                         doc(4, T0 - dt.timedelta(hours=2, minutes=-4))]
        r = self.trabajador(excluidos=("d004",)).ejecutar()
        self.assertEqual(r["descartes"], {"replay_historico": 1, "procedencia_web_no_confirmada": 2, "excluida": 1})
        self.assertEqual([p["opensearch_id"] for p in r["seleccion"]], ["d003"])
        self.assertIn("procedencia del registro web: en_vivo", self.prov.prompts[0])

    def test_avisos_del_agente_no_se_excluyen(self):
        self.idx.docs = [doc(0, T0 - dt.timedelta(hours=1), tipo="flooding")]
        r = self.trabajador().ejecutar()
        self.assertEqual((r["pendientes_por_categoria"], r["completados"]), ({"agente_wazuh": 1}, 1))

    def test_otro_agente_o_nombre_no_entra(self):
        self.idx.docs = [doc(0, T0 - dt.timedelta(hours=1), nombre="OTRO"), doc(1, T0 - dt.timedelta(hours=1), agente="002")]
        self.assertEqual(self.trabajador().ejecutar()["leidos"], 0)

    def test_antiguas_primero_y_desempate_determinista(self):
        t = T0 - dt.timedelta(hours=1)
        self.idx.docs = [doc(0, t, wid="b"), doc(1, t, wid="a"), doc(2, t - dt.timedelta(minutes=5)),
                         doc(3, t, wid="a", indice="wazuh-alerts-4.x-2026.11.12")]
        r = self.trabajador(limites=dict(continua.LIMITES, por_ejecucion=4, por_hora_movil=10)).ejecutar()
        self.assertEqual([p["opensearch_id"] for p in r["seleccion"]], ["d002", "d003", "d001", "d000"])

    def test_paginacion_cobertura_incompleta_y_avance_sin_saltar(self):
        self.poblar(10)
        t = self.trabajador(pagina=3, max_paginas=2, limites=dict(continua.LIMITES, por_ejecucion=2, por_hora_movil=100))
        r = t.ejecutar()
        self.assertEqual((r["cobertura"], r["leidos"], r["total_en_ventana"]), ("incompleta", 6, 10))
        self.assertIn("mínimo", r["nota_cobertura"])
        enviados = list(i["opensearch_id"] for i in self.estado()["intentos"])
        for _ in range(8):
            self.reloj.avanzar(minutes=15)
            t.ejecutar()
            enviados = [i["opensearch_id"] for i in self.estado()["intentos"]]
        self.assertEqual(enviados, [f"d{i:03d}" for i in range(10)])     # todas, en orden, sin duplicados

    def test_llegada_tardia_dentro_de_la_ventana(self):
        self.poblar(2)
        self.trabajador().ejecutar()
        self.idx.docs.append(doc(50, T0 - dt.timedelta(hours=4)))         # llega tarde con @timestamp anterior
        self.reloj.avanzar(minutes=15)
        r = self.trabajador().ejecutar()
        self.assertEqual([p["opensearch_id"] for p in r["seleccion"]], ["d050"])

    def test_cupo_agotado_no_pierde_pendientes_aunque_envejezcan(self):
        # 1 invocación al día: las pendientes superan pronto la ventana de 48 h y solo la marca las conserva.
        self.poblar(9, desde=T0 - dt.timedelta(hours=47), paso=dt.timedelta(hours=1))
        t = self.trabajador(limites=dict(continua.LIMITES, por_dia=1))
        for _ in range(9):
            t.ejecutar()
            self.reloj.avanzar(days=1)
        enviados = [i["opensearch_id"] for i in self.estado()["intentos"]]
        self.assertEqual(enviados, [f"d{i:03d}" for i in range(9)])

    def test_marca_apunta_a_la_pendiente_mas_antigua(self):
        self.poblar(5)
        self.trabajador().ejecutar()
        m = self.estado()["marca"]
        self.assertEqual(m["pendiente_mas_antigua_utc"], self.idx.docs[2]["_source"]["@timestamp"])


class CortesYErroresTests(Base):
    def test_429_real_pausa_hasta_el_dia_siguiente(self):
        self.poblar(4)
        self.prov = Prov([{"ok": False, "texto": "", "error": "ClientError: 429 RESOURCE_EXHAUSTED", "codigo_http": 429}])
        r = self.trabajador().ejecutar()
        e = self.estado()
        self.assertEqual((r["resultado"], r["llamadas"], e["pausa"]["motivo"]), ("pausa_activada", 1, "http_429"))
        self.assertEqual(e["pausa"]["hasta_utc"], continua._iso(continua.inicio_dia_siguiente_utc(T0)))
        self.reloj.avanzar(hours=2)
        self.assertEqual(self.trabajador().ejecutar()["resultado"], "en_pausa")
        self.reloj.t = continua.inicio_dia_siguiente_utc(T0) + dt.timedelta(minutes=1)
        self.prov = Prov()
        r = self.trabajador().ejecutar()
        self.assertEqual(r["llamadas"], 2)
        self.assertNotIn("d000", [p["opensearch_id"] for p in r["seleccion"]])     # el fallido no se reintenta

    def test_429_no_se_deduce_del_mensaje(self):
        self.poblar(2)
        self.prov = Prov([{"ok": False, "texto": "", "error": "HTTP 429 cuota"}])
        r = self.trabajador().ejecutar()
        self.assertIsNone(self.estado()["pausa"])
        self.assertEqual((r["fallidos"], self.estado()["intentos"][0]["codigo_http"]), (1, None))

    def test_tres_fallos_consecutivos(self):
        self.poblar(6)
        self.prov = Prov([{"ok": False, "texto": "", "error": "timeout"}] * 3)
        self.trabajador().ejecutar()
        self.reloj.avanzar(minutes=15)
        r = self.trabajador().ejecutar()
        e = self.estado()
        self.assertEqual((e["fallos_consecutivos"], e["pausa"]["motivo"], r["llamadas"]), (3, "3_fallos_consecutivos", 1))

    def test_completado_reinicia_fallos(self):
        self.poblar(4)
        self.prov = Prov([{"ok": False, "texto": "", "error": "timeout"}, {}])
        self.trabajador().ejecutar()
        self.assertEqual(self.estado()["fallos_consecutivos"], 0)

    def test_error_de_lectura_no_gasta_cupo(self):
        self.poblar(3)
        self.idx.fallo = ConnectionError(f"https://usuario:{SECRETO}@indexador caído")
        r = self.trabajador().ejecutar()
        self.assertEqual((r["resultado"], r["error"], self.prov.n), ("error_lectura", "ConnectionError", 0))
        self.assertEqual(self.estado()["intentos"], [])
        self.idx.fallo = None
        self.assertEqual(self.trabajador().ejecutar()["llamadas"], 2)

    def test_pausar_y_reanudar_sin_reintentos(self):
        self.poblar(4)
        a = continua.Almacen(self.dir, "003")
        continua.pausar(a, self.reloj())
        self.assertEqual(self.trabajador().ejecutar()["resultado"], "en_pausa")
        continua.reanudar(a, self.reloj())
        self.assertEqual(self.trabajador().ejecutar()["llamadas"], 2)


class SecretosContratoEInmutabilidadTests(Base):
    def test_secretos_fuera_del_estado_y_la_salida(self):
        self.poblar(2)
        self.prov = Prov([{"ok": False, "texto": "", "error": f"api_key={SECRETO}"}])
        r = self.trabajador().ejecutar()
        with open(os.path.join(self.dir, "estado.json"), encoding="utf-8") as f:
            texto = f.read()
        self.assertNotIn(SECRETO, texto)
        self.assertNotIn(SECRETO, json.dumps(r, default=str))
        self.idx.fallo = RuntimeError(f"Authorization: Bearer {SECRETO}")
        self.reloj.avanzar(minutes=15)
        r = self.trabajador().ejecutar()
        with open(os.path.join(self.dir, "estado.json"), encoding="utf-8") as f:
            self.assertNotIn(SECRETO, f.read())

    def test_medicion_y_contrato_vigente(self):
        self.poblar(1)
        self.trabajador().ejecutar()
        i = self.estado()["intentos"][0]
        m = i["medicion"]
        self.assertEqual((i["estado"], m["version"], m["estado_llamada"], m["estado_analisis"], m["invocaciones_analizador"]),
                         ("completado", "medicion_v2", "ok", "COMPLETED", 1))
        self.assertEqual(m["entrada_sha256"], hashlib.sha256(self.prov.prompts[0].encode()).hexdigest())
        self.assertEqual(i["entrada_sha256"], m["entrada_sha256"])
        self.assertEqual((m["modelo_configurado"], m["modelo_respuesta"], m["tokens"]["total"]), ("fake-m", "fake-m-001", 120))
        self.assertIn("codigo_http_llamada", m)
        fila = Alert.objects.get(pk=i["alert_id"])
        self.assertEqual((fila.estado_analisis, fila.veredicto_ia, fila.severidad), ("COMPLETED", "REQUIERE_ATENCION", 5))

    def test_permisos_del_estado(self):
        self.poblar(1)
        self.trabajador().ejecutar()
        self.assertEqual(stat.S_IMODE(os.stat(self.dir).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.dir, "estado.json")).st_mode), 0o600)
        os.chmod(self.dir, 0o755)
        with self.assertRaises(continua.EstadoError):
            self.trabajador().ejecutar()

    def test_ensayo_no_escribe_ni_llama(self):
        self.poblar(3)
        r = self.trabajador().ejecutar(ensayo=True)
        self.assertEqual((r["resultado"], len(r["seleccion"]), r["quedarian_pendientes"], self.prov.n), ("ensayo", 2, 1, 0))
        self.assertFalse(os.path.exists(self.dir))
        self.assertEqual(Alert.objects.count(), 0)

    def test_filas_208_y_209_intactas(self):
        snaps = {}
        for osid, est in (("d000", "COMPLETED"), ("d001", "COMPLETED")):
            snaps[osid] = {"schema_version": "1.4", "x": osid}
            Alert.objects.create(opensearch_id=osid, titulo="t", descripcion="d", estado_analisis=est,
                                 veredicto_ia="REQUIERE_ATENCION", riesgo_ia="LOW", contexto_ia_snapshot=snaps[osid])
        self.poblar(3)
        self.trabajador(excluidos=("d000", "d001")).ejecutar()
        for osid, s in snaps.items():
            self.assertEqual(Alert.objects.get(opensearch_id=osid).contexto_ia_snapshot, s)
        self.assertEqual([i["opensearch_id"] for i in self.estado()["intentos"]], ["d002"])


class CodigoHttpYComandoTests(Base):
    def test_codigo_http_real_de_gemini(self):
        from google.genai import errors
        p = proveedores.GeminiDeveloperProvider()
        for exc, esperado in ((errors.ClientError(429, {"error": {"message": f"cuota {SECRETO}"}}), 429),
                              (RuntimeError("HTTP 429"), None)):
            with mock.patch.object(p, "_cliente", side_effect=exc):
                self.assertEqual(p.analizar("x").codigo_http, esperado)

    def test_codigo_http_real_de_vertex(self):
        p = proveedores.VertexTunedProvider()
        err = urllib.error.HTTPError("https://x", 429, "Too Many", {}, io.BytesIO(b"{}"))
        with mock.patch.object(p, "error_configuracion", return_value=None), \
                mock.patch.object(p, "_token", return_value="t"), mock.patch.object(p, "url", return_value="https://x"), \
                mock.patch("urllib.request.urlopen", side_effect=err):
            self.assertEqual(p.analizar("x").codigo_http, 429)

    def test_comando_ver_estado_pausar_reanudar_y_sin_clave(self):
        out = io.StringIO()
        call_command("ingesta_continua", "--estado-dir", self.dir, "--agente", "003", "--pausar", stdout=out)
        self.assertEqual(json.loads(out.getvalue())["pausa"]["motivo"], "manual")
        out = io.StringIO()
        call_command("ingesta_continua", "--estado-dir", self.dir, "--agente", "003", "--ver-estado", stdout=out)
        v = json.loads(out.getvalue())
        self.assertEqual((v["pausa"]["motivo"], v["limites"]), ("manual", continua.LIMITES))
        call_command("ingesta_continua", "--estado-dir", self.dir, "--agente", "003", "--reanudar", stdout=io.StringIO())
        ids = ["--agente", "003", "--nombre-agente", "AGENTE-PRUEBA", "--activo", "SRV-PRUEBA-01"]
        with self.assertRaises(CommandError):        # settings_ci: GEMINI_API_KEY vacía -> no se ejecuta
            call_command("ingesta_continua", "--estado-dir", self.dir, *ids, "--confirmar", stdout=io.StringIO())
        with self.assertRaises(CommandError):        # sin identificadores del despliegue -> no se ejecuta
            call_command("ingesta_continua", "--estado-dir", self.dir, "--agente", "003", "--ensayo", stdout=io.StringIO())
        with self.assertRaises(CommandError):
            call_command("ingesta_continua", "--estado-dir", "relativa", "--agente", "003", "--ver-estado",
                         stdout=io.StringIO())

    def test_error_inesperado_sin_mensaje_ni_traza(self):
        out = io.StringIO()
        with mock.patch.object(continua.Trabajador, "ejecutar", side_effect=RuntimeError(f"Bearer {SECRETO}")), \
                mock.patch.dict(os.environ, {"GEMINI_API_KEY": "x"}):
            with self.assertRaises(CommandError) as cm:
                call_command("ingesta_continua", "--estado-dir", self.dir, "--agente", "003", "--nombre-agente", "A",
                             "--activo", "B", "--ensayo", stdout=out)
        self.assertNotIn(SECRETO, out.getvalue() + str(cm.exception))
        self.assertEqual(json.loads(out.getvalue())["tipo"], "RuntimeError")

    def test_limites_fijos_documentados(self):
        self.assertEqual(continua.LIMITES, {"por_ejecucion": 2, "por_hora_movil": 6, "por_dia": 30})
        self.assertEqual((str(continua.ZONA_DIA), continua.INTERVALO_MIN), ("America/Bogota", 15))


# =========================================================================== revisión v1 -> v2
def _intento(osid, reservado, invocado=None, estado="completado"):
    return {"opensearch_id": osid, "reservado_utc": continua._iso(reservado), "dia_bogota": continua.dia_bogota(reservado),
            "invocado_utc": continua._iso(invocado) if invocado else None, "estado": estado}


def _guardar_estado(directorio, intentos, **extra):
    a = continua.Almacen(directorio, "003")
    a.preparar()
    e = continua._estado_inicial("003", T0)
    e["intentos"] = intentos
    e.update(extra)
    a.guardar(e)
    return a


class CupoPorInstanteEfectivoTests(Base):
    """Punto 1: el cupo se cobra en el instante de invocación (o de reserva si no consta)."""

    def _seis_de_la_revision(self):
        d = dt.datetime(2026, 11, 12, 17, 0, 0, tzinfo=UTC)
        s = dt.timedelta(seconds=10)
        return [_intento("a0", d, d + s), _intento("a1", d + dt.timedelta(seconds=1), d + dt.timedelta(seconds=11)),
                _intento("b0", d + dt.timedelta(minutes=15), d + dt.timedelta(minutes=15)),
                _intento("b1", d + dt.timedelta(minutes=15), d + dt.timedelta(minutes=15)),
                _intento("c0", d + dt.timedelta(minutes=30), d + dt.timedelta(minutes=30)),
                _intento("c1", d + dt.timedelta(minutes=30), d + dt.timedelta(minutes=30))]

    def test_reproduccion_de_la_revision_seis_invocaciones_en_la_hora(self):
        ahora = dt.datetime(2026, 11, 12, 18, 0, 5, tzinfo=UTC)
        c = continua.cupo(self._seis_de_la_revision(), ahora, 0)
        self.assertEqual((c["hora_movil"]["usados"], c["disponibles"]), (6, 0))
        # Extremo a extremo: con pendientes reales, el trabajador no hace ninguna llamada.
        _guardar_estado(self.dir, self._seis_de_la_revision())
        self.reloj.t = ahora
        self.poblar(3, desde=ahora - dt.timedelta(hours=2))
        r = self.trabajador(desde=ahora - dt.timedelta(days=2)).ejecutar()
        self.assertEqual((r["llamadas"], self.prov.n, r["cupo_inicial"]["hora_movil"]["usados"]), (0, 0, 6))
        self.reloj.t = dt.datetime(2026, 11, 12, 18, 0, 12, tzinfo=UTC)       # salen las dos invocadas a las 17:00:10/11
        self.assertEqual(self.trabajador(desde=ahora - dt.timedelta(days=2)).ejecutar()["llamadas"], 2)

    def test_cruce_de_medianoche_entre_reserva_e_invocacion(self):
        reserva = dt.datetime(2026, 11, 14, 4, 59, 59, tzinfo=UTC)            # 23:59:59 del 13 en Bogotá
        invoc = dt.datetime(2026, 11, 14, 5, 0, 5, tzinfo=UTC)                # 00:00:05 del 14 en Bogotá
        i = _intento("x", reserva, invoc)
        self.assertEqual(i["dia_bogota"], "2026-11-13")                       # etiqueta de la reserva: ya no decide
        dia14 = dt.datetime(2026, 11, 14, 20, 0, tzinfo=UTC)
        dia13 = dt.datetime(2026, 11, 14, 4, 59, 59, 500000, tzinfo=UTC)
        self.assertEqual(continua.cupo([i], dia14, 0)["dia_bogota"]["usados"], 1)
        self.assertEqual(continua.cupo([i], dia13, 0)["dia_bogota"]["usados"], 0)
        # 29 más el 14 + la cruzada = 30: el 14 está lleno aunque la reserva fuera del 13.
        otros = [_intento(f"y{k}", dt.datetime(2026, 11, 14, 6, 0, tzinfo=UTC) + dt.timedelta(minutes=20 * k))
                 for k in range(29)]
        self.assertEqual(continua.cupo([i] + otros, dia14 + dt.timedelta(hours=2), 0)["dia_bogota"]["restantes"], 0)

    def test_inciertos_y_reservados_cuentan_por_reserva_o_invocacion(self):
        t = T0 - dt.timedelta(minutes=59)
        intentos = [_intento("r", t, None, "incierto"),                       # sin marca: reserva (conservador)
                    _intento("i", t - dt.timedelta(minutes=5), t, "incierto"),  # con marca: invocación
                    _intento("s", t, None, "sin_llamada")]                    # sin llamada: no cuenta
        c = continua.cupo(intentos, T0, 0)
        self.assertEqual(c["hora_movil"]["usados"], 2)
        self.assertEqual(continua.cupo(intentos, T0 + dt.timedelta(minutes=2), 0)["hora_movil"]["usados"], 0)

    def test_revalidacion_antes_de_invocar_sin_cobrar_dos_veces_la_reserva(self):
        # 5 invocaciones en la hora: la propia reserva es la 6.ª y SÍ puede invocar (no se cobra dos veces).
        _guardar_estado(self.dir, [_intento(f"p{k}", T0 - dt.timedelta(minutes=10 + k)) for k in range(5)])
        self.poblar(2)
        r = self.trabajador().ejecutar()
        self.assertEqual((r["llamadas"], self.prov.n), (1, 1))
        # Si al invocar ya no queda cupo (p. ej. tope de ejecución agotado), no se llama y no se consume.
        self.prov = Prov()
        t = self.trabajador()
        e = t.a.leer(self.reloj())
        p = {"alert": sentria_backend._normalizar_hit(self.idx.docs[1]),
             "meta": {"opensearch_id": "d001", "timestamp_utc": "x", "regla": "61102", "nivel": 5, "categoria": "windows"}}
        self.reloj.avanzar(hours=2)
        pausa, consumio = t._procesar(e, p, "ej", usados_en_ejecucion=2)
        i = e["intentos"][-1]
        self.assertEqual((pausa, consumio, self.prov.n, i["estado"], i["motivo"], i["invocado_utc"]),
                         (False, False, 0, "sin_llamada", "cupo_agotado_al_invocar", None))

    def test_estado_v1_se_reconoce_sin_olvidar_intentos_ni_liberar_cupo(self):
        a = continua.Almacen(self.dir, "003")
        a.preparar()
        v1 = {"version": 1, "agente": "003", "creado_utc": continua._iso(T0), "fallos_consecutivos": 1, "pausa": None,
              "marca": None, "ultima_ejecucion": None, "ultimo_completado": None, "errores": [],
              "intentos": [_intento("d000", T0 - dt.timedelta(minutes=30), T0 - dt.timedelta(minutes=29)),
                           _intento("d001", T0 - dt.timedelta(minutes=20), None, "incierto")]}
        with open(a.ruta, "w", encoding="utf-8") as f:
            json.dump(v1, f)
        os.chmod(a.ruta, 0o600)
        self.poblar(4)
        r = self.trabajador().ejecutar()
        e = self.estado()
        self.assertEqual((e["version"], e["migrado_de_version"]), (2, 1))
        self.assertEqual([i["opensearch_id"] for i in e["intentos"][:2]], ["d000", "d001"])
        self.assertEqual(r["descartes"].get("ya_intentada"), 2)                # no se reintentan
        self.assertEqual(r["cupo_inicial"]["hora_movil"]["usados"], 2)         # siguen contando
        self.assertEqual(e["cobertura"]["inicio_utc"], continua._iso(DESDE))
        with open(a.ruta, "w", encoding="utf-8") as f:
            json.dump(dict(v1, version=3), f)
        with self.assertRaises(continua.EstadoError):
            self.trabajador().ejecutar()


class LecturaParcialTests(Base):
    """Punto 2: respuestas parciales o no verificables del indexador."""

    def _alterar_primera(self, cambio):
        def alterar(q, r):
            cambio(r)
            return r
        self.idx.alterar = alterar

    def _sin_efectos(self, r, tipo, cobertura_previa=None, marca_previa=None):
        self.assertEqual((r["resultado"], r["error"], r["llamadas"], self.prov.n), ("error_lectura", f"incompleta:{tipo}", 0, 0))
        self.assertNotIn("seleccion", r)
        e = self.estado()
        self.assertEqual(e["intentos"], [])
        self.assertEqual(e["cobertura"]["completa_hasta_utc"], cobertura_previa)
        self.assertEqual(e["marca"], marca_previa)
        self.assertEqual(Alert.objects.count(), 0)

    def test_control_respuesta_completa(self):
        self.poblar(1)
        r = self.trabajador().ejecutar()
        self.assertEqual((r["cobertura"], r["total_en_ventana"], r["total_relacion"], r["llamadas"]), ("completa", 1, "eq", 1))

    def test_timed_out(self):
        self.poblar(1)
        self._alterar_primera(lambda r: r.update(timed_out=True))
        self._sin_efectos(self.trabajador().ejecutar(), "timed_out")

    def test_shard_fallido(self):
        self.poblar(1)
        self._alterar_primera(lambda r: r["_shards"].update(successful=1, failed=1))
        self._sin_efectos(self.trabajador().ejecutar(), "shards_fallidos")

    def test_shards_sin_responder_y_metadatos_ausentes(self):
        self.poblar(1)
        self._alterar_primera(lambda r: r["_shards"].update(successful=1))
        self._sin_efectos(self.trabajador().ejecutar(), "shards_incompletos")
        self._alterar_primera(lambda r: r.pop("_shards"))
        self._sin_efectos(self.trabajador().ejecutar(), "shards_ausente")
        self._alterar_primera(lambda r: r.pop("timed_out"))
        self._sin_efectos(self.trabajador().ejecutar(), "timed_out_ausente")

    def test_total_gte_no_se_presenta_como_exacto(self):
        self.poblar(2)
        self._alterar_primera(lambda r: r["hits"]["total"].update(relation="gte"))
        r = self.trabajador().ejecutar(ensayo=True)
        self.assertEqual((r["total_en_ventana"], r["total_minimo"], r["total_relacion"]), (None, 2, "gte"))

    def test_total_inconsistente_con_final_natural(self):
        self.poblar(3)
        self._alterar_primera(lambda r: r["hits"].update(hits=r["hits"]["hits"][:1]))
        self._sin_efectos(self.trabajador().ejecutar(), "total_inconsistente")

    def test_sort_ausente_en_pagina_que_necesita_continuar(self):
        self.poblar(6)
        def quitar(r):
            if r["hits"]["hits"]:
                r["hits"]["hits"][-1] = {k: v for k, v in r["hits"]["hits"][-1].items() if k != "sort"}
        self._alterar_primera(quitar)
        self._sin_efectos(self.trabajador(pagina=3).ejecutar(), "sort_ausente")

    def test_sort_no_progresivo(self):
        self.poblar(9)
        primera = {}
        def repetir(q, r):
            if not q.get("search_after"):
                primera.update(r=json.loads(json.dumps(r)))
                return r
            return json.loads(json.dumps(primera["r"]))            # la página siguiente repite el mismo cursor
        self.idx.alterar = repetir
        self._sin_efectos(self.trabajador(pagina=3).ejecutar(), "sort_no_progresa")

    def test_lectura_parcial_tras_una_correcta_no_avanza_marcas(self):
        self.poblar(5)
        self.trabajador().ejecutar()
        previa_agua, previa_marca = self.estado()["cobertura"]["completa_hasta_utc"], self.estado()["marca"]
        intentos = self.estado()["intentos"]
        self.reloj.avanzar(minutes=15)
        self._alterar_primera(lambda r: r.update(timed_out=True))
        r = self.trabajador().ejecutar()
        e = self.estado()
        self.assertEqual((r["resultado"], r["llamadas"]), ("error_lectura", 0))
        self.assertEqual((e["cobertura"]["completa_hasta_utc"], e["marca"], e["intentos"]), (previa_agua, previa_marca, intentos))

    def test_paginacion_positiva_sigue_funcionando(self):
        self.poblar(7)
        r = self.trabajador(pagina=3, limites=dict(continua.LIMITES, por_ejecucion=10, por_hora_movil=10)).ejecutar(ensayo=True)
        self.assertEqual((r["cobertura"], r["leidos"], r["pendientes"]), ("completa", 7, 7))


class ExclusionComunTests(BaseTx):
    """Punto 3: dos vías simultáneas sobre el mismo documento (procesos/hilos distintos)."""

    def setUp(self):
        super().setUp()
        self.user = User.objects.create_superuser("adm", password="p")
        self.otro_prov = Prov()

    def _en_otro_hilo(self, fn):
        out = {}
        def hilo():
            try:
                out["r"] = fn()
            except BaseException as e:      # noqa: BLE001 - se inspecciona en la prueba
                out["e"] = e
            finally:
                connection.close()
        t = threading.Thread(target=hilo)
        t.start()
        t.join(30)
        return out

    def _vista(self, metodo, url, **kw):
        from django.test import Client
        c = Client()
        c.force_login(self.user)
        return getattr(c, metodo)(url, **kw)

    def _snapshot_intacto(self, fila):
        snap = fila.contexto_ia_snapshot
        self.assertEqual((fila.estado_analisis, snap["_medicion"]["modelo_respuesta"]), ("COMPLETED", "fake-m-001"))

    def test_automatico_y_actualizar_mismo_documento(self):
        self.poblar(1)
        raw = sentria_backend._normalizar_hit(self.idx.docs[0])
        lote = {}
        from dashboard import views as v
        real_lote = v.ingestar_lote
        def espia(alertas):
            lote["c"] = real_lote(alertas)
            return lote["c"]
        def actualizar():
            with mock.patch.object(v, "get_latest_alerts", return_value=[dict(raw)]), \
                    mock.patch.object(v, "ingestar_lote", side_effect=espia), \
                    mock.patch("dashboard.ia.analizador.obtener_proveedor", return_value=self.otro_prov):
                out = self._en_otro_hilo(lambda: self._vista("post", reverse("update_alerts")))
            self.assertEqual(out["r"].status_code, 302)
        self.prov = Prov(durante=actualizar)
        r = self.trabajador().ejecutar()
        self.assertEqual((lote["c"]["en_curso"], lote["c"]["nuevas"], lote["c"]["fallidas"]), (1, 0, 0))
        self.assertEqual((self.prov.n, self.otro_prov.n, r["llamadas"], r["completados"]), (1, 0, 1, 1))
        self._snapshot_intacto(Alert.objects.get(opensearch_id="d000"))
        self.assertEqual(Alert.objects.count(), 1)
        self.assertEqual(continua.cupo(self.estado()["intentos"], self.reloj())["hora_movil"]["usados"], 1)

    def test_automatico_y_reintento_o_reclasificacion(self):
        self.poblar(1)
        resultados = {}
        def manuales():
            fila = Alert.objects.get(opensearch_id="d000")             # PENDING mientras el trabajador llama
            with mock.patch("dashboard.ia.analizador.obtener_proveedor", return_value=self.otro_prov):
                resultados["reanalizar"] = self._en_otro_hilo(lambda: reanalizar_alerta(fila, proveedor=self.otro_prov))
                from dashboard.views import reclasificar_alertas_pendientes
                resultados["lote"] = self._en_otro_hilo(
                    lambda: reclasificar_alertas_pendientes(pausa_segundos=0, proveedor=self.otro_prov))
                resultados["vista"] = self._en_otro_hilo(
                    lambda: self._vista("post", reverse("reintentar_analisis", args=[fila.id])))
        self.prov = Prov(durante=manuales)
        r = self.trabajador().ejecutar()
        self.assertIsInstance(resultados["reanalizar"]["e"], exclusion.AnalisisEnCursoError)
        self.assertEqual((resultados["lote"]["r"]["en_curso"], resultados["lote"]["r"]["analizadas"]), (1, 0))
        self.assertEqual(resultados["vista"]["r"].status_code, 302)          # PENDING: el reintento no procede
        self.assertEqual((self.prov.n, self.otro_prov.n, r["llamadas"]), (1, 0, 1))
        self._snapshot_intacto(Alert.objects.get(opensearch_id="d000"))

    def test_reintento_manual_en_curso_y_trabajador_o_segundo_reintento(self):
        fila = Alert.objects.create(opensearch_id="d000", titulo="t", descripcion="Servicio terminó con error",
                                    severidad=5, estado_analisis="ANALISIS_FALLIDO", wazuh_agent_id="003",
                                    wazuh_rule_id="61102", wazuh_rule_groups="windows, windows_system",
                                    activo_logico=self.activo)
        self.poblar(2)
        segundo = {}
        def durante():
            segundo["vista"] = self._en_otro_hilo(
                lambda: self._vista("post", reverse("reintentar_analisis", args=[fila.id])))
            segundo["trabajador"] = self._en_otro_hilo(lambda: self.trabajador().ejecutar())
        manual = Prov(durante=durante)
        with mock.patch("dashboard.views.get_alert_by_id", return_value=None), \
                mock.patch("dashboard.ia.analizador.obtener_proveedor", return_value=manual):
            self.assertEqual(reanalizar_alerta(fila, proveedor=manual), "analizada")
        self.assertEqual(manual.n, 1)                                        # el segundo reintento no llamó
        self.assertEqual(segundo["vista"]["r"].status_code, 302)
        t = segundo["trabajador"]["r"]
        self.assertEqual(t["descartes"].get("ya_registrada"), 1)            # el trabajador no toca la fila existente
        self.assertEqual([p["opensearch_id"] for p in t["seleccion"]], ["d001"])

    def test_via_manual_con_exclusion_y_trabajador_sin_llamada_ni_cupo(self):
        self.poblar(3)
        with exclusion.exclusion_analisis("d000"):
            r = self._en_otro_hilo(lambda: self.trabajador().ejecutar())["r"]
        e = self.estado()
        d0 = next(i for i in e["intentos"] if i["opensearch_id"] == "d000")
        self.assertEqual((d0["estado"], d0["motivo"]), ("sin_llamada", "analisis_en_curso_otra_via"))
        self.assertFalse(Alert.objects.filter(opensearch_id="d000").exists())
        self.assertEqual([p["opensearch_id"] for p in r["seleccion"]], ["d000", "d001", "d002"])
        self.assertEqual((r["llamadas"], self.prov.n), (2, 2))               # documentos distintos: sin bloqueo
        self.assertEqual(continua.cupo(e["intentos"], self.reloj())["hora_movil"]["usados"], 2)

    def test_otro_proceso_con_la_exclusion(self):
        self.poblar(1)
        codigo = ("import fcntl,hashlib,os,sys,time\n"
                  "r=os.path.join(sys.argv[1],hashlib.sha256(b'd000').hexdigest()+'.lock')\n"
                  "fd=os.open(r,os.O_RDWR|os.O_CREAT,0o600);fcntl.flock(fd,fcntl.LOCK_EX)\n"
                  "print('listo',flush=True);sys.stdin.read()\n")
        exclusion.comprobar()
        hijo = subprocess.Popen([sys.executable, "-I", "-c", codigo, self.excl], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(hijo.stdout.readline().strip(), "listo")
            r = self.trabajador().ejecutar()
        finally:
            hijo.stdin.close()
            hijo.wait(10)
        self.assertEqual((r["llamadas"], r["sin_llamada"], self.prov.n), (0, 1, 0))
        self.assertFalse(Alert.objects.filter(opensearch_id="d000").exists())

    def test_ensayo_no_usa_la_exclusion(self):
        self.poblar(2)
        with exclusion.exclusion_analisis("d000"):
            r = self.trabajador().ejecutar(ensayo=True)
        self.assertEqual((r["resultado"], len(r["seleccion"])), ("ensayo", 2))

    def test_sin_reentrada_accidental_y_recuperacion_sin_anidar(self):
        with exclusion.exclusion_analisis("k"):
            with self.assertRaises(exclusion.ReentradaError):
                with exclusion.exclusion_analisis("k"):
                    pass
            with exclusion.exclusion_analisis("otra"):                       # claves distintas: independientes
                pass
        fila = Alert.objects.create(opensearch_id="d000", titulo="t", descripcion="d", severidad=5,
                                    estado_analisis="PENDING", wazuh_agent_id="003", activo_logico=self.activo)
        self.poblar(1)
        raw = sentria_backend._normalizar_hit(self.idx.docs[0])
        obj, accion = ingestar_alerta(raw, resolver=lambda a: self.activo, politica=POL5, proveedor=self.prov)
        self.assertEqual((obj.id, accion, self.prov.n), (fila.id, "recuperada:analizada", 1))

    def test_guardas_de_completed_y_prueba_controlada_se_mantienen(self):
        c = Alert.objects.create(opensearch_id="c1", titulo="t", descripcion="d", estado_analisis="COMPLETED",
                                 contexto_ia_snapshot={"x": 1})
        p = Alert.objects.create(opensearch_id="p1", titulo="t", descripcion="d", estado_analisis="ANALISIS_FALLIDO",
                                 contexto_ia_snapshot={"_experimento": {"clase": "x"}})
        self.assertEqual(reanalizar_alerta(c, proveedor=self.prov), "completed_sin_cambios")
        self.assertEqual(reanalizar_alerta(p, proveedor=self.prov), "bloqueada_experimento")
        self.assertEqual(self.prov.n, 0)

    def test_directorio_de_exclusion_inseguro_no_llama(self):
        self.poblar(2)
        os.makedirs(self.excl, mode=0o700)
        os.chmod(self.excl, 0o755)
        r = self.trabajador().ejecutar()
        self.assertEqual((r["resultado"], r["llamadas"], self.estado()["intentos"]), ("exclusion_no_disponible", 0, []))
        with self.assertRaises(exclusion.ExclusionError):
            ingestar_alerta(sentria_backend._normalizar_hit(self.idx.docs[0]), politica=POL5, proveedor=self.prov)
        self.assertEqual((self.prov.n, Alert.objects.count()), (0, 0))


class InicioYRecuperacionTests(Base):
    """Punto 4: límite inicial explícito y marca de agua persistente."""

    def test_primer_arranque_con_pendientes_de_mas_de_48h(self):
        self.poblar(3, desde=T0 - dt.timedelta(days=5), paso=dt.timedelta(hours=1))
        r = self.trabajador(desde=T0 - dt.timedelta(days=6)).ejecutar()
        self.assertEqual([p["opensearch_id"] for p in r["seleccion"]], ["d000", "d001"])
        self.assertEqual((r["ventana"]["origen_desde"], r["ventana"]["desde_utc"]),
                         ("inicio_explicito", continua._iso(T0 - dt.timedelta(days=6))))
        e = self.estado()
        self.assertEqual((e["cobertura"]["inicio_utc"], e["cobertura"]["completa_hasta_utc"]),
                         (continua._iso(T0 - dt.timedelta(days=6)), continua._iso(T0)))
        self.reloj.avanzar(minutes=15)
        self.assertEqual([p["opensearch_id"] for p in self.trabajador(desde=T0 - dt.timedelta(days=6)).ejecutar()["seleccion"]],
                         ["d002"])

    def test_sin_desde_no_lee_ni_llama_y_desde_distinto_o_futuro_se_rechaza(self):
        self.poblar(2)
        r = self.trabajador(desde=None).ejecutar()
        self.assertEqual((r["resultado"], r["error"], self.idx.consultas, self.prov.n), ("inicio_no_valido", "falta_desde", 0, 0))
        r = self.trabajador(desde=T0 + dt.timedelta(minutes=1)).ejecutar()
        self.assertEqual(r["error"], "desde_futuro")
        self.trabajador().ejecutar()
        r = self.trabajador(desde=DESDE + dt.timedelta(hours=1)).ejecutar()
        self.assertEqual((r["resultado"], r["error"]), ("inicio_no_valido", "desde_distinto_del_persistido"))
        self.assertEqual(self.trabajador(desde=None).ejecutar(ensayo=True)["resultado"], "ensayo")   # usa el persistido

    def test_nunca_lee_antes_del_inicio(self):
        self.idx.docs = [doc(0, T0 - dt.timedelta(hours=10)), doc(1, T0 - dt.timedelta(hours=2))]
        r = self.trabajador(desde=T0 - dt.timedelta(hours=5)).ejecutar()
        self.assertEqual(([p["opensearch_id"] for p in r["seleccion"]], r["leidos"]), (["d001"], 1))

    def test_parada_larga_recupera_desde_la_marca_de_agua(self):
        self.poblar(1)
        self.trabajador().ejecutar()
        agua = self.estado()["cobertura"]["completa_hasta_utc"]
        self.assertEqual(agua, continua._iso(T0))
        # Llegan alertas justo después y el trabajador queda parado 5 días (sin pendientes conocidas).
        self.idx.docs += [doc(10 + k, T0 + dt.timedelta(hours=1 + k)) for k in range(3)]
        self.reloj.avanzar(days=5)
        r = self.trabajador().ejecutar()
        self.assertEqual((r["ventana"]["origen_desde"], r["ventana"]["desde_utc"]),
                         ("marca_de_agua", continua._iso(T0 - continua.SOLAPE)))
        self.assertEqual([p["opensearch_id"] for p in r["seleccion"]], ["d010", "d011"])
        self.reloj.avanzar(minutes=15)
        self.assertEqual([p["opensearch_id"] for p in self.trabajador().ejecutar()["seleccion"]], ["d012"])

    def test_parada_larga_con_paginas_truncadas_no_salta_pendientes(self):
        self.poblar(1)
        self.trabajador().ejecutar()
        self.idx.docs += [doc(10 + k, T0 + dt.timedelta(hours=1, minutes=k)) for k in range(10)]
        self.reloj.avanzar(days=4)
        t = self.trabajador(pagina=3, max_paginas=2)
        r = t.ejecutar()
        self.assertEqual((r["cobertura"], r["leidos"]), ("incompleta", 6))
        for _ in range(10):                      # el cupo de 6 por hora espacia las invocaciones
            self.reloj.avanzar(minutes=15)
            t.ejecutar()
        enviados = [i["opensearch_id"] for i in self.estado()["intentos"]]
        self.assertEqual(enviados, ["d000"] + [f"d{10 + k:03d}" for k in range(10)])

    def test_llegada_tardia_tras_reanudar_y_limite_residual(self):
        self.poblar(1)
        self.trabajador().ejecutar()
        self.reloj.avanzar(days=3)
        # Tardía dentro del solape de la marca de agua: se recupera.
        self.idx.docs.append(doc(20, T0 - dt.timedelta(minutes=10)))
        # Tardía anterior a (marca de agua - solape) y a 48 h: límite residual documentado, no se promete.
        self.idx.docs.append(doc(21, T0 - dt.timedelta(hours=5)))
        r = self.trabajador().ejecutar()
        self.assertEqual([p["opensearch_id"] for p in r["seleccion"]], ["d020"])

    def test_ensayo_informa_inicio_y_cobertura_sin_persistir(self):
        self.poblar(2)
        r = self.trabajador().ejecutar(ensayo=True)
        self.assertEqual((r["ventana"]["inicio_utc"], r["ventana"]["origen_desde"], r["marca_de_agua_resultante_utc"]),
                         (continua._iso(DESDE), "inicio_explicito", continua._iso(T0)))
        self.assertFalse(os.path.exists(self.dir))


class AjustesMenoresTests(Base):
    def test_help_publicable_sin_identificadores_del_despliegue(self):
        from dashboard.management.commands.ingesta_continua import Command
        self.assertNotIn("003", Command.help)
        self.assertIn("agente configurado", Command.help)

    def test_confirmar_exige_exclusion_explicita_y_desde_valido(self):
        ids = ["--agente", "003", "--nombre-agente", "AGENTE-PRUEBA", "--activo", "SRV-PRUEBA-01"]
        entorno = {k: v for k, v in os.environ.items() if k != exclusion.VARIABLE_DIR}
        entorno["GEMINI_API_KEY"] = "x"
        with mock.patch.dict(os.environ, entorno, clear=True):
            with self.assertRaises(CommandError) as cm:
                call_command("ingesta_continua", "--estado-dir", self.dir, *ids, "--desde", "2026-11-12T08:00:00Z",
                             "--confirmar", stdout=io.StringIO())
        self.assertIn("SENTRIA_EXCLUSION_DIR", str(cm.exception))
        for malo in ("ayer", "2026-11-12T08:00:00"):
            with self.assertRaises(CommandError):
                call_command("ingesta_continua", "--estado-dir", self.dir, *ids, "--desde", malo, "--ensayo",
                             stdout=io.StringIO())
        self.assertFalse(os.path.exists(self.dir))

    def test_entradas_identicas_se_agrupan_sin_deduplicar(self):
        t = T0 - dt.timedelta(hours=1)
        self.idx.docs = [doc(k, t + dt.timedelta(seconds=k), wid=f"w{k}") for k in range(2)]
        for d in self.idx.docs:
            d["_source"]["data"]["win"]["system"]["systemTime"] = _ts(t)        # mismo texto de entrada
        self.trabajador().ejecutar()
        v = self.trabajador().resumen_estado(self.estado(), self.reloj())
        self.assertEqual(self.prov.n, 2)                                        # dos invocaciones, dos eventos
        self.assertEqual(len(v["entradas_identicas"]), 1)
        self.assertEqual(v["entradas_identicas"][0]["opensearch_ids"], ["d000", "d001"])


# =========================================================================== v2.1: llamadas sin cerrar
class InciertoPersistenteTests(BaseTx):
    """Una llamada que pudo ejecutarse y no quedó cerrada bloquea TODAS las vías hasta una revisión humana."""

    def setUp(self):
        super().setUp()
        self.user = User.objects.create_superuser("adm", password="p")
        self.otro = Prov()

    def _cliente(self):
        from django.test import Client
        c = Client()
        c.force_login(self.user)
        return c

    def _mensajes(self, resp):
        from django.contrib.messages import get_messages
        return [str(m) for m in get_messages(resp.wsgi_request)]

    def _foto(self, fila):
        fila.refresh_from_db()
        return {k: getattr(fila, k) for k in ("estado_analisis", "veredicto_ia", "riesgo_ia", "explicacion_ia",
                                               "contexto_ia_snapshot", "analizado_en", "proveedor_ia", "wazuh_rule_id",
                                               "wazuh_rule_groups", "activo_logico_id")}

    def _marcas(self):
        return [m["clave"] for m in exclusion.listar_inciertos()]

    def _caida_del_trabajador(self, n=3):
        self.poblar(n)
        self.prov = Prov(caida=True)
        with self.assertRaises(Caida):
            self.trabajador().ejecutar()
        self.assertEqual(self.prov.n, 1)
        return Alert.objects.get(opensearch_id="d000")

    def test_caida_durante_la_llamada_y_ninguna_via_vuelve_a_llamar(self):
        fila = self._caida_del_trabajador()
        foto = self._foto(fila)
        self.assertEqual((foto["estado_analisis"], self._marcas()), ("PENDING", ["d000"]))
        raw = sentria_backend._normalizar_hit(self.idx.docs[0])
        with mock.patch("dashboard.ia.analizador.obtener_proveedor", return_value=self.otro):
            # «Actualizar» (la última alerta del indexador es justo la incierta)
            with mock.patch("dashboard.views.get_latest_alerts", return_value=[dict(raw)]):
                r = self._cliente().post(reverse("update_alerts"))
            self.assertEqual(r.status_code, 302)
            self.assertTrue(any("requiere revisión" in m for m in self._mensajes(r)))
            # Reclasificación por lote (incluye PENDING)
            from dashboard.views import reclasificar_alertas_pendientes
            lote = reclasificar_alertas_pendientes(pausa_segundos=0, proveedor=self.otro)
            self.assertEqual((lote["requieren_revision"], lote["analizadas"]), (1, 0))
            # Reintento por la vista: aviso explícito aunque la fila no esté en fallo
            r = self._cliente().post(reverse("reintentar_analisis", args=[fila.id]))
            self.assertTrue(any("Reintento no disponible" in m and "requiere revisión" in m for m in self._mensajes(r)))
            # Reanálisis directo e ingesta manual dirigida
            with self.assertRaises(exclusion.AnalisisInciertoError):
                reanalizar_alerta(fila, proveedor=self.otro)
            with self.assertRaises(exclusion.AnalisisInciertoError):
                ingestar_alerta(dict(raw), resolver=lambda a: self.activo, politica=POL5, proveedor=self.otro)
        self.assertEqual(self.otro.n, 0)                                   # ninguna llamada nueva
        self.assertEqual(self._foto(fila), foto)                           # resultado intacto
        # El trabajador, reiniciado: cierra su intento como incierto, no lo reintenta y sigue con los demás.
        self.prov = Prov()
        r = self.trabajador().ejecutar()
        self.assertEqual([p["opensearch_id"] for p in r["seleccion"]], ["d001", "d002"])
        self.assertEqual((r["inciertos_cerrados"], self.prov.n), (1, 2))
        v = self.trabajador().resumen_estado(self.estado(), self.reloj())
        self.assertEqual((v["inciertos_para_revisar"], [m["clave"] for m in v["llamadas_sin_cerrar"]]), (["d000"], ["d000"]))
        self.assertEqual(continua.cupo(self.estado()["intentos"], self.reloj())["hora_movil"]["usados"], 3)   # 1 + 2
        self.assertEqual(self._foto(fila), foto)

    def test_reintento_manual_interrumpido_tambien_queda_bloqueado(self):
        fila = Alert.objects.create(opensearch_id="m1", titulo="t", descripcion="Servicio terminó con error", severidad=5,
                                    estado_analisis="ANALISIS_FALLIDO", wazuh_agent_id="003",
                                    wazuh_rule_groups="windows, windows_system", activo_logico=self.activo)
        with self.assertRaises(Caida):
            reanalizar_alerta(fila, proveedor=Prov(caida=True), resolver=lambda a: self.activo, politica=POL5)
        foto = self._foto(fila)
        self.assertEqual((foto["estado_analisis"], self._marcas()), ("ANALISIS_FALLIDO", ["m1"]))
        with mock.patch("dashboard.ia.analizador.obtener_proveedor", return_value=self.otro), \
                mock.patch("dashboard.views.get_alert_by_id", return_value=None):
            r = self._cliente().post(reverse("reintentar_analisis", args=[fila.id]))
            self.assertTrue(any("requiere revisión" in m for m in self._mensajes(r)))
            from dashboard.views import reclasificar_alertas_pendientes
            self.assertEqual(reclasificar_alertas_pendientes(pausa_segundos=0, proveedor=self.otro)["requieren_revision"], 1)
            # «Actualizar»/ingesta con evidencia fresca: ni siquiera completa la procedencia vacía (regla) de la fila.
            raw = {"opensearch_id": "m1", "agent_id": "003", "rule_id": "61102", "level": 5,
                   "description": "Servicio terminó con error", "groups": "windows, windows_system"}
            with mock.patch("dashboard.views.get_latest_alerts", return_value=[raw]):
                self._cliente().post(reverse("update_alerts"))
        self.assertEqual((self.otro.n, self._foto(fila)), (0, foto))
        self.assertIsNone(foto["wazuh_rule_id"])

    def test_la_marca_sobrevive_al_reinicio(self):
        self._caida_del_trabajador(1)
        codigo = ("import sys; sys.path.insert(0, sys.argv[1]); from dashboard.ia import exclusion as e\n"
                  "try:\n    e.comprobar_no_incierto('d000'); print('libre')\n"
                  "except e.AnalisisInciertoError:\n    print('requiere_revision')\n")
        hijo = subprocess.run([sys.executable, "-I", "-c", codigo, os.getcwd()], capture_output=True, text=True,
                              env={"SENTRIA_EXCLUSION_DIR": self.excl, "PATH": os.environ.get("PATH", "")}, timeout=30)
        self.assertEqual(hijo.stdout.strip(), "requiere_revision")         # otro proceso, sin estado en memoria
        with open(os.path.join(self.excl, hashlib.sha256(b"d000").hexdigest() + ".incierto"), encoding="utf-8") as f:
            m = json.load(f)
        self.assertEqual((m["clave"], m["via"], m["alert_id"]), ("d000", "ingesta", Alert.objects.get(opensearch_id="d000").id))
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.excl, hashlib.sha256(b"d000").hexdigest() + ".incierto")).st_mode), 0o600)

    def test_llamadas_cerradas_no_dejan_marca_y_documentos_distintos_siguen(self):
        self.poblar(3)
        self.prov = Prov([{}, {"ok": False, "texto": "", "error": "timeout"}])       # una correcta y una fallida
        r = self.trabajador().ejecutar()
        self.assertEqual((r["completados"], r["fallidos"], self._marcas()), (1, 1, []))
        fallida = Alert.objects.get(opensearch_id="d001")
        self.assertEqual(reanalizar_alerta(fallida, proveedor=Prov(), resolver=lambda a: self.activo, politica=POL5),
                         "analizada")                                      # la vía manual sigue funcionando
        self.assertEqual(self._marcas(), [])
        # Una marca en d000 no afecta a otro documento.
        exclusion.abrir_llamada("d000", "prueba")
        self.reloj.avanzar(minutes=15)
        self.prov = Prov()
        self.assertEqual([p["opensearch_id"] for p in self.trabajador().ejecutar()["seleccion"]], ["d002"])

    def test_guardas_de_completed_y_prueba_controlada_sin_marca(self):
        c = Alert.objects.create(opensearch_id="c1", titulo="t", descripcion="d", estado_analisis="COMPLETED",
                                 contexto_ia_snapshot={"x": 1})
        p = Alert.objects.create(opensearch_id="p1", titulo="t", descripcion="d", estado_analisis="ANALISIS_FALLIDO",
                                 contexto_ia_snapshot={"_experimento": {"clase": "x"}})
        self.assertEqual(reanalizar_alerta(c, proveedor=self.prov), "completed_sin_cambios")
        self.assertEqual(reanalizar_alerta(p, proveedor=self.prov), "bloqueada_experimento")
        self.assertEqual((self.prov.n, self._marcas()), (0, []))
        # Con marca, una COMPLETED tampoco cambia (se avisa en lugar de decir «duplicada»).
        exclusion.abrir_llamada("c1", "prueba")
        with self.assertRaises(exclusion.AnalisisInciertoError):
            reanalizar_alerta(c, proveedor=self.prov)
        self.assertEqual((Alert.objects.get(pk=c.pk).contexto_ia_snapshot, self.prov.n), ({"x": 1}, 0))

    def test_marca_no_registrable_no_llama(self):
        self.poblar(1)
        exclusion.comprobar()
        os.chmod(self.excl, 0o500)                                          # no se puede escribir la marca
        try:
            with self.assertRaises(exclusion.ExclusionError):
                ingestar_alerta(sentria_backend._normalizar_hit(self.idx.docs[0]), resolver=lambda a: self.activo,
                                politica=POL5, proveedor=self.prov)
        finally:
            os.chmod(self.excl, 0o700)
        self.assertEqual(self.prov.n, 0)

    def test_revision_listar_sin_cambios_y_liberar_con_motivo(self):
        fila = self._caida_del_trabajador(1)
        foto = self._foto(fila)
        out = io.StringIO()
        call_command("revisar_incierto", "--listar", stdout=out)
        lista = json.loads(out.getvalue())
        self.assertEqual((lista[0]["clave"], lista[0]["fila"]["estado_analisis"], lista[0]["fila"]["tiene_medicion"]),
                         ("d000", "PENDING", False))
        self.assertEqual((self._foto(fila), self._marcas()), (foto, ["d000"]))      # listar no cambia nada
        with self.assertRaises(CommandError):
            call_command("revisar_incierto", "--liberar", "d000", stdout=io.StringIO())     # sin motivo
        with self.assertRaises(CommandError):
            call_command("revisar_incierto", "--liberar", "otra", "--motivo", "m", "--revisor", "r", stdout=io.StringIO())
        out = io.StringIO()
        call_command("revisar_incierto", "--liberar", "d000", "--motivo", "sin uso registrado en la consola",
                     "--revisor", "analista", stdout=out)
        self.assertEqual(json.loads(out.getvalue())["liberado"]["revision"]["revisor"], "analista")
        self.assertEqual((self._marcas(), self.otro.n, self.prov.n), ([], 0, 1))    # liberar no envía nada
        self.assertTrue(any(n.startswith(hashlib.sha256(b"d000").hexdigest() + ".revisado.") for n in os.listdir(self.excl)))
        self.assertEqual(self._foto(fila), foto)
        # Tras la revisión, una vía MANUAL puede volver a analizar (llamada nueva y consciente); el trabajador no.
        self.assertEqual(reanalizar_alerta(fila, proveedor=self.otro, resolver=lambda a: self.activo, politica=POL5),
                         "analizada")
        self.assertEqual(self.otro.n, 1)
        self.prov = Prov()
        self.reloj.avanzar(minutes=15)
        self.assertEqual(self.trabajador().ejecutar()["llamadas"], 0)

    def test_revisar_exige_directorio_explicito(self):
        entorno = {k: v for k, v in os.environ.items() if k != exclusion.VARIABLE_DIR}
        with mock.patch.dict(os.environ, entorno, clear=True):
            with self.assertRaises(CommandError):
                call_command("revisar_incierto", "--listar", stdout=io.StringIO())
