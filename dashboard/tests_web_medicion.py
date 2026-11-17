"""
Evidencia web de extremo a extremo y medición por intento (candidato web_y_comparacion_v1).

Sin red ni proveedores reales: fixtures sintéticos y proveedores simulados, BD de pruebas aislada.
"""
import datetime
import hashlib
import json
from types import SimpleNamespace
from unittest import mock

from django.test import TestCase, override_settings

import sentria_backend
from dashboard.dataset import construir_entrada, fingerprint_entrada
from dashboard.ia import proveedores
from dashboard.ia.analizador import analizar_alerta
from dashboard.ia.evidencia import construir_evidencia_tecnica, evidencia_web
from dashboard.ia.ingesta import ingestar_alerta, reanalizar_alerta
from dashboard.ia.politica import cargar_politica, evaluar_elegibilidad
from dashboard.ia.prompt import construir_entrada_e, construir_prompt, hora_del_evento
from dashboard.models import ActivoLogico, Alert

SALIDA = {
    "schema_version": "1.0", "verdict": "REQUIERE_ATENCION", "risk": "LOW",
    "explanation_es": "Respuesta HTTP de acceso denegado sin más evidencia; requiere revisión humana.",
    "cvss_factors": {k: "no_determinado" for k in (
        "attack_vector", "attack_complexity", "privileges_required", "user_interaction", "scope",
        "confidentiality_impact", "integrity_impact", "availability_impact")},
    "cvss_reasoning_es": "Factores no determinados: la entrada no trae factores observados que los sostengan.",
    "recommendation_es": "Revisar el servicio web y su configuración de acceso.",
    "missing_evidence": ["Identidad del cliente"],
}

# Valores privados inyectados a propósito en el documento: no deben aparecer en ningún resultado.
PRIVADOS = ("10.9.8.7", "/judge/secreto?usuario=bob", "usuario=bob", "bob@example.org", "Cookie-XYZ",
            "tok_SECRETO_123", "ref-cliente-777", "uid-evento-555", "Mozilla/5.0 privado")


def _doc(status=401, *, level=5, rule="119602", mode="live", service="domjudge", web_extra=None, data_extra=None,
         ts="2026-11-12T18:00:05.000+0000", source_time="2026-11-12T18:00:01+00:00", osid="w-1"):
    web = {"schema_version": 1, "kind": "http_access", "service": service, "http_method": "POST",
           "http_status": status, "response_bytes": 512, "route_class": "authentication_route", "has_query": True,
           "source_time_utc": source_time, "mode": mode,
           # privados que el recolector NO debería enviar, o que un productor distinto podría añadir:
           "url": PRIVADOS[1], "client_ref": PRIVADOS[6], "event_uid": PRIVADOS[7], "client_ip": PRIVADOS[0],
           "user": PRIVADOS[3], "headers": {"Cookie": PRIVADOS[4], "Authorization": PRIVADOS[5]},
           "user_agent": PRIVADOS[8]}
    web.update(web_extra or {})
    data = {"sentria_source": "web_access", "sentria_web": web, "srcip": PRIVADOS[0]}
    data.update(data_extra or {})
    return {"_id": osid, "_source": {
        "rule": {"description": f"Acceso HTTP requiere autenticacion o fue denegado: {service}, respuesta {status}. "
                                "No confirma un ataque.",
                 "level": level, "groups": ["sentria_web", "web", "accesslog"], "id": rule, "firedtimes": 3},
        "agent": {"id": "003", "name": "HOST-PRIVADO", "ip": "10.0.0.99"},
        "decoder": {"name": "json"}, "@timestamp": ts, "data": data, "full_log": PRIVADOS[1]}}


def _alerta(*a, **kw):
    return sentria_backend._normalizar_hit(_doc(*a, **kw))


def _activo():
    return ActivoLogico.objects.create(
        identificador="SRV-WEB-T", nombre_visible="Servidor web de prueba", tipo_activo="servidor_interno",
        criticidad="media", os_family="windows", os_role="servidor",
        hora_inicio_operacion=datetime.time(0, 0), hora_fin_operacion=datetime.time(23, 59),
        horario_sin_restriccion=True, contexto_autorizado_es="Servidor con servicios web y administración.")


class _Fake(proveedores.ProveedorIA):
    nombre = "gemini_developer"

    def __init__(self, *, ok=True, texto=None, usage=None, error=None, excepcion=None, mv=None, params=True):
        self.n, self.prompts = 0, []
        self._ok, self._texto, self._usage, self._error, self._exc, self._mv = ok, texto, usage, error, excepcion, mv
        self._params = params

    def parametros_medicion(self):
        return {"temperature": 0.1, "reintentos_configurados": 0} if self._params else None

    def analizar(self, prompt):
        self.n += 1
        self.prompts.append(prompt)
        if self._exc is not None:
            raise self._exc
        return proveedores.RespuestaProveedor(
            ok=self._ok, texto=self._texto if self._texto is not None else json.dumps(SALIDA), modelo="fake-m",
            error=self._error, finish_reason="STOP" if self._ok else None, usage=self._usage,
            modelo_respuesta=self._mv)


def _sin_privados(caso, *objetos):
    blob = json.dumps(objetos, ensure_ascii=False, default=str)
    for p in PRIVADOS + ("HOST-PRIVADO", "10.0.0.99"):
        caso.assertNotIn(p, blob)


class ProyeccionWebTests(TestCase):
    def test_estados_401_403_500_y_200(self):
        for status in (401, 403, 500, 200):
            web = _alerta(status)["web"]
            self.assertEqual(web["http_status"], status)
            self.assertEqual(set(web), {"service", "http_method", "http_status", "response_bytes", "route_class",
                                        "has_query", "source_time_utc", "procedencia"})
            self.assertEqual(web["procedencia"], "en_vivo")

    def test_campos_privados_no_se_proyectan(self):
        _sin_privados(self, _alerta(401)["web"])
        self.assertTrue(all(c.startswith("data.sentria") or not c.startswith("data.sentria_web.")
                            for c in sentria_backend._SOURCE_FIELDS))
        for prohibido in ("url", "client_ref", "event_uid", "client_ip", "user", "headers", "collected_time_utc"):
            self.assertNotIn(f"data.sentria_web.{prohibido}", sentria_backend._SOURCE_FIELDS)

    def test_malformados(self):
        self.assertIsNone(_alerta(401, web_extra={"schema_version": 2})["web"])
        self.assertIsNone(_alerta(401, web_extra={"kind": "otro"})["web"])
        self.assertIsNone(_alerta(401, service="nginx-desconocido")["web"])
        self.assertIsNone(_alerta("4O1")["web"])
        self.assertIsNone(_alerta(601)["web"])
        self.assertIsNone(_alerta(401, data_extra={"sentria_source": "otra"})["web"])
        w = _alerta(401, web_extra={"http_method": "BORRAR<script>", "response_bytes": "-", "route_class": "/x/y",
                                    "has_query": "quizá", "source_time_utc": "2026-11-12 18:00:01", "mode": "inventado"})["web"]
        self.assertEqual((w["http_method"], w["response_bytes"], w["route_class"], w["has_query"], w["source_time_utc"],
                          w["procedencia"]), ("OTHER", None, "no_determinado", None, None, "no_determinado"))
        self.assertIsNone(_alerta(401, web_extra={"response_bytes": -5})["web"]["response_bytes"])

    def test_mode_estructurado_no_interrumpe(self):
        for modo in ({}, [], {"x": 1}, ["live"], 1, None):
            w = _alerta(401, web_extra={"mode": modo})["web"]
            self.assertEqual((w["http_status"], w["procedencia"]), (401, "no_determinado"))
        self.assertEqual(_alerta(401, mode="live")["web"]["procedencia"], "en_vivo")
        self.assertEqual(_alerta(401, mode="historical_replay")["web"]["procedencia"], "historico_reproducido")

    def test_has_query_por_tipo(self):
        for valor, esperado in ((True, True), (False, False), ("true", True), ("false", False), (0, None), (1, None),
                                ({}, None), ([], None), ({"a": 1}, None), (["true"], None), ("True", None),
                                ("1", None), (None, None)):
            self.assertIs(_alerta(401, web_extra={"has_query": valor})["web"]["has_query"], esperado, repr(valor))

    def test_lista_con_malformados_no_aborta(self):
        hits = [_doc(401, osid="a", web_extra={"mode": {}}), _doc(403, osid="b", web_extra={"mode": []}),
                _doc(500, osid="c", web_extra={"has_query": {"q": 1}}), _doc(401, osid="d")]
        resp = mock.Mock(status_code=200, raise_for_status=mock.Mock(),
                         json=mock.Mock(return_value={"hits": {"hits": hits}}))
        with mock.patch.object(sentria_backend, "_consultar_indexador", return_value=resp):
            alertas = sentria_backend.get_latest_alerts(size=4, agent_id="003")
        self.assertEqual([a["opensearch_id"] for a in alertas], ["a", "b", "c", "d"])
        self.assertEqual([a["web"]["procedencia"] for a in alertas],
                         ["no_determinado", "no_determinado", "en_vivo", "en_vivo"])
        self.assertIsNone(alertas[2]["web"]["has_query"])

    def test_documento_no_web_sin_capa_web(self):
        doc = _doc(401)
        doc["_source"]["data"] = {"win": {"system": {"eventID": "7023", "channel": "System"}}}
        self.assertIsNone(sentria_backend._normalizar_hit(doc)["web"])

    def test_procedencia_historico_reproducido(self):
        self.assertEqual(_alerta(401, mode="historical_replay")["web"]["procedencia"], "historico_reproducido")


class EvidenciaYPromptWebTests(TestCase):
    def setUp(self):
        self.activo = _activo()

    def test_evidencia_web_llega_al_texto_del_proveedor(self):
        for status in (401, 403, 500, 200):
            e = construir_entrada_e(_alerta(status), self.activo)
            p = construir_prompt(e)
            self.assertIn(f"respuesta HTTP {status} ({str(status)[0]}xx)", p)
            self.assertIn(f"código de respuesta HTTP: {status}", p)
            self.assertIn("servicio web: domjudge", p)
            self.assertIn("método HTTP: POST", p)
            self.assertIn("clase de ruta (sin la ruta): authentication_route", p)
            self.assertIn("parámetros de consulta presentes (sin valores): si", p)
            self.assertIn("bytes de respuesta: 512", p)
            self.assertIn("procedencia del registro web: en_vivo", p)
            self.assertIn("no confirma autenticación fallida ni ataque", p)
            _sin_privados(self, e, p)

    def test_identificado_como_web_no_como_windows(self):
        a = _alerta(401)
        ev = construir_evidencia_tecnica(a)
        self.assertEqual(ev["telemetry_source"], "wazuh_acceso_web")
        self.assertFalse([k for k in ev if k.startswith("win_")])
        momento, fuente, _ = hora_del_evento(a)
        self.assertEqual(fuente, "hora_original_web")
        self.assertEqual(momento.isoformat(), "2026-11-12T18:00:01+00:00")

    def test_hora_original_ausente_o_futura(self):
        self.assertEqual(hora_del_evento(_alerta(401, source_time=None))[1], "hora_original_ausente")
        self.assertEqual(hora_del_evento(_alerta(401, source_time="2026-11-12T19:00:00+00:00"))[1],
                         "hora_original_incoherente")

    def test_historico_reproducido_conserva_hora_y_procedencia(self):
        a = _alerta(401, mode="historical_replay", source_time="2025-03-02T04:05:06+00:00")
        momento, fuente, recepcion = hora_del_evento(a)
        self.assertEqual((fuente, momento.year), ("hora_original_web", 2025))
        self.assertGreater(recepcion, momento)
        self.assertIn("Procedencia: historico_reproducido", construir_prompt(construir_entrada_e(a, self.activo)))

    def test_hora_original_en_diagnostico_no_en_texto(self):
        a = _alerta(401, mode="historical_replay", source_time="2026-07-12T01:05:53+00:00")
        r = analizar_alerta(a, self.activo, proveedor=_Fake())
        d = r["contexto_ia_snapshot"]["_diagnostico_tiempo"]
        self.assertEqual((d["fuente"], d["hora_evento_utc"]), ("hora_original_web", "2026-07-12T01:05:53+00:00"))
        texto = construir_prompt({k: v for k, v in r["contexto_ia_snapshot"].items() if not k.startswith("_")})
        self.assertNotIn("2026-07-12", texto)
        self.assertIn("historico_reproducido", texto)

    def test_evidencia_web_revalida_dict_ajeno(self):
        self.assertEqual(evidencia_web({"service": "domjudge", "http_status": "401", "http_method": "X; rm",
                                        "route_class": "/ruta/privada", "response_bytes": True,
                                        "procedencia": "en_vivo<script>"}),
                         {"web_servicio": "domjudge", "web_metodo_http": "no_determinado", "web_estado_http": "401",
                          "web_clase_estado": "4xx", "web_bytes_respuesta": "no_determinado",
                          "web_clase_ruta": "no_determinado", "web_con_query": "no_determinado",
                          "web_procedencia": "no_determinado"})
        self.assertEqual(evidencia_web(None), {})
        self.assertEqual(evidencia_web({"service": "otro", "http_status": 401}), {})

    def test_otros_tipos_sin_campos_web(self):
        fim = {"description": "Integrity checksum changed.", "level": 7, "groups": "ossec,syscheck,syscheck_entry_modified",
               "rule_id": "550", "syscheck_path": "/etc/hosts", "syscheck_event": "modified", "web": None}
        self.assertFalse([k for k in construir_evidencia_tecnica(fim) if k.startswith("web_")])
        win = {"description": "Servicio terminó", "level": 5, "groups": "windows,windows_system,system_error",
               "rule_id": "61102", "decoder_name": "windows_eventchannel",
               "win": {"event_id": "7023", "channel": "System", "proveedor": "Service Control Manager"}}
        ev = construir_evidencia_tecnica(win)
        self.assertEqual(ev["telemetry_source"], "wazuh_agent")
        self.assertFalse([k for k in ev if k.startswith("web_")])


@override_settings(IA_POLITICA={"nivel_minimo": 5})
class PoliticaWebTests(TestCase):
    def test_minimo_5_y_contexto(self):
        pol = cargar_politica()
        self.assertEqual(pol.nivel_minimo, 5)
        self.assertTrue(evaluar_elegibilidad(_alerta(401), True, pol).elegible)
        self.assertTrue(evaluar_elegibilidad(_alerta(500, rule="119603"), True, pol).elegible)
        self.assertEqual(evaluar_elegibilidad(_alerta(200, level=3, rule="119601"), True, pol).motivo_omision,
                         "NIVEL_NO_ELEGIBLE")
        self.assertEqual(evaluar_elegibilidad(_alerta(401), False, pol).motivo_omision, "SIN_CONTEXTO_ACTIVO")

    def test_nivel_no_se_reclasifica(self):
        self.assertEqual(_alerta(500, level=5, rule="119603")["level"], 5)
        e = construir_entrada_e(_alerta(500, level=5, rule="119603"), _activo())
        self.assertEqual(e["wazuh_level"], 5)


class MedicionTests(TestCase):
    def setUp(self):
        self.activo = _activo()

    def test_exito_con_tokens_y_entrada_inalterada(self):
        fake = _Fake(usage={"prompt": 1200, "candidates": 300, "thoughts": None, "total": 1500}, mv="modelo-v-001")
        r = analizar_alerta(_alerta(401), self.activo, proveedor=fake)
        self.assertEqual(r["estado_analisis"], "COMPLETED")
        m = r["contexto_ia_snapshot"]["_medicion"]
        self.assertEqual(m["tokens"], {"entrada": 1200, "salida": 300, "razonamiento": None, "total": 1500})
        self.assertEqual((m["estado_llamada"], m["estado_analisis"], m["categoria_fallo_analisis"], m["categoria_error_llamada"],
                          m["invocaciones_analizador"], m["tokens_fuente"], m["extension_web"]),
                         ("ok", "COMPLETED", None, None, 1, "usage_del_proveedor", "sentria_web_v1"))
        self.assertEqual((m["modelo_configurado"], m["modelo_respuesta"]), ("fake-m", "modelo-v-001"))
        self.assertEqual(m["entrada_sha256"], hashlib.sha256(fake.prompts[0].encode()).hexdigest())
        self.assertEqual(m["parametros"], {"temperature": 0.1, "reintentos_configurados": 0})
        self.assertEqual((m["reintentos_configurados"], m["intentos_http_observados"]), (0, None))
        self.assertIsInstance(m["duracion_llamada_s"], float)
        self.assertGreaterEqual(m["duracion_analisis_s"], m["duracion_llamada_s"])
        self.assertTrue(m["inicio_llamada_utc"].endswith("+00:00"))
        self.assertEqual(m["id_local"], "w-1")
        # la medición no cambia el texto ni la entrada del dataset ni su huella
        snap = r["contexto_ia_snapshot"]
        sin_p = {k: v for k, v in snap.items() if not k.startswith("_")}
        self.assertEqual(construir_prompt(sin_p), fake.prompts[0])
        ent = construir_entrada(SimpleNamespace(contexto_ia_snapshot=snap))
        self.assertNotIn("_medicion", ent)
        self.assertEqual(fingerprint_entrada(ent),
                         fingerprint_entrada(construir_entrada(SimpleNamespace(contexto_ia_snapshot=sin_p))))
        self.assertNotIn("1500", fake.prompts[0].split("--- ALERTA ---")[1])

    def test_proveedor_sin_conteos_ni_parametros(self):
        r = analizar_alerta(_alerta(401), self.activo, proveedor=_Fake(params=False))
        m = r["contexto_ia_snapshot"]["_medicion"]
        self.assertEqual(m["tokens"], {"entrada": None, "salida": None, "razonamiento": None, "total": None})
        self.assertEqual((m["tokens_fuente"], m["parametros"], m["reintentos_configurados"], m["modelo_respuesta"]),
                         ("no_disponible", None, None, None))

    def test_fallo_del_proveedor_sin_secretos(self):
        fake = _Fake(ok=False, texto="", error="HTTP 429 cuota; api_key=tok_SECRETO_123",
                     usage={"prompt": 900, "candidates": None, "thoughts": None, "total": None})
        r = analizar_alerta(_alerta(500, rule="119603"), self.activo, proveedor=fake)
        self.assertEqual(r["estado_analisis"], "ANALISIS_FALLIDO")
        m = r["contexto_ia_snapshot"]["_medicion"]
        self.assertEqual((m["estado_llamada"], m["categoria_error_llamada"], m["estado_analisis"],
                          m["categoria_fallo_analisis"], m["tokens"]["entrada"]),
                         ("error", "proveedor_no_disponible", "ANALISIS_FALLIDO", "proveedor_no_disponible", 900))
        self.assertNotIn("tok_SECRETO_123", json.dumps(m))

    def test_excepcion_del_proveedor(self):
        fake = _Fake(excepcion=RuntimeError("fallo con Authorization: Bearer tok_SECRETO_123"))
        r = analizar_alerta(_alerta(403), self.activo, proveedor=fake)
        m = r["contexto_ia_snapshot"]["_medicion"]
        self.assertEqual((m["estado_llamada"], m["categoria_error_llamada"], m["invocaciones_analizador"],
                          m["estado_analisis"], m["categoria_fallo_analisis"]),
                         ("error", "proveedor_excepcion", 1, "ANALISIS_FALLIDO", "proveedor_excepcion"))
        self.assertNotIn("tok_SECRETO_123", json.dumps(m))

    def test_entrada_no_representable_en_contrato_cerrado_sin_llamada(self):
        class _Ajustado(_Fake):
            nombre = "vertex_tuned"
            formato_entrada = "exp-entrada-1"
        fake = _Ajustado()
        r = analizar_alerta(_alerta(401), self.activo, proveedor=fake)
        self.assertEqual((r["estado_analisis"], fake.n), ("ANALISIS_FALLIDO", 0))
        m = r["contexto_ia_snapshot"]["_medicion"]
        self.assertEqual((m["estado_llamada"], m["motivo_sin_llamada"], m["categoria_error_llamada"],
                          m["invocaciones_analizador"], m["estado_analisis"], m["categoria_fallo_analisis"]),
                         ("sin_llamada", "entrada_no_representable", None, 0, "ANALISIS_FALLIDO", "entrada_no_representable"))

    def _rechazo(self, salida, *, privacidad=False):
        uso = {"prompt": 1000, "candidates": 200, "thoughts": None, "total": 1200}
        fake = _Fake(texto=salida if isinstance(salida, str) else json.dumps(salida), usage=uso, mv="mv-1")
        fake.valida_privacidad_salida = privacidad
        r = analizar_alerta(_alerta(401), self.activo, proveedor=fake)
        m = r["contexto_ia_snapshot"]["_medicion"]
        self.assertEqual((r["estado_analisis"], m["estado_llamada"], m["categoria_error_llamada"], m["estado_analisis"]),
                         ("ANALISIS_FALLIDO", "ok", None, "ANALISIS_FALLIDO"))
        self.assertEqual(m["categoria_fallo_analisis"], r["contexto_ia_snapshot"]["_diagnostico_fallo"]["categoria"])
        self.assertEqual((m["tokens"]["total"], m["modelo_respuesta"], fake.n), (1200, "mv-1", 1))
        self.assertIsInstance(m["duracion_llamada_s"], float)
        self.assertIsInstance(m["duracion_analisis_s"], float)
        return m["categoria_fallo_analisis"]

    def test_respuesta_ok_json_invalido(self):
        self.assertEqual(self._rechazo("esto no es JSON"), "no_json")

    def test_respuesta_ok_incumple_contrato(self):
        self.assertEqual(self._rechazo(dict(SALIDA, verdict="QUIZA")), "contrato_invalido")

    def test_respuesta_ok_rechazada_por_privacidad(self):
        salida = dict(SALIDA, explanation_es="El acceso procede de 10.1.2.3 y requiere revisión humana del servicio.")
        self.assertEqual(self._rechazo(salida, privacidad=True), "bloqueo_privacidad")

    def test_respuesta_ok_rechazada_por_sustento(self):
        salida = dict(SALIDA, cvss_factors=dict(SALIDA["cvss_factors"], attack_vector="fisico"))
        self.assertEqual(self._rechazo(salida), "factor_sin_sustento")

    def test_extension_web_solo_en_eventos_web(self):
        win = {"description": "Servicio terminó", "level": 5, "groups": "windows,windows_system,system_error",
               "rule_id": "61102", "decoder_name": "windows_eventchannel", "timestamp": "2026-11-12T16:37:43.000+0000",
               "win": {"event_id": "7023", "channel": "System", "proveedor": "Service Control Manager",
                       "system_time": "2026-11-12T16:37:40Z"}}
        m = analizar_alerta(win, self.activo, proveedor=_Fake())["contexto_ia_snapshot"]["_medicion"]
        self.assertIsNone(m["extension_web"])

    def test_gemini_sdk_simulado_entrega_uso_y_version(self):
        resp = SimpleNamespace(text=json.dumps(SALIDA), parsed=SALIDA, model_version="gemini-x-001",
                               candidates=[SimpleNamespace(finish_reason=SimpleNamespace(name="STOP"))],
                               usage_metadata=SimpleNamespace(prompt_token_count=10, candidates_token_count=5,
                                                              thoughts_token_count=None, total_token_count=15))
        prov = proveedores.GeminiDeveloperProvider()
        cliente = SimpleNamespace(models=SimpleNamespace(generate_content=mock.Mock(return_value=resp)))
        with mock.patch.object(prov, "_cliente", return_value=cliente), mock.patch.object(prov, "_config", return_value=None):
            r = prov.analizar("texto")
        self.assertEqual((r.ok, r.usage["total"], r.modelo_respuesta), (True, 15, "gemini-x-001"))
        params = prov.parametros_medicion()
        self.assertEqual((params["temperature"], params["reintentos_configurados"]), (0.1, 0))
        self.assertFalse({"api_key", "authorization", "headers", "endpoint", "url"} & {k.lower() for k in params})


class ReconstruccionYCompletadasTests(TestCase):
    def setUp(self):
        self.activo = _activo()

    def _resolver(self, alert):
        return self.activo

    def test_reingesta_de_fallida_conserva_evidencia_web(self):
        a = _alerta(401)
        fake_mal = _Fake(ok=False, texto="", error="timeout")
        obj, accion = ingestar_alerta(a, resolver=self._resolver, proveedor=fake_mal)
        self.assertEqual((accion, obj.estado_analisis), ("fallida", "ANALISIS_FALLIDO"))
        fake = _Fake()
        obj2, accion2 = ingestar_alerta(_alerta(401), resolver=self._resolver, proveedor=fake)
        self.assertEqual((obj2.pk, accion2), (obj.pk, "recuperada:analizada"))
        self.assertIn("código de respuesta HTTP: 401", fake.prompts[0])
        self.assertIn("web_estado_http", Alert.objects.get(pk=obj.pk).contexto_ia_snapshot["evidencia_tecnica"])

    def _reingesta(self, primera, fresca):
        obj, accion = ingestar_alerta(primera, resolver=self._resolver, proveedor=_Fake(ok=False, texto="", error="timeout"))
        self.assertEqual(obj.estado_analisis, "ANALISIS_FALLIDO")
        fake = _Fake()
        obj2, accion2 = ingestar_alerta(fresca, resolver=self._resolver, proveedor=fake)
        self.assertEqual((obj2.pk, accion2, fake.n), (obj.pk, "recuperada:analizada", 1))
        return fake.prompts[0], Alert.objects.get(pk=obj.pk).contexto_ia_snapshot["evidencia_tecnica"]

    def test_reingesta_fim_usa_evidencia_nueva(self):
        base = {"opensearch_id": "fim-1", "agent_id": "003", "description": "Integrity checksum changed.", "level": 7,
                "groups": "ossec,syscheck,syscheck_entry_modified", "rule_id": "550",
                "timestamp": "2026-11-12T10:00:00.000+0000", "syscheck_path": "/etc/hosts", "syscheck_hash_present": True}
        texto, ev = self._reingesta(dict(base, syscheck_event="added"), dict(base, syscheck_event="modified"))
        self.assertIn("Evento FIM: modified", texto)
        self.assertEqual((ev["fim_event_type"], ev["path_category"]), ("modified", "configuracion_sistema"))

    def test_reingesta_windows_usa_evidencia_nueva(self):
        base = {"opensearch_id": "win-1", "agent_id": "003", "description": "Servicio terminó con error", "level": 5,
                "groups": "windows,windows_system,system_error", "rule_id": "61102", "decoder_name": "windows_eventchannel",
                "timestamp": "2026-11-12T16:37:43.000+0000"}
        win = {"channel": "System", "proveedor": "Service Control Manager", "system_time": "2026-11-12T16:37:40Z"}
        texto, ev = self._reingesta(dict(base, win=dict(win, event_id="7023")), dict(base, win=dict(win, event_id="7031")))
        self.assertIn("ID de evento de Windows: 7031", texto)
        self.assertEqual(ev["win_id_evento"], "7031")

    def test_completada_no_se_toca(self):
        # equivalente a la fila 208: COMPLETED, Windows, snapshot sin `_medicion`
        snap = {"schema_version": "1.4", "wazuh_level": 5, "evidencia_tecnica": {"win_id_evento": "7023"}}
        fila = Alert.objects.create(opensearch_id="w-208", titulo="t", descripcion="d", severidad=5,
                                    estado_analisis="COMPLETED", veredicto_ia="REQUIERE_ATENCION", riesgo_ia="LOW",
                                    activo_logico=self.activo, wazuh_agent_id="003", contexto_ia_snapshot=snap)
        fake = _Fake()
        self.assertEqual(reanalizar_alerta(fila, proveedor=fake, resolver=self._resolver), "completed_sin_cambios")
        _, accion = ingestar_alerta(_alerta(401, osid="w-208"), resolver=self._resolver, proveedor=fake)
        self.assertEqual((accion, fake.n), ("duplicada", 0))
        fila.refresh_from_db()
        self.assertEqual(fila.contexto_ia_snapshot, snap)
