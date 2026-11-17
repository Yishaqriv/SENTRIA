"""
Pruebas del apartado «Comparación de IA» (solo superusuario). BD de pruebas aislada (settings_ci, SQLite), proveedores
falsos y red bloqueada: ninguna prueba llama a un proveedor, al indexador ni lee credenciales.
"""
import copy
import hashlib
import io
import json
import socket
import uuid
from unittest import mock, skipUnless

from django.contrib.auth.models import User
from django.test import Client, TestCase
from django.urls import reverse

from dashboard.comparacion import estadisticas as E
from dashboard.comparacion import graficas as G
from dashboard.comparacion import intercambio as I
from dashboard.comparacion import local as L
from dashboard.comparacion import normalizacion as N
from dashboard.comparacion.privacidad import IdentificadoresPrivados
from dashboard.comparacion.views import _celda_csv
from dashboard.models import Alert, CasoComparacion, EjecucionComparacion, LoteImportacionComparacion

ESQ = "4c67891e7e608a4f564d580af6e916cc8eb1c3d701947d4fccd9b3bf546d78c2"
H = lambda s: hashlib.sha256(s.encode()).hexdigest()  # noqa: E731
PARAMS = {"esquema_salida_sha256": ESQ, "instruccion_sistema": None, "max_output_tokens": 8192,
          "reintentos_configurados": 0, "response_mime_type": "application/json", "temperature": 0.1,
          "thinking_budget": 0, "timeout_ms": 60000}


def medicion(entrada, *, tokens=(1527, 386, None, 1913), lat=4.398, analisis=4.782, informado="gemini-3.6-flash",
             llamada="ok", estado="COMPLETED", inicio="2026-11-13T00:25:01.123Z", formato="prompt_sentria"):
    e, s, r, t = tokens
    return {"version": "medicion_v2", "id_local": "DOC-PRIVADO-0000000001", "proveedor": "gemini_developer",
            "modelo_configurado": "models/gemini-3.5-flash", "modelo_respuesta": informado,
            "formato_entrada": formato, "extension_web": None, "entrada_sha256": H(entrada),
            "entrada_caracteres": len(entrada), "plantilla_sha256": None, "parametros": dict(PARAMS),
            "inicio_llamada_utc": inicio if llamada != "sin_llamada" else None,
            "duracion_llamada_s": lat, "duracion_analisis_s": analisis,
            "invocaciones_analizador": 0 if llamada == "sin_llamada" else 1, "reintentos_configurados": 0,
            "intentos_http_observados": None, "estado_llamada": llamada,
            "motivo_sin_llamada": "entrada_no_representable" if llamada == "sin_llamada" else None,
            "categoria_error_llamada": "timeout" if llamada == "error" else None, "codigo_http_llamada": None,
            "estado_analisis": estado, "categoria_fallo_analisis": None if estado == "COMPLETED" else "contrato_invalido",
            "finish_reason": "STOP" if llamada == "ok" else None,
            "tokens": {"entrada": e, "salida": s, "razonamiento": r, "total": t},
            "tokens_fuente": "usage_del_proveedor" if any(x is not None for x in tokens) else "no_disponible"}


def alerta(osid, entrada, *, med=True, grupos=("windows", "windows_system"), respuesta=None, retraso=5,
           web_procedencia=None, **kw):
    snap = {"schema_version": "1.4", "evidencia_tecnica": {"rule_id": "61102"},
            "_diagnostico_tiempo": {"retraso_segundos": retraso}}
    if web_procedencia is not None:
        snap["evidencia_tecnica"]["web_procedencia"] = web_procedencia
    if med:
        snap["_medicion"] = medicion(entrada, **kw)
    completed = (kw.get("estado", "COMPLETED") == "COMPLETED")
    return Alert.objects.create(
        opensearch_id=osid, titulo="t", descripcion="d", estado_analisis="COMPLETED" if completed else "ANALISIS_FALLIDO",
        veredicto_ia="REQUIERE_ATENCION" if completed else None, riesgo_ia="LOW" if completed else None,
        respuesta_ia_original=respuesta if respuesta is not None else
        f'{{"verdict":"REQUIERE_ATENCION","n":"{hashlib.sha256(osid.encode()).hexdigest()[:8]}"}}', wazuh_rule_groups=list(grupos), contexto_ia_snapshot=snap, proveedor_ia="gemini_developer")


def usuario(nombre, *, rol="ANALISTA", superusuario=False, staff=False, activo=True):
    u = User.objects.create_user(nombre, password="x", is_superuser=superusuario, is_staff=staff, is_active=activo)
    u.perfilusuario.rol = rol
    u.perfilusuario.save()
    return u


class _Base(TestCase):
    def setUp(self):
        self.su = usuario("raiz_super", rol="ADMIN", superusuario=True, staff=True)
        self.red = mock.patch.object(socket.socket, "connect", side_effect=AssertionError("red prohibida"))
        self.red.start()
        self.addCleanup(self.red.stop)
        from dashboard.ia import proveedores as P
        for cls in P.PROVEEDORES.values():
            p = mock.patch.object(cls, "analizar", side_effect=AssertionError("llamada a la IA prohibida"))
            p.start()
            self.addCleanup(p.stop)

    def cliente(self, u=None, csrf=False):
        c = Client(enforce_csrf_checks=csrf)
        if u is not None:
            c.force_login(u)
        return c


# ------------------------------------------------------------------------------------------------ permisos
class PermisosTests(_Base):
    def setUp(self):
        super().setUp()
        a = alerta("OSID-PERMISOS-000000001", "entrada-permisos\n")
        L.registrar(self.su)
        self.ej = EjecucionComparacion.objects.get(alerta_local=a)
        self.grupo = E.grupo_de(self.ej)

    def endpoints(self):
        g = f"?grupo={self.grupo}"
        gets = [reverse("comparacion"), reverse("comparacion_detalle", args=[self.ej.uuid]),
                reverse("comparacion_exportar_csv"), reverse("comparacion_exportar_json")]
        for t in G.TIPOS:
            gets += [reverse("comparacion_grafica_datos", args=[t]) + g,
                     reverse("comparacion_grafica_manifiesto", args=[t]) + g]
            gets += [reverse("comparacion_grafica", args=[t, f]) + g for f in G.FORMATOS]
        posts = [reverse("comparacion_registrar_locales"), reverse("comparacion_importar"),
                 reverse("comparacion_importar_confirmar"),
                 reverse("comparacion_procedencia", args=[self.ej.caso.clave])]
        return gets, posts

    def test_superusuario_activo_accede(self):
        c = self.cliente(self.su)
        gets, _ = self.endpoints()
        for url in gets:
            if "/grafica/" in url and url.split("?")[0].endswith((".png", ".svg", ".pdf")) and not G.disponible():
                continue
            r = c.get(url)
            self.assertEqual(r.status_code, 200, url)
        self.assertContains(c.get(reverse("cola_atencion")), "Comparación de IA")

    def test_sin_permiso_no_obtiene_datos_de_ningun_endpoint(self):
        casos = {
            "admin_no_super": usuario("admin_no_super", rol="ADMIN"),
            "staff_no_super": usuario("staff_no_super", rol="ANALISTA", staff=True),
            "analista": usuario("analista1"),
            "invitado": usuario("invitado1", rol="INVITADO"),
        }
        gets, posts = self.endpoints()
        antes = (EjecucionComparacion.objects.count(), CasoComparacion.objects.count())
        for nombre, u in casos.items():
            c = self.cliente(u)
            for url in gets:
                r = c.get(url)
                self.assertEqual(r.status_code, 403, (nombre, url))
                self.assertNotIn(str(self.ej.uuid).encode(), r.content)
                self.assertNotIn(self.ej.caso.entrada_sha256.encode(), r.content)
            for url in posts:
                r = c.post(url, {"procedencia": "web_natural"})
                self.assertEqual(r.status_code, 403, (nombre, url))
            self.assertNotContains(c.get(reverse("cola_atencion")), "Comparación de IA")
        self.assertEqual(antes, (EjecucionComparacion.objects.count(), CasoComparacion.objects.count()))
        self.assertEqual(CasoComparacion.objects.get().procedencia_asignada_por, None)

    def test_anonimo_e_inactivo_van_al_login_sin_datos(self):
        inactivo = usuario("super_inactivo", superusuario=True, activo=False)
        gets, posts = self.endpoints()
        for c in (self.cliente(), self.cliente(inactivo)):
            for url in gets + posts:
                r = c.get(url) if url in gets else c.post(url)
                self.assertEqual(r.status_code, 302, url)
                self.assertIn("/accounts/login/", r["Location"])
                self.assertNotIn(str(self.ej.uuid).encode(), r.content)

    def test_superusuario_desactivado_con_sesion_abierta_pierde_el_acceso(self):
        c = self.cliente(self.su)
        self.assertEqual(c.get(reverse("comparacion")).status_code, 200)
        User.objects.filter(pk=self.su.pk).update(is_active=False)
        r = c.get(reverse("comparacion"))
        self.assertEqual(r.status_code, 302)

    def test_post_exige_csrf_y_get_no_escribe(self):
        c = self.cliente(self.su, csrf=True)
        self.assertEqual(c.post(reverse("comparacion_registrar_locales")).status_code, 403)
        self.assertEqual(self.cliente(self.su).get(reverse("comparacion_registrar_locales")).status_code, 405)
        self.assertEqual(self.cliente(self.su).get(reverse("comparacion_importar")).status_code, 405)
        alerta("OSID-PERMISOS-000000002", "otra entrada\n")
        n = EjecucionComparacion.objects.count()
        r = self.cliente(self.su).get(reverse("comparacion"))
        self.assertEqual(r.context["pendientes_locales"], 1)
        self.assertEqual(EjecucionComparacion.objects.count(), n)          # el GET no sincroniza

    def test_rbac_existente_sin_cambios(self):
        from usuarios.decorators import usuario_tiene_rol
        admin = usuario("admin2", rol="ADMIN")
        self.assertTrue(usuario_tiene_rol(admin, ("ADMIN",)))               # ADMIN sigue siendo ADMIN…
        self.assertFalse(admin.is_superuser)                                # …pero no superusuario
        self.assertEqual(self.cliente(admin).get(reverse("comparacion")).status_code, 403)


# ------------------------------------------------------------------------------------------- registro local
class RegistroLocalTests(_Base):
    def test_registra_mediciones_sin_modificar_alertas_y_es_idempotente(self):
        a1 = alerta("OSID-LOCAL-0000000000001", "E1\n")
        a2 = alerta("OSID-LOCAL-0000000000002", "E1\n", tokens=(1527, 393, None, 1920), lat=3.346, analisis=3.734)
        a3 = alerta("OSID-LOCAL-0000000000003", "E3\n", med=False)            # sin medición (tipo fila 208)
        fotos = {a.pk: (copy.deepcopy(a.contexto_ia_snapshot), a.respuesta_ia_original, a.veredicto_ia)
                 for a in (a1, a2, a3)}
        r = L.registrar(self.su)
        self.assertEqual((r["registradas"], r["casos_nuevos"]), (2, 1))
        self.assertEqual(L.registrar(self.su)["registradas"], 0)
        self.assertEqual(EjecucionComparacion.objects.count(), 2)
        self.assertEqual(CasoComparacion.objects.count(), 1)                  # mismo texto = mismo caso
        for a in Alert.objects.all():
            self.assertEqual(fotos[a.pk], (a.contexto_ia_snapshot, a.respuesta_ia_original, a.veredicto_ia))
        e = EjecucionComparacion.objects.get(alerta_local=a1)
        self.assertEqual((e.latencia_proveedor_s, e.duracion_analisis_s, e.duracion_ejecucion_s), (4.398, 4.782, None))
        self.assertEqual((e.tokens_entrada, e.tokens_salida, e.tokens_razonamiento, e.tokens_total),
                         (1527, 386, None, 1913))
        self.assertEqual((e.modelo_solicitado, e.modelo_informado), ("models/gemini-3.5-flash", "gemini-3.6-flash"))
        self.assertEqual(e.origen_medicion, "observada_local")
        self.assertNotIn("id_local", json.dumps(e.parametros))

    def test_no_atribuye_modelo_ni_tokens_no_registrados(self):
        a = alerta("OSID-LOCAL-0000000000009", "E9\n", tokens=(None, None, None, None), informado=None, lat=None,
                   analisis=0.5, llamada="sin_llamada", estado="ANALISIS_FALLIDO")
        L.registrar(self.su)
        e = EjecucionComparacion.objects.get(alerta_local=a)
        self.assertEqual((e.modelo_informado, e.tokens_total, e.latencia_proveedor_s), (None, None, None))
        self.assertEqual(E.estado_ui(e), "sin_llamada")

    def test_procedencia_explicita_no_por_antiguedad(self):
        # Revisión v1, hallazgo 4: la procedencia web sale de evidencia_tecnica.web_procedencia, nunca del retraso.
        win = alerta("OSID-PROC-00000000000001", "W\n", retraso=26069)
        replay = alerta("OSID-PROC-00000000000002", "REPLAY\n", grupos=("web", "accesslog"), retraso=60,
                        web_procedencia="historico_reproducido")
        vivo = alerta("OSID-PROC-00000000000003", "VIVO\n", grupos=("web", "accesslog"), retraso=10 * 86400,
                      web_procedencia="en_vivo")
        nodet = alerta("OSID-PROC-00000000000004", "NODET\n", grupos=("web", "accesslog"),
                       web_procedencia="no_determinado")
        sinev = alerta("OSID-PROC-00000000000005", "SINEV\n", grupos=("web", "accesslog"), retraso=120 * 86400)
        rara = alerta("OSID-PROC-00000000000006", "RARA\n", grupos=("web",), web_procedencia="inventada")
        diag = alerta("OSID-PROC-00000000000007", "DIAG\n", grupos=("wazuh", "agent_flooding"))
        L.registrar(self.su)
        proc = [EjecucionComparacion.objects.get(alerta_local=a).caso.procedencia
                for a in (win, replay, vivo, nodet, sinev, rara, diag)]
        self.assertEqual(proc, ["windows_natural", "web_historico_reproducido", "web_natural", "no_determinada",
                                "no_determinada", "no_determinada", "diagnostico_agente"])

    def test_medicion_incoherente_no_se_registra(self):
        a = alerta("OSID-LOCAL-0000000000010", "E10\n", tokens=(2000, 100, None, 50))
        r = L.registrar(self.su)
        self.assertEqual(r["no_registrables"], 1)
        self.assertFalse(EjecucionComparacion.objects.filter(alerta_local=a).exists())


# ------------------------------------------------------------------------------------------------ importación
def doc_de(qs):
    return json.dumps(I.exportar(qs, filtros={}, privados=IdentificadoresPrivados()), ensure_ascii=False).encode()


def linea_v2(**kw):
    base = {"registro_version": "registro_comparacion_v2", "uuid": str(uuid.uuid4()), "caso": "CASO-X-01",
            "formato_entrada": "prompt_sentria", "entrada_sha256": H("caso x\n"), "esquema_sha256_canonico": ESQ,
            "capa_e_sha256": H("ctx"), "repeticion": 1, "proveedor": "otro_proveedor", "modelo_solicitado": "m-1",
            "modelo_informado": "m-1-0613", "configuracion": {"temperature": 0.1, "max_output_tokens": 8192},
            "fecha_utc": "2026-11-12T10:00:00Z", "estado_llamada": "ok", "estado_analisis": "COMPLETED",
            "tiempo_proveedor_s": 2.5, "tiempo_total_s": 2.9, "tokens_entrada": 1600, "tokens_salida": 300,
            "tokens_razonamiento": None, "tokens_total": 1900, "tokens_fuente": "usage_del_proveedor",
            "veredicto": "REQUIERE_ATENCION", "riesgo": "LOW", "respuesta_sha256": H("resp-x"),
            "codigo_ejecucion_sha256": H("codigo"), "adaptador_sha256": H("adaptador"),
            "esquema_efectivo_sha256": ESQ, "equivalencia": "equivalente",
            "definicion_tiempo": "ejecutor v2: monotonic alrededor de analizar()"}
    base.update(kw)
    return json.dumps(base, ensure_ascii=False)


class ImportacionTests(_Base):
    def importar(self, contenido, casos_nuevos=True, **kw):
        return I.confirmar(contenido, nombre="prueba.jsonl", usuario=self.su, registrar_casos_nuevos=casos_nuevos, **kw)

    def test_valida_repetida_y_conflictiva_sin_sobrescribir(self):
        uid = str(uuid.uuid4())
        lote = self.importar(linea_v2(uuid=uid).encode())
        self.assertEqual(lote.resumen["recuento"], {"importada": 1})
        e = EjecucionComparacion.objects.get(uuid=uid)
        self.assertEqual((e.origen_medicion, e.tokens_razonamiento, e.latencia_proveedor_s), ("importada", None, 2.5))
        self.assertEqual(self.importar(linea_v2(uuid=uid).encode()).resumen["recuento"], {"existente": 1})
        r = self.importar(linea_v2(uuid=uid, tokens_salida=301).encode())
        self.assertEqual(r.resumen["recuento"], {"conflicto": 1})
        e.refresh_from_db()
        self.assertEqual((e.tokens_salida, EjecucionComparacion.objects.count()), (300, 1))
        self.assertEqual(LoteImportacionComparacion.objects.count(), 3)

    def test_caso_nuevo_requiere_confirmacion_y_mismo_nombre_no_es_mismo_caso(self):
        self.importar(linea_v2().encode())
        r = self.importar(linea_v2(entrada_sha256=H("otro texto\n")).encode(), casos_nuevos=False)
        self.assertEqual(r.resumen["recuento"], {"omitida": 1})
        a = I.analizar(linea_v2(entrada_sha256=H("otro texto\n")).encode(), privados=IdentificadoresPrivados())
        self.assertEqual(a["filas"][0]["resultado"], "caso_nuevo")
        self.assertIn("mismo nombre", a["filas"][0]["motivo"])
        self.importar(linea_v2(entrada_sha256=H("otro texto\n")).encode())
        self.assertEqual(CasoComparacion.objects.filter(codigo="CASO-X-01").count(), 2)

    def test_archivos_incompatibles_y_mal_formados(self):
        malos = [b"", b"\xff\xfe", b"{no json", b'{"formato": "sentria_comparacion", "version": 2, "casos": [], "ejecuciones": []}',
                 b'{"registro_version": "registro_comparacion_v9"}', linea_v2().encode() + b"\n" +
                 json.dumps({"registro_version": "registro_comparacion_v1"}).encode(),
                 b'{"registro_version": "registro_comparacion_v2", "a": 1, "a": 2}',
                 b'{"registro_version": "registro_comparacion_v2", "tokens_total": NaN}',
                 b'{"registro_version": "registro_comparacion_v2", "tokens_total": Infinity}',
                 b"x" * (I.MAX_BYTES + 1), b"\n".join([b'{"registro_version": "registro_comparacion_v2"}'] * 2001),
                 b"!!python/object/apply:os.system ['echo x']"]
        for m in malos:
            with self.assertRaises(I.ArchivoInvalido, msg=m[:60]):
                I.analizar(m, privados=IdentificadoresPrivados())
        self.assertEqual(EjecucionComparacion.objects.count(), 0)

    def test_valores_numericos_y_contradicciones_se_rechazan(self):
        malos = [{"tokens_total": True}, {"tokens_total": -1}, {"tokens_total": "1900"}, {"tokens_total": 1.5},
                 {"tiempo_proveedor_s": -0.1}, {"tiempo_proveedor_s": "2"}, {"tiempo_proveedor_s": 1e9},
                 {"tokens_total": 100}, {"estado_llamada": "sin_llamada"},
                 {"estado_llamada": "fallida", "estado_analisis": "COMPLETED"}, {"uuid": "no-uuid"},
                 {"uuid": "00000000-0000-0000-0000-000000000000"}, {"entrada_sha256": "ABC"},
                 {"fecha_utc": "2026-11-12T10:00:00"}, {"fecha_utc": "2099-01-01T00:00:00Z"},
                 {"codigo_http": 99}, {"repeticion": 0}, {"modelo_informado": "=HYPERLINK(1)"},
                 {"estado_analisis": "ANALISIS_FALLIDO"}]                # veredicto con análisis no aceptado
        for kw in malos:
            a = I.analizar(linea_v2(**kw).encode(), privados=IdentificadoresPrivados())
            self.assertEqual(a["filas"][0]["resultado"], "rechazada", kw)
            self.assertNotIn("1900", a["filas"][0]["motivo"] or "")          # el motivo no repite valores

    def test_parametros_anidados_y_definicion_libre(self):
        ok = {"configuracion": {"generation_config": {"responseMimeType": "application/json",
                                                      "thinkingConfig": {"thinkingLevel": "MINIMAL"}},
                                "timeout_s": 120},
              "definicion_tiempo": "ejecutor v2: monotonic alrededor de analizar(); tiempo_total = proceso"}
        a = I.analizar(linea_v2(**ok).encode(), privados=IdentificadoresPrivados())
        self.assertEqual(a["filas"][0]["resultado"], "caso_nuevo", a["filas"][0]["motivo"])
        for malo in ({"configuracion": {"generation_config": {"apiKey": "x"}}},
                     {"configuracion": {"a": {"b": {"c": {"d": 1}}}}},
                     {"configuracion": {"lista": list(range(30))}},
                     {"definicion_tiempo": "linea\ncon salto"}):
            a = I.analizar(linea_v2(**malo).encode(), privados=IdentificadoresPrivados())
            self.assertEqual(a["filas"][0]["resultado"], "rechazada", malo)

    def test_longitudes_de_columna_se_validan_antes_de_escribir(self):
        # SQLite no limita varchar; MySQL sí: lo que no cabe se rechaza como dato, nunca como error de la BD.
        for campo, largo in (("categoria_error", 81), ("finish_reason", 41), ("riesgo", 21), ("proveedor", 61)):
            kw = {campo: "a" * largo}
            if campo == "riesgo":
                kw["veredicto"] = "REQUIERE_ATENCION"
            a = I.analizar(linea_v2(**kw).encode(), privados=IdentificadoresPrivados())
            self.assertEqual(a["filas"][0]["resultado"], "rechazada", campo)
            self.assertIn("supera", a["filas"][0]["motivo"])
        largo = "ejecutor v2: monotonic alrededor de analizar(); tiempo_total = proceso desde la preparación"
        a = I.analizar(linea_v2(definicion_tiempo=largo).encode(), privados=IdentificadoresPrivados())
        self.assertEqual(a["filas"][0]["resultado"], "caso_nuevo")

    def test_faltantes_legitimos_quedan_null(self):
        uid = str(uuid.uuid4())
        self.importar(linea_v2(uuid=uid, tokens_entrada=None, tokens_salida=None, tokens_total=None,
                               tiempo_proveedor_s=None, modelo_informado=None, tiempo_total_s=None).encode())
        e = EjecucionComparacion.objects.get(uuid=uid)
        self.assertEqual((e.tokens_total, e.latencia_proveedor_s, e.modelo_informado, e.duracion_ejecucion_s),
                         (None, None, None, None))

    def test_datos_privados_o_credenciales_rechazan_el_registro(self):
        alerta("DocPrivadoDePrueba000001", "E-priv\n", med=False)
        inst = IdentificadoresPrivados.de_la_instancia()
        privados = IdentificadoresPrivados(inst.ids_documento, ["SRV-PRIV-77"], ["raiz_super"])
        self.assertIn("DocPrivadoDePrueba000001", inst.ids_documento)
        malos = [{"api_key": "x"}, {"configuracion": {"temperature": 0.1, "password": "x"}},
                 {"observaciones": "clave " + "AI" + "za" + "0" * 35}, {"observaciones": "ver 192.0.2.15"},
                 {"observaciones": "ver https://servidor.ejemplo/x"}, {"observaciones": "en /home/usuario/x"},
                 {"observaciones": "doc DocPrivadoDePrueba000001"}, {"observaciones": "activo SRV-PRIV-77"},
                 {"observaciones": "usuario raiz_super"}, {"observaciones": "DB_PASSWORD=x"},
                 {"respuesta_observada": "contacto a@b.co", "respuesta_sha256": H("contacto a@b.co")},
                 {"observaciones": "cookie sessionid=abc"}]
        for kw in malos:
            a = I.analizar(linea_v2(**kw).encode(), privados=privados)
            self.assertEqual(a["filas"][0]["resultado"], "rechazada", kw)
            self.assertNotIn("192.0.2.15", json.dumps(a))
            self.assertNotIn("DocPrivadoDePrueba000001", json.dumps(a))

    def test_referencia_v1_y_fila_local_no_se_fusionan_por_respuesta(self):
        resp209 = '{"verdict": "REQUIERE_ATENCION", "risk": "LOW"}'
        local = alerta("OSID-209-SIMULADA-0001", "web-209\n", grupos=("web", "accesslog"), respuesta=resp209)
        L.registrar(self.su)
        ref = {"registro_version": "registro_comparacion_v1", "caso": "CASO-WEB-01", "formato_entrada": "prompt_sentria",
               "entrada_sha256": H("web-209\n"), "esquema_sha256_canonico": ESQ, "capa_e_sha256": H("ctx209"),
               "repeticion": 1, "proveedor": "gemini_developer", "modelo_solicitado": "models/gemini-3.5-flash",
               "modelo_informado": "gemini-3.6-flash", "fecha_utc": "2026-11-12", "estado_llamada": "ok",
               "estado_analisis": "COMPLETED", "tiempo_proveedor_s": 4.398, "tiempo_total_s": None,
               "tokens_entrada": 1527, "tokens_salida": 386, "tokens_razonamiento": None, "tokens_total": 1913,
               "tokens_fuente": "usage_del_proveedor", "respuesta_sha256": H(resp209), "veredicto": "REQUIERE_ATENCION",
               "riesgo": "LOW", "observaciones": "referencia observada en SENTRIA",
               "configuracion": {"temperature": 0.1, "max_output_tokens": 8192}, "manifiesto_codigo_sha256": None,
               "respuesta_archivo": "casos/CASO-WEB-01/respuesta_referencia_gemini.json"}
        ref208 = dict(ref, caso="CASO-WIN-01", entrada_sha256=H("win-208\n"), respuesta_sha256=H("r208"),
                      modelo_informado=None, tiempo_proveedor_s=None, tokens_entrada=None, tokens_salida=None,
                      tokens_total=None, tokens_fuente="no_disponible (anterior a la medición medicion_v2)")
        contenido = (json.dumps(ref) + "\n" + json.dumps(ref208) + "\n").encode()
        # La referencia v1 de la 209 no tiene identidad propia: coincidir en la respuesta no demuestra que sea la
        # fila local. Queda «ambigua»: ni se fusiona ni se importa sin decisión expresa.
        a = I.analizar(contenido, privados=IdentificadoresPrivados())
        self.assertEqual(a["recuento"], {"ambigua": 1, "caso_nuevo": 1})
        lote = self.importar(contenido)
        self.assertEqual(lote.resumen["recuento"], {"omitida": 1, "importada": 1})
        self.assertEqual(EjecucionComparacion.objects.filter(caso__entrada_sha256=H("web-209\n")).count(), 1)
        e208 = EjecucionComparacion.objects.get(caso__entrada_sha256=H("win-208\n"))
        self.assertEqual((e208.origen_medicion, e208.tokens_total, e208.modelo_informado, e208.inicio_utc,
                          e208.identidad_derivada), ("referencia", None, None, None, True))
        self.assertIn("fecha declarada 2026-11-12", e208.observaciones)
        uid = e208.uuid
        self.assertEqual(self.importar(contenido).resumen["recuento"], {"existente": 1, "omitida": 1})
        self.assertEqual(EjecucionComparacion.objects.get(caso__entrada_sha256=H("win-208\n")).uuid, uid)
        # Ida y vuelta: exportar e importar de nuevo no crea filas y conserva la identidad derivada.
        doc = doc_de(EjecucionComparacion.objects.all())
        self.assertEqual(I.analizar(doc, privados=IdentificadoresPrivados())["recuento"], {"existente": 2})
        self.assertIn('"identidad_derivada": true', doc.decode())
        # Con decisión expresa se guarda como ejecución SEPARADA (no fusionada) y sigue siendo idempotente.
        lote = self.importar(contenido, importar_ambiguas=True)
        self.assertEqual(lote.resumen["recuento"], {"existente": 1, "importada_como_separada": 1})
        self.assertEqual(EjecucionComparacion.objects.filter(caso__entrada_sha256=H("web-209\n")).count(), 2)
        self.assertEqual(self.importar(contenido, importar_ambiguas=True).resumen["recuento"], {"existente": 2})
        self.assertEqual(local.contexto_ia_snapshot["_medicion"]["tokens"]["total"], 1913)

    def test_documento_alterado_se_rechaza(self):
        alerta("OSID-DOC-000000000000001", "doc\n")
        L.registrar(self.su)
        doc = json.loads(doc_de(EjecucionComparacion.objects.all()))
        doc["ejecuciones"][0]["tokens_total"] = 99999
        a = I.analizar(json.dumps(doc).encode(), privados=IdentificadoresPrivados())
        self.assertEqual(a["filas"][0]["resultado"], "rechazada")
        self.assertIn("huella_contenido", a["filas"][0]["motivo"])

    def test_exportacion_sin_ids_privados_y_texto_privado_omitido(self):
        a = alerta("OSID-EXP-0000000000000001", "exp\n", respuesta='{"nota": "host 10.1.2.3"}')
        L.registrar(self.su)
        doc = doc_de(EjecucionComparacion.objects.all())
        self.assertNotIn(b"OSID-EXP", doc)
        self.assertNotIn(b"10.1.2.3", doc)
        self.assertNotIn(b"raiz_super", doc)
        self.assertNotIn(b'"alerta_local', doc)
        d = json.loads(doc)
        self.assertEqual(d["ejecuciones"][0]["texto_omitido"], ["respuesta_observada"])
        self.assertIsNotNone(d["ejecuciones"][0]["respuesta_sha256"])
        self.assertEqual(I.analizar(doc, privados=IdentificadoresPrivados())["recuento"], {"existente": 1})
        self.assertEqual(a.pk, EjecucionComparacion.objects.get().alerta_local_id)

    def test_flujo_web_vista_previa_confirmar_y_cancelar(self):
        c = self.cliente(self.su)
        arch = io.BytesIO(linea_v2().encode())
        arch.name = "../../etc/passwd.jsonl"
        r = c.post(reverse("comparacion_importar"), {"archivo": arch, "participante": "P2"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(EjecucionComparacion.objects.count(), 0)            # la vista previa no escribe
        sha = r.context["sha256"]
        self.assertEqual(c.post(reverse("comparacion_importar_confirmar"), {"sha256": "0" * 64}).status_code, 302)
        self.assertEqual(EjecucionComparacion.objects.count(), 0)
        c.post(reverse("comparacion_importar_confirmar"), {"sha256": sha, "accion": "confirmar",
                                                            "registrar_casos_nuevos": "1"})
        e = EjecucionComparacion.objects.get()
        self.assertEqual((e.participante, e.lote.archivo_nombre), ("P2", "passwd.jsonl"))
        self.assertEqual(c.post(reverse("comparacion_importar_confirmar"), {"sha256": sha}).status_code, 302)
        self.assertEqual(LoteImportacionComparacion.objects.count(), 1)       # sin vista previa vigente
        arch2 = io.BytesIO(linea_v2().encode())
        arch2.name = "b.jsonl"
        r = c.post(reverse("comparacion_importar"), {"archivo": arch2})
        c.post(reverse("comparacion_importar_confirmar"), {"sha256": r.context["sha256"], "accion": "cancelar"})
        self.assertEqual(EjecucionComparacion.objects.count(), 1)

    def test_registros_inmutables(self):
        self.importar(linea_v2().encode())
        e = EjecucionComparacion.objects.get()
        with self.assertRaises(ValueError):
            e.save()
        with self.assertRaises(ValueError):
            EjecucionComparacion.objects.update(tokens_total=1)
        with self.assertRaises(ValueError):
            EjecucionComparacion.objects.all().delete()


# --------------------------------------------------------------------------------- estadísticas y gráficas
class EstadisticasTests(_Base):
    def setUp(self):
        super().setUp()
        lineas = [
            linea_v2(proveedor="prov_a", modelo_informado="a-1", tiempo_proveedor_s=2.0, tokens_total=1900),
            linea_v2(proveedor="prov_a", modelo_informado="a-1", tiempo_proveedor_s=4.0, tokens_total=1950,
                     respuesta_sha256=H("r2")),
            linea_v2(proveedor="prov_a", modelo_informado="a-1", tiempo_proveedor_s=None, tokens_total=None,
                     respuesta_sha256=H("r3")),
            linea_v2(proveedor="prov_a", modelo_informado="a-2", tiempo_proveedor_s=0.0, respuesta_sha256=H("r4")),
            linea_v2(proveedor="prov_b", modelo_informado=None, modelo_solicitado="b-alias",
                     tiempo_proveedor_s=3.0, tokens_razonamiento=500, respuesta_sha256=H("r5")),
            linea_v2(entrada_sha256=H("otro caso\n"), caso="CASO-Y", proveedor="prov_a", modelo_informado="a-1",
                     tiempo_proveedor_s=50.0, respuesta_sha256=H("r6")),
            linea_v2(proveedor="prov_a", modelo_informado="a-1", configuracion={"temperature": 0.7},
                     tiempo_proveedor_s=40.0, respuesta_sha256=H("r7")),
        ]
        I.confirmar("\n".join(lineas).encode(), nombre="x.jsonl", usuario=self.su, registrar_casos_nuevos=True)
        self.filas, _ = E.consulta({})

    def test_no_mezcla_casos_ni_protocolos_y_series_por_modelo_informado(self):
        gr = E.grupos(self.filas)
        self.assertEqual(len(gr), 3)                                  # caso X/proto 1, caso X/proto 2, caso Y
        principal = max(gr, key=lambda g: g["n"])
        d = E.datos_grupo(self.filas, principal["id"])
        self.assertEqual([s["serie"] for s in d["latencia"]],
                         ["prov_a · a-1", "prov_a · a-2", "prov_b · no informado (solicitado: b-alias)"])
        a1 = d["latencia"][0]
        self.assertEqual((sorted(a1["valores"]), a1["n_medido"], a1["n_ausente"], a1["mediana"]), ([2.0, 4.0], 2, 1, 3.0))
        self.assertEqual(d["latencia"][1]["valores"], [0.0])           # un 0 real se conserva como medición
        self.assertNotIn(50.0, sum((s["valores"] for s in d["latencia"]), []))
        self.assertNotIn(40.0, sum((s["valores"] for s in d["latencia"]), []))
        t = d["tokens"][2]
        self.assertEqual((t["total"]["mediana"], t["razonamiento"]["valores"]), (1900, [500]))  # sin sumar

    def test_filtros_lista_cerrada(self):
        f = E.leer_filtros({"caso": "x", "estado": "drop table", "desde": "2026-13-01", "grupo": "../../",
                            "proveedor": "prov_a", "repeticion": "0"})
        self.assertEqual(f, {"proveedor": "prov_a"})

    @skipUnless(G.disponible(), "matplotlib no instalado en este entorno")
    def test_figuras_reales_y_descargas_coherentes(self):
        g = max(E.grupos(self.filas), key=lambda x: x["n"])["id"]
        c = self.cliente(self.su)
        for t in G.TIPOS:
            png = c.get(reverse("comparacion_grafica", args=[t, "png"]) + f"?grupo={g}")
            self.assertEqual(png.content[:8], b"\x89PNG\r\n\x1a\n")
            self.assertIn(b"pHYs", png.content[:200])
            i = png.content.index(b"pHYs") + 4
            self.assertEqual(int.from_bytes(png.content[i:i + 4], "big"), 11811)        # 300 ppp
            self.assertIn("attachment", png["Content-Disposition"])
            svg = c.get(reverse("comparacion_grafica", args=[t, "svg"]) + f"?grupo={g}").content
            pdf = c.get(reverse("comparacion_grafica", args=[t, "pdf"]) + f"?grupo={g}").content
            self.assertIn(b"<svg", svg[:400])
            self.assertTrue(pdf.startswith(b"%PDF"))
            for blob in (png.content, svg, pdf):
                for prohibido in (b"raiz_super", b"OSID-", b"AIza", b"<script"):
                    self.assertNotIn(prohibido, blob)
            datos = c.get(reverse("comparacion_grafica_datos", args=[t]) + f"?grupo={g}").content
            man = json.loads(c.get(reverse("comparacion_grafica_manifiesto", args=[t]) + f"?grupo={g}").content)
            self.assertEqual(man["datos_csv_sha256"], hashlib.sha256(datos).hexdigest())
            uu_csv = {ln.split(";")[0] for ln in datos.decode("utf-8-sig").splitlines()[1:]}
            self.assertEqual(uu_csv, {x["uuid"] for x in man["ejecuciones"]})
            self.assertEqual(man["renderizador"]["png_ppp"], 300)
        self.assertEqual(c.get(reverse("comparacion_grafica", args=["latencia", "exe"]) + f"?grupo={g}").status_code, 404)
        self.assertEqual(c.get(reverse("comparacion_grafica", args=["otra", "png"]) + f"?grupo={g}").status_code, 404)
        self.assertEqual(c.get(reverse("comparacion_grafica", args=["latencia", "png"])).status_code, 404)

    @skipUnless(G.disponible(), "matplotlib no instalado en este entorno")
    def test_un_solo_proveedor_avisa_y_no_inventa_ceros(self):
        g = [x for x in E.grupos(self.filas) if x["caso"].codigo == "CASO-Y"][0]["id"]
        d = E.datos_grupo(self.filas, g)
        fig = G._latencia(d)
        textos = " ".join(t.get_text() for t in fig.texts)
        self.assertIn("un solo proveedor", textos)
        self.assertEqual(len(d["latencia"]), 1)
        d2 = dict(d, latencia=[dict(d["latencia"][0], valores=[], n_medido=0, n_ausente=1, mediana=None)])
        fig2 = G._latencia(d2)
        ax = fig2.axes[0]
        self.assertEqual(sum(len(col.get_offsets()) for col in ax.collections if hasattr(col, "get_offsets")), 0)
        self.assertIn("No disponible\n1 sin dato", " ".join(t.get_text() for t in ax.texts))

    def test_texto_de_datos_neutralizado(self):
        self.assertEqual(G.texto_seguro("a$b$\\c\n"), r"a\$b\$/c ")
        self.assertEqual(_celda_csv("=1+1"), "'=1+1")
        self.assertEqual(_celda_csv(None), "No disponible")
        self.assertEqual(_celda_csv(0), "0")

    def test_sin_dependencia_de_graficas_responde_503_y_los_datos_siguen(self):
        g = E.grupos(self.filas)[0]["id"]
        c = self.cliente(self.su)
        with mock.patch.object(G, "disponible", return_value=False):
            self.assertEqual(c.get(reverse("comparacion_grafica", args=["latencia", "png"]) + f"?grupo={g}").status_code, 503)
            self.assertEqual(c.get(reverse("comparacion_grafica_datos", args=["latencia"]) + f"?grupo={g}").status_code, 200)
            self.assertContains(c.get(reverse("comparacion") + f"?grupo={g}"), "no están disponibles")

    def test_html_escapado_en_detalle(self):
        resp = "<script>alert(1)</script>"
        uid = str(uuid.uuid4())
        I.confirmar(linea_v2(uuid=uid, respuesta_observada=resp, respuesta_sha256=H(resp),
                             entrada_sha256=H("esc\n")).encode(),
                    nombre="e.jsonl", usuario=self.su, registrar_casos_nuevos=True)
        r = self.cliente(self.su).get(reverse("comparacion_detalle", args=[uid]))
        self.assertNotContains(r, "<script>alert(1)</script>")
        self.assertContains(r, "&lt;script&gt;")

    def test_get_e_importacion_no_tocan_ia_red_ni_credenciales(self):
        c = self.cliente(self.su)
        with mock.patch("dashboard.ia.proveedores.obtener_proveedor", side_effect=AssertionError("IA")), \
                mock.patch("sentria_backend.get_latest_alerts", side_effect=AssertionError("indexador"), create=True), \
                mock.patch.dict("os.environ", {"GEMINI_API_KEY": "CLAVE-SENTINELA-NO-USAR"}):
            for url in (reverse("comparacion"), reverse("comparacion_exportar_csv"), reverse("comparacion_exportar_json")):
                r = c.get(url)
                self.assertEqual(r.status_code, 200)
                self.assertNotIn(b"CLAVE-SENTINELA", r.content)
            arch = io.BytesIO(linea_v2().encode())
            arch.name = "z.jsonl"
            self.assertEqual(c.post(reverse("comparacion_importar"), {"archivo": arch}).status_code, 200)


# ------------------------------------------------------------------------------- correcciones de la revisión v1
class CorreccionesRevisionV1Tests(_Base):
    """Hallazgos 1–3 de revision_v1 (el 4, procedencia explícita, está en RegistroLocalTests)."""

    def importar(self, contenido, **kw):
        return I.confirmar(contenido, nombre="r.jsonl", usuario=self.su, registrar_casos_nuevos=True, **kw)

    def grupos_por_uuid(self):
        filas, _ = E.consulta({})
        return {str(e.uuid): E.grupo_de(e) for e in filas}

    # -- 1. repeticiones con la misma respuesta ---------------------------------------------------------------
    def test_archivo_con_dos_repeticiones_identicas_en_respuesta_cuenta_n2(self):
        u1, u2 = str(uuid.uuid4()), str(uuid.uuid4())
        comun = dict(respuesta_sha256=H("misma respuesta"), proveedor="prov_rep", modelo_informado="m-rep")
        contenido = (linea_v2(uuid=u1, tiempo_proveedor_s=2.0, **comun) + "\n" +
                     linea_v2(uuid=u2, tiempo_proveedor_s=3.5, repeticion=2, **comun)).encode()
        a = I.analizar(contenido, privados=IdentificadoresPrivados())
        self.assertEqual([f["resultado"] for f in a["filas"]], ["caso_nuevo", "caso_nuevo"])
        self.assertIn("se conserva como repetición", a["filas"][1]["motivo"])
        self.assertEqual(self.importar(contenido).resumen["recuento"], {"importada": 2})
        filas, _ = E.consulta({})
        d = E.datos_grupo(filas, E.grupo_de(filas[0]))
        self.assertEqual((d["n"], d["latencia"][0]["n_medido"], sorted(d["latencia"][0]["valores"])), (2, 2, [2.0, 3.5]))
        # Reimportar los mismos UUID no añade filas; mismo UUID con otro contenido sigue siendo conflicto.
        self.assertEqual(self.importar(contenido).resumen["recuento"], {"existente": 2})
        r = self.importar(linea_v2(uuid=u1, tiempo_proveedor_s=9.9, **comun).encode())
        self.assertEqual(r.resumen["recuento"], {"conflicto": 1})
        self.assertEqual(EjecucionComparacion.objects.count(), 2)

    def test_local_e_importada_con_misma_respuesta_en_ambos_sentidos(self):
        resp = '{"verdict": "REQUIERE_ATENCION", "risk": "LOW", "n": "igual"}'
        # local primero, luego importación de otra ejecución (UUID propio) con la misma respuesta
        alerta("OSID-REP-000000000000001", "rep\n", respuesta=resp, lat=4.0, analisis=4.4)
        self.assertEqual(L.registrar(self.su)["registradas"], 1)
        caso = CasoComparacion.objects.get()
        otra = linea_v2(proveedor="gemini_developer", entrada_sha256=caso.entrada_sha256, respuesta_sha256=H(resp),
                        tiempo_proveedor_s=5.0, configuracion=dict((k, v) for k, v in PARAMS.items()
                                                                   if k != "esquema_salida_sha256"))
        self.assertEqual(self.importar(otra.encode()).resumen["recuento"], {"importada": 1})
        self.assertEqual(EjecucionComparacion.objects.filter(caso=caso).count(), 2)
        # importación primero, luego registro local con la misma respuesta
        resp2 = '{"verdict": "REQUIERE_ATENCION", "risk": "LOW", "n": "igual2"}'
        self.importar(linea_v2(proveedor="gemini_developer", entrada_sha256=H("rep2\n"), respuesta_sha256=H(resp2)).encode())
        alerta("OSID-REP-000000000000002", "rep2\n", respuesta=resp2)
        r = L.registrar(self.su)
        self.assertEqual((r["registradas"], r["repeticiones_con_misma_respuesta"], r["ambiguas_no_registradas"]), (1, 1, 0))
        self.assertEqual(EjecucionComparacion.objects.filter(caso__entrada_sha256=H("rep2\n")).count(), 2)
        self.assertEqual(L.registrar(self.su)["registradas"], 0)              # idempotente por la alerta

    def test_local_frente_a_referencia_v1_queda_ambigua_hasta_decidir(self):
        resp = '{"verdict": "REQUIERE_ATENCION", "risk": "LOW", "n": "ref"}'
        ref = {"registro_version": "registro_comparacion_v1", "caso": "CASO-REF", "formato_entrada": "prompt_sentria",
               "entrada_sha256": H("refamb\n"), "esquema_sha256_canonico": ESQ, "proveedor": "gemini_developer",
               "estado_llamada": "ok", "estado_analisis": "COMPLETED", "respuesta_sha256": H(resp),
               "veredicto": "REQUIERE_ATENCION", "riesgo": "LOW", "observaciones": "referencia observada en SENTRIA"}
        self.importar((json.dumps(ref) + "\n").encode())
        alerta("OSID-AMB-000000000000001", "refamb\n", respuesta=resp)
        r = L.registrar(self.su)
        self.assertEqual((r["registradas"], r["ambiguas_no_registradas"]), (0, 1))
        self.assertEqual(EjecucionComparacion.objects.count(), 1)
        r = L.registrar(self.su, incluir_ambiguas=True)
        self.assertEqual(r["registradas"], 1)
        self.assertEqual(sorted(EjecucionComparacion.objects.values_list("identidad_derivada", flat=True)), [False, True])

    def test_identidad_derivada_debe_ser_booleana_en_el_documento(self):
        self.importar(linea_v2().encode())
        doc = json.loads(doc_de(EjecucionComparacion.objects.all()))
        doc["ejecuciones"][0]["identidad_derivada"] = "no"
        a = I.analizar(json.dumps(doc).encode(), privados=IdentificadoresPrivados())
        self.assertEqual(a["filas"][0]["resultado"], "rechazada")

    # -- 2. no verificada no es equivalente -------------------------------------------------------------------
    def test_no_verificada_y_equivalente_son_grupos_distintos_en_tabla_figuras_csv_y_manifiesto(self):
        ue, un = str(uuid.uuid4()), str(uuid.uuid4())
        self.importar((linea_v2(uuid=ue, equivalencia="equivalente") + "\n" +
                       linea_v2(uuid=un, equivalencia="no_verificada", respuesta_sha256=H("otra"))).encode())
        g = self.grupos_por_uuid()
        self.assertNotEqual(g[ue], g[un])
        c = self.cliente(self.su)
        pagina = c.get(reverse("comparacion"))
        self.assertEqual(len(pagina.context["grupos"]), 2)
        self.assertContains(pagina, "Condiciones sin verificar")
        for uid, equiv in ((ue, "equivalente"), (un, "no_verificada")):
            datos = c.get(reverse("comparacion_grafica_datos", args=["latencia"]) + f"?grupo={g[uid]}").content
            filas = datos.decode("utf-8-sig").splitlines()
            self.assertEqual(len(filas), 2)
            self.assertIn(uid, filas[1])
            self.assertIn(f";{equiv};", filas[1])
            man = json.loads(c.get(reverse("comparacion_grafica_manifiesto", args=["latencia"]) + f"?grupo={g[uid]}").content)
            self.assertEqual((man["equivalencia"], [x["uuid"] for x in man["ejecuciones"]]), (equiv, [uid]))
        if G.disponible():
            filas, _ = E.consulta({})
            fig = G._latencia(E.datos_grupo(filas, g[un]))
            self.assertIn("no es una comparación controlada", " ".join(t.get_text() for t in fig.texts))
            self.assertNotIn(E.datos_grupo(filas, g[un])["caso"].entrada_sha256[:12], " ".join(t.get_text() for t in fig.texts))

    # -- 3. esquema efectivo y parámetros completos -----------------------------------------------------------
    def test_esquema_efectivo_distinto_o_ausente_y_parametro_adicional_separan_grupos(self):
        base, otro, sin, extra = (str(uuid.uuid4()) for _ in range(4))
        cfg = {"temperature": 0.1, "max_output_tokens": 8192}
        self.importar("\n".join([
            linea_v2(uuid=base, configuracion=cfg),
            linea_v2(uuid=otro, configuracion=cfg, esquema_efectivo_sha256="d" * 64, respuesta_sha256=H("o")),
            linea_v2(uuid=sin, configuracion=cfg, esquema_efectivo_sha256=None, equivalencia="no_verificada",
                     respuesta_sha256=H("s")),
            linea_v2(uuid=extra, configuracion=dict(cfg, top_p=0.9), respuesta_sha256=H("x")),
        ]).encode())
        g = self.grupos_por_uuid()
        self.assertEqual(len({g[base], g[otro], g[sin], g[extra]}), 4)
        filas, _ = E.consulta({})
        por_uuid = {str(e.uuid): e for e in filas}
        self.assertEqual(E.protocolo(por_uuid[sin])[1]["esquema_efectivo"], "no_declarado")
        self.assertEqual(E.protocolo(por_uuid[base])[1]["esquema_efectivo"], ESQ)
        self.assertEqual(E.protocolo(por_uuid[base])[1]["esquema_referencia"], ESQ)
        self.assertIn("top_p", E.protocolo(por_uuid[extra])[1]["parametros"])
        d = E.datos_grupo(filas, g[sin])
        self.assertEqual((d["equivalencia"], d["detalle"]["esquema_efectivo"]), ("no_verificada", "no_declarado"))
        # La huella del esquema dentro de los parámetros no duplica la identidad: mismo protocolo con o sin ella.
        con_clave = linea_v2(configuracion=dict(cfg, esquema_salida_sha256=ESQ), respuesta_sha256=H("k"))
        self.importar(con_clave.encode())
        filas, _ = E.consulta({})
        nuevo = [e for e in filas if str(e.uuid) not in g][0]
        self.assertEqual(E.grupo_de(nuevo), g[base])


class PresentacionTests(_Base):
    """Revisión visual: vista principal en lenguaje sencillo; huellas e identificadores solo en «Ver detalles»."""

    @staticmethod
    def visibles_fuera_de_detalles(html_bytes):
        import html as H_
        import re
        s = html_bytes.decode("utf-8")
        s = re.sub(r"<details.*?</details>", "", s, flags=re.S)
        s = re.sub(r"<(script|style)\b.*?</\1>", "", s, flags=re.S)
        texto = H_.unescape(re.sub(r"<[^>]+>", " ", s))
        return re.findall(r"\b[0-9a-f]{32,}\b|\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", texto), texto

    def test_sin_identificadores_largos_fuera_de_ver_detalles_y_textos_sencillos(self):
        alerta("OSID-PRES-000000000000001", "pres\n", tokens=(None, None, None, None), lat=None, analisis=0.4,
               llamada="error", estado="ANALISIS_FALLIDO", informado=None)
        alerta("OSID-PRES-000000000000002", "pres\n")
        L.registrar(self.su)
        c = self.cliente(self.su)
        filas, _ = E.consulta({})
        g = E.grupo_de(filas[0])
        for url in (reverse("comparacion"), reverse("comparacion") + f"?grupo={g}",
                    *(reverse("comparacion_detalle", args=[e.uuid]) for e in filas)):
            largos, texto = self.visibles_fuera_de_detalles(c.get(url).content)
            self.assertEqual(largos, [], url)
            self.assertNotIn("REQUIERE_ATENCION", texto)
            self.assertNotIn("usage_del_proveedor", texto)
        principal = c.get(reverse("comparacion") + f"?grupo={g}")
        self.assertContains(principal, "Cómo leer los tiempos y los tokens")
        self.assertContains(principal, "Ver detalles")
        self.assertContains(principal, "WIN-L01")                       # código legible, no derivado de la huella
        self.assertContains(principal, "No disponible")
        detalle = c.get(reverse("comparacion_detalle", args=[filas[0].uuid]))
        self.assertContains(detalle, "Ver detalles técnicos")
        self.assertContains(detalle, filas[0].caso.entrada_sha256)      # conservado para reproducir, en detalles
        self.assertContains(detalle, "desde que se envía el caso hasta que el proveedor responde")


# ------------------------------------------------------------------------------ resumen del conjunto congelado
from dashboard.comparacion import conjuntos as CJ  # noqa: E402
from dashboard.comparacion import resumen as RS  # noqa: E402
from dashboard.models import ConjuntoComparacion  # noqa: E402

FICT_A, FICT_B = "prov_ficticio_a", "prov_ficticio_b"          # proveedores FICTICIOS: solo existen en las pruebas


def _l(prov, modelo, caso, rep, lat, tok, minuto, **kw):
    e, s, t = tok if tok else (None, None, None)
    base = dict(proveedor=prov, modelo_informado=modelo, modelo_solicitado=modelo, caso=f"CASO-{caso}",
                entrada_sha256=H(f"caso {caso}\n"), repeticion=rep, tiempo_proveedor_s=lat, tokens_entrada=e,
                tokens_salida=s, tokens_total=t, tokens_razonamiento=None, respuesta_sha256=H(f"{prov}{modelo}{caso}{rep}{kw}"),
                configuracion={"temperature": 0.1}, fecha_utc=f"2026-11-12T10:{minuto:02d}:00Z")
    base.update(kw)
    return linea_v2(**base)


def doc_con_conjunto(codigo="PILOTO-PRUEBA", version=1, casos_extra=(), quitar=()):
    doc = json.loads(doc_de(EjecucionComparacion.objects.all()))
    casos = {c["clave"]: c for c in doc["casos"]}
    for c in casos_extra:
        n = N.caso(c)
        casos[n["clave"]] = dict(c, clave=n["clave"])
    for q in quitar:
        casos.pop(q, None)
    doc["casos"] = sorted(casos.values(), key=lambda x: x["clave"])
    claves = sorted(casos)
    norm = {k: N.caso(v) for k, v in casos.items()}
    reglas = {"una_invocacion_por_caso_y_repeticion": True, "reintentos": 0, "agregacion": CJ.REGLA_AGREGACION}
    doc["conjunto"] = {"codigo": codigo, "version": version, "descripcion": "conjunto de prueba", "reglas": reglas,
                       "casos": claves, "manifiesto_sha256": CJ.huella_manifiesto(codigo, version, "conjunto de prueba",
                                                                                 reglas, [norm[k] for k in claves])}
    return json.dumps(doc, ensure_ascii=False).encode()


CASO_D = {"formato_entrada": "prompt_sentria", "entrada_sha256": H("caso D\n"), "esquema_sha256": ESQ,
          "codigo": "CASO-D", "procedencia": "windows_natural"}


class ResumenConjuntoTests(_Base):
    def setUp(self):
        super().setUp()
        lineas = [
            _l(FICT_A, "a-1", "A", 1, 2.0, (100, 10, 110), 1), _l(FICT_A, "a-1", "A", 2, 4.0, (110, 20, 130), 2),
            _l(FICT_A, "a-1", "B", 1, 5.0, (200, 20, 220), 3), _l(FICT_A, "a-1", "C", 1, None, None, 4),
            _l(FICT_B, "b-1", "A", 1, 1.0, (90, 9, 99), 5), _l(FICT_B, "b-1", "B", 1, 3.0, (180, 18, 198), 6),
            _l(FICT_B, "b-1", "B", 2, None, None, 7),
            _l(FICT_B, "b-1", "B", 3, 9.0, (1, 1, 2), 8, equivalencia="no_verificada", esquema_efectivo_sha256=None),
        ]
        I.confirmar("\n".join(lineas).encode(), nombre="f.jsonl", usuario=self.su, registrar_casos_nuevos=True)
        lote = I.confirmar(doc_con_conjunto(casos_extra=[CASO_D]), nombre="c.json", usuario=self.su,
                           registrar_casos_nuevos=True)
        self.assertEqual(lote.resumen["conjunto"]["resultado"], "creado")
        self.cj = ConjuntoComparacion.objects.get()

    def serie(self, r, prov, equiv="equivalente"):
        return next(s for s in r["series"] if s["proveedor"] == prov and s["equivalencia"] == equiv)

    def test_agregados_cobertura_faltantes_y_repeticiones(self):
        r = RS.calcular(self.cj)
        self.assertEqual(r["n_casos"], 4)
        a, b = self.serie(r, FICT_A), self.serie(r, FICT_B)
        self.assertEqual((a["n_casos"], a["n_pendientes"], a["n_ejecuciones"]), (3, 1, 4))
        self.assertEqual((a["tiempo"]["media_por_caso"], a["tiempo"]["mediana_por_caso"]), (4.0, 4.0))   # A=3, B=5
        self.assertEqual((a["tiempo"]["n_medidas"], a["tiempo"]["n_faltantes"]), (3, 1))
        te = a["tokens"]["tokens_entrada"]
        self.assertEqual((te["total_observado"], te["n_medidas"], te["n_faltantes"]), (410, 3, 1))
        self.assertAlmostEqual(te["promedio_por_ejecucion"], 410 / 3)
        self.assertEqual((b["n_casos"], b["n_ejecuciones"], b["tiempo"]["media_por_caso"]), (2, 3, 2.0))
        self.assertEqual(self.serie(r, FICT_B, "no_verificada")["n_ejecuciones"], 1)        # aparte, no comparable
        comp = r["comparacion"]
        self.assertEqual(comp["n_casos_comunes"], 2)                                     # A y B (C solo en a-1)
        ca = next(s for s in comp["series"] if s["proveedor"] == FICT_A)
        cb = next(s for s in comp["series"] if s["proveedor"] == FICT_B)
        self.assertEqual((ca["tiempo_media_por_caso"], cb["tiempo_media_por_caso"]), (4.0, 2.0))
        self.assertEqual(ca["tokens_entrada"]["media_por_caso"], (105 + 200) / 2)        # A=(100+110)/2, B=200
        self.assertFalse(r["pendiente_otro_proveedor"])
        p = RS.calcular(self.cj, repeticiones="primera")
        self.assertEqual(self.serie(p, FICT_A)["tiempo"]["media_por_caso"], 3.5)          # A=2 (primera), B=5

    def test_otra_version_de_modelo_y_otro_protocolo_son_series_separadas(self):
        I.confirmar("\n".join([_l(FICT_B, "b-2", "A", 1, 7.0, (1, 1, 2), 9),
                               _l(FICT_A, "a-1", "B", 2, 8.0, (1, 1, 2), 10, configuracion={"temperature": 0.7})]).encode(),
                    nombre="g.jsonl", usuario=self.su)
        r = RS.calcular(self.cj)
        etiquetas = sorted((s["proveedor"], s["modelo"], s["protocolo"]) for s in r["series"] if s["equivalencia"] == "equivalente")
        self.assertEqual(len(etiquetas), 4)
        self.assertEqual(self.serie(r, FICT_A)["n_ejecuciones"] + 1, sum(s["n_ejecuciones"] for s in r["series"] if s["proveedor"] == FICT_A))

    def test_un_solo_proveedor_queda_pendiente(self):
        r = RS.calcular(self.cj, serie=self.serie(RS.calcular(self.cj), FICT_A)["id"])
        self.assertTrue(r["pendiente_otro_proveedor"])
        self.assertIsNone(r["comparacion"])
        c = self.cliente(self.su)
        pagina = c.get(reverse("comparacion") + f"?conjunto={CJ.identificador(self.cj)}&serie={self.serie(r, FICT_A)['id']}")
        self.assertContains(pagina, "Pendiente de resultados de otro proveedor")

    def test_conjunto_idempotente_y_conflicto_de_version(self):
        self.assertEqual(I.analizar(doc_con_conjunto(casos_extra=[CASO_D]), privados=IdentificadoresPrivados())["conjunto"]["estado"], "existente")
        with self.assertRaises(I.ArchivoInvalido):                                        # misma versión, otros casos
            I.analizar(doc_con_conjunto(), privados=IdentificadoresPrivados())
        doc = json.loads(doc_con_conjunto(casos_extra=[CASO_D]))
        doc["conjunto"]["descripcion"] = "alterado"
        with self.assertRaises(I.ArchivoInvalido):                                        # huella alterada
            I.analizar(json.dumps(doc).encode(), privados=IdentificadoresPrivados())
        I.confirmar(doc_con_conjunto(version=2), nombre="v2.json", usuario=self.su, registrar_casos_nuevos=True)
        self.assertEqual(ConjuntoComparacion.objects.count(), 2)                          # ampliar = otra versión

    def test_lineas_del_ejecutor_con_referencia_al_conjunto(self):
        ref = {"codigo": self.cj.codigo, "version": 1, "manifiesto_sha256": self.cj.manifiesto_sha256}
        ok = _l(FICT_B, "b-1", "C", 1, 2.2, (1, 1, 2), 20, conjunto=ref)
        fuera = _l(FICT_B, "b-1", "Z", 1, 2.2, (1, 1, 2), 21, conjunto=ref)
        desconocido = _l(FICT_B, "b-1", "C", 2, 2.2, (1, 1, 2), 22, conjunto=dict(ref, codigo="OTRO"))
        a = I.analizar("\n".join([ok, fuera, desconocido]).encode(), privados=IdentificadoresPrivados())
        self.assertEqual([f["resultado"] for f in a["filas"]], ["nueva", "rechazada", "rechazada"])
        self.assertIn("no pertenece", a["filas"][1]["motivo"])
        self.assertIn("desconocido", a["filas"][2]["motivo"])

    def test_csv_permite_recalcular_y_ficha_coherente(self):
        import csv as csv_
        c = self.cliente(self.su)
        q = f"?conjunto={CJ.identificador(self.cj)}"
        datos = c.get(reverse("comparacion_resumen_datos") + q).content
        ficha = json.loads(c.get(reverse("comparacion_resumen_ficha") + q).content)
        self.assertEqual(ficha["datos_csv_sha256"], hashlib.sha256(datos).hexdigest())
        filas = list(csv_.DictReader(io.StringIO(datos.decode("utf-8-sig")), delimiter=";"))
        sa = next(s for s in ficha["series"] if s["proveedor"] == FICT_A and s["equivalencia"] == "equivalente")
        mias = [f for f in filas if f["Serie"] == sa["id"] and f["UUID"] != "No disponible"]
        porcaso = {}
        for f in mias:
            if f["Latencia del proveedor (s)"] != "No disponible":
                porcaso.setdefault(f["Clave del caso"], []).append(float(f["Latencia del proveedor (s)"]))
        medias = [sum(v) / len(v) for v in porcaso.values()]
        self.assertAlmostEqual(sum(medias) / len(medias), sa["tiempo"]["media_por_caso"])
        pend = [f for f in filas if f["Serie"] == sa["id"] and f["Resultado"].startswith("Pendiente")]
        self.assertEqual(len(pend), sa["n_pendientes"])
        self.assertEqual(ficha["comparacion"]["n_casos_comunes"], 2)

    @skipUnless(G.disponible(), "matplotlib no instalado en este entorno")
    def test_figuras_del_resumen(self):
        c = self.cliente(self.su)
        q = f"?conjunto={CJ.identificador(self.cj)}"
        for t in G.TIPOS_RESUMEN:
            png = c.get(reverse("comparacion_resumen_grafica", args=[t, "png"]) + q)
            self.assertEqual((png.status_code, png.content[:4]), (200, b"\x89PNG"))
            self.assertIn(b"<svg", c.get(reverse("comparacion_resumen_grafica", args=[t, "svg"]) + q).content[:400])
            self.assertTrue(c.get(reverse("comparacion_resumen_grafica", args=[t, "pdf"]) + q).content.startswith(b"%PDF"))
        self.assertEqual(c.get(reverse("comparacion_resumen_grafica", args=["otro", "png"]) + q).status_code, 404)
        r = RS.calcular(self.cj)
        textos = " ".join(t.get_text() for t in G._resumen_tiempo(r).texts).replace("\n", " ")
        self.assertIn("cada caso pesa", textos)
        self.assertNotIn(self.cj.manifiesto_sha256[:12], textos)

    def test_permisos_de_las_rutas_nuevas_y_exportacion_del_conjunto(self):
        q = f"?conjunto={CJ.identificador(self.cj)}"
        urls = [reverse("comparacion_resumen_datos") + q, reverse("comparacion_resumen_ficha") + q,
                reverse("comparacion_resumen_grafica", args=["tiempo", "png"]) + q,
                reverse("comparacion_exportar_json") + q]
        for u in (usuario("adm_rs", rol="ADMIN"), usuario("staff_rs", staff=True), usuario("inv_rs", rol="INVITADO")):
            for url in urls:
                self.assertEqual(self.cliente(u).get(url).status_code, 403, url)
        for url in urls:
            self.assertEqual(self.cliente().get(url).status_code, 302)
        doc = self.cliente(self.su).get(reverse("comparacion_exportar_json") + q).content
        d = json.loads(doc)
        self.assertEqual(d["conjunto"]["manifiesto_sha256"], self.cj.manifiesto_sha256)
        self.assertEqual(len(d["casos"]), 4)                                              # también CASO-D sin ejecuciones
        self.assertEqual(I.analizar(doc, privados=IdentificadoresPrivados())["recuento"], {"existente": 8})
        # cambiar la procedencia editable de un caso no rompe la huella del conjunto exportado
        caso = CasoComparacion.objects.get(codigo="CASO-A")
        self.cliente(self.su).post(reverse("comparacion_procedencia", args=[caso.clave]), {"procedencia": "web_natural"})
        doc2 = self.cliente(self.su).get(reverse("comparacion_exportar_json") + q).content
        self.assertEqual(I.analizar(doc2, privados=IdentificadoresPrivados())["conjunto"]["estado"], "existente")
