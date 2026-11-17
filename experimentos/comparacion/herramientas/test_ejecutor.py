#!/usr/bin/env python3
"""
Pruebas SIN RED del ejecutor v2 (cada escenario en un proceso hijo: el aislamiento cambia el entorno e instala una
trampa de auditoría que no se puede retirar). Proveedores falsos; cero llamadas reales.

  EJECUTOR_CODIGO=../../codigo/sentria python -m unittest test_ejecutor -v
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

AQUI = os.path.dirname(os.path.abspath(__file__))
def _buscar_casos():
    # Repositorio: casos SINTÉTICOS de ../fixtures_sinteticos/casos. Paquete del equipo: ../conjunto/casos o ../casos.
    for d in (os.environ.get("EJECUTOR_CASOS"), os.path.join(AQUI, "..", "fixtures_sinteticos", "casos"),
              os.path.join(AQUI, "..", "conjunto", "casos"), os.path.join(AQUI, "..", "casos")):
        if d and os.path.isdir(d):
            return os.path.normpath(d)
    raise SystemExit("No se encuentran los casos (EJECUTOR_CASOS, ../fixtures_sinteticos/casos, ../conjunto/casos o ../casos)")


CASOS = _buscar_casos()


def _caso_de_tipo(tipo):
    for n in sorted(os.listdir(CASOS)):
        with open(os.path.join(CASOS, n, "ficha.json"), encoding="utf-8") as f:
            fi = json.load(f)
        if tipo in f"{fi.get('procedencia_conjunto') or ''} {fi.get('tipo') or ''}":
            return n
    raise SystemExit(f"No hay un caso de tipo {tipo}")


def _buscar_codigo():
    # Raíz del repositorio (donde está manage.py) o, en el paquete del equipo, ../../codigo/sentria.
    for d in (os.environ.get("EJECUTOR_CODIGO"), os.path.join(AQUI, "..", "..", ".."),
              os.path.join(AQUI, "..", "..", "codigo", "sentria")):
        if d and os.path.isfile(os.path.join(d, "dashboard", "ia", "prompt.py")):
            return os.path.abspath(d)
    raise SystemExit("No se encuentra el código de SENTRIA (EJECUTOR_CODIGO)")


WEB, WIN = _caso_de_tipo("web"), _caso_de_tipo("windows")
CODIGO = _buscar_codigo()
EJECUTOR = os.path.join(AQUI, "ejecutar_caso.py")
SENTINELAS = {"DB_PASSWORD": "SENTINELA-BD", "DJANGO_SECRET_KEY": "SENTINELA-SECRETO", "WAZUH_INDEXER_PASS": "SENTINELA-WZ",
              "SENTRIA_ENV_FILE": "/no/existe/.env", "MYSQL_PWD": "SENTINELA-MYSQL"}

ADAPTADOR = r'''
import json, os, socket
from dashboard.ia.proveedores import ProveedorIA, RespuestaProveedor
REF = open(os.environ.get("REF_RESPUESTA", "/no"), encoding="utf-8").read() if os.environ.get("REF_RESPUESTA") else "{}"
MODO = "%(modo)s"
class Falso(ProveedorIA):
    nombre, _modelo = "falso", "modelo-falso"
    def parametros_medicion(self):
        return {"temperature": 0.1, "esquema_salida_sha256": "%(esquema)s"}
    def analizar(self, prompt):
        if MODO == "ok":
            return RespuestaProveedor(ok=True, texto=REF, modelo=self._modelo, modelo_respuesta="falso-001",
                                      usage={"prompt": 10, "candidates": 5, "thoughts": None, "total": 15},
                                      finish_reason="STOP")
        if MODO == "429":
            return RespuestaProveedor(ok=False, texto="", modelo=self._modelo, codigo_http=429,
                                      error="ClientError: 429 api_key=CLAVE-FALSA-SIN-VALOR https://x.invalid/y")
        if MODO == "red_en_preparacion":
            raise AssertionError("no aplica")
        raise RuntimeError("fallo con api_key=CLAVE-FALSA-SIN-VALOR en /home/alguien/x")
# %(comentario)s
'''


def entorno(**extra):
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": tempfile.gettempdir(), **SENTINELAS, **extra}
    return env


def leer(ruta):
    with open(ruta, encoding="utf-8") as f:
        return json.loads(f.read())


def correr(args, env=None, codigo_hijo=None):
    cmd = [sys.executable, "-I", EJECUTOR, *args] if codigo_hijo is None else [sys.executable, "-I", "-c", codigo_hijo, *args]
    return subprocess.run(cmd, env=env or entorno(), capture_output=True, text=True, timeout=120, cwd=AQUI)


class EjecutorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ejecutor_prueba_")
        self.addCleanup(shutil.rmtree, self.tmp)
        self.ref = os.path.join(CASOS, WEB, "respuesta_referencia_gemini.json")
        self.esquema = leer(os.path.join(CASOS, WEB, "ficha.json"))["esquema_salida"]["sha256_canonico"]

    def adaptador(self, modo, esquema=None, comentario="v1"):
        p = os.path.join(self.tmp, f"adaptador_{modo}_{comentario}.py")
        with open(p, "w", encoding="utf-8") as f:
            f.write(ADAPTADOR % {"modo": modo, "esquema": esquema or self.esquema, "comentario": comentario})
        return p

    def confirmar(self, modo, caso=WEB, **kw):
        reg = os.path.join(self.tmp, "registro.jsonl")
        r = correr(["--codigo", CODIGO, "--caso", os.path.join(CASOS, caso), "--proveedor", "falso",
                    "--adaptador", self.adaptador(modo, **kw) + ":Falso", "--confirmar", "--registro", reg,
                    "--permitir-variable", "REF_RESPUESTA"],
                   env=entorno(REF_RESPUESTA=self.ref) | {"SENTRIA_ENV_FILE": ""})
        self.assertEqual(r.returncode, 0, r.stderr[-800:])
        with open(reg, encoding="utf-8") as f:
            return [json.loads(x) for x in f][-1], reg

    def test_ensayo_con_entorno_hostil_no_usa_variables_ni_env(self):
        with open(os.path.join(self.tmp, ".env"), "w") as f:
            f.write("GEMINI_API_KEY=NO-DEBE-LEERSE\n")
        r = correr(["--codigo", CODIGO, "--caso", os.path.join(CASOS, WIN), "--proveedor", "gemini_developer",
                    "--ensayo"])
        self.assertEqual(r.returncode, 0, r.stderr[-800:])
        d = json.loads(r.stdout)
        self.assertEqual((d["referencia_validada_como_sentria"], d["llamadas"], d["equivalencia"]),
                         ("COMPLETED", 0, "equivalente"))
        for v in SENTINELAS.values():
            self.assertNotIn(v, r.stdout + r.stderr)

    def test_aislamiento_vacia_entorno_y_activa_trampas(self):
        hijo = (
            "import os, sys, socket; sys.argv=['x']; sys.path.insert(0, %r)\n"
            "import importlib.util as u; s=u.spec_from_file_location('e', %r); e=u.module_from_spec(s); s.loader.exec_module(e)\n"
            "e.aislar_proceso('gemini_developer')\n"
            "print(sorted(k for k in os.environ if k.startswith(('DB_','DJANGO_','WAZUH_','SENTRIA_','MYSQL'))))\n"
            "res=[]\n"
            "for f in (lambda: open(%r), lambda: __import__('dotenv'), lambda: __import__('sentria_project.settings'),\n"
            "          lambda: socket.getaddrinfo('localhost', 80), lambda: __import__('MySQLdb')):\n"
            "    try: f(); res.append('permitido')\n"
            "    except (PermissionError, ImportError): res.append('bloqueado')\n"
            "print(res)\n") % (CODIGO, EJECUTOR, os.path.join(self.tmp, ".env"))
        open(os.path.join(self.tmp, ".env"), "w").close()
        r = correr([], codigo_hijo=hijo)
        self.assertEqual(r.returncode, 0, r.stderr[-800:])
        lineas = r.stdout.strip().splitlines()
        self.assertEqual(lineas[0], "[]")
        self.assertEqual(lineas[1], str(["bloqueado"] * 5))

    def test_rechaza_otro_django(self):
        r = correr(["--codigo", CODIGO, "--caso", os.path.join(CASOS, WIN), "--proveedor", "gemini_developer"],
                   env=entorno(DJANGO_SETTINGS_MODULE="sentria_project.settings"))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("DJANGO_SETTINGS_MODULE", r.stderr)
        hijo = ("import sys; sys.path.insert(0, %r)\nfrom django.conf import settings; settings.configure()\n"
                "import importlib.util as u; s=u.spec_from_file_location('e', %r); e=u.module_from_spec(s); s.loader.exec_module(e)\n"
                "e.aislar_proceso('gemini_developer')\n") % (CODIGO, EJECUTOR)
        r = correr([], codigo_hijo=hijo)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("Django ya está configurado", r.stderr)

    def test_confirmar_se_niega_en_el_entorno_del_autor(self):
        r = correr(["--codigo", CODIGO, "--caso", os.path.join(CASOS, WIN), "--proveedor", "gemini_developer",
                    "--confirmar", "--registro", os.path.join(self.tmp, "r.jsonl")])
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "r.jsonl")))

    def test_exito_error_informado_y_excepcion_quedan_registrados(self):
        ok, _ = self.confirmar("ok")
        self.assertEqual((ok["estado_llamada"], ok["estado_analisis"], ok["tokens_total"], ok["tokens_razonamiento"],
                          ok["modelo_informado"], ok["equivalencia"]), ("ok", "COMPLETED", 15, None, "falso-001", "equivalente"))
        self.assertEqual(ok["registro_version"], "registro_comparacion_v2")
        self.assertIsNotNone(ok["uuid"])
        e429, _ = self.confirmar("429")
        self.assertEqual((e429["estado_llamada"], e429["categoria_error"], e429["codigo_http"], e429["tokens_total"]),
                         ("error", "http_429", 429, None))
        exc, reg = self.confirmar("excepcion")
        self.assertEqual((exc["estado_llamada"], exc["estado_analisis"], exc["categoria_error"]),
                         ("error", "ANALISIS_FALLIDO", "excepcion_adaptador:RuntimeError"))
        self.assertIsNotNone(exc["tiempo_proveedor_s"])
        self.assertIsNone(exc["tokens_total"])
        with open(reg, encoding="utf-8") as f:
            texto = f.read()
        for prohibido in ("CLAVE-FALSA", "x.invalid", "/home/alguien", "Traceback", *SENTINELAS.values()):
            self.assertNotIn(prohibido, texto)
        self.assertEqual(len({json.loads(x)["uuid"] for x in texto.splitlines()}), 3)

    def test_cambio_de_adaptador_o_codigo_se_refleja_en_las_huellas(self):
        a, _ = self.confirmar("ok", comentario="v1")
        b, _ = self.confirmar("ok", comentario="v2-modificado")
        self.assertNotEqual(a["adaptador_sha256"], b["adaptador_sha256"])
        self.assertEqual(a["codigo_ejecucion_sha256"], b["codigo_ejecucion_sha256"])
        self.assertEqual(a["manifiesto_codigo_sha256"], b["manifiesto_codigo_sha256"])      # identidad del paquete base
        copia = os.path.join(self.tmp, "codigo_copia")
        shutil.copytree(CODIGO, copia, ignore=shutil.ignore_patterns("__pycache__", ".env", "*.sqlite3"))
        with open(os.path.join(copia, "dashboard", "ia", "contrato.py"), "a", encoding="utf-8") as f:
            f.write("\n# cambio local del participante\n")
        reg = os.path.join(self.tmp, "registro2.jsonl")
        r = correr(["--codigo", copia, "--caso", os.path.join(CASOS, WEB), "--proveedor", "falso", "--adaptador",
                    self.adaptador("ok") + ":Falso", "--confirmar", "--registro", reg, "--permitir-variable", "REF_RESPUESTA"],
                   env=entorno(REF_RESPUESTA=self.ref) | {"SENTRIA_ENV_FILE": ""})
        self.assertEqual(r.returncode, 0, r.stderr[-800:])
        c = leer(reg)
        self.assertNotEqual(c["codigo_ejecucion_sha256"], a["codigo_ejecucion_sha256"])
        self.assertEqual(c["entrada_sha256"], a["entrada_sha256"])                          # entrada congelada intacta

    def test_esquema_distinto_es_variante_y_no_representable_es_incompatible(self):
        v, _ = self.confirmar("ok", esquema="0" * 64)
        self.assertEqual(v["equivalencia"], "variante")
        reg = os.path.join(self.tmp, "r3.jsonl")
        r = correr(["--codigo", CODIGO, "--caso", os.path.join(CASOS, WEB), "--proveedor", "vertex_tuned",
                    "--confirmar", "--registro", reg], env=entorno() | {"SENTRIA_ENV_FILE": ""})
        self.assertEqual(r.returncode, 0, r.stderr[-800:])
        d = leer(reg)
        self.assertEqual((d["estado_llamada"], d["equivalencia"], d["tiempo_proveedor_s"], d["tokens_total"]),
                         ("sin_llamada", "incompatible", None, None))

    def test_permitir_variable_no_reabre_credenciales_del_despliegue(self):
        r = correr(["--codigo", CODIGO, "--caso", os.path.join(CASOS, WIN), "--proveedor", "gemini_developer",
                    "--permitir-variable", "DB_PASSWORD"])
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("SENTINELA-BD", r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()


class ConjuntoTests(unittest.TestCase):
    """ejecutar_conjunto.py: presupuesto explícito, una invocación por caso y repetición, reanudación sin repetir."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="conjunto_prueba_")
        self.addCleanup(shutil.rmtree, self.tmp)
        self.cj = os.path.join(self.tmp, "conjunto")
        os.makedirs(os.path.join(self.cj, "casos"))
        casos = []
        for c in (WIN, WEB):
            shutil.copytree(os.path.join(CASOS, c), os.path.join(self.cj, "casos", c))
            ficha = leer(os.path.join(CASOS, c, "ficha.json"))
            casos.append({"codigo": c, "entrada_sha256": ficha["archivos"]["entrada.txt"]["sha256"]})
        # las fichas apuntan a ../../esquema_salida.json: se copia al nivel del conjunto
        shutil.copy(os.path.join(CASOS, "..", "esquema_salida.json"), os.path.join(self.cj, "esquema_salida.json"))
        self.man = {"codigo": "PRUEBA-CJ", "version": 1, "manifiesto_sha256": "f" * 64, "casos": casos}
        with open(os.path.join(self.cj, "manifiesto_conjunto.json"), "w", encoding="utf-8") as f:
            json.dump(self.man, f)
        esq = leer(os.path.join(CASOS, WEB, "ficha.json"))["esquema_salida"]["sha256_canonico"]
        self.ad = os.path.join(self.tmp, "adaptador.py")
        with open(self.ad, "w", encoding="utf-8") as f:
            f.write(ADAPTADOR % {"modo": "ok", "esquema": esq, "comentario": "cj"})
        self.reg = os.path.join(self.tmp, "registro.jsonl")
        self.ref = os.path.join(CASOS, WEB, "respuesta_referencia_gemini.json")

    def correr_cj(self, *extra):
        args = [sys.executable, "-I", os.path.join(AQUI, "ejecutar_conjunto.py"), "--codigo", CODIGO, "--conjunto",
                self.cj, "--proveedor", "falso", "--adaptador", self.ad + ":Falso", "--permitir-variable",
                "REF_RESPUESTA", *extra]
        return subprocess.run(args, env=entorno(REF_RESPUESTA=self.ref) | {"SENTRIA_ENV_FILE": ""},
                              capture_output=True, text=True, timeout=300)

    def lineas(self):
        if not os.path.exists(self.reg):
            return []
        with open(self.reg, encoding="utf-8") as f:
            return [json.loads(x) for x in f]

    def test_ensayo_sin_llamadas(self):
        r = self.correr_cj("--ensayo")
        self.assertEqual(r.returncode, 0, r.stderr[-500:])
        self.assertEqual(json.loads(r.stdout.strip().splitlines()[-1])["invocaciones"], 0)
        self.assertEqual(self.lineas(), [])

    def test_presupuesto_obligatorio_y_suficiente(self):
        for extra in ([], ["--max-llamadas", "1"]):
            r = self.correr_cj("--confirmar", "--registro", self.reg, *extra)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("Presupuesto", r.stderr)
        self.assertEqual(self.lineas(), [])

    def test_una_invocacion_por_caso_y_reanudar_no_repite(self):
        r = self.correr_cj("--confirmar", "--registro", self.reg, "--max-llamadas", "2")
        self.assertEqual(r.returncode, 0, r.stderr[-500:] + r.stdout[-500:])
        l1 = self.lineas()
        self.assertEqual(len(l1), 2)
        self.assertTrue(all(x["conjunto"]["codigo"] == "PRUEBA-CJ" and x["repeticion"] == 1 for x in l1))
        self.assertEqual({x["entrada_sha256"] for x in l1}, {c["entrada_sha256"] for c in self.man["casos"]})
        r = self.correr_cj("--confirmar", "--registro", self.reg, "--max-llamadas", "2")
        self.assertEqual(json.loads(r.stdout.strip().splitlines()[-1])["saltados_ya_registrados"], 2)
        self.assertEqual(len(self.lineas()), 2)
        r = self.correr_cj("--confirmar", "--registro", self.reg, "--max-llamadas", "4", "--repeticiones", "2")
        self.assertEqual(json.loads(r.stdout.strip().splitlines()[-1])["invocaciones"], 2)
        self.assertEqual(sorted(x["repeticion"] for x in self.lineas()), [1, 1, 2, 2])

    def test_caso_fuera_del_conjunto_se_rechaza(self):
        man = dict(self.man, casos=self.man["casos"][:1])
        otro = os.path.join(self.tmp, "otro_manifiesto.json")
        with open(otro, "w", encoding="utf-8") as f:
            json.dump(man, f)
        r = correr(["--codigo", CODIGO, "--caso", os.path.join(self.cj, "casos", WEB), "--proveedor",
                    "gemini_developer", "--conjunto", otro, "--ensayo"])
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("no pertenece al conjunto", r.stderr)
