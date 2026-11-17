"""
Aislamiento de `settings_ci`: la suite no lee el `.env` local, ni un `SENTRIA_ENV_FILE` heredado, ni credenciales
del shell.

Cada prueba copia `sentria_project/`, `dashboard/`, `usuarios/` y `sentria_backend.py` a una carpeta temporal,
escribe allí un `.env` con valores FICTICIOS («CANARIO-…») y arranca Django en un proceso aparte (`python -I`, sin
la ruta del repositorio). Nunca se usa ni se lee el `.env` real del repositorio: el proceso hijo solo ve la copia.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
CANARIO = "CANARIO"
VARIABLES = (
    "DJANGO_SECRET_KEY", "DJANGO_DEBUG", "DJANGO_ALLOWED_HOSTS", "DB_NAME", "DB_USER", "DB_PASSWORD", "DB_HOST",
    "DB_PORT", "WAZUH_URL", "WAZUH_INDEX_NAME", "WAZUH_TLS_SHA256", "INDEXER_USER", "INDEXER_PASS",
    "GEMINI_API_KEY", "GEMINI_MODEL", "GEMINI_TUNED_ENDPOINT", "IA_PROVIDER", "IA_VERTEX_HABILITADO",
    "VERTEX_AUTENTICACION", "VERTEX_TOKEN_ARCHIVO", "GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_API_KEY",
    "IA_AGENTES_BLOQUEADOS", "SENTRIA_MODO_REVISION", "SENTRIA_EXCLUSION_DIR",
    "SENTRIA_MIGRAR_LEGADO_AUTORIZADO", "SENTRIA_GEMINI_REAL_AUTORIZADO", "SENTRIA_CONGELAR_AUTORIZADO",
    "SENTRIA_ACEPTAR_LOTE_AUTORIZADO",
)

# Proceso hijo: arranca Django con la configuración indicada, importa sentria_backend (que recarga el archivo de
# entorno con override=True) y devuelve SOLO nombres, nunca valores salvo los marcadores esperados.
_HIJO = r"""
import json, os, sys
sys.path.insert(0, sys.argv[1])
os.environ["DJANGO_SETTINGS_MODULE"] = sys.argv[2]
import django
django.setup()
from django.conf import settings
import sentria_backend
def _tiene(v):
    return "CANARIO" in repr(v)
env_file = os.environ.get("SENTRIA_ENV_FILE", "")
print(json.dumps({
    "entorno_con_canario": sorted(k for k, v in os.environ.items() if "CANARIO" in v),
    "ajustes_con_canario": sorted(k for k in dir(settings) if k.isupper() and _tiene(getattr(settings, k))),
    "backend_con_canario": sorted(k for k in dir(sentria_backend) if k.isupper()
                                  and _tiene(getattr(sentria_backend, k))),
    "secret_key_marcador": settings.SECRET_KEY == "ci-insecure-placeholder-not-a-secret",
    "secret_key_del_env_local": settings.SECRET_KEY == "CANARIO-ENV-DJANGO_SECRET_KEY",
    "gemini_api_key_vacia": os.environ.get("GEMINI_API_KEY") == "",
    "motor_bd": settings.DATABASES["default"]["ENGINE"],
    "env_file": env_file,
    "env_file_tam": os.path.getsize(env_file) if env_file else None,
    "env_file_modo": oct(os.stat(env_file).st_mode & 0o777) if env_file else None,
    "env_dir_modo": oct(os.stat(os.path.dirname(env_file)).st_mode & 0o777) if env_file else None,
}))
"""


def _escribir_env(ruta, prefijo):
    with open(os.open(ruta, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w", encoding="utf-8") as f:
        for v in VARIABLES:
            f.write(f"{v}={CANARIO}-{prefijo}-{v}\n")


class AislamientoSettingsCiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix="sentria-aislamiento-")
        cls.base = Path(cls._tmp.name)
        cls.copia = cls.base / "proyecto"
        ignorar = shutil.ignore_patterns("__pycache__", "*.pyc", ".env", "*.env")
        for d in ("sentria_project", "dashboard", "usuarios"):
            shutil.copytree(RAIZ / d, cls.copia / d, ignore=ignorar)
        shutil.copy2(RAIZ / "sentria_backend.py", cls.copia / "sentria_backend.py")
        _escribir_env(cls.copia / ".env", "ENV")                   # .env local de la copia
        cls.heredado = cls.base / "heredado.env"
        _escribir_env(cls.heredado, "HEREDADO")                    # SENTRIA_ENV_FILE heredado del shell
        cls.home = cls.base / "home"
        cls.home.mkdir()

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _ejecutar(self, modulo, extra):
        entorno = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(self.home),
                   "TMPDIR": str(self.base), "LANG": "C.UTF-8", "MPLCONFIGDIR": str(self.base / "mpl")}
        entorno.update(extra)
        r = subprocess.run([sys.executable, "-I", "-B", "-c", _HIJO, str(self.copia), modulo],
                           cwd=str(self.base), env=entorno, capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, msg=r.stderr[-2000:].replace(CANARIO, "<marcador>"))
        return json.loads(r.stdout.strip().splitlines()[-1])

    def test_settings_ci_ignora_env_local_archivo_heredado_y_shell(self):
        shell = {v: f"{CANARIO}-SHELL-{v}" for v in VARIABLES}
        shell["SENTRIA_ENV_FILE"] = str(self.heredado)
        r = self._ejecutar("sentria_project.settings_ci", shell)
        self.assertEqual(r["entorno_con_canario"], [])
        self.assertEqual(r["ajustes_con_canario"], [])
        self.assertEqual(r["backend_con_canario"], [])
        self.assertTrue(r["secret_key_marcador"])
        self.assertTrue(r["gemini_api_key_vacia"])
        self.assertEqual(r["motor_bd"], "django.db.backends.sqlite3")

    def test_archivo_de_entorno_vacio_privado_y_borrado_al_salir(self):
        r = self._ejecutar("sentria_project.settings_ci", {})
        self.assertEqual((r["env_file_tam"], r["env_file_modo"], r["env_dir_modo"]), (0, "0o600", "0o700"))
        self.assertTrue(r["env_file"].startswith(str(self.base)))
        self.assertFalse(os.path.exists(os.path.dirname(r["env_file"])))

    def test_settings_de_produccion_siguen_cargando_el_env_local(self):
        # Control: el mismo .env ficticio SÍ lo carga la configuración normal, que no cambia.
        r = self._ejecutar("sentria_project.settings", {})
        self.assertTrue(r["secret_key_del_env_local"])
        self.assertIn("SECRET_KEY", r["ajustes_con_canario"])
