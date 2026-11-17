"""
Settings SOLO para pruebas y `makemigrations` en local, SIN MySQL.

No contiene secretos reales: todos los valores son marcadores obvios. Nunca
debe usarse en producción. Uso:

    python manage.py test --settings=sentria_project.settings_ci
    python manage.py makemigrations --settings=sentria_project.settings_ci

Aislamiento del entorno (solo en este proceso de pruebas; `settings.py`,
`env_utils.py` y `sentria_backend.py` no cambian):

1. Se crea una carpeta temporal privada (700) con un archivo de entorno VACÍO
   (600) y se apunta `SENTRIA_ENV_FILE` a él. `settings.py` y
   `sentria_backend.py` (que recarga el archivo con `override=True` al
   importarse) cargan ese archivo vacío y no el `.env` local del proyecto ni
   el `SENTRIA_ENV_FILE` heredado del shell.
2. Se retiran del entorno heredado las variables que SENTRIA o los clientes
   de Google leen y que pueden llevar credenciales, destinos reales o
   autorizaciones (`_RETIRAR`).
3. Se FUERZAN valores marcadores para las variables obligatorias (no
   `setdefault`: un valor real del shell no sobrevive).
4. La base de datos es SQLite en memoria y el directorio de exclusión es una
   subcarpeta de la carpeta temporal, que se borra al terminar el proceso.

Las pruebas que necesitan otra configuración la fijan ellas mismas con
`mock.patch.dict(os.environ, ...)`. La comprobación de este aislamiento está
en `sentria_project/tests_aislamiento_ci.py`.
"""
import atexit
import os
import shutil
import sys
import tempfile

from django.core.exceptions import ImproperlyConfigured

if "sentria_project.settings" in sys.modules:
    # settings.py ya se importó (y cargó su .env) en este proceso: el aislamiento ya no es posible.
    raise ImproperlyConfigured("settings_ci debe importarse antes que sentria_project.settings.")

_RETIRAR = (
    # Wazuh
    "WAZUH_URL", "WAZUH_INDEX_NAME", "WAZUH_TLS_SHA256", "INDEXER_USER", "INDEXER_PASS",
    # Proveedores de IA (SENTRIA y variables que leen por su cuenta los clientes de Google)
    "GEMINI_MODEL", "GEMINI_TUNED_ENDPOINT", "IA_VERTEX_HABILITADO", "VERTEX_AUTENTICACION",
    "VERTEX_TOKEN_ARCHIVO", "GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_API_KEY", "GOOGLE_GENAI_USE_VERTEXAI",
    "GOOGLE_CLOUD_PROJECT", "GOOGLE_CLOUD_LOCATION",
    # Política, revisión y despliegue
    "IA_AGENTES_BLOQUEADOS", "SENTRIA_MODO_REVISION", "DJANGO_ALLOWED_HOSTS",
    # Autorizaciones de comandos con efectos reales
    "SENTRIA_MIGRAR_LEGADO_AUTORIZADO", "SENTRIA_GEMINI_REAL_AUTORIZADO", "SENTRIA_CONGELAR_AUTORIZADO",
    "SENTRIA_ACEPTAR_LOTE_AUTORIZADO",
)

_MARCADORES = {
    "DJANGO_SECRET_KEY": "ci-insecure-placeholder-not-a-secret",
    "DJANGO_DEBUG": "False",
    "DB_NAME": "ci",
    "DB_USER": "ci",
    "DB_PASSWORD": "ci",
    "DB_HOST": "localhost",
    "DB_PORT": "3306",
    "GEMINI_API_KEY": "",            # el proveedor de IA se simula en las pruebas
    "IA_PROVIDER": "gemini_developer",
}

_DIR_TEMPORAL = tempfile.mkdtemp(prefix="sentria-ci-")          # 700
atexit.register(shutil.rmtree, _DIR_TEMPORAL, ignore_errors=True)
_ENV_VACIO = os.path.join(_DIR_TEMPORAL, "vacio.env")
with open(os.open(_ENV_VACIO, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w", encoding="utf-8"):
    pass

for _nombre in _RETIRAR:
    os.environ.pop(_nombre, None)
os.environ.update(_MARCADORES)
os.environ["SENTRIA_ENV_FILE"] = _ENV_VACIO
os.environ["SENTRIA_EXCLUSION_DIR"] = os.path.join(_DIR_TEMPORAL, "exclusion")

from sentria_project.settings import *  # noqa: E402,F401,F403

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}

PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
