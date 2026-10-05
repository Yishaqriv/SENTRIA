"""
Settings SOLO para pruebas y `makemigrations` en local, SIN MySQL.

No contiene secretos reales: todos los valores son marcadores obvios. Nunca
debe usarse en producción. Uso:

    DJANGO_SETTINGS_MODULE=sentria_project.settings_ci \\
        python manage.py test
    DJANGO_SETTINGS_MODULE=sentria_project.settings_ci \\
        python manage.py makemigrations

Se rellenan las variables obligatorias ANTES de importar settings.py (que
falla con ImproperlyConfigured si faltan) y luego se sustituye la base de
datos por SQLite en memoria. No se conecta a MySQL ni se leen credenciales.
"""
import os

# Aislamiento: las pruebas nunca dependen de un .env real ni del entorno del
# desarrollador. Si hay un SENTRIA_ENV_FILE en el shell, se ignora aquí.
os.environ.pop("SENTRIA_ENV_FILE", None)

os.environ.setdefault("DJANGO_SECRET_KEY", "ci-insecure-placeholder-not-a-secret")
os.environ.setdefault("DJANGO_DEBUG", "False")
os.environ.setdefault("DB_NAME", "ci")
os.environ.setdefault("DB_USER", "ci")
os.environ.setdefault("DB_PASSWORD", "ci")
os.environ.setdefault("DB_HOST", "localhost")
os.environ.setdefault("DB_PORT", "3306")
os.environ.setdefault("GEMINI_API_KEY", "")   # el proveedor de IA se mockea en las pruebas
os.environ.setdefault("IA_PROVIDER", "gemini_developer")

from sentria_project.settings import *  # noqa: E402,F401,F403

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}

PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
