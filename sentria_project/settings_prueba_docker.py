"""
Settings SOLO para probar la imagen Docker de forma aislada. Nunca en producción.

Parte de `settings_ci` (sin `.env`, valores marcadores, sin secretos reales) y
cambia la base de datos por un SQLite TEMPORAL en archivo, para que el arranque
(migraciones + servidor) comparta datos entre procesos. Sin MySQL, Wazuh ni
proveedores reales de IA: no hay credenciales y `GEMINI_API_KEY` queda vacía.

    docker run --rm --network none \\
        -e DJANGO_SETTINGS_MODULE=sentria_project.settings_prueba_docker \\
        -e SENTRIA_MIGRAR_AL_ARRANCAR=1 sentria:prueba
"""
import os

from sentria_project.settings_ci import *  # noqa: F401,F403

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": os.environ.get("SENTRIA_SQLITE_PRUEBA", "/tmp/sentria_prueba.sqlite3"),
    }
}
