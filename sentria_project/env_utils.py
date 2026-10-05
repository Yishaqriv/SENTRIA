"""
Localización segura del archivo de entorno (`.env`) de SENTRIA.

El código puede ejecutarse desde un worktree distinto al que contiene el `.env`
canónico (p. ej. `manage.py` en `sentria_cierre`, `.env` en `sentria_project`).
`SENTRIA_ENV_FILE` permite indicar explícitamente qué archivo cargar.

Este módulo NO copia secretos, NO crea archivos, NO hace `symlink`, NO ejecuta
`source`, NO imprime valores. Sólo devuelve la ruta a cargar (con `python-dotenv`)
o falla de forma clara.
"""
from __future__ import annotations

import os
from pathlib import Path


class EnvFileError(RuntimeError):
    """El `SENTRIA_ENV_FILE` indicado no existe o tiene permisos inseguros."""


def localizar_env_file(base_dir):
    """
    Devuelve el `Path` del `.env` a cargar, o `None` si no hay ninguno.

    Precedencia:
      1. `$SENTRIA_ENV_FILE` — si está definido, es OBLIGATORIO que exista, sea
         un archivo regular y tenga permisos <= 0600 (sin acceso de grupo ni de
         otros). Si no cumple, se lanza `EnvFileError`.
      2. `<base_dir>/.env` — comportamiento normal: se usa si existe.
      3. Ninguno — se devuelve `None` (las variables vendrán del entorno real o
         `settings.py` fallará luego con `ImproperlyConfigured` al faltar alguna).
    """
    ruta = os.environ.get("SENTRIA_ENV_FILE", "").strip()
    if ruta:
        p = Path(ruta).expanduser()
        if not p.is_file():
            raise EnvFileError(
                f"SENTRIA_ENV_FILE='{p}' no existe o no es un archivo regular."
            )
        modo = p.stat().st_mode & 0o777
        if modo & 0o077:
            raise EnvFileError(
                f"SENTRIA_ENV_FILE='{p}' tiene permisos inseguros ({oct(modo)}). "
                f"Se exige 0600 o más restrictivo (sin acceso de grupo ni de otros)."
            )
        return p

    local = Path(base_dir) / ".env"
    return local if local.is_file() else None
