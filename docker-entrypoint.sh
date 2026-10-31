#!/bin/sh
set -e

# Las migraciones NO se aplican solas: contra una base real deben hacerse de forma
# deliberada. Para una prueba con base temporal: SENTRIA_MIGRAR_AL_ARRANCAR=1.
if [ "${SENTRIA_MIGRAR_AL_ARRANCAR:-0}" = "1" ]; then
    python manage.py migrate --noinput
fi

# Falla pronto si la configuración es inválida (variables obligatorias, settings).
python manage.py check

exec "$@"
