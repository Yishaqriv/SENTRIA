# Pruebas de esta versión

**Ejecución única:** 17 nov 2026, de 01:51:19 a 01:54:15 UTC, sobre copias aisladas del árbol de esta versión. Es una ejecución local, **no una ejecución de GitHub Actions**: el workflow [`.github/workflows/pruebas.yml`](../../.github/workflows/pruebas.yml) aún no se ha ejecutado en GitHub.

**Árbol probado:** todos los archivos de esta versión; solo este informe se reescribió después con los resultados. Su manifiesto SHA-256 (una línea por archivo en el formato de `sha256sum`, rutas relativas ordenadas por bytes con `LC_ALL=C sort`) tiene la huella `1a138b729c2b0281899b9f7c79d8ab7a6854ea8b3ae04197953b70898131c27c` y 239 archivos; la copia se verificó contra él antes de ejecutar.

**Entorno:**
- Python 3.12.3 en Ubuntu, con un entorno virtual cuyas 23 versiones fijadas coinciden con `requirements.txt` (incluido Matplotlib 3.11.2).
- Fase limpia: `env -i`, sin archivo de entorno, sin claves ni credenciales; `HOME` y `TMPDIR` temporales.
- Fase hostil: la misma suite con un `.env` en la carpeta del proyecto, un `SENTRIA_ENV_FILE` heredado y 29 variables en el entorno del proceso (credenciales, destinos, proveedores, autorizaciones), todo con valores **ficticios** («CANARIO-…»). Comprueba que el resultado no depende del entorno del desarrollador.
- Base: SQLite en memoria (`sentria_project.settings_ci`). Sin MySQL, sin Wazuh y sin proveedores de IA.
- Red: cada orden de Django y el generador se ejecutaron con [`scripts/ci/sin_red.py`](../../scripts/ci/sin_red.py), que bloquea y cuenta cualquier conexión o resolución de nombres que no sea local. Las pruebas del ejecutor usan la trampa de red del propio ejecutor.

## Resultados

| Paso | Orden | Resultado | Conexiones bloqueadas |
|---|---|---|---|
| Comprobación de Django | `manage.py check` | Sin problemas | 0 |
| Migraciones al día | `manage.py makemigrations --check --dry-run` | Sin cambios pendientes | 0 |
| Migraciones en base aislada | `manage.py migrate` (SQLite en memoria) | 35 migraciones aplicadas, incluidas `dashboard 0015` y `0016` | 0 |
| **Suite de Django** (limpia) | `manage.py test -v 2` | **757 ejecutadas: 757 aprobadas, 0 fallidas, 0 con error, 0 omitidas** (77,7 s) | 0 |
| **Suite de Django** (hostil) | `manage.py test -v 2` con el entorno ficticio | **757 ejecutadas: 757 aprobadas, 0 fallidas, 0 con error, 0 omitidas** (74,6 s) | 0 |
| Casos sintéticos al día | `generar_casos_sinteticos.py --comprobar` | 9 archivos, 0 distintos | 0 |
| **Pruebas del ejecutor** (suite aparte) | `python -m unittest -v test_ejecutor test_exportacion` | **17 ejecutadas: 17 aprobadas, 0 fallidas, 0 omitidas** | (trampa propia) |
| Opciones de los comandos documentados | `--help` de `ingestar_alertas`, `ingesta_continua`, `revisar_incierto` y `asignar_agente_activo` | Las 4 responden con sus opciones | 0 |
| Configuración de la prueba de la imagen | `manage.py check --settings=sentria_project.settings_prueba_docker` (fuera del contenedor) | Sin problemas | 0 |
| Contraprueba del aislamiento | `sentria_project.tests_aislamiento_ci` con el `settings_ci.py` anterior a esta corrección | Falla como se esperaba: 2 de 3 (quedaban 29 variables ficticias en el entorno y no había archivo de entorno vacío) | 0 |
| Sintaxis de las unidades de ejemplo | `systemd-analyze --user verify`, con los marcadores sustituidos por valores ficticios | Sin errores en la ejecución del 16 nov 2026 (21:16 UTC); las unidades no han cambiado desde entonces (mismas huellas) y no se repitió | — |

Composición de la suite de Django por archivo (métodos de prueba definidos): `dashboard/tests.py` 598, `dashboard/tests_ingesta_continua.py` 78, `dashboard/tests_comparacion.py` 46, `dashboard/tests_web_medicion.py` 32, `sentria_project/tests_aislamiento_ci.py` 3 y `usuarios/tests.py` 0. Las 17 pruebas del ejecutor son otra suite y no se suman a las 757.

**Aislamiento de `settings_ci`:** `tests_aislamiento_ci.py` copia el código a una carpeta temporal con un `.env` ficticio, arranca Django en otro proceso e importa `sentria_backend` (que recarga el archivo de entorno con prioridad). Comprueba que no queda ningún valor ficticio en el entorno, en los ajustes de Django ni en las constantes de `sentria_backend`, que el archivo de entorno usado está vacío (600, carpeta 700) y se borra al terminar, y, como control, que la configuración normal sí sigue cargando ese `.env`.

**Avisos:** 6 avisos `UserWarning` de Django en cada ejecución de la suite por la ausencia de la carpeta `staticfiles/`, que solo existe tras `collectstatic`. No afectan al resultado.

## Lo que no se probó

- La ejecución en GitHub Actions.
- La construcción de la imagen Docker con esta versión (la configuración `settings_prueba_docker` solo se comprobó fuera del contenedor).
- La instalación desde cero con `pip install -r requirements.txt` (se usó un entorno ya instalado con las mismas versiones).
- Llamadas reales a proveedores, el indexador de Wazuh o MySQL: las pruebas los simulan a propósito.
- La ejecución de las unidades de ejemplo de `despliegue/systemd/` (solo se verificó su sintaxis) y los recolectores del servidor Windows.
