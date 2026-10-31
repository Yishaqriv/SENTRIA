# Configuración de SENTRIA (versión `6d8c6b5`)


SENTRIA lee su configuración de variables de entorno. Este documento lista **todas las variables que lee el código**, cuál es su valor si faltan y si aparecen en `.env.example`. No contiene ningún valor real.

## 1. Cómo se carga el archivo de entorno

`sentria_project/settings.py` llama a `localizar_env_file` (`sentria_project/env_utils.py`) y carga el archivo con `python-dotenv`, sin sustituir las variables que ya existan en el proceso:
1. si está definida `SENTRIA_ENV_FILE`, carga ese archivo. Tiene que existir, ser un archivo regular y tener permisos 600 o más restrictivos; si no, el arranque se detiene con un error;
2. si no está definida, carga `.env` de la carpeta del proyecto, si existe;
3. si no hay ninguno, usa solo las variables del proceso.

`sentria_backend.py` vuelve a cargar el mismo archivo, esta vez **con prioridad** sobre las variables del proceso (`override=True`). Por eso conviene no definir una misma variable con valores distintos en el entorno y en el archivo.

`SENTRIA_ENV_FILE` elige el archivo, así que **se define en el entorno del proceso** (la unidad del servicio, la orden de Docker o la terminal), no dentro del propio archivo. La configuración de la suite (`settings_ci.py`) la ignora a propósito.

## 2. Variables de la aplicación

| Variable | La lee | Si falta | En `.env.example` |
|---|---|---|---|
| `DJANGO_SECRET_KEY` | `settings.py` | **Obligatoria:** el arranque se detiene | Sí |
| `DJANGO_DEBUG` | `settings.py` | Vale `True`. Solo el texto exacto `True` activa la depuración. **Fuera del desarrollo, definir `False`** | Sí |
| `DJANGO_ALLOWED_HOSTS` | `settings.py` | Lista vacía. Separar con comas | Sí |
| `DB_NAME` | `settings.py` | `bdsentria` | Sí |
| `DB_USER`, `DB_PASSWORD`, `DB_HOST`, `DB_PORT` | `settings.py` | **Obligatorias** | Sí |
| `WAZUH_URL` | `sentria_backend.py` | `https://localhost:9200` | Sí |
| `INDEXER_USER`, `INDEXER_PASS` | `sentria_backend.py` | Vacías: la consulta al indexador falla | Sí |
| `WAZUH_TLS_SHA256` | `sentria_backend.py` | Vacía: SENTRIA no consulta el indexador ni envía credenciales | Sí |
| `WAZUH_INDEX_NAME` | `sentria_backend.py` | `wazuh-alerts-*` | Sí |
| `GEMINI_API_KEY` | `dashboard/ia/proveedores.py` | Vacía: el modelo base no puede consultarse | Sí |
| `GEMINI_MODEL` | `proveedores.py`, `sentria_backend.py` | `models/gemini-3.5-flash` | Sí |
| `IA_PROVIDER` | `proveedores.py` | `gemini_developer` (modelo base) | Sí |
| `IA_VERTEX_HABILITADO` | `proveedores.py` | Desactivado: solo `1` lo habilita | Sí |
| `GEMINI_TUNED_ENDPOINT` | `proveedores.py` | Vacío | Sí |
| `VERTEX_AUTENTICACION` | `proveedores.py` | `adc` | Sí |
| `VERTEX_TOKEN_ARCHIVO` | `proveedores.py` | Vacío; solo con `token_archivo` | Sí |
| `GOOGLE_APPLICATION_CREDENTIALS` | `proveedores.py` | Opcional (variable estándar de Google). Si se define, SENTRIA exige una ruta absoluta, fuera del repositorio y con permisos 600 | No; es estándar de Google |
| **`SENTRIA_ENV_FILE`** | `sentria_project/env_utils.py` | Se usa `.env` del proyecto | Solo como comentario: se define en el entorno del proceso |
| **`SENTRIA_MODO_REVISION`** | `settings.py`, `dashboard/lotes.py` | `DOBLE`: quien completa un candidato del conjunto de ajuste no puede aprobarlo. `REVISOR_UNICO_LOTE` permite que un único revisor apruebe, solo aceptando un lote sellado. Cualquier otro valor equivale a `DOBLE` | Sí |
| **`IA_AGENTES_BLOQUEADOS`** | `settings.py`, `dashboard/ia/resolver.py` | Lista vacía. `agent.id` de Wazuh, separados por comas, que no se pueden asociar a un activo ni enviar al modelo | Sí |
| **`SENTRIA_MIGRAR_AL_ARRANCAR`** | `docker-entrypoint.sh` | `0`: la imagen no aplica migraciones al arrancar. Con `1`, ejecuta `migrate` antes de `check`. Pensada para pruebas con una base temporal; contra una base real, las migraciones se aplican a mano y después de un respaldo | Sí |

## 3. Líneas de `.env.example` para estas variables

Al final de [`.env.example`](../../.env.example):

```
# Archivo de entorno: SENTRIA_ENV_FILE se define en el entorno del proceso (unidad
# de servicio, docker run o terminal), no en este archivo. Si se define, el archivo
# debe existir y tener permisos 600 o más restrictivos.

# Modo de aprobación del conjunto de ajuste: DOBLE (por defecto) | REVISOR_UNICO_LOTE.
# No cambiarlo sin una decisión registrada.
SENTRIA_MODO_REVISION=DOBLE

# agent.id de Wazuh que no se asocian a un activo ni se envían al modelo,
# separados por comas. Vacío: ninguno.
IA_AGENTES_BLOQUEADOS=

# Solo imagen Docker: 1 aplica las migraciones al arrancar (pruebas con base temporal).
# Contra una base real, dejar 0 y migrar a mano después de un respaldo.
SENTRIA_MIGRAR_AL_ARRANCAR=0
```

## 4. Variables de operación que no van en `.env.example`

No configuran la aplicación: autorizan una operación concreta o sirven para una prueba. Se definen solo en la orden que las necesita.

| Variable | La lee | Para qué |
|---|---|---|
| `SENTRIA_ACEPTAR_LOTE_AUTORIZADO` | comando `aceptar_lote` | Autoriza escribir la aceptación de un lote |
| `SENTRIA_CONGELAR_AUTORIZADO` | comando `congelar_entradas` | Autoriza escribir los sellos de entrada |
| `SENTRIA_SQLITE_PRUEBA` | `settings_prueba_docker.py` | Ruta de la base SQLite de la prueba aislada de la imagen |

## 5. Lo que se usó en el laboratorio

- **Máquina virtual:** un lanzador privado armaba un entorno mínimo con `SENTRIA_ENV_FILE`, `WAZUH_TLS_SHA256`, `DJANGO_ALLOWED_HOSTS` y `SENTRIA_MODO_REVISION`, y el resto venía del archivo de entorno. La aplicación se sirvió con `runserver`. Los registros conservados no permiten establecer el valor de `DJANGO_DEBUG` durante las pruebas.
- **Docker:** la imagen fija `DJANGO_DEBUG=False` y usa Gunicorn. La configuración se montó en volúmenes de solo lectura.

Los valores reales no se documentan aquí ni en el repositorio.
