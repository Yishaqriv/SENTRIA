# Manual de instalación de SENTRIA (versión `6d8c6b5`)


Se contrastó con el árbol versionado de `6d8c6b5` y con los registros del laboratorio. Para escribirlo no se instaló, no se ejecutó ni se arrancó nada.

**Cómo leer las marcas:**
- **[C]**: comprobado en ejecución en el laboratorio, con la evidencia indicada.
- **[D]**: documentado en el código o en un procedimiento, sin ejecución registrada.
- **[F]**: falta un dato o una evidencia.

Las evidencias de las marcas [C] son registros del laboratorio que no se publican en el repositorio.

Los valores reales no van en el manual; se escriben `<ASÍ>`.

## 1. Qué se instala

SENTRIA es una aplicación Django que lee alertas del indexador de Wazuh, prepara una entrada depurada y enmascarada, consulta un modelo de lenguaje y guarda el resultado en MySQL para que una persona lo revise.

Necesita cuatro piezas externas:
- un Wazuh con su indexador;
- una base MySQL;
- una clave de la API de Gemini;
- de forma opcional, un modelo ajustado en Vertex AI.

En el laboratorio funcionó de dos formas:

| Instalación | Dónde | Cómo se ejecutó | Estado |
|---|---|---|---|
| A. Entorno virtual de Python | Máquina virtual Ubuntu, junto a Wazuh 4.14.5 | Servidor de desarrollo de Django (`runserver`): lanzado a mano y, desde el 12 oct 2026, como servicio del usuario del sistema | [C] según los registros del laboratorio |
| B. Docker | Computador de escritorio con Windows y Docker Desktop | Un contenedor de dashboard y contenedores temporales de análisis | [C] imagen probada el 12 oct 2026 |

## 2. Qué contiene el repositorio

El código es el de `6d8c6b5`, comprobado con `git ls-files` **[C]**. La documentación se añadió en un commit posterior, sin cambios funcionales:

| Incluido en el repositorio | Para qué |
|---|---|
| `.env.example` | Plantilla de las variables de configuración, sin valores |
| `sentria_project/settings.py` | Configuración de Django. Lee el archivo de entorno y falla si falta una variable obligatoria. No contiene secretos |
| `sentria_project/env_utils.py` | Localiza el archivo de entorno (sección 4) |
| `sentria_project/settings_ci.py`, `settings_prueba_docker.py` | Configuraciones de prueba: suite sin red y prueba aislada de la imagen. No sirven para operar |
| `requirements.txt`, `Dockerfile`, `docker-entrypoint.sh`, `.dockerignore` | Dependencias e imagen |
| `scripts/laboratorio_windows/generar_eventos_fim.ps1` | Script que generó eventos de integridad de archivos en Windows |
| `README.md`, `CHANGELOG.md` y `docs/producto/` | Descripción general, cambios por versión, configuración y manuales |

**No incluido:**
- **`.env`:** está en `.gitignore` y `.dockerignore`, y así debe ser, porque lleva secretos.
- **Lanzador y unidad de la VM:** el lanzador del servicio (`lanzar_dashboard_vm.py`), la unidad `sentria-dashboard.service` y sus comprobaciones son archivos privados del laboratorio, fuera del repositorio: la instalación A se describe aquí con órdenes genéricas.
- **Scripts del PC:** volúmenes, importación de credenciales, túnel SSH y lanzadores de análisis son archivos privados del laboratorio, fuera del repositorio. La instalación B se describe con órdenes genéricas equivalentes.

Todas las variables que lee el código, con su valor por defecto, están en [CONFIGURACION.md](CONFIGURACION.md).

## 3. Requisitos

| Elemento | Requisito | Estado |
|---|---|---|
| Wazuh | 4.14.5 (servidor, indexador y panel). Para instalarlo todo en un servidor, la documentación pide 4 vCPU, 8 GiB de RAM y 50 GB para hasta 25 agentes, según la documentación de Wazuh | [C] versión. La VM tenía unos 7,8 GB de RAM (registro del 7 sep) [F: CPU y disco] |
| Cuenta del indexador | De solo lectura sobre `wazuh-alerts-*`. En el laboratorio tenía los roles `own_index` y `sentria_reader_role` | [C] 7 sep: `_count` y `_search` sobre `wazuh-alerts-*` respondieron 200, y `/`, `/_cluster/health`, `/.opensearch-security/_search`, `_cat/indices` y `wazuh-alerts-*/_mapping`, 403. 12 oct: `_count` 200 y `_cat/indices` 403. **No se probaron otras rutas ni permisos.** [F] cómo se creó el rol |
| Python | 3.12 (la imagen usa `python:3.12-slim`; la VM, 3.12.3) | [C] |
| Dependencias | `requirements.txt`. `mysqlclient` necesita las cabeceras de MySQL o MariaDB, `pkg-config` y un compilador | [C] en la imagen. [F] en la VM no consta que el entorno se instalara exactamente desde este archivo |
| MySQL | Una base y un usuario con permisos sobre ella | [C] la del director, por un túnel TCP de ngrok. [F] versión del servidor |
| Gemini | Clave de la API y nombre del modelo | [C] |
| Vertex AI (opcional) | Endpoint del modelo ajustado y credenciales de Google | [C] en ejecuciones de prueba |

## 4. El archivo de entorno: quién lo lee y cómo

La configuración no se lee del archivo por arte de magia. Copiar un `.env` sirve solo si queda donde `settings.py` lo busca. **[D]** (código: `settings.py` y `env_utils.py`)
1. Al arrancar cualquier orden de Django (`manage.py`, gunicorn), `settings.py` llama a `localizar_env_file()`:
   - si existe la variable de entorno **`SENTRIA_ENV_FILE`**, carga ese archivo. Tiene que existir, ser un archivo normal y tener permisos 600 o más restrictivos; si no, el arranque se detiene con un error;
   - si no está definida, carga **`<carpeta del proyecto>/.env`**, si existe;
   - si no hay ninguno, usa solo las variables que ya tenga el entorno del proceso.
2. El archivo lo lee `python-dotenv` (`load_dotenv`). En `settings.py` **no sustituye** las variables que ya estén definidas en el entorno del proceso, pero `sentria_backend.py` vuelve a cargar el mismo archivo con prioridad sobre ellas. Conviene no definir una misma variable con valores distintos en el entorno y en el archivo.
3. Si falta una obligatoria (`DJANGO_SECRET_KEY`, `DB_USER`, `DB_PASSWORD`, `DB_HOST`, `DB_PORT`), el arranque se detiene con un mensaje que la nombra.
4. **`DJANGO_DEBUG` vale `True` si no se define.** Fuera del desarrollo hay que poner `DJANGO_DEBUG=False` de forma explícita. La imagen Docker ya la fija en `False`.

En el laboratorio [C]:
- la VM usaba `SENTRIA_ENV_FILE` hacia un archivo 600 fuera del repositorio;
- los contenedores, hacia un archivo dentro de un volumen montado en solo lectura.

Variables principales (los valores, nunca en el manual; la lista completa está en [CONFIGURACION.md](CONFIGURACION.md)):

| Variable | Para qué | Nota |
|---|---|---|
| `DJANGO_SECRET_KEY` | Clave de la aplicación | Generarla para cada instalación |
| `DJANGO_DEBUG` | Modo de depuración | `False` fuera del desarrollo. Solo el valor exacto `True` lo activa, y es el predeterminado si la variable falta. Valor usado en la VM durante las pruebas: **no determinado**; los registros conservados no lo establecen, y una lectura actual no probaría el valor histórico |
| `DJANGO_ALLOWED_HOSTS` | Nombres con los que se abre la web, separados por comas | |
| `DB_NAME`, `DB_USER`, `DB_PASSWORD`, `DB_HOST`, `DB_PORT` | MySQL | Con un túnel, el host y el puerto cambian al reiniciarlo |
| `WAZUH_URL`, `WAZUH_INDEX_NAME` | Indexador y patrón de índices (`wazuh-alerts-*`) | |
| `INDEXER_USER`, `INDEXER_PASS` | Cuenta de solo lectura | |
| `WAZUH_TLS_SHA256` | Huella SHA-256 del certificado del indexador | Sin ella, o si no coincide, SENTRIA no consulta Wazuh ni envía credenciales [C] |
| `GEMINI_API_KEY`, `GEMINI_MODEL` | Modelo base | |
| `IA_PROVIDER` | `gemini_developer` (por defecto) o `vertex_tuned` | El ajustado es experimental y está desactivado por defecto |
| `IA_VERTEX_HABILITADO`, `GEMINI_TUNED_ENDPOINT`, `VERTEX_AUTENTICACION`, `VERTEX_TOKEN_ARCHIVO` | Modelo ajustado | Sección 7 |

**Huella del certificado.** Se calcula sobre el certificado del indexador en formato DER: `openssl s_client -connect <INDEXADOR>:9200 </dev/null | openssl x509 -outform DER | sha256sum`. [D]; [F] no consta con qué orden se obtuvo la del laboratorio.

**Si SENTRIA rechaza el indexador por una huella distinta, no hay que copiar sin más la que devuelve la conexión:**
1. Confirmar con quien administra Wazuh si el certificado se regeneró.
2. Verificar la huella esperada en el propio servidor del indexador o por un canal de confianza.
3. Solo después, actualizar `WAZUH_TLS_SHA256`.

Una huella distinta también puede indicar que la conexión no llega al servidor correcto.

## 5. Instalación A: entorno virtual en Linux (como en la máquina virtual)

Órdenes completas, en una terminal, como el usuario que ejecutará SENTRIA **[D]**, salvo donde se marca:

```
# 1. Obtener el código en la versión entregada
git clone https://github.com/Yishaqriv/SENTRIA.git sentria
cd sentria
git checkout 6d8c6b5            # o la rama cierre/3e-windows-lab

# 2. Dependencias del sistema para mysqlclient (Ubuntu; requiere sudo)
sudo apt-get install -y python3-venv python3-dev build-essential default-libmysqlclient-dev pkg-config

# 3. Entorno virtual y dependencias
python3 -m venv <RUTA_VENV>
<RUTA_VENV>/bin/pip install -r requirements.txt

# 4. Archivo de entorno fuera del repositorio, con permisos 600
cp .env.example <RUTA_CONFIG>/sentria.env
chmod 600 <RUTA_CONFIG>/sentria.env
#    editarlo y completar los valores (sección 4)
export SENTRIA_ENV_FILE=<RUTA_CONFIG>/sentria.env

# 5. Comprobar la configuración (no escribe en la base)
<RUTA_VENV>/bin/python manage.py check

# 6. Migraciones: SOLO después de un respaldo de la base
<RUTA_VENV>/bin/python manage.py migrate

# 7. Primer administrador (pide nombre y contraseña)
<RUTA_VENV>/bin/python manage.py createsuperuser

# 8. Estáticos: solo si se sirve con gunicorn y DJANGO_DEBUG=False (WhiteNoise los sirve
#    desde staticfiles/, dentro de la carpeta del proyecto; el usuario necesita escribir en ella)
<RUTA_VENV>/bin/python manage.py collectstatic --noinput

# 9. Arrancar (servidor WSGI; ver la nota sobre runserver)
<RUTA_VENV>/bin/gunicorn sentria_project.wsgi:application --bind 127.0.0.1:8000
```

| Paso | Estado |
|---|---|
| 1 | [C] la copia de trabajo del laboratorio está en `6d8c6b5` |
| 2–3 | [D]; las dependencias del sistema salen del `Dockerfile` |
| 4 | [C] archivo 600 fuera del repositorio y `SENTRIA_ENV_FILE` |
| 5 | [C] |
| 6 | [C] migraciones 0012 y 0013, el 7 oct, con respaldo nativo previo y prueba de restauración |
| 7 | [D]; [F] no hay registro de cómo se crearon las cuentas del laboratorio |
| 8 | [D]: es lo que hace la imagen Docker al construirse (`Dockerfile`), y no se ejecutó fuera de ella. Con `runserver` y `DJANGO_DEBUG=True` no hace falta |
| 9 | [D] con gunicorn. En el laboratorio, la VM usó `runserver` (ver abajo) |

**Cómo se arrancó en el laboratorio [C].** Se usó un servicio de usuario de systemd (`sentria-dashboard.service`) con lingering. Un lanzador privado:
1. comprueba la versión y la integridad del archivo de entorno;
2. arma un entorno mínimo en memoria (`SENTRIA_ENV_FILE`, `WAZUH_TLS_SHA256`, `DJANGO_ALLOWED_HOSTS` y `SENTRIA_MODO_REVISION`);
3. ejecuta `manage.py runserver <IP>:8000 --noreload`.

`runserver` es el servidor de desarrollo de Django y no se recomienda fuera de un laboratorio. El lanzador y la unidad no están en el repositorio (sección 2).

**Verificar:** la página `/accounts/login/` responde 200, `/` redirige al inicio de sesión (302) y la hoja de estilos responde 200. **[C]** en la VM (script de comprobación del laboratorio). Con gunicorn y `DJANGO_DEBUG=False`, los estáticos los sirve WhiteNoise después del paso 8. **[D]** fuera de la imagen.

## 6. Instalación B: Docker (como en el computador de escritorio)

Órdenes con valores sustituibles. En Windows, en PowerShell con Docker Desktop en marcha; en Linux, igual.

```
# 1. Código y construcción de la imagen
git clone https://github.com/Yishaqriv/SENTRIA.git sentria
cd sentria
git checkout 6d8c6b5
docker build -t sentria:<ETIQUETA> .

# 2. Volúmenes: configuración del dashboard, secretos de los análisis y datos de los análisis
docker volume create <VOL_CONFIG>
docker volume create <VOL_SECRETOS>
docker volume create <VOL_DATOS>

# 3. Llenar los volúmenes. El contenedor corre como uid 10001, y SENTRIA rechaza un archivo de
#    entorno o de credenciales con permisos de grupo u otros: carpetas 10001 y 700, archivos 10001 y 600.
#    <CARPETA_LOCAL> tiene los archivos preparados a mano, sin subirlos a ningún repositorio.

# 3a. Configuración del dashboard: clave de Django, DJANGO_ALLOWED_HOSTS y base de datos; no lleva indexador ni modelo
docker run --rm --user 0 --network none -v <VOL_CONFIG>:/config -v "<CARPETA_LOCAL>:/origen:ro" --entrypoint sh sentria:<ETIQUETA> -c "cp /origen/dashboard.env /config/sentria.env && chown 10001:10001 /config /config/sentria.env && chmod 700 /config && chmod 600 /config/sentria.env"

# 3b. Configuración de los análisis: base de datos, clave de Django, indexador (URL, cuenta de solo lectura,
#     huella WAZUH_TLS_SHA256 e índice) y el proveedor que se use (sección 4 y sección 7)
docker run --rm --user 0 --network none -v <VOL_SECRETOS>:/secretos -v "<CARPETA_LOCAL>:/origen:ro" --entrypoint sh sentria:<ETIQUETA> -c "cp /origen/analisis.env /secretos/sentria.env && chown 10001:10001 /secretos /secretos/sentria.env && chmod 700 /secretos && chmod 600 /secretos/sentria.env"

# 3c. Solo con el modelo ajustado y una cuenta de servicio: el archivo de credenciales, junto a la
#     configuración de los análisis. En analisis.env:
#       VERTEX_AUTENTICACION=adc
#       GOOGLE_APPLICATION_CREDENTIALS=/secretos/<CREDENCIAL>.json
docker run --rm --user 0 --network none -v <VOL_SECRETOS>:/secretos -v "<CARPETA_LOCAL>:/origen:ro" --entrypoint sh sentria:<ETIQUETA> -c "cp /origen/<CREDENCIAL>.json /secretos/<CREDENCIAL>.json && chown 10001:10001 /secretos/<CREDENCIAL>.json && chmod 600 /secretos/<CREDENCIAL>.json"

# 3d. Datos de los análisis (registros de llamadas): carpeta escribible por 10001
docker run --rm --user 0 --network none -v <VOL_DATOS>:/datos --entrypoint sh sentria:<ETIQUETA> -c "chown 10001:10001 /datos && chmod 700 /datos"

# 3e. Al terminar, borrar la copia local de los archivos de <CARPETA_LOCAL> si ya no hace falta

# 4. Dashboard: solo en la interfaz local, configuración en solo lectura
docker run -d --name sentria-dashboard --user 10001 -p 127.0.0.1:<PUERTO>:8000 -e SENTRIA_ENV_FILE=/config/sentria.env -v <VOL_CONFIG>:/config:ro sentria:<ETIQUETA>

# 5. Un análisis puntual con el comando (contenedor temporal): lee la configuración de 3b
#    (y, si aplica, la credencial de 3c) desde /secretos, en solo lectura
docker run --rm --user 10001 -e SENTRIA_ENV_FILE=/secretos/sentria.env -v <VOL_SECRETOS>:/secretos:ro -v <VOL_DATOS>:/datos sentria:<ETIQUETA> python manage.py ingestar_alertas --agent-id <ID> --dry-run
```

Qué espera la imagen **[D]** (`Dockerfile`, `docker-entrypoint.sh`):
- **Usuario:** corre como `sentria` (uid 10001), sin privilegios, con `DJANGO_DEBUG=False`.
- **Configuración:** por variables de entorno (`--env-file`) o por un archivo que indique `SENTRIA_ENV_FILE`. El entrypoint no exige un montaje concreto. Las rutas `/config`, `/secretos` y `/datos` son las que se usaron en el laboratorio.
- **Arranque:** el entrypoint ejecuta `python manage.py check` y luego la orden pedida. Por defecto es gunicorn en el puerto 8000.
- **Migraciones:** **no** las aplica, salvo con `-e SENTRIA_MIGRAR_AL_ARRANCAR=1`. Contra una base real se aplican de forma deliberada, después de un respaldo: `docker run --rm --user 10001 -e SENTRIA_ENV_FILE=... -v ... sentria:<ETIQUETA> python manage.py migrate`.

Estado en el laboratorio:
- **[C]** construcción y prueba aislada (sin red, SQLite temporal, sin credenciales; `check`, inicio de sesión 200, estáticos y suite de 598 pruebas dentro del contenedor);
- **[C]** traslado de la imagen con `docker save`, la huella del archivo, `docker load` y el Id;
- **[C]** volúmenes con propietario 10001 y permisos 700;
- **[C]** dashboard con `SENTRIA_ENV_FILE=/config/...`, un único montaje de solo lectura y el puerto ligado a la interfaz local;
- **[C]** análisis con `/secretos` en solo lectura y `/datos` para el registro de llamadas;
- **[C]** en el laboratorio, las migraciones se aplicaron desde la VM.

Las órdenes 2 y 3 son genéricas, **[D]**: no se ejecutaron tal cual. En el laboratorio, scripts privados con comprobaciones (sección 2) hicieron lo equivalente:
- empaquetaron en la VM los archivos de los análisis, cifrados: el archivo de entorno, la credencial de la cuenta de servicio del modelo ajustado y la reserva del piloto;
- los descifraron dentro de un contenedor temporal, directamente en `/secretos`;
- dejaron en `/config` la configuración del dashboard, sin indexador ni modelo.

La reserva del piloto es propia de las pruebas y no hace falta para operar. Los nombres de archivo de este manual son genéricos.

**Contenedor y otra máquina.** Si el indexador está en otra máquina, el laboratorio usó un túnel SSH desde el PC hacia la VM, con una cuenta que solo permite reenviar el puerto del indexador, en vez de abrir el indexador a la red. El contenedor llegaba por `host.docker.internal`. **[C]** El procedimiento es un registro privado del laboratorio, fuera del repositorio.

## 7. Modelo ajustado (opcional)

- **Activación:** `IA_PROVIDER=vertex_tuned`, `IA_VERTEX_HABILITADO=1` y `GEMINI_TUNED_ENDPOINT=projects/<PROYECTO>/locations/<us|eu>/endpoints/<ID>`. **[D]** (`ia/proveedores.py`)
- **`VERTEX_AUTENTICACION` elige el mecanismo**, no la credencial:
  - **`adc`** (por defecto) usa las credenciales predeterminadas de aplicación de Google (`google.auth.default`). ADC busca credenciales en su orden habitual, y una de las formas es la variable estándar **`GOOGLE_APPLICATION_CREDENTIALS`**, con la ruta de un archivo de cuenta de servicio. No son excluyentes: con `adc` se puede definir `GOOGLE_APPLICATION_CREDENTIALS`. Si está definida, SENTRIA exige que el archivo tenga ruta absoluta, esté fuera del repositorio, sea un archivo normal del usuario actual y tenga permisos 600; si no, rechaza la configuración.
  - **`token_archivo`**, solo para pruebas controladas: un token de acceso de corta duración en `VERTEX_TOKEN_ARCHIVO` (archivo 600 fuera del repositorio), sin renovación ni vuelta a ADC.
- En el laboratorio [C]:
  - el PC usó `adc` con un archivo de cuenta de servicio en el volumen de secretos;
  - la VM usó scripts por ejecución, con su propia credencial;
  - el servicio de la VM no tiene configuración de Vertex AI.
- [F] el endpoint y el proyecto no se publican. Para reproducir el ajustado hace falta el modelo del equipo o un ajuste nuevo.

## 8. Retirada

- **VM:** `systemctl --user stop sentria-dashboard.service`, quitar la unidad, `systemctl --user daemon-reload` y, si ya no hace falta, desactivar el lingering con `sudo loginctl disable-linger <USUARIO>`. **[D]** (procedimiento privado del laboratorio)
- **Docker:** `docker stop sentria-dashboard` y `docker rm sentria-dashboard`. Los datos están en MySQL y en los volúmenes: no usar `docker volume rm` ni `prune` sin un respaldo. **[D]**

## 9. Problemas frecuentes

| Síntoma | Causa probable | Qué hacer |
|---|---|---|
| «Falta la variable de entorno obligatoria …» | La variable no está en el archivo que se cargó, o se cargó otro archivo | Revisar `SENTRIA_ENV_FILE` y el contenido del archivo |
| «SENTRIA_ENV_FILE … tiene permisos inseguros» | Permisos de grupo u otros | `chmod 600`. En Docker, propietario 10001 |
| «Bad Request (400)» | El nombre con el que se abre la web no está en `DJANGO_ALLOWED_HOSTS` | Añadirlo |
| No consulta Wazuh | Indexador inaccesible o huella distinta | Revisar `WAZUH_URL`. Ante una huella distinta, seguir la sección 4, sin aceptar la nueva automáticamente |
| No conecta con MySQL | Host, puerto o credencial; con un túnel, el extremo cambia al reiniciarlo | Confirmar los valores vigentes con quien administra la base |
| Errores detallados en el navegador | `DJANGO_DEBUG` sin definir, que vale `True` | Definir `DJANGO_DEBUG=False` |
