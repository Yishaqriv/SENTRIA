# SENTRIA: AI-Alert Security Classification

SENTRIA es el prototipo del proyecto de grado de Ingeniería de Sistemas de la Universidad El Bosque (2026). Integra el SIEM de código abierto Wazuh, un modelo de lenguaje de la familia Gemini y una aplicación web en Django para depurar, clasificar en contexto y apoyar la revisión de alertas de seguridad.

La versión entregada es el commit `6d8c6b528d67a37b72b24197841669e10b31cc64` (`6d8c6b5`) de la rama `cierre/3e-windows-lab`. Esta documentación se añadió después, sin cambiar el código. Los cambios por versión están en [`CHANGELOG.md`](CHANGELOG.md).

**Objetivo general:** desarrollar y validar, en un entorno controlado, un prototipo que integre un SIEM, un modelo de lenguaje de gran escala ajustado mediante fine-tuning y una aplicación web para depurar, clasificar contextualmente y apoyar la gestión de alertas de seguridad.

**Alcance del laboratorio:**
- una máquina virtual Ubuntu con Wazuh 4.14.5 (un solo nodo) y SENTRIA;
- dos equipos Windows con agentes de Wazuh;
- una base MySQL remota.

SENTRIA se ejecutó de dos formas: en la máquina virtual, con el servidor de desarrollo de Django (como servicio del usuario desde el 12 oct 2026), y en uno de los equipos Windows, con la imagen Docker, que usa Gunicorn. Lo que se comprobó en la imagen (Gunicorn, usuario sin privilegios, depuración desactivada) no describe la instalación de la máquina virtual. **No se validó en una organización real.**

## Componentes y flujo de una alerta

| Componente | En el código |
|---|---|
| Ingesta desde el indexador de Wazuh | `sentria_backend.py`, `dashboard/ia/ingesta.py`, comando `ingestar_alertas` |
| Activos, política y ventanas de mantenimiento | `dashboard/ia/resolver.py`, `dashboard/ia/politica.py`, `dashboard/mantenimiento.py` |
| Entrada y enmascaramiento | `dashboard/ia/evidencia.py`, `dashboard/ia/prompt.py`, `dashboard/ia/anonimizacion.py` |
| Proveedores del modelo | `dashboard/ia/proveedores.py` |
| Controles de la respuesta | `dashboard/ia/contrato.py`, `dashboard/ia/sustento.py`, `dashboard/dataset.py` (privacidad de la salida) |
| Colas, revisión y métricas | `dashboard/views.py`, `dashboard/revision.py`, `dashboard/metricas_eval.py` |
| Usuarios y roles | `usuarios/` |

Flujo de una alerta:
1. **Consulta.** SENTRIA consulta el indexador de Wazuh (`wazuh-alerts-*`) con una cuenta de solo lectura. Solo sigue si el certificado coincide con la huella TLS fijada en la configuración.
2. **Duplicados y política.** No guarda dos veces la misma alerta y aplica una política de elegibilidad: por defecto, nivel 7 o superior y un perfil de activo asociado. La acción web guarda las no elegibles con su motivo, y siguen visibles; el comando de ingesta solo las cuenta.
3. **Entrada.** Para las elegibles, construye la entrada con una lista cerrada de campos, el contexto del activo y la ventana de mantenimiento, y enmascara los datos identificables que siguen patrones conocidos. El enmascaramiento no garantiza el anonimato.
4. **Modelo.** Consulta el modelo:
   - **por defecto, el modelo base** (Gemini 3.5 Flash por la API de Gemini);
   - el modelo ajustado en Vertex AI (proveedor `vertex_tuned`) es experimental y está **desactivado por defecto**: solo actúa si la configuración lo habilita.
5. **Controles.** Comprueba la respuesta: el contrato JSON, el sustento de los ocho campos internos inspirados en CVSS v3.1 (no forman una puntuación CVSS) y, con el modelo ajustado, la privacidad de la salida. Si falla un control, la alerta queda como análisis fallido, sin veredicto, y nunca como falso positivo.
6. **Colas y revisión.** Presenta las alertas en colas: requiere atención, falsos positivos, auditoría selectiva, pendientes y fallidas, omitidas por política y análisis legado. La persona que revisa **puede** confirmar o corregir la clasificación con un motivo; la revisión es opcional. La respuesta original del modelo no se sobrescribe.

## Requisitos

- Python 3.12 y las dependencias de `requirements.txt`. `mysqlclient` necesita las cabeceras de MySQL o MariaDB y un compilador.
- Un servidor MySQL para la ejecución normal. La suite de pruebas usa SQLite en memoria.
- Un indexador de Wazuh accesible y una cuenta de solo lectura sobre `wazuh-alerts-*`.
- Una clave de la API de Gemini. Para el modelo ajustado, un proyecto de Google Cloud con el modelo desplegado en Vertex AI.

La instalación paso a paso está en el [manual de instalación](docs/producto/MANUAL_INSTALACION.md). Sus órdenes genéricas no se han comprobado de punta a punta; el manual indica qué pasos se comprobaron en el laboratorio y cuáles no.

## Configuración

La configuración se lee de variables de entorno. `sentria_project/settings.py` carga un archivo de entorno con `python-dotenv`:
- el archivo que indique la variable `SENTRIA_ENV_FILE`, que debe existir y tener permisos 600 o más restrictivos;
- si no está definida, `.env` en la carpeta del proyecto.

`settings.py` no sustituye las variables que ya existan en el entorno, pero `sentria_backend.py` vuelve a cargar el mismo archivo con prioridad sobre ellas. Conviene no definir una misma variable con valores distintos en el entorno y en el archivo. El detalle está en [`docs/producto/CONFIGURACION.md`](docs/producto/CONFIGURACION.md).

1. Copiar [`.env.example`](.env.example) a un archivo propio y completar los valores. Ese archivo **nunca se sube al repositorio**; `.gitignore` y `.dockerignore` ya lo excluyen.
2. **Definir `DJANGO_DEBUG=False` de forma explícita** fuera del desarrollo: si no se define, vale `True`. La imagen Docker ya la fija en `False`.
3. **Variables obligatorias:** `DJANGO_SECRET_KEY`, `DB_USER`, `DB_PASSWORD`, `DB_HOST` y `DB_PORT`. Si falta una, el arranque se detiene con un mensaje que la nombra.
4. **Modelo ajustado:** `VERTEX_AUTENTICACION` elige el mecanismo, `adc` (por defecto) o `token_archivo` (solo para pruebas controladas). Con `adc`, las credenciales de Google se obtienen como de costumbre; si se define `GOOGLE_APPLICATION_CREDENTIALS`, SENTRIA exige un archivo con ruta absoluta, fuera del repositorio y con permisos 600.
5. **Huella del indexador:** si SENTRIA rechaza el indexador por una huella distinta, hay que verificar con quien administra Wazuh el certificado esperado antes de cambiar `WAZUH_TLS_SHA256`; no se acepta sin más la huella que devuelva la conexión.

## Uso

```bash
python manage.py check
python manage.py migrate            # después de un respaldo de la base
python manage.py createsuperuser
python manage.py runserver          # servidor de desarrollo de Django
```

- **`runserver`** es el servidor de desarrollo de Django y es el que se usó en la máquina virtual del laboratorio. Los registros conservados no permiten establecer el valor que tenía `DJANGO_DEBUG` en esa instalación durante las pruebas. Para otro entorno, la imagen Docker sirve la aplicación con Gunicorn y `DJANGO_DEBUG=False`.
- **«Actualizar»** (administrador o analista) trae y procesa la alerta más reciente, con una consulta al modelo como máximo.
- **Comando de ingesta:** `python manage.py ingestar_alertas --agent-id <id> --dry-run` hace el ensayo sin escrituras ni llamadas al modelo. Para ejecutar, sustituir `--dry-run` por `--confirmar`; son opciones excluyentes y una de ellas es obligatoria. Consulta hasta 100 alertas de un agente con el nivel mínimo de la política (7 por defecto; `--scan-limit`, máximo 500) y envía al modelo las primeras elegibles, hasta 3 por ejecución (`--max-analisis`, máximo 3).
- **«Reclasificar fallidas»** (administrador) vuelve a analizar en una sola ejecución todas las alertas pendientes, fallidas u omitidas, sin tope total de llamadas y con una pausa de 4 segundos entre ellas.
- **Perfiles de activo:** se registran en el panel de administración de Django y se asocian a los agentes con `asignar_agente_activo`. El comando `cargar_activos_cafe` es heredado del escenario inicial, que el proyecto retiró.

**Docker:**
- `Dockerfile` construye una imagen con el usuario `sentria` (uid 10001), sin privilegios, con `DJANGO_DEBUG=False`, que sirve la aplicación con Gunicorn en el puerto 8000.
- `docker-entrypoint.sh` ejecuta `manage.py check` al arrancar.
- Aplica las migraciones solo con `SENTRIA_MIGRAR_AL_ARRANCAR=1`.
- La configuración se pasa por variables de entorno o con `SENTRIA_ENV_FILE` apuntando a un archivo montado.

## Pruebas y evidencias

| Qué | Fecha | Alcance |
|---|---|---|
| Suite automática: `python manage.py test --settings=sentria_project.settings_ci` | Ejecutada el 29 oct 2026 sobre `6d8c6b5` | 598 pruebas, sin MySQL, sin servicios externos y con el proveedor del modelo simulado. Comprueban el software, no la calidad del modelo |
| Cobertura (coverage.py) | 29 oct 2026 | 86 % total, que combina sentencias (87,9 %) y ramas (80,0 %); sin migraciones ni pruebas |
| Análisis estático (ruff y bandit) | 29 oct 2026 | 359 hallazgos de ruff y 93 de bandit, sin revisar uno por uno ni corregir. No equivalen a vulnerabilidades confirmadas |
| Prueba aislada de la imagen Docker | 12 oct 2026 | `check`, inicio de sesión y la suite de 598 pruebas dentro del contenedor, sin red ni credenciales |
| Pruebas del laboratorio | De septiembre al 12 oct 2026 | Pruebas controladas de integridad de archivos y de política o USB, y pilotos con alertas naturales. Entre ellas, FIM-PC01-1 (12 oct 2026), con el modelo ajustado: 4 análisis, 2 rechazados por el control de sustento |
| Revisiones humanas | Hasta el 27 oct 2026 | 64 revisiones de análisis del modelo base. Con ese modelo, 8 de 36 alertas de pruebas controladas etiquetadas como falsas alarmas se clasificaron como falso positivo (22 %). Es un resultado exploratorio, sin ataques en la muestra y sin revisión ciega |

Los informes completos de estas pruebas son registros del equipo y no se publican en el repositorio.

## Limitaciones conocidas

- **Validación:** solo en un laboratorio controlado. No se midieron el tiempo de respuesta, la aceptación de los usuarios ni el rendimiento, y no se hicieron pruebas de penetración.
- **Resultados del modelo:** son exploratorios. La muestra no tenía ataques confirmados, y las etiquetas las registró un integrante del equipo, con scripts que llaman a la función de revisión de la aplicación y a partir de propuestas preparadas con apoyo de IA, sin revisión ciega. No permiten establecer una eficacia generalizable ni que el modelo ajustado supere al base.
- **Controles:** no comprueban que el veredicto sea correcto ni revisan el texto de la explicación. El enmascaramiento sigue patrones y no garantiza el anonimato.
- **Ingesta:** es bajo demanda; no hay una tarea programada.
- **Servidor de la máquina virtual:** se usó el servidor de desarrollo de Django, no uno de producción.
- **Roles:**
  - una cuenta nueva recibe por defecto el rol de analista;
  - el campo «activo» del perfil no interviene en los permisos: el acceso se corta desactivando la cuenta (casilla «Active»);
  - las rutas `api/token/` de JWT están habilitadas, pero la aplicación no las usa.
- **Credenciales:** el historial del repositorio contiene credenciales de versiones anteriores, que deben tratarse como comprometidas. Su estado está en el [manual de administración](docs/producto/MANUAL_ADMINISTRACION.md), sección 7.
- **Código heredado:** `sentria_web.py`, `views.py` de la raíz, `leer_alerta.py` y `sentria_gemini.py` son prototipos anteriores que no forman parte de la aplicación.

## Documentación

| Archivo | Para qué |
|---|---|
| [`docs/producto/MANUAL_INSTALACION.md`](docs/producto/MANUAL_INSTALACION.md) | Instalación en entorno virtual y con Docker |
| [`docs/producto/MANUAL_ADMINISTRACION.md`](docs/producto/MANUAL_ADMINISTRACION.md) | Cuentas, activos, ingesta, ventanas, conjunto de ajuste, credenciales y operación |
| [`docs/producto/MANUAL_AGENTES.md`](docs/producto/MANUAL_AGENTES.md) | Incorporación de agentes de Wazuh |
| [`docs/producto/MANUAL_USUARIO.md`](docs/producto/MANUAL_USUARIO.md) | Uso para analistas e invitados, con capturas |
| [`docs/producto/CONFIGURACION.md`](docs/producto/CONFIGURACION.md) | Todas las variables de entorno que lee el código |
| [`CHANGELOG.md`](CHANGELOG.md) | Cambios por versión, con sus commits |
| [`.env.example`](.env.example) | Plantilla de configuración, sin valores reales |
| `requirements.txt`, `Dockerfile`, `docker-entrypoint.sh`, `.dockerignore` | Dependencias e imagen |
| `sentria_project/settings_ci.py`, `settings_prueba_docker.py` | Configuraciones de prueba |
| [`scripts/laboratorio_windows/generar_eventos_fim.ps1`](scripts/laboratorio_windows/generar_eventos_fim.ps1) | Generación de eventos de integridad de archivos en Windows |

No forman parte del repositorio el documento de grado y sus anexos, los diagramas, ni los scripts privados del laboratorio (el lanzador y la unidad de servicio de la máquina virtual y los scripts del equipo Windows).

## Equipo

Proyecto de grado de Ingeniería de Sistemas, Universidad El Bosque, 2026.

- **Integrantes:** Andrés Felipe Meneses Feria, Miguel Alejandro Pineda Velazco y Yishaq Santiago Riveros Lopez.
- **Director:** Diego Fernando Rodríguez Castañeda.
