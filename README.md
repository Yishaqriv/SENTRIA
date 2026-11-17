# SENTRIA: AI-Alert Security Classification

SENTRIA es el prototipo del proyecto de grado de Ingeniería de Sistemas de la Universidad El Bosque (2026). Integra el SIEM de código abierto Wazuh, un modelo de lenguaje de la familia Gemini y una aplicación web en Django para depurar, clasificar en contexto y apoyar la revisión de alertas de seguridad.

**Objetivo general:** desarrollar y validar, en un entorno controlado, un prototipo que integre un SIEM, un modelo de lenguaje de gran escala ajustado mediante fine-tuning y una aplicación web para depurar, clasificar contextualmente y apoyar la gestión de alertas de seguridad.

Los cambios por versión, con sus commits, están en [`CHANGELOG.md`](CHANGELOG.md).

## Versiones e instalaciones

| | Octubre de 2026 (`6d8c6b5`) | Noviembre de 2026 (esta versión) |
|---|---|---|
| Código | Rama `cierre/3e-windows-lab`, commit `6d8c6b5` | `6d8c6b5` más la evidencia web, la medición, la ingesta continua y la comparación de proveedores |
| Equipos con agente | La máquina virtual Ubuntu (Wazuh 4.14.5 y SENTRIA) y dos equipos Windows del equipo | Los mismos, más un servidor Windows en uso real con servicios web en contenedores, administrado por un tercero y conectado por una red privada virtual |
| Nivel mínimo de la política | 7 | 5 |
| Ingesta | Bajo demanda: «Actualizar» y el comando `ingestar_alertas` | Lo anterior, más un trabajador periódico acotado sobre el agente del servidor |
| Medición por análisis | No | Latencia, duración, tokens informados, modelo solicitado e informado |
| Base de datos | MySQL remota | La misma |

La aplicación se sirvió en la máquina virtual con el servidor de desarrollo de Django (como servicio del usuario) y, en octubre, también en uno de los equipos Windows con la imagen Docker, que usa Gunicorn. Lo comprobado en la imagen no describe la instalación de la máquina virtual, y la imagen no se reconstruyó con los cambios de noviembre. **La validación es de laboratorio**: el servidor de noviembre aporta eventos reales, pero no es una validación en una organización.

## Componentes

| Componente | En el código |
|---|---|
| Lectura del indexador de Wazuh y normalización | `sentria_backend.py` (`_normalizar_hit`, `_win_crudo`, `_web_crudo`) |
| Ingesta manual y reanálisis | `dashboard/ia/ingesta.py`, comando `ingestar_alertas`, vistas de `dashboard/views.py` |
| Ingesta continua acotada | `dashboard/ia/continua.py`, comando `ingesta_continua` |
| Exclusión común y llamadas sin cerrar | `dashboard/ia/exclusion.py`, comando `revisar_incierto` |
| Activos, política y ventanas de mantenimiento | `dashboard/ia/resolver.py`, `dashboard/ia/politica.py`, `dashboard/mantenimiento.py` |
| Entrada y enmascaramiento | `dashboard/ia/evidencia.py`, `dashboard/ia/prompt.py`, `dashboard/ia/anonimizacion.py` |
| Proveedores del modelo y medición | `dashboard/ia/proveedores.py`, `dashboard/ia/analizador.py` (`_medicion`) |
| Controles de la respuesta | `dashboard/ia/contrato.py`, `dashboard/ia/sustento.py`, `dashboard/dataset.py` (privacidad de la salida) |
| Colas, revisión y métricas | `dashboard/views.py`, `dashboard/revision.py`, `dashboard/metricas_eval.py` |
| Comparación de IA (solo superusuario) | `dashboard/comparacion/`, migraciones `0015` y `0016` |
| Usuarios y roles | `usuarios/` |
| Reglas de Wazuh para accesos web | `wazuh/reglas/sentria_web_rules.xml` |

## Flujo de una alerta

1. **Consulta.** SENTRIA lee el indexador de Wazuh (`wazuh-alerts-*`) con una cuenta de solo lectura. Solo sigue si el certificado coincide con la huella TLS fijada en la configuración.
2. **Normalización.** Toma una lista cerrada de campos. Para los accesos web de un recolector externo (servicios `domjudge` y `tomcat`) guarda método, código HTTP, bytes, clase de ruta, presencia de parámetros, hora original y procedencia (en vivo o histórico reproducido); nunca la URL, los parámetros, el cliente, el usuario ni las cabeceras.
3. **Duplicados y política.** No guarda dos veces la misma alerta y aplica la política de elegibilidad: en esta versión, **nivel 5 o superior** (el valor por defecto del código es 7; `settings.py` fija 5), un perfil de activo asociado y que no sea ruido operativo excluido. «Actualizar» guarda las no elegibles con su motivo; los comandos de ingesta solo las cuentan.
4. **Entrada.** Para las elegibles, construye la entrada con el contexto del activo y la ventana de mantenimiento, y enmascara los datos identificables que siguen patrones conocidos. El enmascaramiento no garantiza el anonimato.
5. **Modelo.** Por defecto, el modelo base por la API de Gemini (`GEMINI_MODEL`, por defecto `models/gemini-3.5-flash`). El modelo ajustado en Vertex AI (`vertex_tuned`) es experimental y está **desactivado por defecto**. Antes de llamar, una exclusión por alerta impide que dos vías analicen el mismo documento a la vez, y una marca persistente impide reenviar una llamada que pudo ejecutarse y no quedó cerrada.
6. **Controles y medición.** Comprueba el contrato JSON, el sustento de los ocho campos internos inspirados en CVSS v3.1 (no forman una puntuación CVSS) y, con el modelo ajustado, la privacidad de la salida. Si falla un control, la alerta queda como análisis fallido, nunca como falso positivo. Guarda la medición del intento: estado de la llamada y del análisis, tiempos, tokens que informa el proveedor (ausentes como vacíos, nunca 0) y el modelo informado por la respuesta, que puede diferir del solicitado.
7. **Colas y revisión.** Presenta las alertas en colas (requiere atención, falsos positivos, auditoría selectiva, pendientes y fallidas, omitidas por política y análisis legado). La revisión humana es opcional y no sobrescribe la respuesta original del modelo.

## Requisitos

- Python 3.12 y las dependencias de `requirements.txt`. `mysqlclient` necesita las cabeceras de MySQL o MariaDB, `pkg-config` y un compilador. Matplotlib solo se usa para las gráficas de «Comparación de IA».
- Un servidor MySQL para la ejecución normal. Las pruebas usan SQLite en memoria.
- Un indexador de Wazuh accesible y una cuenta de solo lectura sobre `wazuh-alerts-*`.
- Una clave de la API de Gemini. Para el modelo ajustado, un proyecto de Google Cloud con el modelo desplegado en Vertex AI.

La instalación paso a paso está en el [manual de instalación](docs/producto/MANUAL_INSTALACION.md), que indica qué pasos se comprobaron en el laboratorio y cuáles no.

## Configuración

La configuración se lee de variables de entorno. `sentria_project/settings.py` carga con `python-dotenv` el archivo que indique `SENTRIA_ENV_FILE` (debe existir y tener permisos 600 o más restrictivos) o, si no está definida, `.env` en la carpeta del proyecto. `sentria_backend.py` vuelve a cargar el mismo archivo con prioridad sobre el entorno: conviene no definir una variable con valores distintos en los dos sitios. Todas las variables están en [`docs/producto/CONFIGURACION.md`](docs/producto/CONFIGURACION.md).

1. Copiar [`.env.example`](.env.example) a un archivo propio fuera del repositorio y completarlo. `.gitignore` y `.dockerignore` excluyen los archivos de entorno.
2. **Definir `DJANGO_DEBUG=False`** fuera del desarrollo: si falta, vale `True`.
3. **Obligatorias:** `DJANGO_SECRET_KEY`, `DB_USER`, `DB_PASSWORD`, `DB_HOST` y `DB_PORT`. Si falta una, el arranque se detiene y la nombra.
4. **Ingesta continua:** `SENTRIA_EXCLUSION_DIR`, el mismo directorio privado y persistente para el dashboard y para el comando.
5. **Huella del indexador:** ante una huella distinta, verificar el certificado con quien administra Wazuh antes de cambiar `WAZUH_TLS_SHA256`.
6. **Política:** se cambia con `IA_POLITICA` en `settings.py`, no con una variable de entorno.

## Uso

```bash
python manage.py check
python manage.py migrate            # después de un respaldo de la base
python manage.py createsuperuser
python manage.py runserver          # servidor de desarrollo de Django
```

Qué escribe y qué llama al modelo:

| Acción | Escribe en la base | Puede llamar al modelo |
|---|---|---|
| «Actualizar» (administrador o analista) | Sí | Sí, una vez como máximo |
| «Reintentar» una alerta (administrador o analista) | Sí | Sí, una vez |
| «Reclasificar fallidas» (administrador) | Sí | **Sí, sin tope total**, con 4 s entre llamadas |
| `ingestar_alertas --agent-id <ID> --dry-run` | No | No |
| `ingestar_alertas --agent-id <ID> --confirmar` | Sí | Sí, hasta 3 por ejecución (`--max-analisis`) |
| `ingesta_continua ... --ensayo` | No | No |
| `ingesta_continua ... --confirmar` | Sí | Sí: 2 por ejecución, 6 por hora móvil y 30 por día de Bogotá como máximo |
| `ingesta_continua ... --ver-estado`, `revisar_incierto --listar` | No | No |
| `revisar_incierto --liberar <CLAVE> --motivo … --revisor …` | No: retira la marca del directorio de exclusión y deja un registro con el motivo | No |
| «Comparación de IA» (solo superusuario) | Solo al registrar mediciones o importar | Nunca |

`ingestar_alertas` lee hasta 100 alertas de un agente (`--scan-limit`, máximo 500) con el nivel mínimo de la política. `ingesta_continua` exige `--estado-dir`, `--agente`, `--nombre-agente`, `--activo` y `--desde`; su uso y sus límites están en el [manual de administración](docs/producto/MANUAL_ADMINISTRACION.md), sección 4 bis, y hay unidades de systemd de ejemplo en [`despliegue/systemd/`](despliegue/systemd/). Los perfiles de activo se crean en el panel de administración de Django y se asocian a los agentes con `asignar_agente_activo`.

**Docker:** el `Dockerfile` construye una imagen con un usuario sin privilegios (uid 10001), `DJANGO_DEBUG=False` y Gunicorn en el puerto 8000; `docker-entrypoint.sh` ejecuta `check` al arrancar y solo migra con `SENTRIA_MIGRAR_AL_ARRANCAR=1`. La imagen se probó con `6d8c6b5`; no se ha reconstruido con esta versión.

## Comparación de proveedores

El apartado «Comparación de IA» guarda mediciones de distintos proveedores sobre las mismas entradas, las importa de otras instancias sin duplicarlas y las resume por proveedor y modelo informado, sin convertir ausencias en ceros ni elegir un ganador. Ver [`docs/producto/COMPARACION_IA.md`](docs/producto/COMPARACION_IA.md).

El [ejecutor independiente](experimentos/comparacion/README.md) envía la misma entrada a otro proveedor mediante un adaptador propio del experimento. **Ese adaptador no cambia el proveedor que usa SENTRIA**, y cambiar una clave de API no basta para comparar proveedores. Esta versión no publica resultados comparativos.

## Pruebas y evidencias

```bash
python manage.py test --settings=sentria_project.settings_ci
cd experimentos/comparacion/herramientas && python -m unittest -v test_ejecutor test_exportacion
```

- La suite de Django usa SQLite en memoria y proveedores simulados, sin Wazuh ni MySQL; comprueba el software, no la calidad del modelo. `settings_ci.py` no carga el `.env` local ni un `SENTRIA_ENV_FILE` heredado y retira del entorno las credenciales y destinos que lee SENTRIA; lo comprueba `sentria_project/tests_aislamiento_ci.py` con valores ficticios. Las pruebas del ejecutor son otra suite, con casos sintéticos.
- El resultado de la ejecución sobre esta versión está en [`docs/validacion/PRUEBAS_CANDIDATO.md`](docs/validacion/PRUEBAS_CANDIDATO.md). La integración continua está definida en [`.github/workflows/pruebas.yml`](.github/workflows/pruebas.yml).
- Las evidencias del laboratorio que se pueden publicar (reglas web con `wazuh-logtest`, recepción y análisis en el servidor, composición del conjunto de comparación) están en [`docs/validacion/`](docs/validacion/README.md), como agregados con la huella del informe privado del que salen.
- Las mediciones de octubre de 2026 sobre `6d8c6b5` (598 pruebas, cobertura del 86 %, hallazgos de ruff y bandit, prueba aislada de la imagen Docker, pruebas controladas y 64 revisiones humanas) están descritas en el [`CHANGELOG.md`](CHANGELOG.md) y en los manuales; sus informes completos son registros del equipo.

## Limitaciones conocidas

- **Validación:** de laboratorio. No se hicieron pruebas de carga, de capacidad ni de escalabilidad, ni pruebas de penetración, y no se midieron el tiempo de respuesta de los analistas ni la aceptación de los usuarios. Sí se midieron la latencia de cada llamada al proveedor y la duración de cada análisis en la ingesta continua (12 análisis, [`docs/validacion/`](docs/validacion/README.md), sección 3); describen esas llamadas, no la capacidad del sistema.
- **Resultados del modelo:** exploratorios. Que un análisis termine `COMPLETED` significa que superó el contrato y los controles, no que el veredicto sea correcto. Los resultados de octubre no tenían ataques confirmados en la muestra ni revisión ciega, y no permiten afirmar que el modelo ajustado supere al base.
- **Controles:** antes de aceptar una respuesta, SENTRIA comprueba su forma y su sustento estructurado: JSON estricto; contrato (campos, valores permitidos, tipos y longitudes, sin propiedades de más); que cada factor CVSS afirmado coincida con el que SENTRIA observó en la entrada con reglas deterministas; y, solo con el modelo ajustado, que la respuesta no contenga patrones de IP, correo, rutas de archivo o nombres de campos de los registros crudos de Wazuh. **Ningún control valida la corrección semántica:** no se comprueba que el veredicto o el riesgo sean correctos ni que la explicación, el razonamiento CVSS o la recomendación sean ciertos o coherentes con la alerta; de esos textos solo se comprueba la longitud, y un aviso que no bloquea busca en el razonamiento alguna mención de los factores que quedaron sin determinar. El enmascaramiento de la entrada sigue patrones y no garantiza el anonimato.
- **Ingesta continua:** un solo agente por trabajador. El orden de paginación (`@timestamp`, `id`, `_index`) no tiene un desempate único y puede saltarse eventos empatados; en el inventario del servidor faltó 1 evento de nivel 3 de 39 162. La corrección está propuesta y **no aplicada**. Los documentos indexados con mucho retraso o borrados por la retención no se recuperan.
- **Comparación:** la serie del resumen (proveedor, modelo y protocolo) no separa observaciones anteriores de ejecuciones nuevas con el mismo modelo y parámetros. Los históricos del conjunto usan el perfil actual del activo.
- **Modelo:** la respuesta de Gemini informó `gemini-3.6-flash` cuando se pidió `models/gemini-3.5-flash`; SENTRIA guarda ambos y no los iguala.
- **Servidor de la máquina virtual:** se usa el servidor de desarrollo de Django, no uno de producción.
- **Roles:** una cuenta nueva recibe por defecto el rol de analista; el campo «activo» del perfil no interviene en los permisos (el acceso se corta desactivando la cuenta); las rutas `api/token/` de JWT están habilitadas, pero la aplicación no las usa.
- **Credenciales:** el historial del repositorio contiene credenciales de versiones anteriores, que deben tratarse como comprometidas. Su estado está en el [manual de administración](docs/producto/MANUAL_ADMINISTRACION.md), sección 7.
- **Código heredado:** `sentria_web.py`, `views.py` de la raíz, `leer_alerta.py` y `sentria_gemini.py` son prototipos anteriores que no forman parte de la aplicación.

## Documentación

| Archivo | Para qué |
|---|---|
| [`docs/producto/MANUAL_INSTALACION.md`](docs/producto/MANUAL_INSTALACION.md) | Instalación en entorno virtual y con Docker |
| [`docs/producto/MANUAL_ADMINISTRACION.md`](docs/producto/MANUAL_ADMINISTRACION.md) | Cuentas, activos, política, ingesta manual y continua, ventanas, conjunto de ajuste, credenciales y operación |
| [`docs/producto/COMPARACION_IA.md`](docs/producto/COMPARACION_IA.md) | Apartado de comparación de proveedores |
| [`docs/producto/MANUAL_AGENTES.md`](docs/producto/MANUAL_AGENTES.md) | Incorporación de agentes de Wazuh |
| [`docs/producto/MANUAL_USUARIO.md`](docs/producto/MANUAL_USUARIO.md) | Uso para analistas e invitados, con capturas |
| [`docs/producto/CONFIGURACION.md`](docs/producto/CONFIGURACION.md) | Todas las variables de entorno que lee el código |
| [`docs/validacion/README.md`](docs/validacion/README.md) | Evidencias publicables y resultado de las pruebas |
| [`wazuh/README.md`](wazuh/README.md) | Reglas y formato de los accesos web |
| [`experimentos/comparacion/README.md`](experimentos/comparacion/README.md) | Ejecutor independiente de la comparación |
| [`despliegue/systemd/`](despliegue/systemd/) | Unidades de ejemplo de la ingesta continua |
| [`CHANGELOG.md`](CHANGELOG.md) | Cambios por versión |
| [`.env.example`](.env.example) | Plantilla de configuración, sin valores reales |
| `requirements.txt`, `Dockerfile`, `docker-entrypoint.sh`, `.dockerignore` | Dependencias e imagen |
| `sentria_project/settings_ci.py`, `settings_prueba_docker.py` | Configuraciones de prueba |
| [`scripts/laboratorio_windows/generar_eventos_fim.ps1`](scripts/laboratorio_windows/generar_eventos_fim.ps1) | Generación de eventos de integridad de archivos en Windows |

No forman parte del repositorio el documento de grado y sus anexos, los diagramas, los lanzadores y unidades privados del laboratorio, los recolectores del servidor Windows, los registros, los conjuntos de casos ni las respuestas de los modelos.

## Equipo

Proyecto de grado de Ingeniería de Sistemas, Universidad El Bosque, 2026.

- **Integrantes:** Andrés Felipe Meneses Feria, Miguel Alejandro Pineda Velazco y Yishaq Santiago Riveros Lopez.
- **Director:** Diego Fernando Rodríguez Castañeda.
