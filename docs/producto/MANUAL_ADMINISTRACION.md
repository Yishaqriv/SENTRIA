# Manual de administración de SENTRIA (versión `6d8c6b5`)


Para la persona que administra SENTRIA: cuentas, activos, ingesta, ventanas, conjunto de ajuste, credenciales y operación diaria. Para escribirlo no se ejecutó nada. Las marcas son las del [manual de instalación](MANUAL_INSTALACION.md):
- **[C]**: comprobado en el laboratorio;
- **[D]**: documentado, no comprobado: sin ejecución registrada, y no se ejecutó para escribir este manual;
- **[F]**: falta un dato.

Las evidencias de las marcas [C] son registros del laboratorio que no se publican en el repositorio.

## 1. Roles y permisos

Hay tres roles: Administrador, Analista e Invitado. Un superusuario de Django cuenta como administrador. Una cuenta nueva recibe por defecto el rol de analista, con permisos de escritura. **[D]** (código: `usuarios/models.py`, `usuarios/decorators.py`, decoradores de `dashboard/views.py`)

| Acción | Administrador | Analista | Invitado |
|---|---|---|---|
| Ver las colas, el detalle de las alertas y las ventanas de mantenimiento | Sí | Sí | Sí |
| «Actualizar» (traer y analizar) | Sí | Sí | No |
| Confirmar o corregir una clasificación, reintentar un análisis | Sí | Sí | No |
| Exportar CSV, ver métricas | Sí | Sí | No |
| Crear o cancelar ventanas de mantenimiento | Sí | Sí | No |
| Conjunto de ajuste: bandeja, sincronizar, planificador | Sí | Sí | No |
| «Reclasificar fallidas» | Sí | No | No |
| Gestión de usuarios | Sí | No | No |
| Panel de administración de Django (`/admin/`) | Lo decide Django (ver la nota) | Lo decide Django | Lo decide Django |

**Nota sobre `/admin/`.** El acceso al panel no depende del rol de SENTRIA, sino de las condiciones de Django:
- la cuenta tiene que estar activa y marcada como personal (`is_staff`);
- dentro del panel, cada modelo exige los permisos de Django de esa cuenta, salvo para un superusuario, que los tiene todos.

Una cuenta con el rol de invitado y `is_staff=True` podría entrar al panel si está activa; una de administrador con `is_staff=False` no puede entrar, aunque sea superusuario. La gestión de usuarios de SENTRIA no muestra ni cambia `is_staff`. **[D]** (comportamiento de `django.contrib.admin`; sin prueba registrada en el laboratorio)

Los permisos por rol se comprobaron con la suite (pruebas de navegación por rol y de acciones de escritura por POST) **[C]**. En la vista previa con datos sintéticos, la cuenta de invitado no ve las acciones de escritura **[C]** (captura VP-5 del [manual de usuario](MANUAL_USUARIO.md)).

## 2. Cuentas de usuario

Desde **Usuarios** en el menú lateral (solo administrador):
- **Crear:** nombre de usuario, nombre, correo, contraseña y rol.
- **Editar:** datos y rol, con dos casillas de estado. «Active» (la cuenta de Django), desmarcada, impide iniciar sesión. «Activo» (el perfil de SENTRIA) se guarda, pero en `6d8c6b5` no la usa ninguna comprobación de acceso: desmarcarla no corta el acceso. **[D]** (código; sin prueba registrada)
- **Eliminar:** pide confirmación. Las revisiones y las ventanas que creó la cuenta se conservan, pero pierden su autor (el campo queda vacío).

**Recomendación:** desactivar (casilla «Active») en lugar de eliminar, para no perder la autoría de las revisiones, que se usa en las métricas y en la trazabilidad. **[D]** (`on_delete=SET_NULL` en los modelos)

El código no impide que un administrador elimine su propia cuenta ni la del último administrador. Conviene tener al menos dos cuentas de administrador o el superusuario de la instalación. **[D]**

Estado en el laboratorio: las pantallas de usuarios están en las capturas U-2 y U-3 del [manual de usuario](MANUAL_USUARIO.md), en copias públicas que ocultan los nombres de las cuentas y el correo; la de U-2, además, recortada. Los originales no se publican. [F] no hay registro de cómo se crearon las cuentas.

## 3. Activos lógicos y agentes

SENTRIA solo envía al modelo las alertas de un agente asociado a un **activo lógico**: la descripción del equipo (tipo, criticidad, sistema, uso y horario) que el modelo recibe como contexto.

1. **Crear el activo.** Desde el panel de administración de Django (`/admin/`, «Activos lógicos») **[D]**. En el laboratorio, PC-01 se creó el 12 oct 2026 con el contexto que describió el equipo, revisado antes de guardarlo, según los registros del laboratorio de ese día **[C]**. [F] confirmar si se hizo por el panel o por un script.
2. **Asociar el agente al activo:**
   - `python manage.py asignar_agente_activo --agent-id <ID> --activo <IDENTIFICADOR> --etiqueta <ETIQUETA>`;
   - `--listar` muestra las asociaciones; `--historial`, el registro de cambios, que solo crece;
   - `--desactivar --agent-id <ID>` retira la asociación.

   **[C]** asociaciones del laboratorio: 000 → SRV-01, 001 → LAPTOP-01 y 002 → PC-01.
3. **Comando heredado `cargar_activos_cafe`:** crea o actualiza los 12 activos del escenario del café internet (EP-01 a EP-10, ADM-01 y SRV-01) sin borrar nada. Ese escenario era el inicial del diseño de septiembre de 2026 y se retiró tras la revisión del 27 de octubre. El comando conserva su nombre y no hace falta para una instalación nueva. **[C]** usado en septiembre de 2026, según los registros del laboratorio.

## 4. Política de elegibilidad e ingesta

- **Política:** decide qué alertas se envían al modelo. Sus valores por defecto están en el código (`dashboard/ia/politica.py`): nivel 7 o superior, un activo asociado y que la alerta no corresponda a ruido operativo excluido (por defecto, alertas que traen a la vez los grupos `dpkg` y `config_changed`); no hay reglas ni grupos excluidos. **[C]** en el laboratorio, con esos valores.
- **Cambiar la política:** solo en el servidor, definiendo `IA_POLITICA` en `settings.py`, un diccionario con los campos que se quieran cambiar (`nivel_minimo`, `exige_contexto_activo`, `grupos_excluidos`, `rule_ids_excluidos` o `combinaciones_ruido`); los demás conservan su valor por defecto. En `6d8c6b5` solo aparece como comentario de ejemplo, así que rigen los valores por defecto. No hay pantalla ni variable de entorno para cambiarla. La aplicación web lee la configuración al arrancar, y cada ejecución del comando de ingesta, al empezar. **[D]** el cambio por `IA_POLITICA`: sale del código, no se probó.
- **Qué pasa con las alertas que la política no admite** depende del camino (`6d8c6b5`) **[C]**:
  - con **«Actualizar»**, una alerta nueva no elegible se registra como omitida por política, con su motivo, y queda visible en su cola;
  - el **comando de ingesta** evalúa la política antes de registrar: las no elegibles **solo se cuentan** y no aparecen en ninguna cola. En los modos dirigido y de prueba controlada, una alerta no elegible detiene la orden;
  - un **reanálisis** («Reintentar», «Reclasificar fallidas» o la recuperación de una alerta ya registrada) deja como omitida la alerta que ya no cumpla la política.
- **«Actualizar»** (web; administrador o analista): consulta la alerta más reciente, de cualquier nivel, y la procesa, así que hace como máximo una llamada al modelo. **[C]**
- **Comando de ingesta** (servidor):
  - ensayo sin escrituras ni llamadas: `python manage.py ingestar_alertas --agent-id <ID> --dry-run`;
  - ejecución: `--confirmar`;
  - consulta en el indexador hasta 100 alertas del agente con nivel igual o superior al mínimo de la política (7 por defecto) (`--scan-limit`, máximo 500), y analiza las primeras elegibles, hasta 3 por ejecución (`--max-analisis`, tope fijo de 3);
  - **[C]** en los pilotos y las pruebas, con sus propios topes. No está programado: no hay tarea periódica **[C]**.
- **«Reclasificar fallidas»** (solo administrador): vuelve a analizar en una sola ejecución todas las alertas pendientes, fallidas u omitidas, salvo las de pruebas controladas, con una pausa de 4 s entre llamadas y **sin tope total de llamadas**. Puede consumir cuota de la API: usarla a sabiendas. **[D] Documentada, no comprobada:** sale del código; no consta su uso en el laboratorio con `6d8c6b5`.
- **Modos de piloto y de prueba controlada** del comando (`--piloto`, `--iniciar-experimento`, `--opensearch-id`, …): exigen registros privados sellados y confirmación escrita. Son para pruebas, no para la operación. **[C]**

## 5. Ventanas de mantenimiento

En **Mantenimiento** (administrador o analista):
1. Elegir el activo.
2. Poner el inicio y el fin en la hora local del activo.
3. Elegir la categoría:
   - actualización de software o parches;
   - cambio de configuración;
   - mantenimiento de hardware;
   - respaldo o restauración;
   - reinicio de servicios;
   - limpieza;
   - otro.
4. Elegir el alcance de la operación autorizada:
   - cuentas y grupos locales;
   - privilegios;
   - instalación o actualización de software;
   - configuración de servicios;
   - política de auditoría;
   - archivos del directorio de laboratorio;
   - conexión de dispositivos;
   - otro.
5. Escribir una descripción breve, que no se envía al modelo.

Una ventana se puede cancelar, pero no se borra. **[D]** (código y plantilla). En el laboratorio, las ventanas de las pruebas (por ejemplo, W1 y W2 de FIM-PC01-1) se crearon con un script que usa la función de la aplicación, no desde la pantalla **[C]** (script privado del laboratorio). La pantalla se probó con datos sintéticos **[C]** (captura VP-4 del [manual de usuario](MANUAL_USUARIO.md)).

## 6. Conjunto de ajuste (dataset)

Las pantallas **Dataset**, **Sincronizar** y **Planificador** (administrador o analista) gestionan los candidatos a ejemplo de ajuste que salen de las revisiones **[D]** (código de `6d8c6b5`).

**Cómo se preparó en el laboratorio el conjunto del ajuste del 7 oct [C].** Se hizo sobre todo con scripts privados que llaman a las funciones de la aplicación, no con las pantallas:
- **revisiones y borradores de la salida objetivo:** `registrar_revision` y `dataset.guardar_borrador`;
- **envío a revisión:** `dataset.validar_para_revision` y `dataset.enviar_a_revision`;
- **aprobación:** el comando `aceptar_lote --escribir`, en el modo `REVISOR_UNICO_LOTE`: un lote de 38 candidatos y otro con la 149, según los registros del laboratorio del 7 oct 2026.

**Evidencia de las pantallas [C]:** consultas GET autenticadas a `/dataset/`, al detalle de varios candidatos y a `/dataset/planificador/` respondieron 200, con una sesión temporal y sin escrituras (registro del laboratorio). [F] No consta qué operaciones de escritura se hicieron desde la pantalla. La alerta 128, aprobada antes en el modo de doble revisión y que quedó fuera del conjunto del ajuste, no tiene registrada la vía por la que se aprobó.

El ajuste en sí se lanzó fuera de la aplicación, en Vertex AI. Para la operación normal no hace falta.

## 7. Credenciales

- **Dónde están:** en el `.env` (600), fuera del repositorio. En Docker, en volúmenes montados en solo lectura. Nunca en la imagen ni en el código. **[C]**
- **Estado (31 oct 2026):**
  - la clave de Gemini se revocó;
  - la contraseña de administración del indexador y la clave de Django se rotaron;
  - **la credencial de MySQL sigue pendiente de rotación**, porque depende del administrador del servidor;
  - el historial público del repositorio contiene credenciales antiguas: hay que tratarlas como comprometidas.
- **Rotar una credencial:** cambiarla en el servicio (indexador, MySQL, Google), actualizar el `.env` o el volumen, reiniciar la aplicación y comprobar el acceso. **[D]**; los procedimientos aplicados son registros privados del laboratorio **[C]**.
- **Huella del indexador:** si se regenera el certificado de Wazuh, hay que actualizar `WAZUH_TLS_SHA256`; si no, SENTRIA deja de consultar. **[D]**

## 8. Operación

| Tarea | Máquina virtual (servicio de usuario) | Docker |
|---|---|---|
| Estado | `systemctl --user status sentria-dashboard.service` | `docker ps --filter name=<CONTENEDOR>` |
| Detener / arrancar | `systemctl --user stop sentria-dashboard.service` / `systemctl --user start sentria-dashboard.service` | `docker stop <CONTENEDOR>` / `docker start <CONTENEDOR>` |
| Registros | `journalctl --user -u sentria-dashboard.service` y el log de la unidad | `docker logs --tail 100 <CONTENEDOR>` |
| Tras reiniciar el equipo | El servicio no está habilitado: se arranca a mano o se decide `enable` | Abrir Docker Desktop y arrancar el contenedor |

Estado: **[C]** en la VM (12 oct). En Docker, **[C]** el contenedor del dashboard del PC; las órdenes generales son **[D]**.

El servicio de la VM sirve la aplicación con el servidor de desarrollo de Django (`runserver`), no con Gunicorn; los registros conservados no permiten establecer el valor de `DJANGO_DEBUG` durante las pruebas ([manual de instalación](MANUAL_INSTALACION.md), sección 5). La imagen Docker usa Gunicorn y fija `DJANGO_DEBUG=False`.

**Respaldos de MySQL:** antes de cada migración se hizo un respaldo nativo y se probó su restauración **[C]** (registros del laboratorio). No hay respaldos programados **[C]**.

**Actualizar a una versión nueva:**
1. Respaldar la base.
2. Obtener el código.
3. Revisar si hay migraciones (`manage.py showmigrations`).
4. Aplicarlas de forma deliberada.
5. Reiniciar el servicio o recrear el contenedor con la imagen nueva.

**[D]**; en el laboratorio, el paso a `6d8c6b5` no tenía migraciones y se hizo reiniciando el dashboard **[C]**.

## 9. Lo que este manual no cubre

- La administración de Wazuh: reglas, decodificadores y usuarios del indexador. Está en la documentación de Wazuh; la parte de agentes está en el [manual de agentes](MANUAL_AGENTES.md).
- La API con tokens JWT: las rutas existen, pero ninguna parte de la aplicación las usa.
