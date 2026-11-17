# Apartado «Comparación de IA»

Para quien administra la instalación. Describe el apartado que guarda y resume mediciones de distintos proveedores sobre las mismas entradas. Las marcas son las del [manual de instalación](MANUAL_INSTALACION.md): **[C]** comprobado en el laboratorio, **[D]** documentado sin ejecución registrada, **[F]** falta un dato.

## 1. Quién puede usarlo

Solo el **superusuario real** de Django: una cuenta autenticada, activa y con `is_superuser`. El rol Administrador de SENTRIA o `is_staff` no bastan. Una cuenta sin permiso recibe 403 sin datos; una sesión anónima va al inicio de sesión. **[C]** suite (`dashboard/tests_comparacion.py`) y despliegue del 13 nov 2026. Código: `dashboard/comparacion/views.py`, función `solo_superusuario`.

El enlace aparece en el menú lateral solo para esa cuenta (`dashboard/templates/sentria/base_app.html`).

## 2. Qué hace y qué no hace

- **No llama a ningún modelo, al indexador ni lee credenciales.** Las páginas GET solo leen; lo que escribe va por POST con CSRF.
- **Registrar mediciones propias:** convierte las mediciones que ya guardó el análisis de esta instalación (`_medicion` del snapshot de cada alerta, versión `medicion_v2`) en ejecuciones de comparación. Es idempotente: una alerta se registra una vez. No modifica las alertas. Las filas anteriores a la medición no se registran. (`dashboard/comparacion/local.py`)
- **Importar** (vista previa y confirmación): admite el documento que exporta este mismo apartado y los registros JSONL del [ejecutor independiente](../../experimentos/comparacion/README.md). Solo interpreta JSON; no abre rutas ni URLs del archivo. Lo ya existente no se modifica: el mismo UUID con otro contenido es un conflicto. Un registro con secretos, direcciones IP, correos, URLs, rutas absolutas o identificadores privados de la instalación se rechaza entero. (`intercambio.py`, `privacidad.py`)
- **Conjuntos congelados:** se crean solo al importar un documento que trae un bloque «conjunto», con un manifiesto por huella; la pertenencia de un caso se decide por la huella de su entrada, no por su nombre. (`conjuntos.py`)
- **Exportar:** CSV y JSON de las ejecuciones con los filtros actuales, y el documento para otra instancia.
- **Gráficas:** PNG, SVG y PDF por grupo (mismo caso, protocolo y equivalencia), con sus datos en CSV y un manifiesto JSON. Una serie sin mediciones aparece como «sin medición», nunca como 0; no hay ranking ni «ganador». (`graficas.py`)
- **Resumen del conjunto:** por proveedor y modelo informado, cobertura de casos (k de N), número de ejecuciones, tiempo por caso (media y mediana entre casos, cada caso con el mismo peso) y tokens por ejecución medida. Solo compara series «equivalente» sobre los casos que todas cubren. (`resumen.py`)

## 3. Reglas de los datos

- **Ausente no es cero.** Un token o un tiempo que el proveedor no informó queda como «No disponible».
- **Modelo solicitado y modelo informado** se guardan por separado. Una versión informada distinta forma otra serie: en el laboratorio se pidió `models/gemini-3.5-flash` y las respuestas informaron `gemini-3.6-flash` **[C]**.
- **Identidad = UUID de la ejecución.** Dos ejecuciones con la misma respuesta son dos mediciones. Un registro sin UUID (formato antiguo) que coincide con otro queda «ambiguo» y no se fusiona.
- **Tokens no son dinero** y la aceptación del contrato no es exactitud del veredicto.
- **Limitación conocida:** la serie del resumen (proveedor, modelo y protocolo) no separa observaciones anteriores de ejecuciones nuevas controladas con el mismo modelo y parámetros; si se importan ambas, se agrupan juntas.

## 4. Instalación

1. **Migraciones aditivas** `dashboard 0015` (casos, ejecuciones y lotes de importación) y `0016` (conjuntos y su relación con los casos). No modifican tablas existentes. Aplicarlas después de un respaldo: `python manage.py migrate dashboard`. **[C]** aplicadas en el MySQL del laboratorio el 13 nov 2026, con respaldo previo.
2. **Gráficas (opcional):** Matplotlib y sus dependencias están fijadas en `requirements.txt`. Sin Matplotlib el resto del apartado funciona y las direcciones de las figuras responden 503 con el aviso de que falta la dependencia. Matplotlib necesita un directorio de caché escribible: definir `MPLCONFIGDIR` en el entorno del proceso hacia un directorio privado. **[C]** en el entorno del servicio de la máquina virtual (Matplotlib 3.11.2). **[D]** en la imagen Docker: no se reconstruyó con esta dependencia.
3. Crear o usar una cuenta de superusuario (`python manage.py createsuperuser`).

## 5. Estado en el laboratorio

- Desplegado en la máquina virtual el 13 nov 2026 **[C]**.
- Conjunto `SENTRIA-PILOTO-COMP v1` (9 casos) creado por importación; el v3 (74 casos) preparado para importarse en otras instancias **[C]**. Composición en [`docs/validacion/`](../validacion/README.md).
- Las campañas de comparación con otros proveedores se ejecutaron en otra instalación; sus resultados no forman parte de esta versión **[F]**.
