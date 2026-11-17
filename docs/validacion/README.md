# Evidencias de validación publicables

Este índice reúne lo que se puede comprobar de la versión de noviembre de 2026 sin publicar datos del laboratorio. Cada entrada indica cómo se obtuvo, la fecha o el corte, el código o la huella que la respalda, el resultado y su límite.

**Tipos de evidencia:**
- **Repetible:** cualquiera puede repetirla con el repositorio (pruebas automáticas y fixtures sintéticos).
- **Comprobada en el laboratorio:** la ejecutó el equipo sobre la instalación real. El repositorio publica solo agregados derivados (carpeta [`datos/`](datos/)) y la huella SHA-256 del informe privado del que salen. La huella permite al equipo demostrar qué informe se usó; no permite reconstruir su contenido.

Los registros completos (líneas de log, entradas enviadas al modelo, respuestas, identificadores de documentos, nombres de agentes y activos) no se publican.

## 1. Pruebas automáticas (repetible)

| Qué | Cómo | Resultado | Límite |
|---|---|---|---|
| Suite de Django | `python manage.py test --settings=sentria_project.settings_ci` | Ver [`PRUEBAS_CANDIDATO.md`](PRUEBAS_CANDIDATO.md) | SQLite en memoria, proveedores simulados, sin Wazuh ni MySQL. Comprueba el software, no la calidad del modelo |
| Ejecutor de comparación | `python -m unittest -v test_ejecutor test_exportacion` en [`experimentos/comparacion/herramientas/`](../../experimentos/comparacion/herramientas/) | Ver [`PRUEBAS_CANDIDATO.md`](PRUEBAS_CANDIDATO.md) | Casos sintéticos y proveedores falsos; es otra suite, no se suma a la de Django |
| Fixtures sintéticos | `python experimentos/comparacion/fixtures_sinteticos/generar_casos_sinteticos.py --comprobar` | Ver [`PRUEBAS_CANDIDATO.md`](PRUEBAS_CANDIDATO.md) | Solo comprueba que los casos versionados coinciden con los que genera el código actual |

## 2. Reglas web con `wazuh-logtest` (comprobada en el laboratorio)

Registros históricos reales de acceso web del servidor Windows, convertidos al esquema web 1 y pasados por `wazuh-logtest` con las reglas de [`wazuh/reglas/sentria_web_rules.xml`](../../wazuh/reglas/sentria_web_rules.xml). No se ingirió ningún evento ni se llamó a ningún modelo.

| Muestra | Fecha del informe (UTC) | Resultado | Por regla | Datos |
|---|---|---|---|---|
| DOMjudge (nginx) | 14 nov 2026, 06:32 | **54 de 54** con la regla, el nivel 5 y el decodificador `json` esperados | 119602: 34; 119603: 20 | [`datos/logtest_domjudge.json`](datos/logtest_domjudge.json) |
| Tomcat | 14 nov 2026, 07:01 | **60 de 60** | 119602: 40; 119603: 20 | [`datos/logtest_tomcat.json`](datos/logtest_tomcat.json) |

- **Ejecución:** el equipo, con permisos de administración, en el servidor de Wazuh. La configuración del manager y las reglas no cambiaron durante la prueba (lo comprueba el propio validador).
- **Límite:** confirma solo la regla, el nivel y el decodificador de cada registro. No valida el contexto del activo en la fecha histórica ni dice nada sobre si hubo un ataque.

## 3. Recepción y análisis en el servidor (comprobada en el laboratorio)

Agregados en [`datos/ingesta_servidor.json`](datos/ingesta_servidor.json).

**Inventario del agente del servidor** (lectura del indexador, sin escrituras ni llamadas):
- 39 162 eventos declarados por el indexador entre el 12 nov 2026, 05:30 UTC, y el 14 nov 2026, 05:47 UTC; se leyeron 39 161.
- El evento que faltó es de nivel 3: un empate en el orden de paginación lo dejó fuera. El mismo orden lo usa el trabajador de ingesta continua; hay una propuesta de corrección, **no aplicada** en esta versión.
- 13 eventos tienen nivel 5 o superior (10 textos de entrada distintos). Una consulta dirigida confirmó 13 de 13, con las mismas identidades, hasta el 14 nov 2026, 06:35 UTC.

**Pruebas funcionales del 12 nov 2026:**
- Ingesta dirigida de un evento de Windows de nivel 5 (`ingestar_alertas --opensearch-id … --confirmar`): una llamada al modelo y análisis `COMPLETED`. La entrada reconstruida después desde la fila coincidió, por huella, con la capturada antes del envío.
- Reproducción de un acceso web histórico 401 en el servidor: el indexador recibió exactamente un documento con la regla 119602, nivel 5; una ingesta dirigida lo analizó con una llamada (`COMPLETED`). La respuesta informó el modelo `gemini-3.6-flash` cuando se había pedido `models/gemini-3.5-flash`.

**Ingesta continua** (temporizador cada 15 min, del 13 nov 2026, 00:25 UTC, al corte del 16 nov 2026, 21:00 UTC):
- 12 intentos, 12 análisis `COMPLETED`, ninguno fallido ni incierto; 8 entradas distintas. Por categoría: Windows 9, avisos del agente de Wazuh 2, web 1.
- Un error de lectura del indexador no consumió llamadas ni contó como fallo.
- Medición `medicion_v2` en los 12: tokens informados por el proveedor en los 12; modelo solicitado `models/gemini-3.5-flash` e informado `gemini-3.6-flash` en los 12; latencia de la llamada con mediana de 4,05 s (3,13–5,69 s); duración del análisis con mediana de 4,43 s.

**Límites:** `COMPLETED` significa que la respuesta superó el contrato JSON y los controles de sustento, no que el veredicto sea correcto. Son observaciones de un único proveedor en una sola instalación; no son una comparación ni una prueba de carga o de capacidad del sistema. Los tokens son conteos del proveedor, no un coste.

## 4. Conjunto común de comparación v3 (comprobada en el laboratorio)

Agregados en [`datos/conjunto_v3_composicion.json`](datos/conjunto_v3_composicion.json). Manifiesto `SENTRIA-PILOTO-COMP v3`: `08b501a10bcbdef00dacf7155a487bf95ac69e1b9c9f4f2fd7e6202d365af639`.

- **74 entradas distintas**, cada una reconstruida exactamente por el código de esta versión: 65 accesos web históricos reproducidos (31 DOMjudge y 34 Tomcat), 6 eventos naturales de Windows, 2 avisos del agente de Wazuh y 1 acceso web en vivo.
- **35 grupos** si se ignora el valor del tamaño de la respuesta (36 si se distingue «desconocido» de un número). 49 casos caen en 10 grupos con más de un caso; el mayor tiene 10.
- 10 casos tienen una respuesta de referencia observada de Gemini; los 64 restantes no tienen ninguna.

**Límites:** 74 entradas no son 74 escenarios independientes ni 74 ataques; ninguno está confirmado como ataque. Los históricos usan el perfil actual del activo, así que no prueban autorización ni mantenimiento en la fecha histórica. Las respuestas de referencia son observaciones, no respuestas correctas ni etiquetas. El conjunto completo (entradas y contextos) es material privado del equipo.

## 5. Lo que no está en esta versión

- **Tablas y gráficas de comparación entre proveedores.** Las campañas de comparación se ejecutaron fuera de esta máquina y sus registros (JSONL) no se han contrastado todavía con el código ni con el cálculo de quien las ejecutó. No se publica ninguna cifra comparativa hasta hacerlo, separando campañas, mediciones y medianas por llamada o por caso.
- **Recolectores web del servidor Windows.** Ver [`wazuh/README.md`](../../wazuh/README.md).
- **Ejecución de la imagen Docker con estos cambios.** La imagen no se reconstruyó para esta versión.
