# Reglas de Wazuh para los accesos web

[`reglas/sentria_web_rules.xml`](reglas/sentria_web_rules.xml) clasifica los eventos de acceso web que un recolector externo escribe como JSON en un archivo que lee el agente de Wazuh. Es idéntico, por huella SHA-256 (`7b5f2b477fb899f56a1845f4ff9fe612d107538aa35e84db81aebd0b6faf212c`), al archivo instalado en el servidor de Wazuh del laboratorio el 12 nov 2026 (comprobado el 16 nov 2026).

| Regla | Nivel | Condición |
|---|---|---|
| 119600 | 0 | JSON con `sentria_source = web_access` y `sentria_web.kind = http_access` |
| 119601 | 3 | Además, `sentria_web.http_status` es un código HTTP de tres cifras |
| 119602 | 5 | Respuesta 401 o 403 |
| 119603 | 5 | Respuesta 5xx |

Un código HTTP por sí solo no confirma un ataque. Con la política de esta versión (nivel mínimo 5), las reglas 119602 y 119603 son elegibles para el análisis si el agente tiene un activo asociado.

**Instalación** (en el servidor de Wazuh, con permisos de administración): copiar el archivo a `/var/ossec/etc/rules/`, validar con `wazuh-logtest` y reiniciar el manager. No se incluye un instalador: la instalación del laboratorio se hizo con un script privado.

## Formato que espera SENTRIA (esquema 1)

`sentria_backend._web_crudo` solo acepta estos campos y descarta cualquier otro, aunque el documento lo traiga:

| Campo (`data.…`) | Valores admitidos |
|---|---|
| `sentria_source` | `web_access` |
| `sentria_web.schema_version` | `1` |
| `sentria_web.kind` | `http_access` |
| `sentria_web.service` | `domjudge` o `tomcat`; cualquier otro descarta el evento |
| `sentria_web.http_method` | Método HTTP estándar; otro valor se guarda como `OTHER` |
| `sentria_web.http_status` | `100`–`599` |
| `sentria_web.response_bytes` | Entero o ausente |
| `sentria_web.route_class` | `api`, `authentication_route`, `static_asset`, `root`, `other`; otro valor se guarda como `no_determinado` |
| `sentria_web.has_query` | Booleano o las cadenas exactas `true`/`false` |
| `sentria_web.source_time_utc` | Fecha ISO 8601 con zona |
| `sentria_web.mode` | `live` (evento observado ahora) o `historical_replay` (registro histórico reproducido a propósito); cualquier otro valor deja la procedencia como `no_determinado` |

SENTRIA nunca reexporta URL, parámetros de consulta, dirección del cliente, usuario, cabeceras ni identificadores del evento. La ingesta continua solo analiza de forma automática los accesos con `mode = live`.

## Lo que no está en el repositorio

Los recolectores que generan estos eventos en el servidor Windows (lectura pasiva de los registros de nginx y Tomcat dentro de contenedores Docker, con seudónimos del cliente) y los muestreos históricos usados para el conjunto de comparación tienen todavía valores propios de la instalación: nombres de contenedor, rutas de registros, destino del manager y versión del agente. No se publican hasta separarlos en parámetros y probarlos en un entorno aislado.
