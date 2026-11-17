# Ejecutor independiente de la comparación de proveedores

Herramientas para enviar **la misma entrada** que SENTRIA construye a otro proveedor de modelos, una vez por caso y repetición, y registrar el resultado en un formato que el apartado «Comparación de IA» de SENTRIA puede importar (`registro_comparacion_v2`). Son herramientas del experimento: **no forman parte de la operación de SENTRIA** ni se instalan en la imagen Docker.

## Proveedor de SENTRIA frente a adaptador del experimento

- **Proveedor operativo de SENTRIA:** el que elige `IA_PROVIDER` (`gemini_developer` por defecto o `vertex_tuned`, experimental), en [`dashboard/ia/proveedores.py`](../../dashboard/ia/proveedores.py). Es el único que usan la aplicación web, `ingestar_alertas` e `ingesta_continua`.
- **Adaptador del experimento:** una clase propia que se pasa a `ejecutar_caso.py` con `--adaptador RUTA.py:Clase` y que **solo** existe dentro del ejecutor. Partir de [`herramientas/plantilla_adaptador.py`](herramientas/plantilla_adaptador.py).

Cambiar una clave de API o un nombre de modelo no convierte a SENTRIA en otro proveedor: cada proveedor necesita su propio código, con su forma de pedir JSON, sus parámetros y su manera de informar tokens y modelo. El ejecutor registra por separado la huella del código de SENTRIA y la del adaptador realmente cargados, y declara si la ejecución es equivalente al protocolo común (`equivalente`, `variante`, `incompatible` o `no_verificada`).

## Archivos

| Archivo | Qué hace |
|---|---|
| `herramientas/ejecutar_caso.py` | Un caso con un proveedor. `--ensayo` (por defecto): comprueba huellas, reconstrucción exacta de la entrada y representabilidad, **sin red ni llamadas**. `--confirmar`: **una llamada** con las credenciales de quien lo ejecuta, sin reintentos; escribe en el registro indicado |
| `herramientas/ejecutar_conjunto.py` | Todos los casos de un conjunto. `--confirmar` exige `--max-llamadas` mayor o igual que casos × repeticiones y no repite lo ya registrado |
| `herramientas/exportar_resultados.py` | Tabla HTML y CSV local de un registro, sin red ni base de datos |
| `herramientas/plantilla_adaptador.py` | Plantilla de adaptador para un proveedor que SENTRIA no implementa |
| `herramientas/test_ejecutor.py`, `test_exportacion.py`, `probar_ejecutor_sin_red.py` | Pruebas sin red, con proveedores falsos |
| `fixtures_sinteticos/` | Dos casos **sintéticos** (web y Windows) y el esquema de salida común, generados por `generar_casos_sinteticos.py` |

El docstring de `dashboard/comparacion/intercambio.py` nombra la ruta que tenían estas herramientas en el paquete del equipo (`comparacion/herramientas/`); en el repositorio están aquí.

## Aislamiento

`ejecutar_caso.py` no carga la configuración de SENTRIA ni ningún `.env`, no abre la base de datos ni el indexador y vacía el entorno salvo las variables básicas y las credenciales del proveedor elegido (más las que se permitan con `--permitir-variable`, que no admite `DB_*`, `DJANGO_*`, `SENTRIA_*` ni `WAZUH_*`). Abrir un `.env`, importar clientes de base de datos o abrir la red fuera de la llamada confirmada provoca un error. Con `--confirmar` se niega si encuentra `SENTRIA_ENV_FILE` en el entorno.

## Uso con los casos sintéticos (sin llamadas)

```bash
cd experimentos/comparacion
python herramientas/ejecutar_caso.py --codigo ../.. --caso fixtures_sinteticos/casos/SINT-WEB-01 \
       --proveedor gemini_developer --ensayo
cd herramientas && python -m unittest -v test_ejecutor test_exportacion
```

Los casos sintéticos no provienen de ningún servidor: su contexto está escrito a mano en `generar_casos_sinteticos.py` y su `respuesta_referencia_gemini.json` es un JSON sintético que cumple el contrato (el nombre del archivo es el que espera el ejecutor; no es una respuesta de Gemini).

## Conjunto real y protocolo

El conjunto común usado en el laboratorio (`SENTRIA-PILOTO-COMP v3`, 74 entradas) es material privado del equipo; su composición agregada está en [`docs/validacion/`](../../docs/validacion/README.md). Antes de ejecutar contra un proveedor real hay que acordar proveedores, repeticiones, lugar, orden y presupuesto de llamadas: cada repetición completa son 74 llamadas por proveedor.
