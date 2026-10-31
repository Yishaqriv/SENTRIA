# Changelog

Formato: una sección por versión principal, de la más reciente a la más antigua. Cada versión remite a sus commits. Las fechas son las de los commits (hora de Bogotá), no las del desarrollo: buena parte del trabajo de septiembre se versionó el 5 de octubre.

## Documentación de entrega (31 oct 2026)

Sin cambios funcionales sobre `6d8c6b5`:
- `README.md` actualizado y este `CHANGELOG.md`;
- `.env.example` con las variables `SENTRIA_MODO_REVISION`, `IA_AGENTES_BLOQUEADOS` y `SENTRIA_MIGRAR_AL_ARRANCAR`, y una nota sobre `SENTRIA_ENV_FILE`;
- `docs/producto/`: configuración y manuales de instalación, administración, agentes y usuario, con sus capturas;
- `usuarios/tests.py`: el comentario de la plantilla de Django se sustituye por la ubicación real de las pruebas (solo comentario).

## Versión entregada: `6d8c6b5` (12 oct 2026)

Rama `cierre/3e-windows-lab`, commit `6d8c6b528d67a37b72b24197841669e10b31cc64`. Es la versión con la que se hicieron la validación del laboratorio, la suite de 598 pruebas, la imagen Docker y la prueba controlada FIM-PC01-1.

- `6d8c6b5` (12 oct): pruebas controladas con procedencia verificable y sin reintentos.

Mediciones posteriores sobre este commit (29 oct 2026), sin cambiar el código:
- cobertura combinada de sentencias y ramas del 86 % (87,9 % de las sentencias y 80,0 % de las ramas; sin migraciones ni pruebas);
- hallazgos de ruff (359) y bandit (93), sin revisar uno por uno ni corregir.

## Interfaz y empaquetado (10–11 oct 2026)

- `63aa4c6` (11 oct): interfaz con panel de detalle y estáticos servidos en Docker.
- `b0952fe` (11 oct): imagen Docker sin secretos en el contexto, con usuario sin privilegios y prueba aislada.
- `438acba` (10 oct): el piloto no repite textos idénticos.
- `186467b`, `c10b24a` (10 oct): factores CVSS observados y regla del nivel de Wazuh en la entrada del modelo base.

## Seguridad de la conexión y controles de la respuesta (8–9 oct 2026)

- `f8540b7` (9 oct): huella TLS obligatoria en todas las consultas al indexador.
- `ad4e4ff` (9 oct): sustento simétrico de los factores CVSS para todos los proveedores.
- `fcc1a27`, `157d64f` (8 oct): «Actualizar alertas» y «Reclasificar fallidas» solo por POST con CSRF.
- `fdb4961` (8 oct): tipo de activo `equipo_personal` y horario sin restricción explícito.

## Modelo ajustado y pilotos (8 oct 2026)

- `d6da305`: proveedor experimental `vertex_tuned`, desactivado por defecto.
- `ef87928`: sustento de los impactos, token temporal por archivo y análisis dirigido con `vertex_tuned`.
- `153f616`, `b1ea46a`, `925477d`: ingesta por lotes y piloto acotado con registro persistente, reserva explícita y huella TLS en el piloto.
- `cf20223`: catálogo del proveedor de eventos Microsoft-Windows-Security-SPP.

## Conjunto de ajuste y revisión (7 oct 2026)

- `288e36c`: sellos inmutables de entrada y salida para la revisión y la aprobación.
- `b8efff6`: las vistas GET del conjunto de ajuste no sincronizan ni escriben.
- `ba9d2a8`: modo de revisión consolidada por lote (`REVISOR_UNICO_LOTE`).

## Análisis con IA, colas y laboratorio Windows (5–6 oct 2026)

Primer commit del trabajo hecho en septiembre: análisis con contrato, política de elegibilidad, activos lógicos, ventanas de mantenimiento, revisión humana, métricas y conjunto de ajuste.
- `027c1e9` (5 oct): análisis con IA y conjunto de ajuste supervisado.
- `0b31e35` (5 oct): operación por colas y planificación del conjunto de ajuste.
- `afa9240` (5 oct): laboratorio Windows, huella semántica y evidencia de SCA y de cuentas.
- `d0fc4ed`, `74f2490`, `11cc52f`, `feb219b`, `fe62d69` (6 oct): ajustes de la evidencia de Windows, hora original del evento y alcance de la autorización en las ventanas.

## Aplicación Django (20 may 2026)

- `2e238d8`: backend Django con el dashboard y la gestión de usuarios.
- `23f3456`, `5d43d4b`: `.gitignore` y retirada de `settings.py` del repositorio.

## Prototipo inicial con Flask y Gemini (12–15 mar 2026)

- `b6d959b` a `be674c8` (12–13 mar): creación del repositorio y README inicial.
- `1e04f30` (15 mar): primera versión con Wazuh, Gemini y Flask.
- `8f4bf38` (15 mar): `.gitignore`.

## Fuera de esta versión

- Un cambio de permisos por rol (RBAC) preparado aparte no forma parte de esta versión ni se validó en el laboratorio.
