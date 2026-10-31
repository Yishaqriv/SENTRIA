# Manual de agentes de Wazuh para SENTRIA


Explica cómo se incorporó un equipo al laboratorio, de modo que sus alertas lleguen a Wazuh y SENTRIA pueda analizarlas. Para escribirlo no se instaló nada ni se tocó la red. Las marcas:
- **[C]**: comprobado en el laboratorio;
- **[D]**: documentado, sin ejecución registrada;
- **[F]**: falta un dato.

Las evidencias de las marcas [C] son registros del laboratorio que no se publican en el repositorio.

Las direcciones, los nombres de equipo y las huellas reales no se incluyen.

## 1. Agentes del laboratorio

| Agente | Equipo | Sistema | Activo en SENTRIA | Cómo se incorporó | Estado |
|---|---|---|---|---|---|
| 000 | Máquina virtual (el propio servidor de Wazuh) | Ubuntu 24.04 | SRV-01 | Agente local del servidor; no se instala aparte | [C] |
| 001 | Portátil (anfitrión de VirtualBox) | Windows | LAPTOP-01 | Conecta a la VM por el reenvío de puertos del NAT de VirtualBox | [C] conectado. **[F] no hay registro de su instalación** (anterior a septiembre de 2026) |
| 002 | Computador de escritorio | Windows, con Docker Desktop | PC-01 | Instalado el 12 oct 2026 con el procedimiento de la sección 3 | [C] (registros del laboratorio, 12 oct 2026) |

Versión: el servidor, el indexador y el panel son la 4.14.5-1, y el agente 002 es la 4.14.5-1. **El agente no debe ser más nuevo que el servidor.** Ya existía una 4.14.6 y no se usó. **[C]**

## 2. Red

| Puerto | Uso | En el laboratorio |
|---|---|---|
| 1514/tcp | Eventos del agente al servidor | Reenviado desde el portátil a la VM. Para el PC, regla de firewall limitada a la dirección del PC **[C]** |
| 1515/tcp | Inscripción del agente | Abierto solo durante la inscripción del 002 y cerrado después **[C]** |
| 9200/tcp | Indexador | Solo local en la VM; SENTRIA en Docker llega por un túnel SSH restringido **[C]** |

La VM usaba el NAT de VirtualBox, así que los demás equipos solo la alcanzaban a través de reglas de reenvío en el portátil. Los scripts privados del laboratorio que abren y cierran ese acceso comprueban el estado antes de cambiarlo y deshacen lo propio si algo falla. **[C]**

**Riesgo conocido:** el servidor acepta inscripciones sin contraseña (`use_password no`). Con 1515 abierto a la red, cualquier equipo podría inscribirse. Por eso se abrió solo durante la inscripción. Para un uso fuera del laboratorio se recomienda una contraseña de inscripción, que es un cambio en el servidor de Wazuh. **[D]**

## 3. Instalar un agente Windows

1. **Comprobación previa (solo lectura):** equipo, red, conectividad a 1514 y 1515 y que no haya otro agente. **[C]** (scripts privados de comprobación)
2. **Descargar el instalador oficial** de la misma versión que el servidor, `wazuh-agent-4.14.5-1.msi`, de `packages.wazuh.com`, y comprobar su huella con la publicada. **[C]** el SHA-512 coincidió con el publicado.
3. **Instalar** en PowerShell como administrador:

   `msiexec.exe /i wazuh-agent-4.14.5-1.msi /q WAZUH_MANAGER="<SERVIDOR>" WAZUH_REGISTRATION_SERVER="<SERVIDOR>" WAZUH_AGENT_NAME="<NOMBRE_NUEVO>"`

   y después `NET START WazuhSvc`. **[C]** (12 oct 2026)
   - **El nombre del agente tiene que ser nuevo.** Con la política por defecto, un nombre repetido puede sustituir a un agente que lleve más de una hora desconectado.
   - No usar el nombre real del equipo si contiene datos personales.
4. **Cerrar la inscripción:** retirar el reenvío y la regla de 1515 y conservar 1514. **[C]** (script privado del laboratorio)
5. **Verificar:** en el panel de Wazuh, el agente nuevo aparece como activo y los anteriores siguen igual. En el servidor, `sudo /var/ossec/bin/agent_control -l` (lectura). **[C]** 001 y 002 activos.

## 4. Asociar el agente en SENTRIA

Sin un activo asociado, las alertas del agente no llegan al modelo: la acción web las guarda como omitidas y el comando solo las cuenta.
1. Crear el activo lógico con el contexto real del equipo, que tiene que describir el equipo, no inventarse:
   - tipo;
   - criticidad;
   - sistema y función;
   - uso;
   - horario y zona horaria.

   **[C]** PC-01, «equipo personal», criticidad media, sin restricción de horario, America/Bogota.
2. `python manage.py asignar_agente_activo --agent-id <ID> --activo <IDENTIFICADOR> --etiqueta <ETIQUETA>` **[C]** (002 → PC-01).

Más detalle en el [manual de administración](MANUAL_ADMINISTRACION.md), sección 3.

## 5. Integridad de archivos (FIM) en un agente Windows

Para las pruebas controladas se vigiló una carpeta aislada de laboratorio en el PC. **[C]** (FIM-PC01-1, 12 oct 2026)
- Los agentes 001 y 002 solo están en el grupo `default`, cuyo `agent.conf` está vacío. Por eso la configuración FIM del 002 es la local de su `ossec.conf`. No se cambió `default`, para no afectar al 001.
- Cambio aplicado:
  1. copia del `ossec.conf`;
  2. añadir `<directories realtime="yes" check_all="yes">C:\SENTRIA-LAB</directories>`;
  3. validar el XML;
  4. reiniciar el agente;
  5. comprobar la línea base.
- Reglas que se disparan: 550 («Integrity checksum changed», nivel 7), 553 («File deleted», nivel 7) y 554 («File added», nivel 5). Con la política de SENTRIA, la 554 no llega al modelo, porque su nivel es menor que 7.
- Vuelta atrás: restaurar la copia del `ossec.conf` y reiniciar el agente.

Fuente: el plan y los registros privados de la prueba FIM-PC01-1. Los eventos de la prueba se generaron con [`generar_eventos_fim.ps1`](../../scripts/laboratorio_windows/generar_eventos_fim.ps1).

## 6. Agentes Linux

En el laboratorio no se instaló ningún agente Linux aparte: el 000 es el agente local del servidor. **[D]** para la instalación de un agente Linux: seguir la documentación oficial de Wazuh para la misma versión del servidor. [F] sin procedimiento propio ni prueba.

## 7. Retirar un agente

- Quitar la asociación en SENTRIA: `asignar_agente_activo --desactivar --agent-id <ID>`. El historial se conserva. **[D]**
- Retirar el acceso de red que se abrió para el equipo: script privado del laboratorio. **[D]** (preparado, no ejecutado).
- Desinstalar el agente y retirarlo del servidor (`manage_agents`): documentación de Wazuh. **[D]**

## 8. Datos que faltan

- Cómo y cuándo se instaló el agente 001 y con qué versión inicial.
- La configuración local del agente del portátil (FIM y registros que envía), que no se registró.
