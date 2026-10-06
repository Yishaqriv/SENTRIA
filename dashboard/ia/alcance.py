"""
Alcance de la autorización de mantenimiento (entrada 1.3).

Una ventana declara QUÉ tipo de operación autoriza (categoría cerrada). La entrada recibe el alcance de la ventana
que cubre el evento (`maintenance_scope`) y si la operación OBSERVADA en la evidencia corresponde a ese alcance
(`maintenance_scope_match`). La correspondencia es conservadora:
- una operación solo se tipifica con evidencia estructurada o con una regla de Wazuh inequívoca; si no, `no_determinado`;
- un alcance nunca cubre otro tipo de operación (p. ej. `archivos_laboratorio` no cubre cuentas, privilegios,
  auditoría ni dispositivos), y un cambio de privilegios demostrado exige `gestion_privilegios`;
- `coincide` dice que el TIPO de operación estaba autorizado; no afirma ausencia de privilegios ni de riesgo.
Nunca llegan al prompt tickets, nombres, descripciones ni identificadores: solo estas categorías.
"""
from __future__ import annotations

ALCANCES = (
    ("gestion_cuentas_locales", "Gestión de cuentas y grupos locales"),
    ("gestion_privilegios", "Cambios de privilegios (grupos privilegiados)"),
    ("instalacion_actualizacion_software", "Instalación o actualización de software"),
    ("configuracion_servicios", "Configuración de servicios"),
    ("politica_auditoria_seguridad", "Política de auditoría de seguridad"),
    ("archivos_laboratorio", "Archivos del directorio aislado de laboratorio"),
    ("conexion_dispositivos", "Conexión de dispositivos externos"),
    ("otro_no_tipificado", "Otro (no tipificado)"),
)
NO_DECLARADO = "no_declarado"          # ventanas anteriores a la 1.3: nunca se completan a posteriori
ALCANCES_VALIDOS = tuple(a for a, _ in ALCANCES)
ALCANCE_CHOICES = ALCANCES + ((NO_DECLARADO, "No declarado (ventana anterior al alcance)"),)
COINCIDENCIAS = ("coincide", "no_coincide", "no_determinado", "no_aplica")

# Reglas cuyo tipo de operación es inequívoco aunque la entrada no traiga evidencia estructurada.
_OPERACION_POR_REGLA = {
    "60112": "politica_auditoria_seguridad",   # 4719: cambio de la política de auditoría del sistema
    "60227": "conexion_dispositivos",          # 6416: dispositivo externo reconocido
}
_CON_PRIVILEGIOS = {"elevacion", "reduccion", "privilegios_root"}
_SIN_CAMBIO_PRIVILEGIO_DEMOSTRADO = {"no_indicado", "sin_cambio_privilegiado"}


def operacion_observada(evidencia, rule_id=None):
    """Tipo de operación según la evidencia categórica de la entrada (o `no_determinado`)."""
    ev = evidencia or {}
    if ev.get("cuenta_operacion"):
        priv = ev.get("cuenta_cambio_privilegios")
        if priv in _CON_PRIVILEGIOS:
            return "gestion_privilegios"
        if priv in _SIN_CAMBIO_PRIVILEGIO_DEMOSTRADO:
            return "gestion_cuentas_locales"
        return "no_determinado"                   # p. ej. control de cuenta modificado: no se tipifica
    if ev.get("fim_event_type") not in (None, "no_aplica", "no_determinado"):
        return "archivos_laboratorio" if ev.get("path_category") == "laboratorio_controlado" else "no_determinado"
    return _OPERACION_POR_REGLA.get(str(rule_id or ""), "no_determinado")


def alcance_en_entrada(estado_ventana, alcance):
    """Valor de `maintenance_scope`: el alcance de la ventana que cubre el evento."""
    if estado_ventana == "sin_ventana_declarada":
        return "no_aplica"
    if estado_ventana != "dentro_ventana_declarada":
        return "no_determinado"
    return alcance if alcance in ALCANCES_VALIDOS else NO_DECLARADO


def coincidencia(estado_ventana, alcance, observada):
    """Valor de `maintenance_scope_match`."""
    if estado_ventana == "sin_ventana_declarada":
        return "no_aplica"
    if (estado_ventana != "dentro_ventana_declarada" or alcance not in ALCANCES_VALIDOS
            or alcance == "otro_no_tipificado" or observada not in ALCANCES_VALIDOS):
        return "no_determinado"
    return "coincide" if alcance == observada else "no_coincide"
