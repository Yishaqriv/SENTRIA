"""Textos sencillos en español para la interfaz de «Comparación de IA» (la vista principal no muestra huellas)."""

RESULTADO_IMPORTACION = {
    "nueva": "Nueva",
    "caso_nuevo": "Caso nuevo (hay que confirmarlo)",
    "existente": "Ya registrada (no se duplica)",
    "conflicto": "Conflicto: mismo identificador con otros datos",
    "ambigua": "Ambigua: no se puede saber si es la misma ejecución",
    "rechazada": "Rechazada",
    "omitida": "No importada",
    "importada": "Importada",
    "importada_como_separada": "Importada como ejecución separada",
}

FORMATO_ARCHIVO = {
    "sentria_comparacion": "Exportación de otra instancia de SENTRIA",
    "registro_comparacion_v2": "Registro del ejecutor independiente",
    "registro_comparacion_v1": "Registro antiguo o referencia del paquete",
}

EQUIVALENCIA = {
    "equivalente": "Mismas condiciones, verificadas",
    "variante": "Condiciones distintas (no comparar con las demás)",
    "incompatible": "No se pudo enviar el caso",
    "no_verificada": "Condiciones sin verificar",
}

ESTADO_ANALISIS = {"COMPLETED": "Aceptada por SENTRIA", "ANALISIS_FALLIDO": "Rechazada o fallida"}

VEREDICTO = {"REQUIERE_ATENCION": "Requiere atención", "FALSO_POSITIVO": "Falso positivo"}
RIESGO = {"LOW": "bajo", "MEDIUM": "medio", "HIGH": "alto", "CRITICAL": "crítico"}

TOKENS_FUENTE = {"usage_del_proveedor": "Informados por el proveedor", "no_disponible": "No disponibles"}

# Códigos neutrales legibles para los casos registrados desde esta instancia (no son identidad: la identidad es la
# huella del caso, que queda en «Ver detalles»).
PREFIJO_CASO = {
    "windows_natural": "WIN",
    "web_natural": "WEB",
    "web_historico_reproducido": "WEB-HIST",
    "diagnostico_agente": "AGENTE",
    "no_determinada": "CASO",
}

AYUDA_MEDIDAS = [
    ("Latencia del proveedor", "segundos desde que SENTRIA envía el caso hasta que el proveedor responde."),
    ("Duración del análisis", "latencia más la preparación y la validación de SENTRIA; por eso es algo mayor."),
    ("Tokens", "unidades de texto que cuenta el proveedor: «entrada» es lo enviado y «salida» lo generado. El "
               "total es el que informa el proveedor (no una suma nuestra). Cada proveedor cuenta a su manera."),
    ("Mediana", "el valor del medio de las mediciones; los datos que faltan no cuentan como cero."),
    ("No disponible", "el dato no se midió o el proveedor no lo informó."),
]


def parametros_legibles(p):
    """{'temperature': 0.1, ...} -> 'temperature: 0,1 · …' (sin formato de Python); None -> 'no registrados'."""
    if p is None:
        return "no registrados"
    def v(x):
        if x is None:
            return "ninguno"
        if isinstance(x, bool):
            return "sí" if x else "no"
        if isinstance(x, dict):
            return "{" + ", ".join(f"{k}: {v(y)}" for k, y in sorted(x.items())) + "}"
        return str(x)
    return " · ".join(f"{k}: {v(x)}" for k, x in sorted(p.items())) or "ninguno"


def plural(n, singular, plural_):
    return f"{n} {singular if n == 1 else plural_}"


def lista_recuento(recuento):
    """{clave: n} -> [(texto, n)] en español."""
    return [(RESULTADO_IMPORTACION.get(k, k), v) for k, v in sorted((recuento or {}).items())]
