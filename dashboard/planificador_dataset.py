"""
Planificador (SOLO dry-run) de una futura fábrica de escenarios para acelerar
el dataset supervisado (Sprint 3C/3D).

No genera eventos, no llama a Gemini/Vertex, no escribe JSONL y no expone
datos privados: combina conteos y categorías YA seguras de tres orígenes:

  - legado_recuperado              : alertas legado con `opensearch_id` cuyo
                                      documento de Wazuh todavía existe Y que
                                      la política vigente declara ELEGIBLES
                                      (consulta de solo lectura, agrupada por
                                      familia de regla — nunca por alerta).
                                      "Recuperable" NO significa "apto": las
                                      recuperables no elegibles no cuentan.
  - escenario_ubuntu_controlado    : capacidad ESTIMADA de laboratorio sobre
                                      los activos lógicos Linux ya existentes
                                      (no son alertas reales; es un techo de
                                      planificación y NUNCA entra al pool
                                      utilizable).
  - agente_windows_laptop01_futuro : el próximo origen (agente Windows aún no
                                      conectado). Hoy su disponibilidad es 0 y
                                      queda marcado como pendiente.

Asigna cada "bucket" (familia, origen) COMPLETO a un único conjunto
(entrenamiento/validación/prueba) de forma determinista: ningún bucket se
reparte entre dos conjuntos, así que no puede haber fuga de la misma
familia/escenario entre entrenamiento y prueba, ni duplicados entre conjuntos.
"""
from __future__ import annotations

OBJETIVO_TRAIN = 100
OBJETIVO_VAL = 20
OBJETIVO_TEST_MIN = 20
OBJETIVO_TEST_MAX = 30

ORIGENES = ("legado_recuperado", "escenario_ubuntu_controlado", "agente_windows_laptop01_futuro")
VEREDICTOS = ("FALSO_POSITIVO", "REQUIERE_ATENCION")
VENTANAS = ("dentro_ventana_declarada", "sin_ventana_declarada", "indeterminado")

# Capacidad de laboratorio POR ACTIVO Ubuntu, por combinación
# (veredicto x ventana) — es una estimación de planificación, no alertas reales.
CAPACIDAD_POR_ACTIVO_UBUNTU = 2


def pools_ubuntu_controlado(n_activos_linux, familias):
    """Capacidad ESTIMADA (no real) de escenarios Ubuntu controlados por familia."""
    pools = {}
    if not familias or n_activos_linux <= 0:
        return pools
    por_familia = max(1, (n_activos_linux * CAPACIDAD_POR_ACTIVO_UBUNTU) // max(1, len(familias)))
    for familia in familias:
        pools[(familia, "escenario_ubuntu_controlado")] = por_familia
    return pools


def construir_plan(pools):
    """
    `pools`: dict {(familia, origen): disponibles_int} — conteos/categorías ya
    calculados por el llamador (solo lectura, sin identificadores privados).

    Devuelve un plan de asignación POR BUCKET COMPLETO a train/val/test, sin
    partir ningún bucket entre dos conjuntos (evita fuga entre familia/escenario).
    """
    objetivos = {"train": OBJETIVO_TRAIN, "val": OBJETIVO_VAL, "test": OBJETIVO_TEST_MAX}
    restante = dict(objetivos)
    asignacion = {"train": [], "val": [], "test": []}
    sin_asignar = []

    # Buckets más grandes primero; dentro de un mismo tamaño, orden determinista
    # por clave (nunca aleatorio).
    orden = sorted(((k, v) for k, v in pools.items() if v > 0), key=lambda kv: (-kv[1], kv[0]))

    turno = ["train", "val", "test"]
    i = 0
    intentos_totales = 0
    for (familia, origen), n in orden:
        destino = None
        intentos = 0
        while intentos < 3:
            candidato = turno[i % 3]
            i += 1
            intentos += 1
            if restante[candidato] > 0:
                destino = candidato
                break
        if destino is None:
            sin_asignar.append({"familia": familia, "origen": origen, "n": n})
            continue
        tomado = min(n, restante[destino])
        asignacion[destino].append({"familia": familia, "origen": origen, "n": tomado})
        restante[destino] -= tomado
        if tomado < n:
            sin_asignar.append({"familia": familia, "origen": origen, "n": n - tomado})

    asignado = {k: sum(x["n"] for x in v) for k, v in asignacion.items()}
    return {
        "objetivos": objetivos,
        "asignado": asignado,
        "restante": restante,
        "detalle": asignacion,
        "sin_asignar": sin_asignar,
        "cumple_minimo_test": asignado["test"] >= OBJETIVO_TEST_MIN,
    }


def resumen_por_origen(pools):
    """Totales por origen (para el panel de disponibilidad)."""
    totales = {o: 0 for o in ORIGENES}
    for (familia, origen), n in pools.items():
        totales[origen] = totales.get(origen, 0) + n
    return totales


def pools_utilizables(diag):
    """
    Pool UTILIZABLE: sólo legado recuperable Y elegible (lo único que hoy
    podría completar el flujo real). Las recuperables no elegibles, las que no
    tienen documento y la capacidad estimada de laboratorio NO cuentan.
    """
    por_familia = (diag or {}).get("por_familia_elegible") or {}
    return {(familia, "legado_recuperado"): n for familia, n in por_familia.items() if n > 0}


def resumen_real(diag, n_aprobados):
    """Cifras reales (no proyectadas) y déficit respecto al objetivo."""
    diag = diag or {}
    objetivo_min = OBJETIVO_TRAIN + OBJETIVO_VAL + OBJETIVO_TEST_MIN
    objetivo_max = OBJETIVO_TRAIN + OBJETIVO_VAL + OBJETIVO_TEST_MAX
    return {
        "recuperables": diag.get("recuperables", 0),
        "elegibles": diag.get("recuperable_y_elegible", 0),
        "no_elegibles": diag.get("no_elegible_total", 0),
        "sin_documento_recuperable": diag.get("sin_documento_recuperable", 0),
        "aprobados": n_aprobados,
        "objetivo_min": objetivo_min,
        "objetivo_max": objetivo_max,
        "deficit_min": max(0, objetivo_min - n_aprobados),
        "deficit_max": max(0, objetivo_max - n_aprobados),
    }
