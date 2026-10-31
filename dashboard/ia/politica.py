"""
Política de elegibilidad (Sprint 2B).

`evaluar_elegibilidad()` es una función PURA y configurable que decide si una
alerta debe enviarse a la IA. No toca la base de datos ni el proveedor.

Cuando una alerta NO es elegible, la ingesta la guarda igualmente con
estado_analisis='OMITIDO_POLITICA' y un motivo estructurado; sigue visible,
no es ANALISIS_FALLIDO, no es FALSO_POSITIVO y no se envía al proveedor.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace

# Motivos (deben coincidir con Alert.MOTIVO_OMISION_CHOICES)
SIN_CONTEXTO_ACTIVO = "SIN_CONTEXTO_ACTIVO"
NIVEL_NO_ELEGIBLE = "NIVEL_NO_ELEGIBLE"
RUIDO_OPERATIVO = "RUIDO_OPERATIVO"
REGLA_EXCLUIDA = "REGLA_EXCLUIDA"


@dataclass(frozen=True)
class PoliticaElegibilidad:
    #: nivel Wazuh mínimo para clasificar con IA
    nivel_minimo: int = 7
    #: si es True, una alerta sin ActivoLogico asociado se omite (SIN_CONTEXTO_ACTIVO)
    exige_contexto_activo: bool = True
    #: grupos que, presente CUALQUIERA, excluyen la alerta (REGLA_EXCLUIDA)
    grupos_excluidos: tuple = ()
    #: rule.id que excluyen la alerta (REGLA_EXCLUIDA)
    rule_ids_excluidos: tuple = ()
    #: combinaciones de grupos que, presentes TODOS a la vez, marcan ruido
    #: operativo confirmado (RUIDO_OPERATIVO). Por defecto: solo dpkg+config_changed.
    combinaciones_ruido: tuple = (("dpkg", "config_changed"),)

    def con_overrides(self, overrides: dict | None):
        if not overrides:
            return self
        campos = {k: v for k, v in overrides.items() if k in self.__dataclass_fields__}
        # normaliza listas -> tuplas
        for k in ("grupos_excluidos", "rule_ids_excluidos"):
            if k in campos and campos[k] is not None:
                campos[k] = tuple(campos[k])
        if "combinaciones_ruido" in campos and campos["combinaciones_ruido"] is not None:
            campos["combinaciones_ruido"] = tuple(tuple(c) for c in campos["combinaciones_ruido"])
        return replace(self, **campos)


#: política inicial. Excluye SOLO el ruido confirmado dpkg+config_changed
#: (no todo config_changed, no todo apparmor).
POLITICA_POR_DEFECTO = PoliticaElegibilidad()


def cargar_politica():
    """Devuelve la política por defecto, aplicando settings.IA_POLITICA si existe."""
    try:
        from django.conf import settings
        overrides = getattr(settings, "IA_POLITICA", None)
    except Exception:
        overrides = None
    return POLITICA_POR_DEFECTO.con_overrides(overrides)


@dataclass
class ResultadoPolitica:
    elegible: bool
    estado_analisis: str          # "PENDING" si elegible; "OMITIDO_POLITICA" si no
    motivo_omision: str | None    # uno de los motivos; None si elegible


def _nivel_int(valor):
    try:
        return int(float(valor))
    except (TypeError, ValueError):
        return None


def _grupos(alert):
    g = alert.get("groups")
    if isinstance(g, (list, tuple)):
        return {str(x).strip() for x in g if str(x).strip()}
    if not g:
        return set()
    return {x.strip() for x in str(g).replace(";", ",").split(",") if x.strip()}


def evaluar_elegibilidad(alert, tiene_activo, politica: PoliticaElegibilidad | None = None):
    """
    alert: dict con al menos 'level'/'groups'/'rule_id' (los que haya).
    tiene_activo: bool — si la alerta tiene un ActivoLogico asociado y activo.
    -> ResultadoPolitica
    """
    pol = politica or POLITICA_POR_DEFECTO

    if pol.exige_contexto_activo and not tiene_activo:
        return ResultadoPolitica(False, "OMITIDO_POLITICA", SIN_CONTEXTO_ACTIVO)

    rule_id = str(alert.get("rule_id")) if alert.get("rule_id") not in (None, "") else None
    if rule_id and rule_id in {str(r) for r in pol.rule_ids_excluidos}:
        return ResultadoPolitica(False, "OMITIDO_POLITICA", REGLA_EXCLUIDA)

    grupos = _grupos(alert)
    if grupos & set(pol.grupos_excluidos):
        return ResultadoPolitica(False, "OMITIDO_POLITICA", REGLA_EXCLUIDA)

    for combo in pol.combinaciones_ruido:
        if set(combo).issubset(grupos):
            return ResultadoPolitica(False, "OMITIDO_POLITICA", RUIDO_OPERATIVO)

    nivel = _nivel_int(alert.get("level", alert.get("severidad")))
    if nivel is None or nivel < pol.nivel_minimo:
        return ResultadoPolitica(False, "OMITIDO_POLITICA", NIVEL_NO_ELEGIBLE)

    return ResultadoPolitica(True, "PENDING", None)
