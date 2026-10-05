"""
Ingesta CONTROLADA de alertas reales (Sprint 2E).

Una prueba acotada del flujo automático:
  Wazuh (solo lectura, un único agente) → política (nivel + ruido) →
  Gemini (gemini_developer, con TOPE ABSOLUTO de llamadas) → veredicto automático.

Uso:
  python manage.py ingestar_alertas --agent-id 000 --limit 3 --dry-run
  python manage.py ingestar_alertas --agent-id 000 --limit 3 --confirmar

Reglas duras:
  - `--limit` se recorta a LIMITE_ABSOLUTO (3). Nunca más de 3 análisis / 3
    llamadas reales a Gemini.
  - Un único `--agent-id`, que debe tener una asignación activa a un
    `ActivoLogico`. Ningún otro agente se procesa.
  - No se recorren las alertas históricas: sólo las que devuelve la lectura de
    Wazuh para ese agente.
  - `--dry-run` no llama a Gemini ni escribe en MySQL (sólo lee para deduplicar).
  - Salida = conteos y categorías sanitizadas. Nunca prompts, respuestas crudas
    ni contenido sensible.
"""
import os
import re

from django.core.management.base import BaseCommand, CommandError

from dashboard.ia import proveedores
from dashboard.ia.ingesta import ingestar_alerta
from dashboard.ia.politica import cargar_politica, evaluar_elegibilidad
from dashboard.ia.resolver import resolver_activo_por_agente
from dashboard.models import Alert

import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../')))
from sentria_backend import get_latest_alerts, get_alert_by_id

MAX_ANALISIS_ABS = 3        # tope absoluto de llamadas a Gemini por ejecución
SCAN_LIMIT_DEFAULT = 100
SCAN_LIMIT_MAX = 500

# IPv4 privadas / loopback / link-local: si aparecen en el prompt, la
# anonimización (RNF-03) falló -> se aborta esa llamada como fallo, nunca
# como veredicto.
_IP_PRIVADA = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|169\.254\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"
)


class _ProveedorContado(proveedores.ProveedorIA):
    """
    Envuelve el proveedor real. Garantías:
      - HARD-CAP: nunca deja pasar más de `tope` llamadas de generación.
      - Comprobación de anonimización: si el prompt lleva una IP privada o el
        `agent.id` como token, aborta esa llamada como fallo (jamás veredicto).
      - Sin reintentos: una llamada = un intento.
    """
    def __init__(self, inner, *, tope, agent_id):
        self._inner = inner
        self._tope = tope
        self._agent_id = str(agent_id)
        self.nombre = inner.nombre
        self.llamadas = 0

    def _prompt_sospechoso(self, prompt):
        p = str(prompt)
        if _IP_PRIVADA.search(p):
            return "IP privada en el prompt"
        if self._agent_id and re.search(
                rf"\bagent[^\n]{{0,12}}\b{re.escape(self._agent_id)}\b", p, re.I):
            return "agent.id en el prompt"
        return None

    def analizar(self, prompt):
        if self.llamadas >= self._tope:
            return proveedores.RespuestaProveedor(
                ok=False, texto="", modelo="", error="tope de llamadas de la prueba alcanzado")
        motivo = self._prompt_sospechoso(prompt)
        if motivo:
            return proveedores.RespuestaProveedor(
                ok=False, texto="", modelo="", error=f"anonimización: {motivo}")
        self.llamadas += 1
        return self._inner.analizar(prompt)


def procesar_ingesta_controlada(agent_id, *, scan_limit, max_analisis, dry, conf,
                                get_alertas=get_latest_alerts,
                                obtener_proveedor=proveedores.obtener_proveedor,
                                log=lambda _s: None):
    """
    Núcleo de la ingesta controlada. Devuelve un dict de conteos/categorías
    sanitizadas. `log` recibe cadenas ya sanitizadas (nunca prompts ni
    respuestas). Lanza CommandError ante condiciones que impiden continuar.

    - `scan_limit`   = cuántas candidatas se LEEN de Wazuh (solo lectura).
                       No es un número de llamadas. Recortado a [1, SCAN_LIMIT_MAX].
    - `max_analisis` = tope ABSOLUTO de llamadas a Gemini. Recortado a
                       [0, MAX_ANALISIS_ABS]. Se seleccionan las PRIMERAS N
                       alertas realmente elegibles.
    """
    agent_id = str(agent_id).strip()
    scan_limit = max(1, min(int(scan_limit), SCAN_LIMIT_MAX))
    max_analisis = max(0, min(int(max_analisis), MAX_ANALISIS_ABS))

    activo = resolver_activo_por_agente(agent_id)
    if activo is None:
        raise CommandError(
            f"El agente {agent_id} no tiene una asignación activa a un ActivoLogico "
            f"(o está en IA_AGENTES_BLOQUEADOS). Nada que hacer.")
    log(f"Agente {agent_id} -> activo {activo.identificador}. "
        f"scan-limit {scan_limit}, max-análisis {max_analisis}.")

    politica = cargar_politica()

    try:
        crudas = get_alertas(size=scan_limit, agent_id=agent_id, min_level=politica.nivel_minimo)
    except Exception as exc:
        raise CommandError(f"No se pudo consultar el indexador Wazuh: {type(exc).__name__}")

    def _resolver(alert):
        if str(alert.get('agent_id') or '').strip() != agent_id:
            return None
        return resolver_activo_por_agente(agent_id)

    prov = None
    if conf:
        key = "PRESENTE" if os.environ.get('GEMINI_API_KEY') else "AUSENTE"
        mdl = "PRESENTE" if os.environ.get('GEMINI_MODEL') else "AUSENTE"
        log(f"GEMINI_API_KEY: {key}   GEMINI_MODEL: {mdl}   proveedor: gemini_developer")
        if key != "PRESENTE":
            raise CommandError("GEMINI_API_KEY ausente: no se ejecuta --confirmar.")
        inner = obtener_proveedor('gemini_developer')
        if inner is None:
            raise CommandError("Proveedor gemini_developer no disponible.")
        prov = _ProveedorContado(inner, tope=max_analisis, agent_id=agent_id)

    c = dict(candidatas=0, duplicadas_completed=0, omitidas_ruido=0,
             omitidas_nivel=0, omitidas_sin_activo=0, omitidas_regla=0,
             elegibles=0, elegibles_seleccionadas=0, elegibles_no_seleccionadas=0,
             procedencia_completada=0, completed=0, analisis_fallido=0,
             falso_positivo=0, requiere_atencion=0)

    for raw in crudas:
        c['candidatas'] += 1
        osid = raw.get('opensearch_id')
        existente = Alert.objects.filter(opensearch_id=osid).first() if osid else None

        if existente is not None and existente.estado_analisis == 'COMPLETED':
            c['duplicadas_completed'] += 1
            continue

        tiene_activo = _resolver(raw) is not None
        decision = evaluar_elegibilidad(raw, tiene_activo, politica)
        if not decision.elegible:
            m = decision.motivo_omision
            if m == 'RUIDO_OPERATIVO':       c['omitidas_ruido'] += 1
            elif m == 'NIVEL_NO_ELEGIBLE':   c['omitidas_nivel'] += 1
            elif m == 'SIN_CONTEXTO_ACTIVO': c['omitidas_sin_activo'] += 1
            else:                            c['omitidas_regla'] += 1
            # Esta es una prueba ACOTADA: su objetivo es producir los primeros
            # veredictos, no un volcado masivo. Las alertas omitidas por política
            # sólo se CUENTAN, no se persisten (para eso está `update_alerts`/
            # `ingestar_lote`). Así el comando tiene huella mínima en MySQL.
            continue

        c['elegibles'] += 1

        # Sólo se seleccionan (y analizan) las PRIMERAS `max_analisis` elegibles.
        if c['elegibles_seleccionadas'] >= max_analisis:
            c['elegibles_no_seleccionadas'] += 1
            continue
        c['elegibles_seleccionadas'] += 1

        if dry:
            continue  # sin escritura, sin proveedor

        antes = (existente.wazuh_agent_id, existente.wazuh_rule_id,
                 existente.wazuh_rule_groups) if existente else None
        obj, _accion = ingestar_alerta(raw, resolver=_resolver, politica=politica, proveedor=prov)
        obj.refresh_from_db()
        if existente is not None:
            despues = (obj.wazuh_agent_id, obj.wazuh_rule_id, obj.wazuh_rule_groups)
            if antes != despues:
                c['procedencia_completada'] += 1
        if obj.estado_analisis == 'COMPLETED':
            c['completed'] += 1
            if obj.veredicto_ia == 'FALSO_POSITIVO':      c['falso_positivo'] += 1
            elif obj.veredicto_ia == 'REQUIERE_ATENCION': c['requiere_atencion'] += 1
        else:
            c['analisis_fallido'] += 1

    c['llamadas_reales'] = prov.llamadas if prov is not None else 0
    c['scan_limit'] = scan_limit
    c['max_analisis'] = max_analisis
    c['modo'] = 'dry-run' if dry else 'confirmar'
    return c


def _nivel_int_local(valor):
    try:
        return int(float(str(valor).strip()))
    except (TypeError, ValueError):
        return None


def procesar_una_por_opensearch_id(opensearch_id, agent_id, *,
                                   get_uno=get_alert_by_id,
                                   obtener_proveedor=proveedores.obtener_proveedor,
                                   log=lambda _s: None):
    """
    Análisis DIRIGIDO por el `_id` exacto de OpenSearch (checkpoint 2G.3).

    Sólo `--confirmar`. Garantías duras:
      - exige `agent_id`, que debe ser EXACTAMENTE el agente dueño del documento;
      - TOPE ABSOLUTO de 1 llamada real a Gemini (`_ProveedorContado` tope=1);
      - rechaza cualquier documento cuyo `_id` no sea el solicitado;
      - valida, ANTES de tocar a Gemini: asignación de activo, deduplicación
        (no reingiere un `opensearch_id` ya presente), política y nivel mínimo.
        Si algo no cuadra -> NO llama a Gemini y aborta con `CommandError`.
    Devuelve un dict de conteos/categorías sanitizadas (nunca prompt ni respuesta).
    """
    opensearch_id = str(opensearch_id or "").strip()
    agent_id = str(agent_id or "").strip()
    if not opensearch_id:
        raise CommandError("--opensearch-id vacío.")
    if not agent_id:
        raise CommandError("--agent-id es obligatorio junto con --opensearch-id.")

    activo = resolver_activo_por_agente(agent_id)
    if activo is None:
        raise CommandError(
            f"El agente {agent_id} no tiene asignación activa a un ActivoLogico "
            f"(o está bloqueado). No se llama a Gemini.")

    existente = Alert.objects.filter(opensearch_id=opensearch_id).first()
    if existente is not None:
        raise CommandError(
            f"opensearch_id ya presente en MySQL (estado_analisis="
            f"{existente.estado_analisis}). Este comando no reingiere; abortado.")

    try:
        raw = get_uno(opensearch_id)
    except Exception as exc:
        raise CommandError(f"No se pudo consultar el indexador Wazuh: {type(exc).__name__}")
    if raw is None:
        raise CommandError("El documento solicitado no existe en Wazuh. Abortado.")

    # Rechazo de CUALQUIER documento que no sea EXACTAMENTE el pedido.
    if str(raw.get("opensearch_id") or "") != opensearch_id:
        raise CommandError(
            "El indexador devolvió un documento con `_id` distinto al solicitado. Abortado.")
    if str(raw.get("agent_id") or "").strip() != agent_id:
        raise CommandError(
            f"El documento pertenece a otro agente (su agent.id != {agent_id}). Abortado.")

    politica = cargar_politica()

    nivel = _nivel_int_local(raw.get("level"))
    if nivel is None or nivel < politica.nivel_minimo:
        raise CommandError(
            f"Nivel {nivel} por debajo del mínimo {politica.nivel_minimo}: "
            f"no elegible, no se llama a Gemini.")

    decision = evaluar_elegibilidad(raw, tiene_activo=True, politica=politica)
    if not decision.elegible:
        raise CommandError(
            f"Política: documento NO elegible ({decision.motivo_omision}). "
            f"No se llama a Gemini.")

    key = "PRESENTE" if os.environ.get('GEMINI_API_KEY') else "AUSENTE"
    log(f"Agente {agent_id} -> activo {activo.identificador}. "
        f"opensearch_id validado. GEMINI_API_KEY: {key}. proveedor: gemini_developer. tope: 1 llamada.")
    if key != "PRESENTE":
        raise CommandError("GEMINI_API_KEY ausente: no se ejecuta.")
    inner = obtener_proveedor('gemini_developer')
    if inner is None:
        raise CommandError("Proveedor gemini_developer no disponible.")
    prov = _ProveedorContado(inner, tope=1, agent_id=agent_id)

    def _resolver(alert):
        if str(alert.get('agent_id') or '').strip() != agent_id:
            return None
        if str(alert.get('opensearch_id') or '') != opensearch_id:
            return None
        return resolver_activo_por_agente(agent_id)

    obj, accion = ingestar_alerta(raw, resolver=_resolver, politica=politica, proveedor=prov)
    obj.refresh_from_db()
    return dict(
        opensearch_id=opensearch_id, agent_id=agent_id, activo=activo.identificador,
        accion=accion, alert_id=obj.id, estado_analisis=obj.estado_analisis,
        veredicto_ia=obj.veredicto_ia or "", riesgo_ia=obj.riesgo_ia or "",
        llamadas_reales=prov.llamadas, nivel=nivel,
    )


class Command(BaseCommand):
    help = "Ingesta controlada de alertas reales de un único agente (Sprint 2E / 2E.1 / 2G.3)."

    def add_arguments(self, parser):
        parser.add_argument('--agent-id', dest='agent_id', required=True)
        parser.add_argument('--scan-limit', dest='scan_limit', type=int, default=SCAN_LIMIT_DEFAULT,
                            help=f"candidatas leídas de Wazuh (solo lectura). Máx {SCAN_LIMIT_MAX}.")
        parser.add_argument('--max-analisis', dest='max_analisis', type=int, default=MAX_ANALISIS_ABS,
                            help=f"tope absoluto de llamadas a Gemini. Máx {MAX_ANALISIS_ABS}.")
        parser.add_argument('--opensearch-id', dest='opensearch_id', default=None,
                            help="análisis DIRIGIDO por `_id` exacto de OpenSearch. Exige --confirmar "
                                 "y --agent-id; tope absoluto de 1 llamada real.")
        parser.add_argument('--dry-run', action='store_true')
        parser.add_argument('--confirmar', action='store_true')

    def handle(self, *args, **o):
        dry, conf = bool(o['dry_run']), bool(o['confirmar'])

        if o.get('opensearch_id'):
            if not conf or dry:
                raise CommandError("--opensearch-id exige --confirmar (y no admite --dry-run).")
            r = procesar_una_por_opensearch_id(
                o['opensearch_id'], o['agent_id'], log=self.stdout.write)
            self.stdout.write("")
            self.stdout.write(self.style.SUCCESS("=== Resultado dirigido (categorías sanitizadas) ==="))
            self.stdout.write(f"  opensearch_id:            {r['opensearch_id']}")
            self.stdout.write(f"  agente / activo:          {r['agent_id']} / {r['activo']}")
            self.stdout.write(f"  nivel Wazuh:              {r['nivel']}")
            self.stdout.write(f"  acción de ingesta:        {r['accion']}")
            self.stdout.write(f"  fila MySQL (id):          {r['alert_id']}")
            self.stdout.write(f"  llamadas reales a Gemini: {r['llamadas_reales']}  (tope 1)")
            self.stdout.write(f"  estado_analisis:          {r['estado_analisis']}")
            self.stdout.write(f"  veredicto_ia:             {r['veredicto_ia']}")
            self.stdout.write(f"  riesgo_ia:                {r['riesgo_ia']}")
            return

        if dry == conf:
            raise CommandError("Usa exactamente uno: --dry-run o --confirmar.")
        if o['scan_limit'] > SCAN_LIMIT_MAX:
            self.stdout.write(self.style.WARNING(
                f"--scan-limit {o['scan_limit']} excede el máximo: se limita a {SCAN_LIMIT_MAX}."))
        if o['max_analisis'] > MAX_ANALISIS_ABS:
            self.stdout.write(self.style.WARNING(
                f"--max-analisis {o['max_analisis']} excede el máximo absoluto: se limita a {MAX_ANALISIS_ABS}."))

        c = procesar_ingesta_controlada(
            o['agent_id'], scan_limit=o['scan_limit'], max_analisis=o['max_analisis'],
            dry=dry, conf=conf, log=self.stdout.write)

        self.stdout.write("")
        self.stdout.write(self.style.SUCCESS("=== Resultado (categorías sanitizadas) ==="))
        self.stdout.write(f"  modo:                     {c['modo']}")
        self.stdout.write(f"  candidatas revisadas:     {c['candidatas']}  (scan-limit {c['scan_limit']})")
        self.stdout.write(f"  ya COMPLETED (dedup):     {c['duplicadas_completed']}")
        self.stdout.write(f"  omitidas por política:    ruido={c['omitidas_ruido']} nivel={c['omitidas_nivel']} "
                          f"sin_activo={c['omitidas_sin_activo']} regla={c['omitidas_regla']}")
        self.stdout.write(f"  elegibles (total):        {c['elegibles']}")
        self.stdout.write(f"  elegibles seleccionadas:  {c['elegibles_seleccionadas']}  (tope {c['max_analisis']})")
        self.stdout.write(f"  elegibles no seleccionadas:{c['elegibles_no_seleccionadas']}")
        self.stdout.write(f"  procedencia completada:   {c['procedencia_completada']}")
        self.stdout.write(f"  llamadas reales a Gemini: {c['llamadas_reales']}  (tope {c['max_analisis']})")
        self.stdout.write(f"  COMPLETED:                {c['completed']}")
        self.stdout.write(f"  ANALISIS_FALLIDO:         {c['analisis_fallido']}")
        self.stdout.write(f"  -> FALSO_POSITIVO:        {c['falso_positivo']}")
        self.stdout.write(f"  -> REQUIERE_ATENCION:     {c['requiere_atencion']}")
