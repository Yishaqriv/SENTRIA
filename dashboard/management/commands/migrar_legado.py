"""
Migración SEGURA de alertas del flujo legado al contrato de IA actual
(Sprint 3C/3D, fase 7).

Uso (sólo lectura / diagnóstico):
  python manage.py migrar_legado --agent-id 000 --scan-limit 50 --dry-run

AUTORIZACIONES SEPARADAS (una nunca implica la otra):

  1. Migrar / escribir datos:
       --confirmar  +  SENTRIA_MIGRAR_LEGADO_AUTORIZADO=1
     Sólo migra lo que NO necesita IA: una alerta legado recuperable que la
     política vigente declara no elegible pasa a OMITIDO_POLITICA (con su
     análisis legado preservado). Las elegibles quedan INTACTAS y se cuentan
     como "requieren Gemini". Ninguna llamada a ningún proveedor.

  2. Llamadas reales a Gemini (además de lo anterior):
       --analizar-con-gemini  +  SENTRIA_GEMINI_REAL_AUTORIZADO=1
     Si falta cualquiera de las dos, el comando aborta ANTES de escribir nada
     o de crear un proveedor. Tope absoluto de llamadas: `MAX_ANALISIS_ABS`.

  `--dry-run` nunca escribe ni llama a Gemini (y rechaza --analizar-con-gemini).
  Ninguna variable se fija en el sprint 3C/3D: ambas rutas quedan deshabilitadas.

Reglas duras:
  - Hay que elegir exactamente uno de --dry-run/--confirmar.
  - `--max-analisis` recortado a un tope absoluto conservador (3).
  - `--scan-limit` recortado a un máximo (200).
  - `--confirmar` exige `--agent-id` (con asignación activa) o `--opensearch-id`.
  - MULTIAGENTE, defensa en profundidad: con `--agent-id`, (a) el indexador
    filtra cada consulta por `agent.id` y (b) cada documento devuelto se vuelve
    a comprobar; uno de otro agente se rechaza sin tocar la alerta. El
    `agent.id` nunca aparece en la salida.
  - Política ANTES de Gemini; deduplicación por `opensearch_id`; verificación
    de anonimización del prompt (mismo patrón que `ingestar_alertas`).
  - PRESERVACIÓN: antes de aplicar el contrato nuevo, `riesgo_ia`/
    `explicacion_ia`/`estado`/`severidad` ANTERIORES se copian a
    `Alert.legado_snapshot` (campo aditivo) y nunca se pisan dos veces.
  - REANUDACIÓN SEGURA: cada alerta se procesa y persiste de forma individual
    (sin una transacción global); una alerta ya migrada deja de tener
    `estado_analisis` NULL, así que re-ejecutar el comando tras una
    interrupción simplemente continúa con las que falten.
"""
import os
import re
import sys

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from dashboard.ia import proveedores
from dashboard.ia.ingesta import _enriquecer_procedencia, ingestar_alerta
from dashboard.ia.legado import diagnosticar_legado
from dashboard.ia.persistencia import aplicar_omision
from dashboard.ia.politica import cargar_politica, evaluar_elegibilidad
from dashboard.ia.resolver import resolver_activo_por_agente
from dashboard.models import Alert

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../')))
from sentria_backend import get_alert_by_id

MAX_ANALISIS_ABS = 3          # tope absoluto, conservador, de esta migración
SCAN_LIMIT_DEFAULT = 50
SCAN_LIMIT_MAX = 200
GATE_ENV_VAR = "SENTRIA_MIGRAR_LEGADO_AUTORIZADO"
GEMINI_GATE_ENV_VAR = "SENTRIA_GEMINI_REAL_AUTORIZADO"

_IP_PRIVADA = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|169\.254\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"
)


class _ProveedorContado(proveedores.ProveedorIA):
    """Tope absoluto de llamadas + comprobación de anonimización del prompt."""
    def __init__(self, inner, *, tope, agent_id):
        self._inner = inner
        self._tope = tope
        self._agent_id = str(agent_id or "")
        self.nombre = inner.nombre
        self.llamadas = 0

    def _prompt_sospechoso(self, prompt):
        p = str(prompt)
        if _IP_PRIVADA.search(p):
            return "IP privada en el prompt"
        if self._agent_id and re.search(rf"\bagent[^\n]{{0,12}}\b{re.escape(self._agent_id)}\b", p, re.I):
            return "agent.id en el prompt"
        return None

    def analizar(self, prompt):
        if self.llamadas >= self._tope:
            return proveedores.RespuestaProveedor(
                ok=False, texto="", modelo="", error="tope de llamadas de la migración alcanzado")
        motivo = self._prompt_sospechoso(prompt)
        if motivo:
            return proveedores.RespuestaProveedor(ok=False, texto="", modelo="", error=f"anonimización: {motivo}")
        self.llamadas += 1
        return self._inner.analizar(prompt)


def _preservar_legado(alerta):
    """
    Copia el análisis legado ANTERIOR a `legado_snapshot` antes de tocarlo.
    Idempotente: si ya existe un snapshot, no lo vuelve a pisar (preserva el
    primero, que es el histórico real).
    """
    if alerta.legado_snapshot:
        return
    alerta.legado_snapshot = {
        "riesgo_ia": alerta.riesgo_ia,
        "explicacion_ia": alerta.explicacion_ia,
        "estado": alerta.estado,
        "severidad": alerta.severidad,
        "preservado_en": timezone.now().isoformat(),
    }
    alerta.save(update_fields=["legado_snapshot"])


def _migrar_como_omitida(alerta, raw, activo, motivo):
    """Migración SIN IA: preserva el legado y aplica la omisión de la política."""
    _preservar_legado(alerta)
    _enriquecer_procedencia(alerta, raw)
    if activo is not None and alerta.activo_logico_id != activo.id:
        alerta.activo_logico = activo
        alerta.save(update_fields=["activo_logico"])
    aplicar_omision(alerta, motivo)


def procesar_migracion_legado(*, scan_limit, max_analisis, dry, conf, agent_id=None,
                              opensearch_id=None, analizar_con_gemini=False,
                              get_uno=get_alert_by_id,
                              obtener_proveedor=proveedores.obtener_proveedor,
                              log=lambda _s: None):
    """
    Núcleo del comando. En `dry`, SÓLO diagnostica (solo lectura, sin Gemini).
    En `conf`, exige el gate de migración (`GATE_ENV_VAR`); las llamadas a
    Gemini exigen además `analizar_con_gemini` y `GEMINI_GATE_ENV_VAR`.
    Todas las comprobaciones de autorización ocurren ANTES de cualquier
    escritura o creación de proveedor.
    """
    scan_limit = max(1, min(int(scan_limit), SCAN_LIMIT_MAX))
    max_analisis = max(0, min(int(max_analisis), MAX_ANALISIS_ABS))
    agent_id = str(agent_id).strip() if agent_id not in (None, "") else None

    if dry and analizar_con_gemini:
        raise CommandError("--dry-run nunca llama a Gemini: no combines --dry-run con --analizar-con-gemini.")

    diag = diagnosticar_legado()
    log(f"Diagnóstico (solo lectura): {diag['legado_total']} alertas legado; "
        f"{diag['recuperables']} recuperables en Wazuh, de las cuales "
        f"{diag['recuperable_y_elegible']} elegibles hoy y {diag['no_elegible_total']} no elegibles; "
        f"{diag['sin_documento_recuperable']} sin documento recuperable.")
    log(f"Por motivo de no-elegibilidad: {diag['por_motivo_omision']}")

    resultado = dict(
        modo='dry-run' if dry else 'confirmar',
        gemini_autorizado=False,
        scan_limit=scan_limit, max_analisis=max_analisis,
        diagnostico=diag, migradas=0, migradas_omitidas=0, requieren_gemini=0,
        rechazadas_otro_agente=0, sin_documento=0, fallidas=0, llamadas_reales=0,
    )

    if dry:
        return resultado

    # --- Autorización 1: migración/escritura ---
    if os.environ.get(GATE_ENV_VAR) != "1":
        raise CommandError(
            f"La migración real de alertas legado está deshabilitada en el sprint 3C/3D. "
            f"Para habilitarla explícitamente en un checkpoint futuro, fija {GATE_ENV_VAR}=1. "
            f"Nada se ha escrito ni se ha llamado a Gemini."
        )

    # --- Autorización 2: llamadas reales a Gemini (independiente de la 1) ---
    if analizar_con_gemini and os.environ.get(GEMINI_GATE_ENV_VAR) != "1":
        raise CommandError(
            f"--analizar-con-gemini exige además {GEMINI_GATE_ENV_VAR}=1. "
            f"Nada se ha escrito ni se ha llamado a Gemini."
        )
    if not analizar_con_gemini and os.environ.get(GEMINI_GATE_ENV_VAR) == "1":
        log(f"{GEMINI_GATE_ENV_VAR}=1 sin --analizar-con-gemini: se ignora, no habrá llamadas a Gemini.")

    if not agent_id and not opensearch_id:
        raise CommandError("--confirmar exige --agent-id o --opensearch-id.")

    politica = cargar_politica()
    if agent_id and resolver_activo_por_agente(agent_id) is None:
        raise CommandError("El agente indicado no tiene asignación activa a un ActivoLogico.")

    prov = None
    if analizar_con_gemini:
        if not os.environ.get('GEMINI_API_KEY'):
            raise CommandError("GEMINI_API_KEY ausente: no se ejecuta --analizar-con-gemini.")
        inner = obtener_proveedor('gemini_developer')
        if inner is None:
            raise CommandError("Proveedor gemini_developer no disponible.")
        prov = _ProveedorContado(inner, tope=max_analisis, agent_id=agent_id)
        resultado['gemini_autorizado'] = True

    candidatas = Alert.objects.filter(estado_analisis__isnull=True).exclude(
        opensearch_id__isnull=True).exclude(opensearch_id="")
    if opensearch_id:
        candidatas = candidatas.filter(opensearch_id=opensearch_id)
    candidatas = list(candidatas[:scan_limit])

    def _resolver(alert):
        return resolver_activo_por_agente(alert.get('agent_id'))

    analizadas = 0
    for alerta in candidatas:
        try:
            raw = get_uno(alerta.opensearch_id, agent_id=agent_id)
        except Exception:
            resultado['fallidas'] += 1
            continue
        if raw is None:
            # Con --agent-id incluye documentos de OTROS agentes (filtrados por el indexador).
            resultado['sin_documento'] += 1
            continue
        # Defensa en profundidad: el documento debe ser exactamente el pedido y,
        # con --agent-id, pertenecer exactamente a ese agente.
        if str(raw.get('opensearch_id') or alerta.opensearch_id) != alerta.opensearch_id:
            resultado['fallidas'] += 1
            continue
        if agent_id is not None and str(raw.get('agent_id') or '').strip() != agent_id:
            resultado['rechazadas_otro_agente'] += 1
            continue

        activo = _resolver(raw)
        decision = evaluar_elegibilidad(raw, activo is not None, politica)
        if not decision.elegible:
            _migrar_como_omitida(alerta, raw, activo, decision.motivo_omision)
            resultado['migradas_omitidas'] += 1
            continue
        if prov is None:
            resultado['requieren_gemini'] += 1   # intacta: sin autorización de Gemini
            continue
        if analizadas >= max_analisis:
            continue
        analizadas += 1
        _preservar_legado(alerta)     # SIEMPRE antes de tocar el contrato nuevo
        try:
            ingestar_alerta(raw, resolver=_resolver, politica=politica, proveedor=prov)
            resultado['migradas'] += 1
        except Exception:
            resultado['fallidas'] += 1

    resultado['llamadas_reales'] = prov.llamadas if prov is not None else 0
    return resultado


class Command(BaseCommand):
    help = ("Migración segura y preparatoria de alertas legado (Sprint 3C/3D). "
            "--confirmar y --analizar-con-gemini exigen autorizaciones de entorno separadas.")

    def add_arguments(self, parser):
        parser.add_argument('--agent-id', dest='agent_id', default=None)
        parser.add_argument('--opensearch-id', dest='opensearch_id', default=None)
        parser.add_argument('--scan-limit', dest='scan_limit', type=int, default=SCAN_LIMIT_DEFAULT)
        parser.add_argument('--max-analisis', dest='max_analisis', type=int, default=MAX_ANALISIS_ABS)
        parser.add_argument('--dry-run', action='store_true')
        parser.add_argument('--confirmar', action='store_true')
        parser.add_argument('--analizar-con-gemini', dest='analizar_con_gemini', action='store_true')

    def handle(self, *args, **o):
        dry, conf = bool(o['dry_run']), bool(o['confirmar'])
        if dry == conf:
            raise CommandError("Usa exactamente uno: --dry-run o --confirmar.")

        r = procesar_migracion_legado(
            scan_limit=o['scan_limit'], max_analisis=o['max_analisis'], dry=dry, conf=conf,
            agent_id=o['agent_id'], opensearch_id=o['opensearch_id'],
            analizar_con_gemini=o['analizar_con_gemini'], log=self.stdout.write,
        )
        self.stdout.write("")
        self.stdout.write(self.style.SUCCESS("=== Migración de legado (categorías sanitizadas) ==="))
        self.stdout.write(f"  modo:                   {r['modo']}")
        self.stdout.write(f"  Gemini autorizado:      {'sí' if r['gemini_autorizado'] else 'no'}")
        self.stdout.write(f"  migradas con IA:        {r['migradas']}")
        self.stdout.write(f"  migradas a omitidas:    {r['migradas_omitidas']}")
        self.stdout.write(f"  requieren Gemini:       {r['requieren_gemini']}")
        self.stdout.write(f"  rechazadas otro agente: {r['rechazadas_otro_agente']}")
        self.stdout.write(f"  sin documento:          {r['sin_documento']}")
        self.stdout.write(f"  fallidas:               {r['fallidas']}")
        self.stdout.write(f"  llamadas reales:        {r['llamadas_reales']}  (tope {r['max_analisis']})")
