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
  - `--proveedor vertex_tuned` (lotes o dirigido): configuración y credenciales
    se comprueban ANTES de leer Wazuh; sólo alertas representables en
    `exp-entrada-1`; sin reintentos ni proveedor alternativo.

Piloto acotado (registro persistente, ver dashboard/ia/piloto.py):
  python manage.py ingestar_alertas --agent-id 001 --proveedor vertex_tuned \\
      --iniciar-piloto --registro-piloto /ruta/privada/piloto.jsonl
  python manage.py ingestar_alertas --agent-id 001 --proveedor vertex_tuned \\
      --piloto --registro-piloto /ruta/privada/piloto.jsonl \\
      --reserva /ruta/privada/reserva.json --reserva-sello <sha256> --dry-run | --confirmar
  - Sólo alertas NUEVAS (sin fila en MySQL) con fecha >= inicio del piloto y
    fuera de los episodios y sesiones del manifiesto de reserva (obligatorio,
    con sello verificado; su versión y huella quedan en el registro).
  - --dry-run lee las alertas ACTUALES del indexador Wazuh (solo lectura) y
    MySQL (solo lectura); no pide token, no llama al modelo, no escribe.
  - Máx. 3 intentos por ejecución y el tope total del registro (máx. 30); cada
    intento se registra en disco ANTES de llamar, también si la llamada falla.
"""
import datetime
import os
import re

from django.core.management.base import BaseCommand, CommandError

from dashboard.ia import piloto as piloto_mod
from dashboard.ia import proveedores
from dashboard.ia.ingesta import ingestar_alerta
from dashboard.ia.prompt import _parsear_ts
from dashboard.ia.politica import cargar_politica, evaluar_elegibilidad
from dashboard.ia.resolver import resolver_activo_por_agente
from dashboard.models import Alert

import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../')))
from sentria_backend import IndexadorTLSError, get_latest_alerts, get_alert_by_id

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
    def __init__(self, inner, *, tope, agent_id, antes_de_llamar=None):
        self._inner = inner
        self._tope = tope
        self._agent_id = str(agent_id)
        self._antes_de_llamar = antes_de_llamar     # p. ej. registro persistente del piloto (cuenta el intento)
        self.nombre = inner.nombre
        self.llamadas = 0
        # Capacidades del proveedor real que el analizador consulta (formato de entrada y validaciones extra).
        for atributo in ("formato_entrada", "valida_privacidad_salida", "valida_sustento_impactos", "_modelo"):
            if hasattr(inner, atributo):
                setattr(self, atributo, getattr(inner, atributo))

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
        if self._antes_de_llamar is not None:
            try:
                self._antes_de_llamar()             # se registra ANTES de llamar: un fallo también cuenta
            except piloto_mod.RegistroPilotoError as e:
                return proveedores.RespuestaProveedor(
                    ok=False, texto="", modelo="", error=f"piloto: {e}")
        self.llamadas += 1
        return self._inner.analizar(prompt)


def _motivo_indexador(exc):
    """Motivo sanitizado: el mensaje propio de la huella TLS (sin secretos); en otro caso, solo el tipo."""
    return f"{type(exc).__name__}: {exc}" if isinstance(exc, IndexadorTLSError) else type(exc).__name__


PROVEEDORES_ADMITIDOS = ("gemini_developer", "vertex_tuned")
PROVEEDORES_DIRIGIDOS = PROVEEDORES_ADMITIDOS


def _entrada_representable(raw, activo):
    """True si la alerta cabe en `exp-entrada-1` (la representación que recibe el modelo ajustado). Sin red."""
    from types import SimpleNamespace
    from dashboard.dataset import construir_entrada
    from dashboard.ia.entrada_exportacion import EntradaNoRepresentable, texto_usuario
    from dashboard.ia.prompt import construir_entrada_e
    try:
        texto_usuario(construir_entrada(SimpleNamespace(contexto_ia_snapshot=construir_entrada_e(raw, activo))))
        return True
    except EntradaNoRepresentable:
        return False


def _preparar_proveedor(proveedor, *, conf, tope, agent_id, obtener_proveedor, log, antes_de_llamar=None):
    """
    Comprueba configuración y credenciales ANTES de leer el indexador. Sin reintentos ni proveedor alternativo:
    si el elegido no es utilizable, se aborta. En --dry-run sólo informa (sin red, sin proveedor).
    """
    if proveedor == "gemini_developer":
        key = "PRESENTE" if os.environ.get('GEMINI_API_KEY') else "AUSENTE"
        mdl = "PRESENTE" if os.environ.get('GEMINI_MODEL') else "AUSENTE"
        if not conf:
            return None
        log(f"GEMINI_API_KEY: {key}   GEMINI_MODEL: {mdl}   proveedor: gemini_developer")
        if key != "PRESENTE":
            raise CommandError("GEMINI_API_KEY ausente: no se ejecuta --confirmar.")
        inner = obtener_proveedor('gemini_developer')
        if inner is None:
            raise CommandError("Proveedor gemini_developer no disponible.")
    else:
        inner = obtener_proveedor(proveedor)
        if inner is None:
            raise CommandError(f"Proveedor {proveedor} no disponible.")
        err = inner.comprobar_credenciales(con_red=conf)
        if not conf:
            log(f"proveedor: {proveedor}. Configuración y credenciales (comprobación local): "
                f"{'OK' if not err else 'NO UTILIZABLE: ' + err}")
            return None
        if err:
            raise CommandError(f"{proveedor} no utilizable: {err}. No se lee el indexador ni se llama al modelo.")
        log(f"proveedor: {proveedor}. Configuración y credenciales comprobadas (sin llamar al modelo).")
    return _ProveedorContado(inner, tope=tope, agent_id=agent_id, antes_de_llamar=antes_de_llamar)


def procesar_ingesta_controlada(agent_id, *, scan_limit, max_analisis, dry, conf, proveedor="gemini_developer",
                                registro=None, reserva=None, tls_huella=None,
                                get_alertas=None,
                                obtener_proveedor=proveedores.obtener_proveedor,
                                log=lambda _s: None):
    """
    Núcleo de la ingesta controlada. Devuelve un dict de conteos/categorías
    sanitizadas. `log` recibe cadenas ya sanitizadas (nunca prompts ni
    respuestas). Lanza CommandError ante condiciones que impiden continuar.

    - `scan_limit`   = cuántas candidatas se LEEN de Wazuh (solo lectura).
                       No es un número de llamadas. Recortado a [1, SCAN_LIMIT_MAX].
    - `max_analisis` = tope ABSOLUTO de llamadas al modelo en esta ejecución.
                       Recortado a [0, MAX_ANALISIS_ABS]. Se seleccionan las
                       PRIMERAS N alertas realmente elegibles.
    - `proveedor`    = gemini_developer (por defecto) o vertex_tuned. Con un
                       proveedor de entrada `exp-entrada-1` sólo se seleccionan
                       alertas representables (las demás no se tocan).
    - `registro`     = piloto acotado (`dashboard.ia.piloto.RegistroPiloto`):
                       sólo alertas NUEVAS (sin fila en MySQL) del agente del
                       registro con fecha >= su inicio, y tope total persistente
                       que cuenta cada intento antes de llamar.
    """
    agent_id = str(agent_id).strip()
    if proveedor not in PROVEEDORES_ADMITIDOS:
        raise CommandError(f"--proveedor debe ser uno de {list(PROVEEDORES_ADMITIDOS)}.")
    scan_limit = max(1, min(int(scan_limit), SCAN_LIMIT_MAX))
    max_analisis = max(0, min(int(max_analisis), MAX_ANALISIS_ABS))

    activo = resolver_activo_por_agente(agent_id)
    if activo is None:
        raise CommandError(
            f"El agente {agent_id} no tiene una asignación activa a un ActivoLogico "
            f"(o está en IA_AGENTES_BLOQUEADOS). Nada que hacer.")

    if registro is not None:
        if reserva is None:
            raise CommandError("El piloto exige el manifiesto de reserva (--reserva y --reserva-sello).")
        if not tls_huella:
            raise CommandError("El piloto exige verificar TLS del indexador (--wazuh-tls-sha256): "
                               "no se envían credenciales a Wazuh sin verificación.")
        if registro.agente != agent_id or registro.proveedor != proveedor:
            raise CommandError("El registro del piloto es de otro agente o de otro proveedor. Abortado.")
        analizadas = Alert.objects.filter(
            wazuh_agent_id=agent_id, proveedor_ia=proveedor, creado_en__gte=registro.inicio_utc,
        ).exclude(opensearch_id__isnull=True).exclude(opensearch_id="").values_list("opensearch_id", flat=True)
        try:
            registro.comprobar_coherencia(list(analizadas))
        except piloto_mod.RegistroPilotoError as e:
            raise CommandError(f"Piloto: {e}. Abortado.")
        if conf and registro.restantes <= 0:
            raise CommandError("Piloto: tope total agotado. No se llama al modelo.")
        max_analisis = min(max_analisis, registro.restantes)
        log(f"Reserva: {reserva.version}, sello {reserva.sello[:16]}… verificado "
            f"({reserva.n_episodios} episodios, {reserva.n_sesiones} sesiones).")
        if conf:
            registro.registrar_ejecucion(reserva, modo="confirmar")     # constancia antes de cualquier llamada
        log(f"Piloto: {registro.usados}/{registro.tope_total} intentos usados; "
            f"esta ejecución admite como máximo {max_analisis}.")

    log(f"Agente {agent_id} -> activo {activo.identificador}. "
        f"scan-limit {scan_limit}, max-análisis {max_analisis}.")

    politica = cargar_politica()
    prov = _preparar_proveedor(proveedor, conf=conf, tope=max_analisis, agent_id=agent_id,
                               obtener_proveedor=obtener_proveedor, log=log,
                               antes_de_llamar=registro.registrar_intento if registro is not None else None)
    exige_representable = getattr(proveedores.PROVEEDORES.get(proveedor), "formato_entrada", None) == "exp-entrada-1"

    get_alertas = get_alertas or get_latest_alerts      # resuelto al llamar (sustituible en pruebas)
    log(f"Fuente: indexador Wazuh, lectura ACTUAL de hasta {scan_limit} alertas más recientes del agente "
        f"(nivel >= {politica.nivel_minimo}). {'Ensayo: sin modelo, sin token y sin escrituras.' if dry else ''}")
    log(f"TLS del indexador: huella SHA-256 fijada "
        f"{(tls_huella[:16] + '…') if tls_huella else '(WAZUH_TLS_SHA256 del entorno)'}; "
        f"se comprueba antes de enviar credenciales y, si falta o no coincide, no se consulta.")
    extra = {"tls_huella": tls_huella} if tls_huella else {}
    try:
        crudas = get_alertas(size=scan_limit, agent_id=agent_id, min_level=politica.nivel_minimo, **extra)
    except Exception as exc:
        raise CommandError(f"No se pudo consultar el indexador Wazuh: {_motivo_indexador(exc)}")

    def _resolver(alert):
        if str(alert.get('agent_id') or '').strip() != agent_id:
            return None
        return resolver_activo_por_agente(agent_id)

    c = dict(candidatas=0, duplicadas_completed=0, omitidas_ruido=0,
             omitidas_nivel=0, omitidas_sin_activo=0, omitidas_regla=0,
             elegibles=0, elegibles_seleccionadas=0, elegibles_no_seleccionadas=0,
             procedencia_completada=0, completed=0, analisis_fallido=0,
             falso_positivo=0, requiere_atencion=0,
             no_representables=0, ya_existentes=0, anteriores_al_piloto=0, reservadas=0, seleccion=[])

    for raw in crudas:
        c['candidatas'] += 1
        osid = raw.get('opensearch_id')
        existente = Alert.objects.filter(opensearch_id=osid).first() if osid else None

        if registro is not None:
            # Piloto: sólo alertas naturales NUEVAS. Nunca se reanaliza una existente (en ningún estado) ni se
            # usa una alerta anterior al inicio del piloto (históricos, apartado, pruebas anteriores).
            if not osid or existente is not None:
                c['ya_existentes'] += 1
                continue
            momento = _parsear_ts(raw.get('timestamp'))
            if momento is not None and momento.tzinfo is None:
                momento = momento.replace(tzinfo=datetime.timezone.utc)
            if reserva.reservada(agent_id, momento):      # exclusión EXPLÍCITA (sin fecha también se excluye)
                c['reservadas'] += 1
                continue
            if momento < registro.inicio_utc:
                c['anteriores_al_piloto'] += 1
                continue
        elif existente is not None and existente.estado_analisis == 'COMPLETED':
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

        if exige_representable and not _entrada_representable(raw, activo):
            c['no_representables'] += 1     # no cabe en exp-entrada-1: no se persiste ni se llama
            continue

        c['elegibles'] += 1

        # Sólo se seleccionan (y analizan) las PRIMERAS `max_analisis` elegibles.
        if c['elegibles_seleccionadas'] >= max_analisis:
            c['elegibles_no_seleccionadas'] += 1
            continue
        c['elegibles_seleccionadas'] += 1

        if dry:
            # Ensayo: qué se procesaría (sin escritura, sin proveedor, sin opensearch_id).
            c['seleccion'].append({"regla": str(raw.get('rule_id') or ''), "nivel": raw.get('level'),
                                   "fecha": str(raw.get('timestamp') or '')[:19], "grupos": raw.get('groups') or ''})
            continue

        antes = (existente.wazuh_agent_id, existente.wazuh_rule_id,
                 existente.wazuh_rule_groups) if existente else None
        if registro is not None:
            registro.preparar(osid)
        obj, _accion = ingestar_alerta(raw, resolver=_resolver, politica=politica, proveedor=prov)
        obj.refresh_from_db()
        if registro is not None:
            registro.registrar_resultado(osid, alert_id=obj.id, estado_analisis=obj.estado_analisis)
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
    c['proveedor'] = proveedor
    if registro is not None:
        c['piloto'] = {"usados": registro.usados, "restantes": registro.restantes, "tope_total": registro.tope_total,
                       "reserva_version": reserva.version, "reserva_sello": reserva.sello}
    return c


def _nivel_int_local(valor):
    try:
        return int(float(str(valor).strip()))
    except (TypeError, ValueError):
        return None



def procesar_una_por_opensearch_id(opensearch_id, agent_id, *,
                                   get_uno=get_alert_by_id,
                                   obtener_proveedor=proveedores.obtener_proveedor,
                                   log=lambda _s: None, proveedor="gemini_developer"):
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
    if proveedor not in PROVEEDORES_DIRIGIDOS:
        raise CommandError(f"--proveedor debe ser uno de {list(PROVEEDORES_DIRIGIDOS)}.")
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
        raise CommandError(f"No se pudo consultar el indexador Wazuh: {_motivo_indexador(exc)}")
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

    if proveedor == "gemini_developer":
        key = "PRESENTE" if os.environ.get('GEMINI_API_KEY') else "AUSENTE"
        log(f"Agente {agent_id} -> activo {activo.identificador}. "
            f"opensearch_id validado. GEMINI_API_KEY: {key}. proveedor: gemini_developer. tope: 1 llamada.")
        if key != "PRESENTE":
            raise CommandError("GEMINI_API_KEY ausente: no se ejecuta.")
    inner = obtener_proveedor(proveedor)
    if inner is None:
        raise CommandError(f"Proveedor {proveedor} no disponible.")
    if proveedor == "vertex_tuned":
        err = inner.error_configuracion()          # desactivado o mal configurado: no se llama
        if err:
            raise CommandError(f"vertex_tuned no utilizable: {err}. No se llama al modelo.")
        log(f"Agente {agent_id} -> activo {activo.identificador}. opensearch_id validado. "
            f"proveedor: vertex_tuned. tope: 1 llamada.")
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
        llamadas_reales=prov.llamadas, nivel=nivel, proveedor=proveedor,
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
        parser.add_argument('--proveedor', dest='proveedor', default='gemini_developer',
                            choices=list(PROVEEDORES_ADMITIDOS),
                            help="proveedor del análisis (por defecto gemini_developer), en lotes o dirigido. "
                                 "vertex_tuned exige además IA_VERTEX_HABILITADO=1 y su configuración; "
                                 "sin reintentos ni proveedor alternativo.")
        parser.add_argument('--piloto', action='store_true',
                            help="piloto acotado: sólo alertas NUEVAS del agente posteriores al inicio del piloto, "
                                 "con tope total persistente. Exige --registro-piloto.")
        parser.add_argument('--registro-piloto', dest='registro_piloto', default=None,
                            help="ruta ABSOLUTA del registro privado del piloto (600, fuera del repositorio).")
        parser.add_argument('--iniciar-piloto', action='store_true',
                            help="crea el registro del piloto (falla si ya existe) y termina: no lee Wazuh ni llama "
                                 "al modelo.")
        parser.add_argument('--reserva', dest='reserva', default=None,
                            help="con --piloto (obligatorio): ruta ABSOLUTA del manifiesto privado de reserva (600).")
        parser.add_argument('--reserva-sello', dest='reserva_sello', default=None,
                            help="con --piloto (obligatorio): SHA-256 esperado del manifiesto de reserva.")
        parser.add_argument('--wazuh-tls-sha256', dest='wazuh_tls_sha256', default=None,
                            help="SHA-256 (64 hex) del certificado del indexador: la conexión solo sigue, y solo "
                                 "entonces se envían credenciales, si coincide. Obligatorio con --piloto.")
        parser.add_argument('--tope-total', dest='tope_total', type=int, default=piloto_mod.TOPE_TOTAL_MAX,
                            help=f"solo con --iniciar-piloto: intentos totales del piloto (máx {piloto_mod.TOPE_TOTAL_MAX}).")
        parser.add_argument('--dry-run', action='store_true')
        parser.add_argument('--confirmar', action='store_true')

    def handle(self, *args, **o):
        dry, conf = bool(o['dry_run']), bool(o['confirmar'])

        if o.get('opensearch_id'):
            if o['piloto'] or o['iniciar_piloto'] or o['registro_piloto'] or o['reserva'] or o['reserva_sello'] \
                    or o['wazuh_tls_sha256']:
                raise CommandError("--opensearch-id no se combina con las opciones del piloto.")
            if not conf or dry:
                raise CommandError("--opensearch-id exige --confirmar (y no admite --dry-run).")
            r = procesar_una_por_opensearch_id(
                o['opensearch_id'], o['agent_id'], log=self.stdout.write, proveedor=o['proveedor'])
            self.stdout.write("")
            self.stdout.write(self.style.SUCCESS("=== Resultado dirigido (categorías sanitizadas) ==="))
            self.stdout.write(f"  opensearch_id:            {r['opensearch_id']}")
            self.stdout.write(f"  agente / activo:          {r['agent_id']} / {r['activo']}")
            self.stdout.write(f"  nivel Wazuh:              {r['nivel']}")
            self.stdout.write(f"  proveedor:                {r['proveedor']}")
            self.stdout.write(f"  acción de ingesta:        {r['accion']}")
            self.stdout.write(f"  fila MySQL (id):          {r['alert_id']}")
            self.stdout.write(f"  llamadas reales a Gemini: {r['llamadas_reales']}  (tope 1)")
            self.stdout.write(f"  estado_analisis:          {r['estado_analisis']}")
            self.stdout.write(f"  veredicto_ia:             {r['veredicto_ia']}")
            self.stdout.write(f"  riesgo_ia:                {r['riesgo_ia']}")
            return

        if o['iniciar_piloto']:
            if dry or conf or o['piloto'] or not o['registro_piloto']:
                raise CommandError("--iniciar-piloto exige --registro-piloto y no admite --piloto, --dry-run ni --confirmar.")
            if resolver_activo_por_agente(str(o['agent_id']).strip()) is None:
                raise CommandError(f"El agente {o['agent_id']} no tiene una asignación activa a un ActivoLogico.")
            try:
                cab = piloto_mod.crear(o['registro_piloto'], agente=str(o['agent_id']).strip(),
                                       proveedor=o['proveedor'], tope_total=o['tope_total'])
            except piloto_mod.RegistroPilotoError as e:
                raise CommandError(f"Piloto: {e}.")
            self.stdout.write(self.style.SUCCESS(
                f"Registro del piloto creado: agente {cab['agente']}, proveedor {cab['proveedor']}, "
                f"tope total {cab['tope_total']}, sólo alertas desde {cab['inicio_utc']}."))
            return
        if o['piloto'] != bool(o['registro_piloto']):
            raise CommandError("--piloto y --registro-piloto van siempre juntos.")
        if o['piloto'] != bool(o['reserva']) or o['piloto'] != bool(o['reserva_sello']):
            raise CommandError("--piloto exige --reserva y --reserva-sello (y estas solo valen con --piloto).")
        huella = (o['wazuh_tls_sha256'] or "").strip().lower() or None
        if o['piloto'] and huella is None:
            raise CommandError("--piloto exige --wazuh-tls-sha256: no se envían credenciales a Wazuh sin verificar TLS.")
        if huella is not None and not re.fullmatch(r"[0-9a-f]{64}", huella):
            raise CommandError("--wazuh-tls-sha256 debe ser el SHA-256 completo (64 hex) del certificado.")
        if dry == conf:
            raise CommandError("Usa exactamente uno: --dry-run o --confirmar.")
        if o['scan_limit'] > SCAN_LIMIT_MAX:
            self.stdout.write(self.style.WARNING(
                f"--scan-limit {o['scan_limit']} excede el máximo: se limita a {SCAN_LIMIT_MAX}."))
        if o['max_analisis'] > MAX_ANALISIS_ABS:
            self.stdout.write(self.style.WARNING(
                f"--max-analisis {o['max_analisis']} excede el máximo absoluto: se limita a {MAX_ANALISIS_ABS}."))

        if o['piloto']:
            try:
                reserva = piloto_mod.ManifiestoReserva(o['reserva'], o['reserva_sello'])   # antes de procesar nada
                with piloto_mod.RegistroPiloto(o['registro_piloto']) as registro:
                    c = procesar_ingesta_controlada(
                        o['agent_id'], scan_limit=o['scan_limit'], max_analisis=o['max_analisis'],
                        dry=dry, conf=conf, proveedor=o['proveedor'], registro=registro, reserva=reserva,
                        tls_huella=huella, log=self.stdout.write)
            except piloto_mod.RegistroPilotoError as e:
                raise CommandError(f"Piloto: {e}.")
        else:
            c = procesar_ingesta_controlada(
                o['agent_id'], scan_limit=o['scan_limit'], max_analisis=o['max_analisis'],
                dry=dry, conf=conf, proveedor=o['proveedor'], tls_huella=huella, log=self.stdout.write)

        self.stdout.write("")
        self.stdout.write(self.style.SUCCESS("=== Resultado (categorías sanitizadas) ==="))
        self.stdout.write(f"  modo:                     {c['modo']}")
        self.stdout.write(f"  proveedor:                {c['proveedor']}")
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
        if c['no_representables']:
            self.stdout.write(f"  no representables:        {c['no_representables']}  (no caben en exp-entrada-1)")
        if 'piloto' in c:
            p = c['piloto']
            self.stdout.write(f"  piloto: ya existentes={c['ya_existentes']} reservadas={c['reservadas']} "
                              f"anteriores al inicio={c['anteriores_al_piloto']}")
            self.stdout.write(f"  piloto: reserva {p['reserva_version']} sello {p['reserva_sello'][:16]}…")
            self.stdout.write(f"  piloto: intentos {p['usados']}/{p['tope_total']} (restan {p['restantes']})")
        for i, sel in enumerate(c['seleccion'], 1):
            self.stdout.write(f"  [ensayo] {i}: regla {sel['regla']} nivel {sel['nivel']} {sel['fecha']} {sel['grupos']}")
