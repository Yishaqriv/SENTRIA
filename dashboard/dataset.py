"""
Bandeja del dataset de entrenamiento (Sprint 3A) + editor y doble revisión (3B).

Construye AUTOMÁTICAMENTE candidatos supervisados a partir de:
  - `Alert.contexto_ia_snapshot`  (capa E, ya congelada y anonimizada),
  - la respuesta de la IA (campos del contrato),
  - `RevisionHumana`             (verdad de terreno).

Nunca se copian alertas a mano. Prohibido en un candidato: agent.id,
opensearch_id, rutas exactas, nombres de archivo, usuarios reales, hostname,
IP, respuesta cruda, cualquier dato de capa privada.

Flujo 3B:
  INCOMPLETO --(editor: guardar borrador)--> INCOMPLETO
  INCOMPLETO --(editor: enviar a revisión, validación OK)--> LISTO_PARA_REVISION
  LISTO_PARA_REVISION --(2º revisor: aprobar)--> APROBADO
  LISTO_PARA_REVISION --(2º revisor: devolver)--> DEVUELTO --(editor)--> LISTO_PARA_REVISION
  cualquiera --(revisor: excluir)--> EXCLUIDO
Quien deja LISTO_PARA_REVISION (`completado_por`) NO puede aprobar.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import re

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from . import sellos
from .ia.contrato import CVSS_ENUMS, CVSS_CLAVES, RIESGOS as CONTRATO_RIESGOS, validar_salida_ia
from .models import Alert, CandidatoDataset, RevisionCandidato

_ESTADOS_HUMANOS = ("LISTO_PARA_REVISION", "DEVUELTO", "APROBADO")

# --- Entrada: SÓLO estas claves de la capa E llegan al candidato ---
# Versión de esta lista blanca (se guarda en cada entrada congelada). Cualquier
# cambio de `_CLAVES_ENTRADA` exige una versión nueva: las entradas congeladas no
# se recalculan, y la verificación detecta la diferencia.
#   lista_blanca_v1: 16 claves (027c1e9 … antes de feb219b) = sellos.LEGADO_CLAVES
#   lista_blanca_v2: + maintenance_scope, maintenance_scope_match (feb219b, entrada 1.3)
ENTRADA_SELECCION_VERSION = "lista_blanca_v2"
_CLAVES_ENTRADA = (
    "schema_version", "alert_description_es", "wazuh_level", "wazuh_rule_groups",
    "wazuh_rule_id", "asset_type", "asset_criticality", "asset_os_family",
    "asset_os_role", "operational_window", "maintenance_window",
    "maintenance_category", "maintenance_scope", "maintenance_scope_match",       # 1.3 (opcionales)
    "authorized_context_es", "technical_evidence_es",
    "evidencia_tecnica", "observed_cvss_factors",
)

# --- Patrones que NUNCA deben aparecer en un candidato ---
_RE_IPV4 = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
_RE_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_PREFIJOS_RUTA = ("/home/", "/root/", "/opt/", "/etc/", "/var/", "/usr/",
                  "/tmp/", "/srv/", "/boot/", "/bin/", "/sbin/", "/lib/",
                  "/proc/", "/sys/", "/dev/", "c:\\", "\\\\")
_TOKENS_CRUDOS = ("full_log", "predecoder", "\"agent\"", "'agent'",
                  "agent.id", "agent_id", "hostname", "manager.name")


def _snapshot(alerta):
    return alerta.contexto_ia_snapshot or {}


def familia_alerta(alerta):
    """Familia categórica de la alerta (sin identificadores)."""
    snap = _snapshot(alerta)
    ev = snap.get("evidencia_tecnica") or {}
    grupos = [str(g) for g in (snap.get("wazuh_rule_groups") or alerta.wazuh_rule_groups or [])]
    fim = ev.get("fim_event_type")
    if fim and fim not in ("no_determinado", "no_aplica"):
        return f"fim:{fim}"
    for g in ("authentication_failed", "authentication_success", "sshd",
              "web", "firewall", "ids", "rootcheck", "sudo"):
        if g in grupos:
            return g
    rid = snap.get("wazuh_rule_id") or alerta.wazuh_rule_id
    return f"rule:{rid}" if rid else "no_determinada"


def activo_anonimizado(alerta):
    """Descripción categórica del activo (NUNCA su identificador)."""
    snap = _snapshot(alerta)
    partes = [snap.get("asset_type"), snap.get("asset_os_family"),
              snap.get("asset_criticality")]
    partes = [str(p) for p in partes if p]
    return "/".join(partes) if partes else "no_determinado"


def construir_entrada(alerta):
    """Entrada del ejemplo: subconjunto en lista blanca de la capa E congelada."""
    snap = _snapshot(alerta)
    return {k: snap[k] for k in _CLAVES_ENTRADA if k in snap}


def construir_salida_objetivo(alerta):
    """
    Salida objetivo: parte de la respuesta de Gemini; el `verdict` (y el `risk`
    si el humano lo revisó) se sustituyen por la verdad de terreno.
    """
    rev = getattr(alerta, "revision_humana", None)
    gt_verdict = alerta.veredicto_ia
    risk = alerta.riesgo_ia
    if rev is not None and rev.accion in ("CONFIRMADA", "CORREGIDA"):
        if rev.veredicto_verdad_terreno:
            gt_verdict = rev.veredicto_verdad_terreno
        if rev.riesgo_revisado:
            risk = rev.riesgo_revisado
    return {
        "schema_version": "1.0",
        "verdict": gt_verdict,
        "risk": risk,
        "explanation_es": alerta.explicacion_ia or "",
        "cvss_factors": alerta.factores_cvss or {},
        "cvss_reasoning_es": alerta.justificacion_cvss or "",
        "recommendation_es": alerta.recomendacion_ia or "",
        "missing_evidence": alerta.evidencia_faltante or [],
    }


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


# Huella SEMÁNTICA (versión "semantica_v1"): sólo lo que describe la situación.
# Se excluyen metadatos de esquema/ejecución y contadores que cambian con cada
# evento idéntico: `schema_version`, el texto derivado `technical_evidence_es`
# (repite los campos estructurados y, en snapshots antiguos, incluía
# `rule.firedtimes`) y `evidencia_tecnica.correlated_events` (antes era
# firedtimes). La respuesta de Gemini nunca interviene. Timestamps, IDs,
# agent.id y opensearch_id no forman parte de la entrada.
FINGERPRINT_VERSION = "semantica_v1"
_CLAVES_FUERA_DE_HUELLA = ("schema_version", "technical_evidence_es")
_EVIDENCIA_FUERA_DE_HUELLA = ("correlated_events",)


def entrada_semantica(entrada):
    """Copia de la entrada sin metadatos ni contadores (no muta la original)."""
    sem = {k: v for k, v in (entrada or {}).items() if k not in _CLAVES_FUERA_DE_HUELLA}
    ev = sem.get("evidencia_tecnica")
    if isinstance(ev, dict):
        sem["evidencia_tecnica"] = {k: v for k, v in ev.items() if k not in _EVIDENCIA_FUERA_DE_HUELLA}
    return sem


def fingerprint_entrada(entrada):
    """Huella ESTABLE del contenido semántico de la entrada anonimizada (para deduplicar)."""
    return hashlib.sha256(_canonical(entrada_semantica(entrada)).encode("utf-8")).hexdigest()


def _duplicado_de(cand, fp):
    """
    Primer candidato no excluido con la misma huella SEMÁNTICA. La huella del
    otro se recalcula desde su snapshot congelado (no desde la columna
    `fingerprint`, que en filas históricas puede ser de la versión anterior):
    así no hace falta tocar ni migrar ninguna fila.
    """
    otros = (CandidatoDataset.objects.exclude(pk=cand.pk).exclude(estado="EXCLUIDO")
             .select_related("alerta").order_by("creado_en"))
    for otro in otros:
        entrada_otro = construir_entrada(otro.alerta)
        if entrada_otro and fingerprint_entrada(entrada_otro) == fp:
            return otro.ejemplo_id
    return ""


def ejemplo_id_para(alerta):
    """Identificador opaco y estable del ejemplo. No es la pk ni el opensearch_id."""
    semilla = f"sentria-dataset:{alerta.pk}:{getattr(settings, 'SECRET_KEY', '')}"
    return "EJ-" + hashlib.sha256(semilla.encode("utf-8")).hexdigest()[:16]


def validar_privacidad(*objetos):
    """
    Revisa los objetos serializados en busca de datos prohibidos.
    Devuelve (ok: bool, hallazgos: list[str] sanitizados — categorías, no valores).
    """
    blob = "\n".join(_canonical(o) for o in objetos if o is not None).lower()
    hallazgos = []
    if _RE_IPV4.search(blob):
        hallazgos.append("posible_ip")
    if _RE_EMAIL.search(blob):
        hallazgos.append("posible_email")
    if any(p in blob for p in _PREFIJOS_RUTA):
        hallazgos.append("posible_ruta_exacta")
    if any(t in blob for t in _TOKENS_CRUDOS):
        hallazgos.append("token_de_capa_privada_o_log_crudo")
    return (not hallazgos), hallazgos


def _aparece_identificador(blob, valor):
    """
    ¿Aparece `valor` como identificador independiente en `blob`?

    No basta con una subcadena: el agente "000" no debe confundirse con la
    táctica MITRE "TA0005" ni con el número "1000". Cuenta una aparición
    delimitada por caracteres no alfanuméricos (comillas JSON, espacios, "=",
    ":", "."…), p. ej. `"000"`, `agent.id=000` o `agente 000`. Si el valor es
    numérico, se ignora cuando forma parte de un número mayor ("10.000").
    """
    v = str(valor).strip()
    if not v:
        return False
    for m in re.finditer(rf"(?<![A-Za-z0-9]){re.escape(v)}(?![A-Za-z0-9])", blob, re.IGNORECASE):
        if v.isdigit():
            antes, despues = blob[max(0, m.start() - 2):m.start()], blob[m.end():m.end() + 2]
            if re.fullmatch(r"\d[.,]", antes) or re.fullmatch(r"[.,]\d", despues):
                continue
        return True
    return False


def _fuga_de_identificadores(alerta, *objetos):
    """Comprueba que no aparezcan valores concretos de esta alerta (como identificador independiente)."""
    blob = "\n".join(_canonical(o) for o in objetos if o is not None)
    fugas = []
    for etiqueta, valor in (
        ("agent_id", alerta.wazuh_agent_id),
        ("opensearch_id", alerta.opensearch_id),
        ("identificador_activo", getattr(alerta.activo_logico, "identificador", None)),
    ):
        if valor and _aparece_identificador(blob, valor):
            fugas.append(etiqueta)
    return fugas


def _diagnostico(alerta, cand, entrada, salida, privacidad_ok, hallazgos, fugas, duplicado_de):
    rev = getattr(alerta, "revision_humana", None)
    incompleta_por = []

    if rev is not None and rev.accion == "EXCLUIDA":
        return {"excluida": True, "motivo": rev.motivo_categoria,
                "familia": familia_alerta(alerta),
                "activo_anonimizado": activo_anonimizado(alerta),
                "incompleta_por": []}

    salida_revisada = bool(cand and cand.salida_objetivo_revisada)

    if not salida_revisada:
        incompleta_por.append(
            "el revisor aún no confirmó que revisó riesgo, explicación, CVSS, "
            "recomendación y evidencia faltante")
    else:
        val = validar_salida_ia(_contrato_dict(salida))
        if not val.ok:
            incompleta_por.append("la salida objetivo no cumple el contrato JSON")
        gt = alerta.verdad_terreno
        if gt and salida.get("verdict") != gt:
            incompleta_por.append("la salida objetivo no coincide con la verdad de terreno")

    if not entrada:
        incompleta_por.append("sin contexto_ia_snapshot congelado")
    if not salida.get("verdict") or not salida.get("explanation_es"):
        incompleta_por.append("salida objetivo sin veredicto o sin explicación")
    if not privacidad_ok:
        incompleta_por.append("validación de privacidad no superada")
    if fugas:
        incompleta_por.append("identificadores concretos de la alerta presentes")
    if duplicado_de:
        incompleta_por.append(f"posible duplicado de {duplicado_de}")

    diag = {
        "familia": familia_alerta(alerta),
        "activo_anonimizado": activo_anonimizado(alerta),
        "privacidad_ok": privacidad_ok,
        "hallazgos_privacidad": hallazgos,
        "fugas_identificador": fugas,
        "duplicado_de": duplicado_de,
        "incompleta_por": incompleta_por,
    }
    return diag


def sincronizar_candidato(alerta):
    """
    Crea o actualiza el `CandidatoDataset` de una alerta que tiene revisión
    humana. Devuelve el candidato, o None si la alerta no tiene revisión.

    La sincronización NUNCA promueve un candidato: sólo un humano lo lleva a
    LISTO_PARA_REVISION / APROBADO / DEVUELTO (3B). Si aparece un problema de
    privacidad o de duplicado, el candidato vuelve a INCOMPLETO.

    INMUTABILIDAD (3C/3D): un candidato APROBADO es intocable por esta función
    — ni su salida, ni su diagnóstico, ni su estado cambian aquí jamás. La
    única manera de moverlo es la exclusión explícita y auditada en
    `revisar_candidato`.
    """
    rev = getattr(alerta, "revision_humana", None)
    if rev is None:
        return None

    existente = getattr(alerta, "candidato_dataset", None)
    if existente is not None and existente.estado == "APROBADO":
        return existente

    cand, _creado = CandidatoDataset.objects.get_or_create(
        alerta=alerta, defaults={"ejemplo_id": ejemplo_id_para(alerta)},
    )
    if not cand.ejemplo_id:
        cand.ejemplo_id = ejemplo_id_para(alerta)

    entrada = construir_entrada(alerta)
    salida = salida_objetivo_actual(cand)  # borrador editado si existe
    fp = fingerprint_entrada(entrada) if entrada else ""

    priv_ok, hallazgos = validar_privacidad(entrada, salida)
    fugas = _fuga_de_identificadores(alerta, entrada, salida)
    priv_ok = priv_ok and not fugas

    duplicado_de = _duplicado_de(cand, fp) if fp else ""

    diag = _diagnostico(alerta, cand, entrada, salida, priv_ok, hallazgos, fugas, duplicado_de)
    incompleta_por = diag["incompleta_por"]

    # Estado: EXCLUIDA de la revisión humana manda; un problema nuevo degrada a
    # INCOMPLETO; si no, se conserva el estado que fijó el humano.
    if rev.accion == "EXCLUIDA":
        estado = "EXCLUIDO"
    elif incompleta_por:
        estado = "INCOMPLETO"
    elif cand.estado in _ESTADOS_HUMANOS:
        estado = cand.estado
    else:
        estado = "INCOMPLETO"

    diag["fingerprint_version"] = FINGERPRINT_VERSION
    cand.fingerprint = fp
    cand.privacidad_ok = priv_ok
    cand.duplicado_de = duplicado_de
    cand.diagnostico = diag
    cand.estado = estado
    cand.save()
    return cand


def sincronizar_todos():
    """Sincroniza los candidatos de TODAS las alertas con revisión humana."""
    n = 0
    for alerta in Alert.objects.filter(revision_humana__isnull=False).select_related(
            "revision_humana", "activo_logico"):
        sincronizar_candidato(alerta)
        n += 1
    return n


def vista_bandeja():
    """Filas para la plantilla de la bandeja (datos ya seguros)."""
    filas = []
    for cand in CandidatoDataset.objects.select_related(
            "alerta", "alerta__revision_humana", "completado_por"):
        a = cand.alerta
        rev = getattr(a, "revision_humana", None)
        salida = salida_objetivo_actual_desde(a)
        filas.append({
            "ejemplo_id": cand.ejemplo_id,
            "familia": familia_alerta(a),
            "activo_anonimizado": activo_anonimizado(a),
            "veredicto_ia_original": a.veredicto_ia or "—",
            "verdad_terreno": (rev.veredicto_verdad_terreno if rev else None)
                              or ("(excluida)" if rev and rev.accion == "EXCLUIDA" else "—"),
            "riesgo": salida.get("risk") or "—",
            "estado": cand.estado,
            "estado_display": dict(CandidatoDataset.ESTADO_CHOICES).get(cand.estado, cand.estado),
            "privacidad_ok": cand.privacidad_ok,
            "duplicado_de": cand.duplicado_de,
            "salida_revisada": cand.salida_objetivo_revisada,
            "completado_por": getattr(cand.completado_por, "username", None),
            "incompleta_por": (cand.diagnostico or {}).get("incompleta_por", []),
        })
    return filas


# =====================================================================
# 3B — editor y doble revisión
# =====================================================================
_CAMPOS_SALIDA_EDITABLE = (
    "risk", "explanation_es", "cvss_reasoning_es", "recommendation_es", "missing_evidence",
)


def _contrato_dict(salida):
    """Normaliza `salida` a la forma del contrato JSON (8 campos)."""
    s = dict(salida or {})
    s.setdefault("schema_version", "1.0")
    me = s.get("missing_evidence") or []
    if isinstance(me, str):
        me = [x.strip() for x in me.splitlines() if x.strip()]
    s["missing_evidence"] = me
    s["cvss_factors"] = dict(s.get("cvss_factors") or {})
    return {
        "schema_version": s.get("schema_version", "1.0"),
        "verdict": s.get("verdict"),
        "risk": s.get("risk"),
        "explanation_es": s.get("explanation_es", ""),
        "cvss_factors": s["cvss_factors"],
        "cvss_reasoning_es": s.get("cvss_reasoning_es", ""),
        "recommendation_es": s.get("recommendation_es", ""),
        "missing_evidence": s["missing_evidence"],
    }


def salida_objetivo_actual_desde(alerta):
    """Borrador editado si existe; si no, la salida derivada automáticamente."""
    cand = getattr(alerta, "candidato_dataset", None)
    if cand is not None and cand.salida_objetivo_editada:
        return _contrato_dict(cand.salida_objetivo_editada)
    return construir_salida_objetivo(alerta)


def salida_objetivo_actual(cand):
    if cand.salida_objetivo_editada:
        return _contrato_dict(cand.salida_objetivo_editada)
    return construir_salida_objetivo(cand.alerta)


def respuesta_original_gemini(alerta):
    """Respuesta ORIGINAL de la IA (sólo lectura). Nunca modificable."""
    try:
        data = json.loads(alerta.respuesta_ia_original or "")
        if isinstance(data, dict):
            return data
    except (ValueError, TypeError):
        pass
    return {
        "schema_version": "1.0",
        "verdict": alerta.veredicto_ia,
        "risk": alerta.riesgo_ia,
        "explanation_es": alerta.explicacion_ia or "",
        "cvss_factors": alerta.factores_cvss or {},
        "cvss_reasoning_es": alerta.justificacion_cvss or "",
        "recommendation_es": alerta.recomendacion_ia or "",
        "missing_evidence": alerta.evidencia_faltante or [],
    }


_ES_STOPWORDS = (" el ", " la ", " los ", " las ", " un ", " una ", " de ", " del ",
                 " que ", " se ", " con ", " por ", " para ", " no ", " es ", " en ")


def _parece_espanol(texto):
    t = f" {(texto or '').lower()} "
    return sum(1 for w in _ES_STOPWORDS if w in t) >= 2


def _privacidad_de_salida(alerta, salida):
    """(ok, hallazgos, fugas) para una salida objetivo concreta."""
    data = _contrato_dict(salida)
    ok, hallazgos = validar_privacidad(data)
    fugas = _fuga_de_identificadores(alerta, data)
    return (ok and not fugas), hallazgos, fugas


def validar_para_revision(cand, salida):
    """
    Comprueba si `salida` puede llevar el candidato a LISTO_PARA_REVISION.
    Devuelve (ok, errores[list[str]]).
    """
    a = cand.alerta
    errores = []
    data = _contrato_dict(salida)

    if not construir_entrada(a):
        errores.append("la alerta no tiene contexto_ia_snapshot congelado")

    val = validar_salida_ia(data)
    if not val.ok:
        errores.extend(val.errores)

    gt = a.verdad_terreno
    if not gt:
        errores.append("la alerta no tiene verdad de terreno humana")
    elif data.get("verdict") != gt:
        errores.append(f"verdict debe coincidir con la verdad de terreno ({gt})")

    if not _parece_espanol(data.get("explanation_es")):
        errores.append("explanation_es debe estar en español")
    if not _parece_espanol(data.get("recommendation_es")):
        errores.append("recommendation_es debe estar en español")

    ok_priv, hallazgos, fugas = _privacidad_de_salida(a, data)
    if not ok_priv:
        errores.append(f"privacidad: {', '.join(hallazgos + fugas) or 'no superada'}")

    if cand.duplicado_de:
        errores.append(f"posible duplicado de {cand.duplicado_de}")

    if not cand.salida_objetivo_revisada:
        errores.append("falta la confirmación explícita del revisor")

    return (not errores), errores


def _limpiar_salida_entrante(datos, verdict_bloqueado):
    """Construye la salida objetivo desde el formulario (verdict SIEMPRE = verdad de terreno)."""
    cvss = {}
    for k in CVSS_CLAVES:
        v = (datos.get(f"cvss__{k}") or "").strip()
        cvss[k] = v
    me_raw = datos.get("missing_evidence", "")
    me = [x.strip() for x in str(me_raw).splitlines() if x.strip()]
    return {
        "schema_version": "1.0",
        "verdict": verdict_bloqueado,
        "risk": (datos.get("risk") or "").strip(),
        "explanation_es": (datos.get("explanation_es") or "").strip(),
        "cvss_factors": cvss,
        "cvss_reasoning_es": (datos.get("cvss_reasoning_es") or "").strip(),
        "recommendation_es": (datos.get("recommendation_es") or "").strip(),
        "missing_evidence": me,
    }


def guardar_borrador(cand, datos, autor, *, confirmado=False):
    """
    Guarda el borrador de la salida objetivo. Rechaza si el texto introducido
    contiene datos privados (antes de guardar). No cambia el estado (salvo salir
    de DEVUELTO/LISTO -> a efectos de re-revisión se conserva el estado humano).
    Devuelve (cand, errores).

    PROTECCIÓN DE APROBADO (3C/3D): un candidato APROBADO es inmutable; esta
    función se niega a tocar su salida.
    """
    if cand.estado == "APROBADO":
        return cand, ["este candidato ya está APROBADO: la salida supervisada es inmutable"]
    a = cand.alerta
    salida = _limpiar_salida_entrante(datos, a.verdad_terreno or (a.veredicto_ia))
    ok_priv, hallazgos, fugas = _privacidad_de_salida(a, salida)
    if not ok_priv:
        return cand, [f"no se guarda: privacidad ({', '.join(hallazgos + fugas)})"]
    with transaction.atomic():
        # Fila bloqueada: la comprobación de los sellos y la escritura no se intercalan
        # con otra operación sobre el mismo candidato.
        cand = CandidatoDataset.objects.select_for_update().select_related("alerta").get(pk=cand.pk)
        if cand.estado == "APROBADO":
            return cand, ["este candidato ya está APROBADO: la salida supervisada es inmutable"]
        # Sello: la entrada que ve quien revisa se congela con el primer borrador;
        # si después cambia, no se guarda nada hasta volver a congelarla explícitamente.
        _reg, errores = sellos.asegurar_entrada_revisada(
            cand, construir_entrada(cand.alerta), _snapshot(cand.alerta), autor,
            seleccion_version=ENTRADA_SELECCION_VERSION)
        if errores:
            return cand, errores
        cand.salida_objetivo_editada = _contrato_dict(salida)
        cand.salida_objetivo_revisada = bool(confirmado)
        cand.save(update_fields=["salida_objetivo_editada", "salida_objetivo_revisada", "sincronizado_en"])
    sincronizar_candidato(a)
    cand.refresh_from_db()
    return cand, []


def enviar_a_revision(cand, datos, autor, *, confirmado):
    """
    Guarda el borrador y, si pasa todas las validaciones, deja el candidato
    LISTO_PARA_REVISION con `completado_por = autor`. Devuelve (cand, errores).

    PROTECCIÓN DE APROBADO (3C/3D): un candidato APROBADO es inmutable; esta
    función se niega a reabrirlo.
    """
    if cand.estado == "APROBADO":
        return cand, ["este candidato ya está APROBADO: es inmutable y no vuelve a revisión"]
    a = cand.alerta
    salida = _limpiar_salida_entrante(datos, a.verdad_terreno or a.veredicto_ia)
    ok_priv, hallazgos, fugas = _privacidad_de_salida(a, salida)
    if not ok_priv:
        return cand, [f"no se guarda: privacidad ({', '.join(hallazgos + fugas)})"]

    with transaction.atomic():
        cand = CandidatoDataset.objects.select_for_update().select_related("alerta").get(pk=cand.pk)
        if cand.estado == "APROBADO":
            return cand, ["este candidato ya está APROBADO: es inmutable y no vuelve a revisión"]
        reg, errores = sellos.asegurar_entrada_revisada(
            cand, construir_entrada(cand.alerta), _snapshot(cand.alerta), autor,
            seleccion_version=ENTRADA_SELECCION_VERSION)
        if errores:
            return cand, errores
        cand.salida_objetivo_editada = _contrato_dict(salida)
        cand.salida_objetivo_revisada = bool(confirmado)
        cand.save(update_fields=["salida_objetivo_editada", "salida_objetivo_revisada", "sincronizado_en"])
        cand.refresh_from_db()
        ok, errores = validar_para_revision(cand, salida)
        if not ok:
            return cand, errores
        cand.estado = "LISTO_PARA_REVISION"
        cand.completado_por = autor if getattr(autor, "pk", None) else None
        cand.completado_en = timezone.now()
        cand.save(update_fields=["estado", "completado_por", "completado_en", "sincronizado_en"])
        # Sello de la confirmación: la salida confirmada, enlazada con la entrada revisada vigente.
        sellos.sellar_confirmacion(cand, reg, cand.salida_objetivo_editada, autor)
    sincronizar_candidato(a)
    cand.refresh_from_db()
    return cand, []


def revisar_candidato(cand, *, decision, autor, observaciones=""):
    """
    Segunda revisión. Quien completó el borrador NO puede aprobar.
    `decision` ∈ {APROBADO, DEVUELTO, EXCLUIDO}. Append-only. Devuelve (cand, errores).

    PROTECCIÓN DE APROBADO (3C/3D): un candidato ya APROBADO es inmutable;
    la ÚNICA transición que admite desde ahí es una exclusión EXPLÍCITA y
    auditada (con observaciones obligatorias). Nunca se puede re-aprobar ni
    "devolver" uno ya aprobado — eso no tendría sentido y degradaría un
    resultado que debe quedar congelado.
    """
    if decision not in dict(RevisionCandidato.DECISION_CHOICES):
        return cand, [f"decisión inválida: {decision!r}"]
    autor_pk = getattr(autor, "pk", None)
    if decision in ("DEVUELTO", "EXCLUIDO") and not (observaciones or "").strip():
        return cand, ["hace falta una observación para devolver o excluir"]

    with transaction.atomic():
        # Fila bloqueada: estado, sellos y registro de la decisión se comprueban y
        # escriben sin que otra operación sobre el candidato se intercale.
        cand = CandidatoDataset.objects.select_for_update().select_related("alerta").get(pk=cand.pk)
        if cand.estado == "APROBADO":
            if decision != "EXCLUIDO":
                return cand, ["un candidato APROBADO es inmutable: sólo admite una exclusión explícita y auditada"]
        elif cand.estado not in ("LISTO_PARA_REVISION", "DEVUELTO"):
            return cand, ["el candidato no está listo para una segunda revisión"]
        if decision == "APROBADO" and cand.completado_por_id and autor_pk == cand.completado_por_id:
            return cand, ["quien completó el borrador no puede aprobarlo: hace falta un segundo revisor"]

        entrada, snap, salida = construir_entrada(cand.alerta), _snapshot(cand.alerta), salida_objetivo_actual(cand)
        if decision == "APROBADO":
            ok, errores = validar_para_revision(cand, salida)
            if not ok:
                return cand, ["no se puede aprobar: " + "; ".join(errores)]
            # La entrada y la salida deben ser exactamente las confirmadas.
            errores = sellos.verificar_para_aprobar(cand, entrada, snap, salida)
            if errores:
                return cand, ["no se puede aprobar: " + "; ".join(errores)]

        RevisionCandidato.objects.create(
            candidato=cand, decision=decision,
            autor=autor if autor_pk else None,
            observaciones=(observaciones or "").strip(),
            entrada_sha256=sellos.huella_integridad(entrada) if entrada else "",
            salida_sha256=sellos.huella_integridad(salida),
            serializacion_version=sellos.SERIALIZACION_VERSION,
        )
        if decision == "APROBADO":
            cand.estado = "APROBADO"
        elif decision == "DEVUELTO":
            cand.estado = "DEVUELTO"
        else:
            cand.estado = "EXCLUIDO"
        cand.save(update_fields=["estado", "sincronizado_en"])
    return cand, []
