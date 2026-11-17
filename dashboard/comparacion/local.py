"""
Mediciones de ESTA instancia: `Alert.contexto_ia_snapshot['_medicion']` (medicion_v2) -> EjecucionComparacion.

- `pendientes()` solo LEE (lo usa la página con GET): cuántas filas con medición aún no están registradas.
- `registrar()` escribe y solo se llama desde una vista POST del superusuario. Es idempotente: una alerta se
  registra una vez (OneToOne `alerta_local`, su identidad estable). Otra ejecución con la misma respuesta y UUID
  propio es una repetición distinta y no impide el registro; si la coincidencia es con un registro de identidad
  DERIVADA (línea v1 sin UUID), no se puede demostrar si es la misma ejecución: queda «ambigua» y solo se registra
  (como ejecución separada) con decisión expresa. NUNCA modifica Alert ni su snapshot: solo los lee.
- Filas sin `_medicion` (anteriores a la medición) no se registran desde aquí: su entrada y sus datos no se
  midieron en el envío. Sus referencias llegan, con sus huellas verificadas, por el archivo del paquete.
"""
from __future__ import annotations

import uuid as uuidlib

from django.db import IntegrityError, transaction

from dashboard.models import Alert, CasoComparacion, EjecucionComparacion

from . import normalizacion as N
from .textos import PREFIJO_CASO

DEFINICION_TIEMPO_LOCAL = "medicion_v2: monotonic alrededor de analizar()"


def _alertas_con_medicion():
    return Alert.objects.filter(contexto_ia_snapshot__has_key="_medicion")


def pendientes() -> int:
    registradas = EjecucionComparacion.objects.filter(alerta_local__isnull=False).values("alerta_local_id")
    return _alertas_con_medicion().exclude(pk__in=registradas).count()


WEB_PROCEDENCIA = {"en_vivo": "web_natural", "historico_reproducido": "web_historico_reproducido"}


def procedencia_derivada(alerta, snapshot) -> str:
    """Procedencia genérica (sin ids de agente ni nombres).
    Web: SOLO la evidencia explícita `evidencia_tecnica.web_procedencia` (en_vivo / historico_reproducido); si falta o
    es desconocida, «no_determinada». El retraso de recepción NO decide la procedencia (un replay puede llegar en
    segundos y un evento en vivo con días de retraso). Windows y diagnóstico del agente: por grupos de la regla."""
    grupos = {str(g).lower() for g in (alerta.wazuh_rule_groups or []) if isinstance(g, str)}
    ev = snapshot.get("evidencia_tecnica") if isinstance(snapshot.get("evidencia_tecnica"), dict) else {}
    claves = {str(k) for k in ev}
    if grupos & {"web", "accesslog"} or any(k.startswith("web_") for k in claves):
        return WEB_PROCEDENCIA.get(ev.get("web_procedencia"), "no_determinada")
    if "windows" in grupos or any(k.startswith("win_") for k in claves):
        return "windows_natural"
    if "wazuh" in grupos or "ossec" in grupos:
        return "diagnostico_agente"
    return "no_determinada"


def datos_desde_alerta(alerta) -> tuple[dict, dict]:
    """-> (caso, ejecucion) normalizados. Lanza N.DatoInvalido si la medición no es coherente."""
    snap = alerta.contexto_ia_snapshot
    med = snap.get("_medicion")
    if not isinstance(med, dict) or med.get("version") != "medicion_v2":
        raise N.DatoInvalido("medición ausente o de versión no admitida")
    params = med.get("parametros") if isinstance(med.get("parametros"), dict) else None
    formato = med.get("formato_entrada")
    caso = N.caso({
        "formato_entrada": formato, "entrada_sha256": med.get("entrada_sha256"),
        "esquema_sha256": (params or {}).get("esquema_salida_sha256"),
        "extension_web": med.get("extension_web"), "procedencia": procedencia_derivada(alerta, snap)})
    tok = med.get("tokens") if isinstance(med.get("tokens"), dict) else {}
    completed = med.get("estado_analisis") == "COMPLETED"
    cat = med.get("categoria_error_llamada") or med.get("categoria_fallo_analisis")
    ej = N.ejecucion({
        "uuid": str(uuidlib.uuid4()), "caso_clave": caso["clave"], "repeticion": None,
        "proveedor": med.get("proveedor"), "modelo_solicitado": med.get("modelo_configurado"),
        "modelo_informado": med.get("modelo_respuesta"),
        "parametros": {k: v for k, v in (params or {}).items() if k != "esquema_salida_sha256"} or None,
        "esquema_efectivo_sha256": (params or {}).get("esquema_salida_sha256"),
        "texto_enviado_sha256": med.get("entrada_sha256"),
        "equivalencia": "equivalente" if formato == "prompt_sentria" else "variante",
        "inicio_utc": med.get("inicio_llamada_utc"), "definicion_tiempo": DEFINICION_TIEMPO_LOCAL,
        "latencia_proveedor_s": med.get("duracion_llamada_s"), "duracion_analisis_s": med.get("duracion_analisis_s"),
        "duracion_ejecucion_s": None,
        "tokens_entrada": tok.get("entrada"), "tokens_salida": tok.get("salida"),
        "tokens_razonamiento": tok.get("razonamiento"), "tokens_total": tok.get("total"),
        "tokens_fuente": med.get("tokens_fuente"), "estado_llamada": med.get("estado_llamada"),
        "estado_analisis": med.get("estado_analisis"), "categoria_error": cat,
        "motivo_sin_llamada": med.get("motivo_sin_llamada"), "finish_reason": med.get("finish_reason"),
        "codigo_http": med.get("codigo_http_llamada"),
        "veredicto": alerta.veredicto_ia if completed else None,
        "riesgo": alerta.riesgo_ia if completed else None,
        "respuesta_observada": alerta.respuesta_ia_original or None,
    })
    return caso, ej


def codigo_legible(procedencia) -> str:
    """Código neutral y legible (WIN-L01, WEB-HIST-L01…). No es identidad: puede repetirse entre instancias."""
    prefijo = f"{PREFIJO_CASO.get(procedencia, 'CASO')}-L"
    n = CasoComparacion.objects.filter(codigo__startswith=prefijo).count() + 1
    return f"{prefijo}{n:02d}"


def registrar(usuario, *, incluir_ambiguas=False) -> dict:
    """Registra las mediciones locales aún no registradas. -> resumen con recuentos y motivos sanitizados."""
    resumen = {"registradas": 0, "ambiguas_no_registradas": 0, "repeticiones_con_misma_respuesta": 0,
               "no_registrables": 0, "motivos": {}, "casos_nuevos": 0}
    registradas = EjecucionComparacion.objects.filter(alerta_local__isnull=False).values("alerta_local_id")
    for alerta in _alertas_con_medicion().exclude(pk__in=registradas).order_by("pk"):
        try:
            caso_d, ej = datos_desde_alerta(alerta)
            N.cabe_en_modelo(caso_d, CasoComparacion)
            N.cabe_en_modelo(ej, EjecucionComparacion)
        except N.DatoInvalido as e:
            resumen["no_registrables"] += 1
            resumen["motivos"][str(e)] = resumen["motivos"].get(str(e), 0) + 1
            continue
        obs = N.huella_observacion(caso_d["clave"], ej["proveedor"], ej["respuesta_sha256"], ej["uuid"])
        previas = list(EjecucionComparacion.objects.filter(huella_observacion=obs)
                       .values_list("identidad_derivada", flat=True)) if ej["respuesta_sha256"] else []
        if any(previas) and not incluir_ambiguas:
            resumen["ambiguas_no_registradas"] += 1
            continue
        resumen["repeticiones_con_misma_respuesta"] += int(bool(previas))
        if not CasoComparacion.objects.filter(clave=caso_d["clave"]).exists():
            caso_d["codigo"] = codigo_legible(caso_d["procedencia"])
        try:
            with transaction.atomic():
                caso, creado = CasoComparacion.objects.get_or_create(
                    clave=caso_d["clave"], defaults={**caso_d, "origen_registro": "local"})
                resumen["casos_nuevos"] += int(creado)
                ej.pop("caso_clave")
                EjecucionComparacion.objects.create(
                    caso=caso, origen_medicion="observada_local", origen_declarado="observada_local",
                    huella_observacion=obs, huella_contenido=N.huella_contenido({**ej, "caso_clave": caso.clave}),
                    alerta_local=alerta, registrado_por=usuario, **ej)
                resumen["registradas"] += 1
        except IntegrityError:          # otra petición la registró a la vez: no se duplica
            resumen["motivos"]["registrada en paralelo"] = resumen["motivos"].get("registrada en paralelo", 0) + 1
    return resumen
