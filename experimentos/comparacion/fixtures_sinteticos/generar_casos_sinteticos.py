#!/usr/bin/env python3
"""
Genera los casos SINTÉTICOS que usan las pruebas del ejecutor de comparación (herramientas/test_ejecutor.py).

Los casos NO provienen de ningún servidor ni de ninguna alerta real: el contexto se escribe aquí a mano, la entrada
(`entrada.txt`) se construye con `dashboard.ia.prompt.construir_prompt` del propio repositorio y la respuesta
`respuesta_referencia_gemini.json` es un JSON sintético escrito a mano que cumple el contrato de salida. El nombre del
archivo es el que espera el ejecutor; su contenido no es una respuesta de Gemini.

  python generar_casos_sinteticos.py              # escribe casos/ y esquema_salida.json junto a este archivo
  python generar_casos_sinteticos.py --comprobar  # solo compara con lo versionado; sale con 1 si difiere

Sin red, sin base de datos, sin Django configurado y sin llamadas a ningún proveedor.
"""
import argparse
import hashlib
import json
import os
import sys

AQUI = os.path.dirname(os.path.abspath(__file__))
RAIZ = os.path.normpath(os.path.join(AQUI, "..", "..", ".."))
MANIFIESTO_CODIGO_SINTETICO = "0" * 64      # no hay paquete de código: marcador explícito

CONTEXTO_COMUN = {
    "asset_criticality": "media",
    "asset_os_family": "windows",
    "asset_os_role": "servidor",
    "asset_type": "servidor_interno",
    "authorized_context_es": ("Activo SINTÉTICO de ejemplo para pruebas automáticas. Servidor Windows de laboratorio "
                              "con un servicio web de demostración. No describe ningún equipo real."),
    "maintenance_category": "no_aplica",
    "maintenance_scope": "no_aplica",
    "maintenance_scope_match": "no_aplica",
    "maintenance_window": "sin_ventana_declarada",
    "observed_cvss_factors": {k: "no_determinado" for k in (
        "attack_complexity", "attack_vector", "availability_impact", "confidentiality_impact", "integrity_impact",
        "privileges_required", "scope", "user_interaction")},
    "operational_window": "dentro_horario_operativo",
    "schema_version": "1.4",
}

EVIDENCIA_BASE = {"correlated_events": "no_determinado", "file_extension": "no_aplica", "fim_event_type": "no_aplica",
                  "hash_present": False, "path_category": "no_aplica", "process_category": "no_determinado",
                  "size_info": "no_aplica", "user_role_category": "no_determinado"}

CASOS = {
    "SINT-WEB-01": {
        "tipo": "web_sintetico",
        "descripcion": "Sintético: acceso web 401 de un servicio de demostración (regla 119602, nivel 5)",
        "contexto": {
            "alert_description_es": "Acceso HTTP requiere autenticacion o fue denegado: tomcat, respuesta 401. "
                                    "No confirma un ataque.",
            "wazuh_level": 5, "wazuh_rule_id": "119602", "wazuh_rule_groups": ["sentria_web", "web", "accesslog"],
            "evidencia_tecnica": dict(EVIDENCIA_BASE, rule_groups=["sentria_web", "web", "accesslog"],
                                      rule_id="119602", telemetry_source="wazuh_acceso_web",
                                      web_bytes_respuesta=1000, web_clase_estado="4xx",
                                      web_clase_ruta="authentication_route", web_con_query="no",
                                      web_estado_http="401", web_metodo_http="GET",
                                      web_procedencia="no_determinado", web_servicio="tomcat"),
            "technical_evidence_es": ("Regla de Wazuh nivel 5 (sentria_web, web, accesslog). Caso sintético de prueba: "
                                      "servicio tomcat, método GET, respuesta HTTP 401 (4xx), clase de ruta "
                                      "authentication_route, sin parámetros de consulta, 1000 bytes. Un código HTTP "
                                      "por sí solo no confirma un ataque."),
        },
    },
    "SINT-WIN-01": {
        "tipo": "windows_sintetico",
        "descripcion": "Sintético: evento de sistema de Windows (regla 61102, nivel 5)",
        "contexto": {
            "alert_description_es": "Windows System error event",
            "wazuh_level": 5, "wazuh_rule_id": "61102", "wazuh_rule_groups": ["windows", "windows_system", "system_error"],
            "evidencia_tecnica": dict(EVIDENCIA_BASE, rule_groups=["windows", "windows_system", "system_error"],
                                      rule_id="61102", telemetry_source="wazuh_agent", win_canal="sistema",
                                      win_id_evento="7023", win_proveedor="no_determinado",
                                      win_proveedor_categoria="no_catalogado"),
            "technical_evidence_es": ("Regla de Wazuh nivel 5 (windows, windows_system, system_error). Caso sintético "
                                      "de prueba. Telemetría: wazuh_agent."),
        },
    },
}


def respuesta_sintetica(caso):
    return {
        "schema_version": "1.0",
        "verdict": "REQUIERE_ATENCION",
        "risk": "LOW",
        "explanation_es": f"Respuesta SINTÉTICA para el caso {caso}; no la produjo ningún modelo.",
        "cvss_factors": dict(CONTEXTO_COMUN["observed_cvss_factors"]),
        "cvss_reasoning_es": "Factores no determinados: caso sintético sin evidencia adicional.",
        "recommendation_es": "Sin recomendación: caso sintético de prueba.",
        "missing_evidence": ["Ninguna: caso sintético"],
    }


def _json(obj):
    return (json.dumps(obj, ensure_ascii=False, indent=1, sort_keys=True) + "\n").encode("utf-8")


def construir():
    sys.path.insert(0, RAIZ)
    from dashboard.ia.contrato import esquema_json_salida
    from dashboard.ia.prompt import construir_prompt

    esquema = esquema_json_salida()
    esq_b = _json(esquema)
    canon = json.dumps(esquema, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    archivos = {"esquema_salida.json": esq_b}
    for codigo, d in CASOS.items():
        capa_e = dict(CONTEXTO_COMUN, **d["contexto"])
        entrada = construir_prompt(capa_e).encode("utf-8")
        ctx_b, resp_b = _json(capa_e), _json(respuesta_sintetica(codigo))
        ficha = {
            "caso": codigo, "tipo": d["tipo"], "procedencia_conjunto": "no_determinada",
            "descripcion": d["descripcion"],
            "archivos": {"entrada.txt": {"sha256": hashlib.sha256(entrada).hexdigest()},
                         "contexto_capa_e.json": {"sha256": hashlib.sha256(ctx_b).hexdigest()},
                         "respuesta_referencia_gemini.json": {"sha256": hashlib.sha256(resp_b).hexdigest()}},
            "esquema_salida": {"archivo": "../../esquema_salida.json",
                               "sha256_archivo": hashlib.sha256(esq_b).hexdigest(),
                               "sha256_canonico": hashlib.sha256(canon).hexdigest()},
            "codigo": {"manifiesto_codigo_sha256": MANIFIESTO_CODIGO_SINTETICO},
            "estado_referencia": "sintetica",
            "uso": "Caso sintético para pruebas automáticas: no es una alerta real ni una respuesta de un modelo.",
        }
        base = f"casos/{codigo}/"
        archivos.update({base + "entrada.txt": entrada, base + "contexto_capa_e.json": ctx_b,
                         base + "respuesta_referencia_gemini.json": resp_b, base + "ficha.json": _json(ficha)})
    return archivos


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--comprobar", action="store_true")
    a = ap.parse_args()
    archivos = construir()
    distintos = []
    for rel, b in sorted(archivos.items()):
        ruta = os.path.join(AQUI, rel)
        if a.comprobar:
            if not os.path.isfile(ruta) or open(ruta, "rb").read() != b:
                distintos.append(rel)
            continue
        os.makedirs(os.path.dirname(ruta), exist_ok=True)
        with open(ruta, "wb") as f:
            f.write(b)
    if a.comprobar:
        print(json.dumps({"archivos": len(archivos), "distintos": distintos}, ensure_ascii=False))
        sys.exit(1 if distintos else 0)
    print(json.dumps({"escritos": sorted(archivos)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
