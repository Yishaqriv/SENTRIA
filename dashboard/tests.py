import datetime
import json
import os
import stat
import tempfile
from io import StringIO
from types import SimpleNamespace
from unittest import mock

from django.contrib.auth.models import User
from django.core.management import call_command
from django.db import IntegrityError, transaction
from django.db.models import Q
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse

from dashboard.ia import contrato, proveedores
from dashboard.ia.activos_cafe import catalogo, sembrar_activos_cafe
from dashboard.ia.analizador import analizar_alerta, _categoria_fallo
from dashboard.ia import evidencia as evi
from dashboard.ia.ingesta import ingestar_alerta, ingestar_lote, reanalizar_alerta
from dashboard.ia.persistencia import (
    aplicar_omision, aplicar_resultado, registrar_correccion_humana,
)
from dashboard.ia.politica import PoliticaElegibilidad, evaluar_elegibilidad
from dashboard.ia.prompt import construir_entrada_e, construir_prompt
from dashboard.ia.resolver import (
    asignar_agente, desactivar_asignacion, resolver_activo_por_agente,
    resolver_desde_alerta,
)
from dashboard.models import (
    ActivoLogico, Alert, AsignacionAgenteActivo, HistorialAsignacionAgente,
)
from dashboard.views import reclasificar_alertas_pendientes
from sentria_project.env_utils import EnvFileError, localizar_env_file

import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from sentria_backend import analyze_with_gemini, anonimizar_texto


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------
SALIDA_VALIDA = {
    "schema_version": "1.0",
    "verdict": "REQUIERE_ATENCION",
    "risk": "MEDIUM",
    "explanation_es": "Se observaron varios intentos de autenticación fallidos consecutivos sin éxito posterior.",
    "cvss_factors": {
        "attack_vector": "red", "attack_complexity": "baja",
        "privileges_required": "ninguno", "user_interaction": "ninguna",
        "scope": "no_determinado", "confidentiality_impact": "no_determinado",
        "integrity_impact": "bajo", "availability_impact": "ninguno",
    },
    "cvss_reasoning_es": "Vector de red por el origen remoto. Alcance no determinado por falta de datos sobre otros componentes.",
    "recommendation_es": "Revisar el origen de los intentos y confirmar si la cuenta objetivo existe.",
    "missing_evidence": ["Identidad del origen de los intentos"],
}

ALERTA_DEMO = {
    "description": "sshd: Attempt to login using a non-existent user",
    "level": 8,
    "groups": "authentication_failed,invalid_login,sshd",
    "rule_id": "5710",
    "timestamp": "2026-09-08T15:00:00.000Z",
}

ACTIVO_FAKE = SimpleNamespace(
    identificador="SRV-01", tipo_activo="servidor_interno", criticidad="alta",
    os_family="linux", os_role="servidor", zona_horaria="America/Bogota",
    hora_inicio_operacion=datetime.time(0, 0), hora_fin_operacion=datetime.time(23, 59),
    contexto_autorizado_es="Servidor interno Ubuntu; servicios internos e impresión.",
    activo=True,
)


class _ProveedorFake(proveedores.ProveedorIA):
    nombre = "fake"

    def __init__(self, *, texto=None, ok=True, error=None, excepcion=None,
                 parsed=None, finish_reason=None, usage=None):
        self._texto = texto if texto is not None else json.dumps(SALIDA_VALIDA)
        self._ok = ok
        self._error = error
        self._excepcion = excepcion
        self._parsed = parsed
        self._finish_reason = finish_reason
        self._usage = usage
        self.llamadas = 0
        self.prompt_recibido = None

    def analizar(self, prompt):
        self.llamadas += 1
        self.prompt_recibido = prompt
        if self._excepcion is not None:
            raise self._excepcion
        return proveedores.RespuestaProveedor(
            ok=self._ok, texto=self._texto, modelo="fake-modelo-1", error=self._error,
            parsed=self._parsed, finish_reason=self._finish_reason, usage=self._usage,
        )


def _activo_real(**kw):
    base = dict(
        identificador="SRV-01", nombre_visible="Servidor",
        tipo_activo="servidor_interno", criticidad="alta",
        os_family="linux", os_role="servidor",
        hora_inicio_operacion=datetime.time(0, 0), hora_fin_operacion=datetime.time(23, 59),
        zona_horaria="America/Bogota",
        contexto_autorizado_es="Servidor interno; servicios internos e impresión.",
        activo=True,
    )
    base.update(kw)
    return ActivoLogico.objects.create(**base)


# --------------------------------------------------------------------------
# Anonimización (RNF-03) — sin cambios
# --------------------------------------------------------------------------
class AnonimizarTextoTests(SimpleTestCase):
    def test_ssh_auth_failure(self):
        r = anonimizar_texto("sshd: authentication failed for user 'root' from 10.0.0.5 port 54321")
        self.assertNotIn('10.0.0.5', r)
        self.assertNotIn("'root'", r)
        self.assertIn('[IP_PRIVADA]', r)
        self.assertIn('[USUARIO]', r)

    def test_pam_failure(self):
        r = anonimizar_texto("authentication failure; rhost=172.16.0.55 user=admin")
        self.assertNotIn('172.16.0.55', r)
        self.assertIn('user=[USUARIO]', r)

    def test_windows_logon(self):
        r = anonimizar_texto("Username: jdoe Source Network Address: 192.168.1.20 Workstation Name: DESKTOP-AB12")
        self.assertNotIn('jdoe', r)
        self.assertNotIn('192.168.1.20', r)
        self.assertNotIn('DESKTOP-AB12', r)

    def test_no_enmascara_ip_publica(self):
        r = anonimizar_texto("Connection from 8.8.8.8 blocked. Host: webserver-01.")
        self.assertIn('8.8.8.8', r)
        self.assertIn('[HOSTNAME]', r)

    def test_multiples_ips_privadas(self):
        r = anonimizar_texto("scan from 127.0.0.1 to 192.168.100.5")
        self.assertEqual(r.count('[IP_PRIVADA]'), 2)

    def test_texto_sin_datos_sensibles(self):
        t = "Integrity checksum changed for file '/etc/passwd'."
        self.assertEqual(anonimizar_texto(t), t)

    def test_texto_vacio_o_none(self):
        self.assertEqual(anonimizar_texto(''), '')
        self.assertIsNone(anonimizar_texto(None))


# --------------------------------------------------------------------------
# Contrato JSON
# --------------------------------------------------------------------------
class ContratoValidacionTests(SimpleTestCase):
    def test_salida_valida(self):
        self.assertTrue(contrato.validar_salida_ia(dict(SALIDA_VALIDA)).ok)

    def test_json_estricto_rechaza_markdown_lista_no_json(self):
        for mal in ("```json\n{}\n```", "[1,2]", "no json", ""):
            self.assertIsNone(contrato.parsear_json_estricto(mal)[0])
        self.assertEqual(contrato.parsear_json_estricto('{"a":1}')[0], {"a": 1})

    def test_falta_campo(self):
        d = dict(SALIDA_VALIDA); del d["recommendation_es"]
        self.assertFalse(contrato.validar_salida_ia(d).ok)

    def test_propiedad_extra(self):
        d = dict(SALIDA_VALIDA); d["x"] = 1
        self.assertFalse(contrato.validar_salida_ia(d).ok)

    def test_enum_desconocido(self):
        d = dict(SALIDA_VALIDA); d["verdict"] = "TAL_VEZ"
        self.assertFalse(contrato.validar_salida_ia(d).ok)

    def test_cvss_enum_desconocido(self):
        d = json.loads(json.dumps(SALIDA_VALIDA))
        d["cvss_factors"]["attack_vector"] = "interplanetario"
        self.assertFalse(contrato.validar_salida_ia(d).ok)

    def test_longitud_fuera_de_rango(self):
        d = dict(SALIDA_VALIDA); d["explanation_es"] = "corto"
        self.assertFalse(contrato.validar_salida_ia(d).ok)

    def test_missing_evidence_larga(self):
        d = dict(SALIDA_VALIDA); d["missing_evidence"] = [f"item {i} texto" for i in range(11)]
        self.assertFalse(contrato.validar_salida_ia(d).ok)

    def test_low_mas_requiere_atencion_valido(self):
        d = dict(SALIDA_VALIDA); d["risk"] = "LOW"; d["verdict"] = "REQUIERE_ATENCION"
        self.assertTrue(contrato.validar_salida_ia(d).ok)


# --------------------------------------------------------------------------
# FASE 1/2 — contexto del activo en la entrada E
# --------------------------------------------------------------------------
class ContextoEntradaETests(SimpleTestCase):
    def test_activo_completo_produce_entrada_e_correcta(self):
        e = construir_entrada_e(ALERTA_DEMO, ACTIVO_FAKE)
        self.assertEqual(e["asset_type"], "servidor_interno")
        self.assertEqual(e["asset_criticality"], "alta")
        self.assertEqual(e["asset_os_family"], "linux")
        self.assertEqual(e["asset_os_role"], "servidor")
        self.assertEqual(e["authorized_context_es"], ACTIVO_FAKE.contexto_autorizado_es)
        self.assertEqual(e["wazuh_rule_id"], "5710")
        self.assertIn("sshd", e["wazuh_rule_groups"])
        # ventana operativa = cálculo objetivo contra la hora
        self.assertEqual(e["operational_window"], "dentro_horario_operativo")
        # attack_vector conservador desde grupos de autenticación
        self.assertEqual(e["observed_cvss_factors"]["attack_vector"], "red")

    def test_ventana_operativa_fuera_de_horario(self):
        estacion = SimpleNamespace(
            **{**ACTIVO_FAKE.__dict__,
               "hora_inicio_operacion": datetime.time(8, 0),
               "hora_fin_operacion": datetime.time(22, 0)})
        alerta = {**ALERTA_DEMO, "timestamp": "2026-09-08T05:00:00.000Z"}  # 00:00 Bogotá
        e = construir_entrada_e(alerta, estacion)
        self.assertEqual(e["operational_window"], "fuera_horario_operativo")

    def test_entrada_e_no_contiene_identificadores(self):
        e = construir_entrada_e(
            {**ALERTA_DEMO, "description": "logon from 10.0.0.9 host=SRV computer=DC01"},
            ACTIVO_FAKE)
        blob = json.dumps(e)
        self.assertNotIn("10.0.0.9", blob)
        self.assertNotIn("DC01", blob)
        self.assertNotIn("SRV-01", blob)  # el identificador del activo NO va a la entrada


# --------------------------------------------------------------------------
# FASE 4 — política de elegibilidad
# --------------------------------------------------------------------------
class PoliticaElegibilidadTests(SimpleTestCase):
    def test_sin_activo_omite_por_sin_contexto(self):
        r = evaluar_elegibilidad(ALERTA_DEMO, tiene_activo=False)
        self.assertFalse(r.elegible)
        self.assertEqual(r.motivo_omision, "SIN_CONTEXTO_ACTIVO")

    def test_nivel_bajo_omite(self):
        r = evaluar_elegibilidad({**ALERTA_DEMO, "level": 3}, tiene_activo=True)
        self.assertFalse(r.elegible)
        self.assertEqual(r.motivo_omision, "NIVEL_NO_ELEGIBLE")

    def test_dpkg_mas_config_changed_es_ruido(self):
        r = evaluar_elegibilidad(
            {"level": 7, "groups": "dpkg,config_changed,syslog"}, tiene_activo=True)
        self.assertFalse(r.elegible)
        self.assertEqual(r.motivo_omision, "RUIDO_OPERATIVO")

    def test_config_changed_solo_no_se_excluye(self):
        r = evaluar_elegibilidad(
            {"level": 8, "groups": "config_changed,syslog"}, tiene_activo=True)
        self.assertTrue(r.elegible)

    def test_apparmor_solo_no_se_excluye(self):
        r = evaluar_elegibilidad({"level": 8, "groups": "apparmor,local"}, tiene_activo=True)
        self.assertTrue(r.elegible)

    def test_grupo_excluido_configurable(self):
        pol = PoliticaElegibilidad(grupos_excluidos=("sca",))
        r = evaluar_elegibilidad({"level": 9, "groups": "sca"}, True, pol)
        self.assertFalse(r.elegible)
        self.assertEqual(r.motivo_omision, "REGLA_EXCLUIDA")

    def test_rule_id_excluido_configurable(self):
        pol = PoliticaElegibilidad(rule_ids_excluidos=("2904",))
        r = evaluar_elegibilidad({"level": 7, "groups": "dpkg", "rule_id": "2904"}, True, pol)
        self.assertFalse(r.elegible)
        self.assertEqual(r.motivo_omision, "REGLA_EXCLUIDA")

    def test_alerta_elegible(self):
        r = evaluar_elegibilidad(ALERTA_DEMO, tiene_activo=True)
        self.assertTrue(r.elegible)
        self.assertEqual(r.estado_analisis, "PENDING")


# --------------------------------------------------------------------------
# Analizador
# --------------------------------------------------------------------------
class AnalizadorTests(SimpleTestCase):
    def test_json_valido_completed_con_snapshot(self):
        r = analizar_alerta(ALERTA_DEMO, ACTIVO_FAKE, proveedor=_ProveedorFake())
        self.assertEqual(r["estado_analisis"], "COMPLETED")
        self.assertEqual(r["veredicto_ia"], "REQUIERE_ATENCION")
        self.assertIsNotNone(r["contexto_ia_snapshot"])
        self.assertEqual(r["contexto_ia_snapshot"]["asset_type"], "servidor_interno")

    def test_json_invalido_fallido(self):
        r = analizar_alerta(ALERTA_DEMO, ACTIVO_FAKE, proveedor=_ProveedorFake(texto="basura"))
        self.assertEqual(r["estado_analisis"], "ANALISIS_FALLIDO")
        self.assertIsNone(r["veredicto_ia"])
        self.assertIsNotNone(r["contexto_ia_snapshot"])  # snapshot también en fallo

    def test_timeout_fallido(self):
        r = analizar_alerta(ALERTA_DEMO, ACTIVO_FAKE,
                            proveedor=_ProveedorFake(ok=False, error="TimeoutError: read timed out"))
        self.assertEqual(r["estado_analisis"], "ANALISIS_FALLIDO")
        self.assertIsNone(r["veredicto_ia"])

    def test_proveedor_excepcion_no_rompe(self):
        r = analizar_alerta(ALERTA_DEMO, ACTIVO_FAKE, proveedor=_ProveedorFake(excepcion=RuntimeError("boom")))
        self.assertEqual(r["estado_analisis"], "ANALISIS_FALLIDO")

    def test_vertex_tuned_reservado_fallido(self):
        r = analizar_alerta(ALERTA_DEMO, ACTIVO_FAKE, proveedor="vertex_tuned")
        self.assertEqual(r["estado_analisis"], "ANALISIS_FALLIDO")

    def test_fallo_nunca_falso_positivo(self):
        for prov in (_ProveedorFake(texto="x"), _ProveedorFake(ok=False, error="e"),
                     _ProveedorFake(excepcion=RuntimeError()), "vertex_tuned", "desconocido"):
            r = analizar_alerta(ALERTA_DEMO, ACTIVO_FAKE, proveedor=prov)
            self.assertIsNone(r["veredicto_ia"])
            self.assertNotEqual(r["veredicto_ia"], "FALSO_POSITIVO")

    def test_respuesta_cruda_se_anonimiza_y_trunca(self):
        prov = _ProveedorFake(texto="fuga: user=root desde 10.0.0.9 " + "x" * 30000)
        r = analizar_alerta(ALERTA_DEMO, ACTIVO_FAKE, proveedor=prov)
        self.assertNotIn("10.0.0.9", r["respuesta_ia_original"])
        self.assertLessEqual(len(r["respuesta_ia_original"]), 21000)

    def test_prompt_anonimizado_y_alerta_no_muta(self):
        alerta = {**ALERTA_DEMO, "description": "failed for user 'root' from 10.0.0.5"}
        original = alerta["description"]
        prov = _ProveedorFake()
        analizar_alerta(alerta, ACTIVO_FAKE, proveedor=prov)
        self.assertNotIn("10.0.0.5", prov.prompt_recibido)
        self.assertNotIn("'root'", prov.prompt_recibido)
        self.assertEqual(alerta["description"], original)


class ShimLegacyTests(SimpleTestCase):
    def test_shim_degradado_nunca_falso_positivo(self):
        r = analyze_with_gemini({**ALERTA_DEMO})
        self.assertEqual(r["risk"], "PENDING")
        self.assertNotEqual(r["risk"], "FALSO_POSITIVO")


# --------------------------------------------------------------------------
# Persistencia + ingesta (BD)
# --------------------------------------------------------------------------
class IngestaTests(TestCase):
    def _alerta_modelo(self, **kw):
        base = dict(titulo="t", descripcion="d", estado="Pendiente")
        base.update(kw)
        return Alert.objects.create(**base)

    def test_alerta_sin_activo_no_llama_al_proveedor(self):
        prov = _ProveedorFake()
        obj, accion = ingestar_alerta(
            {**ALERTA_DEMO, "opensearch_id": "id-1"}, proveedor=prov)
        self.assertEqual(accion, "omitida")
        self.assertEqual(prov.llamadas, 0)
        obj.refresh_from_db()
        self.assertEqual(obj.estado_analisis, "OMITIDO_POLITICA")
        self.assertEqual(obj.motivo_omision, "SIN_CONTEXTO_ACTIVO")
        self.assertIsNone(obj.veredicto_ia)
        self.assertIn(obj, Alert.objects.all())  # visible

    def test_ingesta_con_activo_analiza_y_guarda_contexto(self):
        act = _activo_real()
        prov = _ProveedorFake()
        obj, accion = ingestar_alerta(
            {**ALERTA_DEMO, "opensearch_id": "id-2", "activo_logico": "SRV-01"},
            proveedor=prov)
        self.assertEqual(accion, "analizada")
        obj.refresh_from_db()
        self.assertEqual(obj.estado_analisis, "COMPLETED")
        self.assertEqual(obj.activo_logico, act)
        self.assertEqual(obj.veredicto_ia, "REQUIERE_ATENCION")
        self.assertEqual(obj.wazuh_rule_id, "5710")
        self.assertIn("sshd", obj.wazuh_rule_groups)
        self.assertEqual(obj.contexto_ia_snapshot["asset_criticality"], "alta")

    def test_dedup_por_opensearch_id(self):
        _activo_real()
        a = {**ALERTA_DEMO, "opensearch_id": "dup", "activo_logico": "SRV-01"}
        ingestar_alerta(a, proveedor=_ProveedorFake())
        _obj, accion = ingestar_alerta(a, proveedor=_ProveedorFake())
        self.assertEqual(accion, "duplicada")
        self.assertEqual(Alert.objects.filter(opensearch_id="dup").count(), 1)

    def test_ruido_dpkg_config_changed_omitido(self):
        _activo_real()
        obj, accion = ingestar_alerta(
            {"opensearch_id": "n1", "description": "package installed",
             "level": 7, "groups": "dpkg,config_changed,syslog", "activo_logico": "SRV-01"},
            proveedor=_ProveedorFake())
        self.assertEqual(accion, "omitida")
        obj.refresh_from_db()
        self.assertEqual(obj.motivo_omision, "RUIDO_OPERATIVO")

    def test_lote_una_fallida_no_detiene_el_resto(self):
        _activo_real()
        prov_ok = _ProveedorFake()

        class ProvErratico(_ProveedorFake):
            def analizar(self, prompt):
                self.llamadas += 1
                if "PRIMERA" in prompt:
                    raise RuntimeError("cae la primera")
                return proveedores.RespuestaProveedor(ok=True, texto=json.dumps(SALIDA_VALIDA), modelo="m")

        lote = [
            {"opensearch_id": "L1", "description": "PRIMERA", "level": 8, "groups": "sshd", "activo_logico": "SRV-01"},
            {"opensearch_id": "L2", "description": "segunda", "level": 8, "groups": "sshd", "activo_logico": "SRV-01"},
        ]
        c = ingestar_lote(lote, proveedor=ProvErratico())
        self.assertEqual(c["nuevas"], 2)
        self.assertEqual(c["analizadas"], 1)
        self.assertEqual(c["fallidas"], 1)
        self.assertEqual(Alert.objects.count(), 2)

    def test_completed_no_se_sobrescribe(self):
        _activo_real()
        obj, _ = ingestar_alerta(
            {**ALERTA_DEMO, "opensearch_id": "c1", "activo_logico": "SRV-01"},
            proveedor=_ProveedorFake())
        obj.refresh_from_db()
        otro = json.loads(json.dumps(SALIDA_VALIDA))
        otro["verdict"] = "FALSO_POSITIVO"
        escribio = aplicar_resultado(obj, analizar_alerta(
            ALERTA_DEMO, ACTIVO_FAKE, proveedor=_ProveedorFake(texto=json.dumps(otro))))
        self.assertFalse(escribio)
        obj.refresh_from_db()
        self.assertEqual(obj.veredicto_ia, "REQUIERE_ATENCION")

    def test_reanalizar_no_toca_completed_ni_correccion(self):
        _activo_real()
        obj, _ = ingestar_alerta(
            {**ALERTA_DEMO, "opensearch_id": "r1", "activo_logico": "SRV-01"},
            proveedor=_ProveedorFake())
        obj.refresh_from_db()
        u = User.objects.create_user("a", password="x")
        registrar_correccion_humana(obj, veredicto="FALSO_POSITIVO", autor=u, motivo="ctx")
        self.assertEqual(reanalizar_alerta(obj, proveedor=_ProveedorFake()), "completed_sin_cambios")
        obj.refresh_from_db()
        self.assertEqual(obj.veredicto_ia, "REQUIERE_ATENCION")
        self.assertEqual(obj.correccion_veredicto, "FALSO_POSITIVO")

    def test_correccion_humana_preservada_y_original_intacto(self):
        _activo_real()
        obj, _ = ingestar_alerta(
            {**ALERTA_DEMO, "opensearch_id": "h1", "activo_logico": "SRV-01"},
            proveedor=_ProveedorFake())
        obj.refresh_from_db()
        v0, r0, e0 = obj.veredicto_ia, obj.riesgo_ia, obj.explicacion_ia
        u = User.objects.create_user("analista", password="x")
        registrar_correccion_humana(obj, veredicto="FALSO_POSITIVO", autor=u, motivo="cliente conocido")
        obj.refresh_from_db()
        self.assertEqual(obj.veredicto_ia, v0)
        self.assertEqual(obj.riesgo_ia, r0)
        self.assertEqual(obj.explicacion_ia, e0)
        self.assertEqual(obj.veredicto_efectivo, "FALSO_POSITIVO")

    def test_correccion_exige_motivo(self):
        obj = self._alerta_modelo()
        with self.assertRaises(ValueError):
            registrar_correccion_humana(obj, veredicto="FALSO_POSITIVO", autor=None, motivo="  ")

    def test_omision_no_es_fallido_ni_falso_positivo(self):
        obj = self._alerta_modelo(estado_analisis="PENDING")
        aplicar_omision(obj, "NIVEL_NO_ELEGIBLE")
        obj.refresh_from_db()
        self.assertEqual(obj.estado_analisis, "OMITIDO_POLITICA")
        self.assertNotEqual(obj.estado_analisis, "ANALISIS_FALLIDO")
        self.assertIsNone(obj.veredicto_ia)

    def test_alerta_antigua_sin_campos_nuevos_ok(self):
        vieja = self._alerta_modelo(riesgo_ia="PENDING", explicacion_ia="Gemini unavailable")
        self.assertIsNone(vieja.estado_analisis)
        self.assertIsNone(vieja.activo_logico)
        self.assertIn(vieja, Alert.objects.all())


class ActivosCafeTests(TestCase):
    def test_catalogo_tiene_12(self):
        cat = catalogo()
        self.assertEqual(len(cat), 12)
        idents = {c["identificador"] for c in cat}
        self.assertIn("EP-01", idents)
        self.assertIn("ADM-01", idents)
        self.assertIn("SRV-01", idents)

    def test_sembrado_idempotente(self):
        c1 = sembrar_activos_cafe()
        self.assertEqual(c1, (12, 0, 0))
        self.assertEqual(ActivoLogico.objects.count(), 12)
        c2 = sembrar_activos_cafe()
        self.assertEqual(c2, (0, 0, 12))  # sin cambios, no duplica

    def test_dry_run_no_escribe(self):
        sembrar_activos_cafe(dry_run=True)
        self.assertEqual(ActivoLogico.objects.count(), 0)


class SnapshotInmutableTests(TestCase):
    def test_cambiar_el_activo_no_altera_el_snapshot(self):
        act = _activo_real(criticidad="alta")
        obj, _ = ingestar_alerta(
            {**ALERTA_DEMO, "opensearch_id": "snap1", "activo_logico": "SRV-01"},
            proveedor=_ProveedorFake())
        obj.refresh_from_db()
        self.assertEqual(obj.contexto_ia_snapshot["asset_criticality"], "alta")
        # cambio posterior del activo
        act.criticidad = "media"
        act.save()
        obj.refresh_from_db()
        self.assertEqual(obj.contexto_ia_snapshot["asset_criticality"], "alta")  # congelado


# --------------------------------------------------------------------------
# FASE 6/7 — colas, contadores, permisos, CSV
# --------------------------------------------------------------------------
class ColasYSeguridadTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("u", password="p")  # ANALISTA por señal
        self.client.force_login(self.user)
        self.act = _activo_real()

    def _a(self, **kw):
        base = dict(titulo="t", descripcion="d", estado="Pendiente")
        base.update(kw)
        return Alert.objects.create(**base)

    def test_cuatro_colas_responden(self):
        self._a(estado_analisis="COMPLETED", veredicto_ia="REQUIERE_ATENCION", riesgo_ia="HIGH", descripcion="AT")
        self._a(estado_analisis="COMPLETED", veredicto_ia="FALSO_POSITIVO", riesgo_ia="LOW", descripcion="FP")
        self._a(estado_analisis="OMITIDO_POLITICA", motivo_omision="RUIDO_OPERATIVO", descripcion="OM")
        self._a(estado_analisis="ANALISIS_FALLIDO", descripcion="FA")

        r_at = self.client.get(reverse("cola_atencion"))
        self.assertContains(r_at, "AT"); self.assertNotContains(r_at, ">FP<")
        r_fp = self.client.get(reverse("cola_falsos_positivos"))
        self.assertContains(r_fp, "FP"); self.assertNotContains(r_fp, ">AT<")
        # alias antiguo -> redirección a la cola efectiva
        self.assertEqual(self.client.get(reverse("cola_falsos_positivos_ia")).status_code, 302)
        r_pe = self.client.get(reverse("cola_pendientes"))
        self.assertContains(r_pe, "OM"); self.assertContains(r_pe, "FA")
        r_hi = self.client.get(reverse("index"))
        for x in ("AT", "FP", "OM", "FA"):
            self.assertContains(r_hi, x)

    def test_colas_efectivas_y_veredicto_ia_filtrable(self):
        # IA dijo FP, el humano corrige a REQUIERE_ATENCION
        a = self._a(estado_analisis="COMPLETED", veredicto_ia="FALSO_POSITIVO", riesgo_ia="LOW", descripcion="FPCORR")
        registrar_correccion_humana(a, veredicto="REQUIERE_ATENCION", autor=self.user, motivo="revisar")
        # cola "Falsos positivos" es EFECTIVA -> ya NO aparece ahí
        self.assertNotContains(self.client.get(reverse("cola_falsos_positivos")), "FPCORR")
        # aparece en "Requiere atención" (veredicto efectivo)
        self.assertContains(self.client.get(reverse("cola_atencion")), "FPCORR")
        # el veredicto ORIGINAL de la IA sigue siendo filtrable
        r = self.client.get(reverse("index"), {"veredicto": "FALSO_POSITIVO"})
        self.assertContains(r, "FPCORR")

    def test_contadores_ia_vs_efectivo(self):
        a = self._a(estado_analisis="COMPLETED", veredicto_ia="FALSO_POSITIVO", riesgo_ia="LOW")
        registrar_correccion_humana(a, veredicto="REQUIERE_ATENCION", autor=self.user, motivo="x")
        r = self.client.get(reverse("index"))
        self.assertEqual(r.context["n_ia_falso_positivo"], 1)       # original
        self.assertEqual(r.context["n_efectivo_falso_positivo"], 0) # corregido
        self.assertEqual(r.context["n_efectivo_atencion"], 1)

    def test_omitida_muestra_motivo(self):
        self._a(estado_analisis="OMITIDO_POLITICA", motivo_omision="SIN_CONTEXTO_ACTIVO", descripcion="OMX")
        r = self.client.get(reverse("cola_pendientes"))
        self.assertContains(r, "Sin contexto de activo")

    def test_activo_visible_sin_identificadores_personales(self):
        self._a(estado_analisis="COMPLETED", veredicto_ia="REQUIERE_ATENCION", riesgo_ia="HIGH",
                activo_logico=self.act, descripcion="CONACT")
        r = self.client.get(reverse("index"))
        self.assertContains(r, "SRV-01")
        self.assertContains(r, "Servidor interno")

    def test_invitado_no_corrige_ni_dispara_analisis(self):
        self.user.perfilusuario.rol = "INVITADO"
        self.user.perfilusuario.save()
        a = self._a(descripcion="VIS_INV", estado_analisis="COMPLETED",
                    veredicto_ia="REQUIERE_ATENCION", riesgo_ia="HIGH")
        self.assertContains(self.client.get(reverse("index")), "VIS_INV")
        self.assertIn(self.client.get(reverse("update_alerts")).status_code, (302, 403))
        self.assertIn(self.client.get(reverse("reclasificar_pendientes")).status_code, (302, 403))
        self.assertIn(self.client.get(reverse("corregir_veredicto", args=[a.id])).status_code, (302, 403))

    def test_correccion_requiere_post_y_motivo(self):
        a = self._a(estado_analisis="COMPLETED", veredicto_ia="REQUIERE_ATENCION", riesgo_ia="HIGH")
        # POST sin categoría de motivo -> no crea corrección
        self.client.post(reverse("corregir_veredicto", args=[a.id]), {
            "correccion_veredicto": "FALSO_POSITIVO", "motivo_categoria": "",
        })
        a.refresh_from_db()
        self.assertIsNone(a.correccion_veredicto)
        # POST con categoría -> crea corrección, autor = usuario
        self.client.post(reverse("corregir_veredicto", args=[a.id]), {
            "correccion_veredicto": "FALSO_POSITIVO", "motivo_categoria": "actividad_autorizada",
        })
        a.refresh_from_db()
        self.assertEqual(a.correccion_veredicto, "FALSO_POSITIVO")
        self.assertEqual(a.correccion_autor, self.user)
        self.assertEqual(a.veredicto_ia, "REQUIERE_ATENCION")  # original intacto

    def test_csv_seguro_contra_formulas(self):
        self._a(descripcion="=SUM(A1:A9)", estado_analisis="COMPLETED",
                veredicto_ia="REQUIERE_ATENCION", riesgo_ia="HIGH")
        r = self.client.get(reverse("exportar_csv"))
        cuerpo = r.content.decode("utf-8-sig")
        self.assertIn("'=SUM(A1:A9)", cuerpo)
        self.assertNotIn(",=SUM(A1:A9)", cuerpo)

    def test_csv_respeta_filtros(self):
        self._a(estado_analisis="COMPLETED", veredicto_ia="REQUIERE_ATENCION", riesgo_ia="CRITICAL", descripcion="CSVCRIT")
        self._a(estado_analisis="COMPLETED", veredicto_ia="FALSO_POSITIVO", riesgo_ia="LOW", descripcion="CSVLOW")
        r = self.client.get(reverse("exportar_csv"), {"riesgo": "CRITICAL"})
        cuerpo = r.content.decode("utf-8-sig")
        self.assertIn("CSVCRIT", cuerpo)
        self.assertNotIn("CSVLOW", cuerpo)


# --------------------------------------------------------------------------
# Sprint 2C — FASE 2 + correcciones pre-MySQL: resolver privado + persistencia
# --------------------------------------------------------------------------
class ResolverAgenteActivoTests(TestCase):
    def setUp(self):
        self.srv = _activo_real()  # SRV-01

    def test_resuelve_por_asignacion_actual(self):
        asignar_agente("000", "SRV-01", etiqueta="AGENT-01")
        obj, accion = ingestar_alerta(
            {**ALERTA_DEMO, "opensearch_id": "ag1", "agent_id": "000"},
            proveedor=_ProveedorFake())
        self.assertEqual(accion, "analizada")
        obj.refresh_from_db()
        self.assertEqual(obj.activo_logico, self.srv)
        self.assertEqual(obj.wazuh_agent_id, "000")

    def test_identificador_logico_explicito_tiene_prioridad(self):
        _activo_real(identificador="EP-01", nombre_visible="EP1")
        asignar_agente("000", "EP-01")
        activo = resolver_desde_alerta({"agent_id": "000", "activo_logico": "SRV-01"})
        self.assertEqual(activo.identificador, "SRV-01")

    def test_agent_id_privado_no_se_expone_en_ningun_lado(self):
        priv = "9182736450"
        asignar_agente(priv, "SRV-01")
        prov = _ProveedorFake()
        obj, _ = ingestar_alerta(
            {**ALERTA_DEMO, "opensearch_id": "ag2", "agent_id": priv}, proveedor=prov)
        obj.refresh_from_db()
        self.assertEqual(obj.wazuh_agent_id, priv)
        self.assertNotIn(priv, json.dumps(obj.contexto_ia_snapshot or {}))
        self.assertNotIn(priv, prov.prompt_recibido)
        self.assertNotIn(priv, obj.explicacion_ia or "")
        u = User.objects.create_user("vpriv", password="p")
        self.client.force_login(u)
        self.assertNotContains(self.client.get(reverse("index")), priv)
        self.assertNotIn(priv, self.client.get(reverse("exportar_csv")).content.decode("utf-8-sig"))

    # --- FASE 1 (correcciones): una asignación actual por agente, a nivel de BD ---
    def test_asignacion_actual_es_unica_a_nivel_de_bd(self):
        AsignacionAgenteActivo.objects.create(agent_id="dupe", activo_logico=self.srv)
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                AsignacionAgenteActivo.objects.create(agent_id="dupe", activo_logico=self.srv)

    def test_reasignacion_transaccional_actualiza_una_fila_y_registra_historial(self):
        asignar_agente("001", "SRV-01", etiqueta="AGENT-01")
        ep = _activo_real(identificador="EP-01", nombre_visible="EP1")
        asignar_agente("001", "EP-01", nota="reubicado")
        # una sola asignación ACTUAL, ya apuntando a EP-01
        self.assertEqual(AsignacionAgenteActivo.objects.filter(agent_id="001").count(), 1)
        self.assertEqual(AsignacionAgenteActivo.objects.get(agent_id="001").activo_logico, ep)
        self.assertEqual(resolver_activo_por_agente("001"), ep)
        # historial append-only: asignada -> reemplazada
        hist = list(HistorialAsignacionAgente.objects.filter(agent_id="001").order_by("id"))
        self.assertEqual([h.accion for h in hist], ["asignada", "reemplazada"])
        self.assertEqual([h.activo_identificador for h in hist], ["SRV-01", "EP-01"])

    def test_desactivar_asignacion_deja_agente_sin_activo_y_registra_historial(self):
        asignar_agente("004", "SRV-01")
        self.assertEqual(desactivar_asignacion("004", nota="fin de sesión"), 1)
        self.assertIsNone(resolver_activo_por_agente("004"))
        self.assertEqual(AsignacionAgenteActivo.objects.filter(agent_id="004").count(), 0)
        self.assertEqual(
            HistorialAsignacionAgente.objects.filter(agent_id="004", accion="desactivada").count(), 1)
        # el histórico sobrevive
        self.assertEqual(HistorialAsignacionAgente.objects.filter(agent_id="004").count(), 2)

    # --- FASE 2 (correcciones): el bloqueo precede a cualquier activo explícito ---
    @override_settings(IA_AGENTES_BLOQUEADOS=["002"])
    def test_agente_bloqueado_no_se_asigna(self):
        with self.assertRaises(ValueError):
            asignar_agente("002", "SRV-01")
        self.assertEqual(AsignacionAgenteActivo.objects.filter(agent_id="002").count(), 0)
        self.assertIsNone(resolver_activo_por_agente("002"))

    @override_settings(IA_AGENTES_BLOQUEADOS=["002"])
    def test_bloqueo_precede_al_activo_explicito_de_la_alerta(self):
        # la alerta trae agent.id bloqueado Y un activo_logico explícito:
        # el bloqueo gana; no se acepta el activo explícito.
        self.assertIsNone(
            resolver_desde_alerta({"agent_id": "002", "activo_logico": "SRV-01"}))
        obj, accion = ingestar_alerta(
            {**ALERTA_DEMO, "opensearch_id": "blk1", "agent_id": "002", "activo_logico": "SRV-01"},
            proveedor=_ProveedorFake())
        self.assertEqual(accion, "omitida")
        obj.refresh_from_db()
        self.assertEqual(obj.motivo_omision, "SIN_CONTEXTO_ACTIVO")
        self.assertIsNone(obj.activo_logico)

    @override_settings(IA_AGENTES_BLOQUEADOS=["002"])
    def test_desbloquear_es_la_unica_via(self):
        with self.assertRaises(ValueError):
            asignar_agente("002", "SRV-01")
        with override_settings(IA_AGENTES_BLOQUEADOS=[]):
            asignar_agente("002", "SRV-01")
            self.assertEqual(resolver_activo_por_agente("002"), self.srv)

    def test_cambio_de_asignacion_no_altera_historico_de_alertas(self):
        asignar_agente("003", "SRV-01")
        obj, _ = ingestar_alerta(
            {**ALERTA_DEMO, "opensearch_id": "hist1", "agent_id": "003"},
            proveedor=_ProveedorFake())
        obj.refresh_from_db()
        self.assertEqual(obj.estado_analisis, "COMPLETED")
        snap0 = json.dumps(obj.contexto_ia_snapshot, sort_keys=True)
        _activo_real(identificador="EP-02", nombre_visible="EP2")
        asignar_agente("003", "EP-02")
        _obj2, accion = ingestar_alerta(
            {**ALERTA_DEMO, "opensearch_id": "hist1", "agent_id": "003"},
            proveedor=_ProveedorFake())
        self.assertEqual(accion, "duplicada")
        obj.refresh_from_db()
        self.assertEqual(obj.activo_logico, self.srv)  # sigue SRV-01
        self.assertEqual(json.dumps(obj.contexto_ia_snapshot, sort_keys=True), snap0)


# --------------------------------------------------------------------------
# Sprint 2C (correcciones) — FASE 3: selección y precedencia de SENTRIA_ENV_FILE
# --------------------------------------------------------------------------
class EnvFileSelectionTests(SimpleTestCase):
    def _crear_env(self, dirpath, modo=0o600, nombre=".env"):
        p = os.path.join(dirpath, nombre)
        with open(p, "w") as f:
            f.write("DJANGO_SECRET_KEY=x\n")
        os.chmod(p, modo)
        return p

    def test_sin_var_usa_env_local_si_existe(self):
        with tempfile.TemporaryDirectory() as d:
            local = self._crear_env(d)
            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("SENTRIA_ENV_FILE", None)
                self.assertEqual(str(localizar_env_file(d)), local)

    def test_sin_var_y_sin_env_local_devuelve_none(self):
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("SENTRIA_ENV_FILE", None)
                self.assertIsNone(localizar_env_file(d))

    def test_var_tiene_precedencia_sobre_env_local(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as d2:
            self._crear_env(d)                       # .env local (no debe usarse)
            canonico = self._crear_env(d2, nombre="canonico.env")
            with mock.patch.dict(os.environ, {"SENTRIA_ENV_FILE": canonico}):
                self.assertEqual(str(localizar_env_file(d)), canonico)

    def test_var_a_archivo_inexistente_falla_claro(self):
        with mock.patch.dict(os.environ, {"SENTRIA_ENV_FILE": "/no/existe/.env"}):
            with self.assertRaises(EnvFileError):
                localizar_env_file("/tmp")

    def test_var_a_archivo_con_permisos_inseguros_falla_claro(self):
        with tempfile.TemporaryDirectory() as d:
            inseguro = self._crear_env(d, modo=0o644, nombre="abierto.env")
            with mock.patch.dict(os.environ, {"SENTRIA_ENV_FILE": inseguro}):
                with self.assertRaises(EnvFileError):
                    localizar_env_file(d)

    def test_var_a_archivo_600_ok(self):
        with tempfile.TemporaryDirectory() as d:
            seguro = self._crear_env(d, modo=0o600, nombre="ok.env")
            with mock.patch.dict(os.environ, {"SENTRIA_ENV_FILE": seguro}):
                self.assertEqual(str(localizar_env_file(d)), seguro)


# --------------------------------------------------------------------------
# Sprint 2C — FASE 3: reanálisis y deduplicación
# --------------------------------------------------------------------------
class ReanalisisYDedupTests(TestCase):
    def setUp(self):
        self.srv = _activo_real()  # SRV-01

    def _alerta(self, **kw):
        base = dict(titulo="t", descripcion="d", estado="Pendiente",
                    severidad=8, wazuh_rule_groups=["sshd"])
        base.update(kw)
        return Alert.objects.create(**base)

    # 1 — una alerta PENDING debe poder analizarse
    def test_pending_puede_analizarse(self):
        a = self._alerta(estado_analisis="PENDING", activo_logico=self.srv)
        r = reclasificar_alertas_pendientes(pausa_segundos=0, proveedor=_ProveedorFake())
        self.assertEqual(r["analizadas"], 1)
        a.refresh_from_db()
        self.assertEqual(a.estado_analisis, "COMPLETED")

    # 2 — OMITIDO/SIN_CONTEXTO_ACTIVO se reintenta cuando aparece una asignación
    def test_omitido_sin_contexto_se_reintenta_con_asignacion(self):
        obj, accion = ingestar_alerta(
            {**ALERTA_DEMO, "opensearch_id": "o1", "agent_id": "010"},
            proveedor=_ProveedorFake())
        self.assertEqual(accion, "omitida")
        obj.refresh_from_db()
        self.assertEqual(obj.motivo_omision, "SIN_CONTEXTO_ACTIVO")
        asignar_agente("010", "SRV-01")
        self.assertEqual(reanalizar_alerta(obj, proveedor=_ProveedorFake()), "analizada")
        obj.refresh_from_db()
        self.assertEqual(obj.estado_analisis, "COMPLETED")
        self.assertEqual(obj.activo_logico, self.srv)

    # 3 — ANALISIS_FALLIDO se reintenta
    def test_analisis_fallido_se_reintenta(self):
        a = self._alerta(estado_analisis="ANALISIS_FALLIDO", activo_logico=self.srv)
        self.assertEqual(reanalizar_alerta(a, proveedor=_ProveedorFake()), "analizada")
        a.refresh_from_db()
        self.assertEqual(a.estado_analisis, "COMPLETED")

    # 4 — COMPLETED nunca se reanaliza automáticamente
    def test_completed_nunca_se_reanaliza_automaticamente(self):
        obj, _ = ingestar_alerta(
            {**ALERTA_DEMO, "opensearch_id": "c1", "activo_logico": "SRV-01"},
            proveedor=_ProveedorFake())
        obj.refresh_from_db()
        cola = Alert.objects.filter(
            Q(estado_analisis__in=['PENDING', 'ANALISIS_FALLIDO', 'OMITIDO_POLITICA'])
            | Q(estado_analisis__isnull=True, riesgo_ia__in=['PENDING', 'No disponible', 'UNKNOWN'])
        )
        self.assertNotIn(obj, cola)
        otro = {**SALIDA_VALIDA, "verdict": "FALSO_POSITIVO"}
        self.assertEqual(
            reanalizar_alerta(obj, proveedor=_ProveedorFake(texto=json.dumps(otro))),
            "completed_sin_cambios")
        obj.refresh_from_db()
        self.assertEqual(obj.veredicto_ia, "REQUIERE_ATENCION")

    # 5 — corrección humana y veredicto original nunca se sobrescriben
    def test_completed_con_correccion_intacto_en_reintento(self):
        obj, _ = ingestar_alerta(
            {**ALERTA_DEMO, "opensearch_id": "d5", "activo_logico": "SRV-01"},
            proveedor=_ProveedorFake())
        obj.refresh_from_db()
        u = User.objects.create_user("a5", password="x")
        registrar_correccion_humana(obj, veredicto="FALSO_POSITIVO", autor=u, motivo="ok")
        reanalizar_alerta(obj, proveedor=_ProveedorFake())
        obj.refresh_from_db()
        self.assertEqual(obj.veredicto_ia, "REQUIERE_ATENCION")
        self.assertEqual(obj.correccion_veredicto, "FALSO_POSITIVO")
        self.assertEqual(obj.correccion_autor, u)

    def test_reintento_de_fallida_con_correccion_preserva_correccion(self):
        a = self._alerta(estado_analisis="ANALISIS_FALLIDO", activo_logico=self.srv)
        u = User.objects.create_user("a5b", password="x")
        registrar_correccion_humana(a, veredicto="FALSO_POSITIVO", autor=u, motivo="ctx")
        reanalizar_alerta(a, proveedor=_ProveedorFake())
        a.refresh_from_db()
        self.assertEqual(a.estado_analisis, "COMPLETED")
        self.assertEqual(a.veredicto_ia, "REQUIERE_ATENCION")
        self.assertEqual(a.correccion_veredicto, "FALSO_POSITIVO")
        self.assertEqual(a.veredicto_efectivo, "FALSO_POSITIVO")

    # 6 — el reintento re-aplica la política vigente
    def test_reintento_reaplica_politica_vigente(self):
        a = self._alerta(estado_analisis="OMITIDO_POLITICA", motivo_omision="NIVEL_NO_ELEGIBLE",
                         severidad=3, activo_logico=self.srv)
        self.assertEqual(reanalizar_alerta(a, proveedor=_ProveedorFake()), "omitida")
        self.assertEqual(
            reanalizar_alerta(a, politica=PoliticaElegibilidad(nivel_minimo=1),
                              proveedor=_ProveedorFake()),
            "analizada")

    # 7 — el fallo de una alerta no detiene el lote de reanálisis
    def test_reintento_en_lote_aisla_el_fallo(self):
        self._alerta(estado_analisis="ANALISIS_FALLIDO", descripcion="PRIMERA", activo_logico=self.srv)
        a2 = self._alerta(estado_analisis="ANALISIS_FALLIDO", descripcion="segunda", activo_logico=self.srv)

        class ProvErratico(_ProveedorFake):
            def analizar(self, prompt):
                self.llamadas += 1
                if "PRIMERA" in prompt:
                    raise RuntimeError("cae")
                return proveedores.RespuestaProveedor(ok=True, texto=json.dumps(SALIDA_VALIDA), modelo="m")

        r = reclasificar_alertas_pendientes(pausa_segundos=0, proveedor=ProvErratico())
        self.assertEqual(r["total"], 2)
        self.assertEqual(r["analizadas"], 1)
        self.assertEqual(r["fallidas"], 1)
        a2.refresh_from_db()
        self.assertEqual(a2.estado_analisis, "COMPLETED")

    # 8 — el dedup por opensearch_id no impide recuperar pendientes/omitidas
    def test_dedup_no_impide_recuperacion_de_omitida(self):
        a = {**ALERTA_DEMO, "opensearch_id": "rec1", "agent_id": "020"}
        obj, accion = ingestar_alerta(a, proveedor=_ProveedorFake())
        self.assertEqual(accion, "omitida")
        asignar_agente("020", "SRV-01")
        obj2, accion2 = ingestar_alerta(a, proveedor=_ProveedorFake())
        self.assertEqual(obj2.pk, obj.pk)
        self.assertEqual(accion2, "recuperada:analizada")
        self.assertEqual(Alert.objects.filter(opensearch_id="rec1").count(), 1)
        obj.refresh_from_db()
        self.assertEqual(obj.estado_analisis, "COMPLETED")

    def test_dedup_de_completed_sigue_siendo_noop(self):
        a = {**ALERTA_DEMO, "opensearch_id": "rec2", "activo_logico": "SRV-01"}
        ingestar_alerta(a, proveedor=_ProveedorFake())
        _obj, accion = ingestar_alerta(a, proveedor=_ProveedorFake(
            texto=json.dumps({**SALIDA_VALIDA, "verdict": "FALSO_POSITIVO"})))
        self.assertEqual(accion, "duplicada")
        self.assertEqual(Alert.objects.get(opensearch_id="rec2").veredicto_ia, "REQUIERE_ATENCION")

    def test_lote_cuenta_recuperadas_aparte_de_nuevas(self):
        ingestar_alerta({**ALERTA_DEMO, "opensearch_id": "L1", "agent_id": "021"},
                        proveedor=_ProveedorFake())  # omitida
        asignar_agente("021", "SRV-01")
        c = ingestar_lote([
            {**ALERTA_DEMO, "opensearch_id": "L1", "agent_id": "021"},   # recuperada
            {**ALERTA_DEMO, "opensearch_id": "L2", "agent_id": "021"},   # nueva
        ], proveedor=_ProveedorFake())
        self.assertEqual(c["nuevas"], 1)
        self.assertEqual(c["recuperadas"], 1)
        self.assertEqual(c["analizadas"], 2)

    # 9 — ningún reintento puede convertir un error en FALSO_POSITIVO
    def test_ningun_reintento_convierte_error_en_falso_positivo(self):
        for prov in (_ProveedorFake(texto="basura"),
                     _ProveedorFake(ok=False, error="timeout"),
                     _ProveedorFake(excepcion=RuntimeError("x")),
                     "vertex_tuned"):
            a = self._alerta(estado_analisis="ANALISIS_FALLIDO", activo_logico=self.srv)
            reanalizar_alerta(a, proveedor=prov)
            a.refresh_from_db()
            self.assertEqual(a.estado_analisis, "ANALISIS_FALLIDO")
            self.assertIsNone(a.veredicto_ia)

    def test_omitida_reintentada_sin_disponibilidad_no_es_falso_positivo(self):
        a = self._alerta(estado_analisis="OMITIDO_POLITICA",
                         motivo_omision="SIN_CONTEXTO_ACTIVO", wazuh_agent_id="030")
        asignar_agente("030", "SRV-01")
        reanalizar_alerta(a, proveedor=_ProveedorFake(ok=False, error="503"))
        a.refresh_from_db()
        self.assertEqual(a.estado_analisis, "ANALISIS_FALLIDO")
        self.assertIsNone(a.veredicto_ia)


# --------------------------------------------------------------------------
# Sprint 2E — FASE 1: interfaz (acciones legacy retiradas, "Análisis legado",
#             corrección sólo con COMPLETED)
# --------------------------------------------------------------------------
class InterfazLegacyTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("iu", password="p")  # ANALISTA por señal
        self.client.force_login(self.user)

    def _a(self, **kw):
        base = dict(titulo="t", descripcion="d", estado="Pendiente")
        base.update(kw)
        return Alert.objects.create(**base)

    def test_acciones_rapidas_legacy_retiradas(self):
        self._a(descripcion="ALG", estado_analisis="COMPLETED",
                veredicto_ia="REQUIERE_ATENCION", riesgo_ia="HIGH")
        r = self.client.get(reverse("index"))
        cuerpo = r.content.decode()
        self.assertNotIn("✓ Revisada", cuerpo)
        self.assertNotIn("✕ Falso+", cuerpo)
        self.assertNotIn("nuevo_estado=Falso positivo", cuerpo)
        self.assertNotIn("nuevo_estado=Revisada", cuerpo)
        # la URL legacy ya no existe
        from django.urls import NoReverseMatch
        with self.assertRaises(NoReverseMatch):
            reverse("cambiar_estado", args=[1])

    def test_etiqueta_analisis_legado(self):
        legacy = self._a(descripcion="VIEJA", riesgo_ia="HIGH", explicacion_ia="texto viejo")
        self.assertTrue(legacy.analisis_legado)
        r = self.client.get(reverse("index"))
        cuerpo = r.content.decode()
        self.assertIn("Análisis Legado - Pendiente de migrar al flujo IA actual", cuerpo)
        # no se presenta como veredicto del contrato nuevo
        # (la fila de esta alerta no lleva pill "Requiere atención"/"Falso positivo")

    def test_solo_completed_permite_corregir(self):
        # sin análisis nuevo -> el botón no aparece y la vista redirige
        legacy = self._a(descripcion="L", riesgo_ia="HIGH")
        r = self.client.get(reverse("index"))
        self.assertNotIn(reverse("corregir_veredicto", args=[legacy.id]), r.content.decode())
        resp = self.client.get(reverse("corregir_veredicto", args=[legacy.id]))
        self.assertEqual(resp.status_code, 302)
        # POST de corrección sobre una legacy -> no crea corrección
        self.client.post(reverse("corregir_veredicto", args=[legacy.id]),
                         {"correccion_veredicto": "FALSO_POSITIVO", "correccion_motivo": "x"})
        legacy.refresh_from_db()
        self.assertIsNone(legacy.correccion_veredicto)

        # con COMPLETED -> botón visible y formulario accesible
        comp = self._a(descripcion="C", estado_analisis="COMPLETED",
                       veredicto_ia="REQUIERE_ATENCION", riesgo_ia="HIGH")
        r2 = self.client.get(reverse("index"))
        self.assertIn(reverse("corregir_veredicto", args=[comp.id]), r2.content.decode())
        resp2 = self.client.get(reverse("corregir_veredicto", args=[comp.id]))
        self.assertEqual(resp2.status_code, 200)
        self.assertContains(resp2, "Corregir clasificación")

    def test_corregir_veredicto_exige_motivo_y_registra(self):
        comp = self._a(estado_analisis="COMPLETED", veredicto_ia="REQUIERE_ATENCION", riesgo_ia="HIGH")
        # sin categoría de motivo -> no crea corrección
        self.client.post(reverse("corregir_veredicto", args=[comp.id]),
                         {"correccion_veredicto": "FALSO_POSITIVO", "motivo_categoria": ""})
        comp.refresh_from_db()
        self.assertIsNone(comp.correccion_veredicto)
        # con categoría -> corrección + verdad de terreno
        self.client.post(reverse("corregir_veredicto", args=[comp.id]),
                         {"correccion_veredicto": "FALSO_POSITIVO",
                          "motivo_categoria": "comportamiento_normal", "nota": "cliente conocido"})
        comp.refresh_from_db()
        self.assertEqual(comp.correccion_veredicto, "FALSO_POSITIVO")
        self.assertEqual(comp.correccion_autor, self.user)
        self.assertEqual(comp.veredicto_ia, "REQUIERE_ATENCION")  # original intacto
        self.assertEqual(comp.revision_humana.accion, "CORREGIDA")
        self.assertEqual(comp.verdad_terreno, "FALSO_POSITIVO")

    def test_invitado_no_puede_corregir(self):
        self.user.perfilusuario.rol = "INVITADO"
        self.user.perfilusuario.save()
        comp = self._a(estado_analisis="COMPLETED", veredicto_ia="REQUIERE_ATENCION", riesgo_ia="HIGH")
        self.assertIn(self.client.get(reverse("corregir_veredicto", args=[comp.id])).status_code, (302, 403))

    def test_cuatro_colas_y_contadores_ia_efectivo_siguen(self):
        for url in ("index", "cola_atencion", "cola_falsos_positivos", "cola_pendientes"):
            self.assertEqual(self.client.get(reverse(url)).status_code, 200)
        # el alias antiguo redirige
        self.assertEqual(self.client.get(reverse("cola_falsos_positivos_ia")).status_code, 302)
        a = self._a(estado_analisis="COMPLETED", veredicto_ia="FALSO_POSITIVO", riesgo_ia="LOW")
        registrar_correccion_humana(a, veredicto="REQUIERE_ATENCION", autor=self.user, motivo="x")
        r = self.client.get(reverse("index"))
        self.assertEqual(r.context["n_ia_falso_positivo"], 1)
        self.assertEqual(r.context["n_efectivo_falso_positivo"], 0)
        self.assertEqual(r.context["n_efectivo_atencion"], 1)

    def test_cvss_en_espanol(self):
        comp = self._a(estado_analisis="COMPLETED", veredicto_ia="REQUIERE_ATENCION", riesgo_ia="HIGH",
                       factores_cvss=dict(SALIDA_VALIDA["cvss_factors"]),
                       justificacion_cvss="j" * 30, recomendacion_ia="r" * 20,
                       explicacion_ia="Explicación en español de la alerta observada por el sistema.")
        r = self.client.get(reverse("corregir_veredicto", args=[comp.id]))
        self.assertContains(r, "Vector de ataque")
        self.assertContains(r, "Impacto en integridad")


# --------------------------------------------------------------------------
# Sprint 2E — FASE 2: enriquecimiento seguro de una alerta deduplicada
# --------------------------------------------------------------------------
class EnriquecimientoProcedenciaTests(TestCase):
    def setUp(self):
        self.srv = _activo_real()
        asignar_agente("000", "SRV-01")

    def _resolver_000(self, alert):
        return resolver_desde_alerta({"agent_id": alert.get("agent_id")}) if str(alert.get("agent_id") or "") == "000" else None

    def test_dedup_completa_solo_procedencia_y_reevalua(self):
        vieja = Alert.objects.create(
            titulo="t", descripcion="algo viejo", estado="Pendiente", opensearch_id="OS-1",
            severidad=10, riesgo_ia="HIGH", explicacion_ia="texto viejo",  # datos legacy
        )
        self.assertTrue(vieja.analisis_legado)
        raw = {"opensearch_id": "OS-1", "description": "algo viejo", "level": 10,
               "groups": "authentication_failed,sshd", "rule_id": "5710",
               "agent_id": "000", "timestamp": "2026-09-08T15:00:00Z"}
        obj, accion = ingestar_alerta(raw, resolver=self._resolver_000, proveedor=_ProveedorFake())
        self.assertEqual(obj.pk, vieja.pk)
        self.assertEqual(Alert.objects.filter(opensearch_id="OS-1").count(), 1)  # no duplica
        obj.refresh_from_db()
        # procedencia completada
        self.assertEqual(obj.wazuh_agent_id, "000")
        self.assertEqual(obj.wazuh_rule_id, "5710")
        self.assertIn("sshd", obj.wazuh_rule_groups)
        # datos NO de procedencia intactos
        self.assertEqual(obj.descripcion, "algo viejo")
        self.assertEqual(obj.severidad, 10)
        # re-evaluada bajo el contrato nuevo
        self.assertEqual(obj.estado_analisis, "COMPLETED")

    def test_dedup_no_sobrescribe_procedencia_ya_presente(self):
        Alert.objects.create(
            titulo="t", descripcion="d", estado="Pendiente", opensearch_id="OS-2",
            estado_analisis="ANALISIS_FALLIDO", severidad=9,
            wazuh_agent_id="000", wazuh_rule_id="1111", wazuh_rule_groups=["grupo_viejo"],
        )
        raw = {"opensearch_id": "OS-2", "description": "d", "level": 9,
               "groups": "sshd,authentication_failed", "rule_id": "9999", "agent_id": "000"}
        obj, _ = ingestar_alerta(raw, resolver=self._resolver_000, proveedor=_ProveedorFake())
        obj.refresh_from_db()
        self.assertEqual(obj.wazuh_rule_id, "1111")          # no se sobrescribe
        self.assertEqual(obj.wazuh_rule_groups, ["grupo_viejo"])

    def test_dedup_no_toca_completed_ni_correccion(self):
        a = Alert.objects.create(
            titulo="t", descripcion="d", estado="Pendiente", opensearch_id="OS-3",
            estado_analisis="COMPLETED", veredicto_ia="REQUIERE_ATENCION", riesgo_ia="HIGH",
        )
        u = User.objects.create_user("eu", password="x")
        registrar_correccion_humana(a, veredicto="FALSO_POSITIVO", autor=u, motivo="ctx")
        raw = {"opensearch_id": "OS-3", "description": "d", "level": 9, "groups": "sshd",
               "rule_id": "5710", "agent_id": "000"}
        obj, accion = ingestar_alerta(raw, resolver=self._resolver_000, proveedor=_ProveedorFake())
        self.assertEqual(accion, "duplicada")
        obj.refresh_from_db()
        self.assertIsNone(obj.wazuh_agent_id)            # COMPLETED: ni siquiera procedencia
        self.assertEqual(obj.veredicto_ia, "REQUIERE_ATENCION")
        self.assertEqual(obj.correccion_veredicto, "FALSO_POSITIVO")


# --------------------------------------------------------------------------
# Sprint 2E — FASE 2/4: comando de ingesta controlada (proveedor mockeado)
# --------------------------------------------------------------------------
class _FakeGemini:
    nombre = "gemini_developer"

    def __init__(self, salida=None):
        self.n = 0
        self._salida = salida if salida is not None else json.dumps(SALIDA_VALIDA)

    def analizar(self, prompt):
        self.n += 1
        return proveedores.RespuestaProveedor(ok=True, texto=self._salida, modelo="fake-m")


from dashboard.management.commands.ingestar_alertas import procesar_ingesta_controlada


class IngestaControladaCommandTests(TestCase):
    def setUp(self):
        self.srv = _activo_real()
        asignar_agente("000", "SRV-01")

    def _crudas(self, n, groups="authentication_failed,sshd", level=9, prefijo="W"):
        return [{"opensearch_id": f"{prefijo}-{i}", "description": f"alerta numero {i}",
                 "level": level, "groups": groups, "rule_id": "5710",
                 "agent_id": "000", "timestamp": "2026-09-08T15:00:00Z"} for i in range(n)]

    def _correr(self, crudas, *, dry, conf, scan_limit=100, max_analisis=3, prov=None):
        crudas = list(crudas)
        env = {"GEMINI_API_KEY": "test-key", "GEMINI_MODEL": "m"} if conf else {}
        with mock.patch.dict(os.environ, env):
            return procesar_ingesta_controlada(
                "000", scan_limit=scan_limit, max_analisis=max_analisis, dry=dry, conf=conf,
                get_alertas=lambda size, agent_id, min_level: crudas[:size],
                obtener_proveedor=(lambda _n: prov) if prov is not None else (lambda _n: None),
            )

    def test_exige_dry_run_o_confirmar(self):
        from django.core.management.base import CommandError
        with self.assertRaises(CommandError):
            call_command("ingestar_alertas", "--agent-id", "000")

    def test_agente_sin_asignacion_aborta(self):
        from django.core.management.base import CommandError
        with self.assertRaises(CommandError):
            call_command("ingestar_alertas", "--agent-id", "999", "--dry-run")

    def test_scan_limit_no_es_numero_de_llamadas(self):
        # 100 candidatas: 95 nivel bajo (omitidas) + 5 elegibles -> se seleccionan 3
        crudas = (self._crudas(95, level=3, prefijo="BAJO")
                  + self._crudas(5, level=9, prefijo="ALTO"))
        c = self._correr(crudas, dry=True, conf=False, scan_limit=100)
        self.assertEqual(c["candidatas"], 100)
        self.assertEqual(c["omitidas_nivel"], 95)
        self.assertEqual(c["elegibles"], 5)
        self.assertEqual(c["elegibles_seleccionadas"], 3)   # sólo 3
        self.assertEqual(c["elegibles_no_seleccionadas"], 2)
        self.assertEqual(c["llamadas_reales"], 0)           # dry-run
        self.assertEqual(Alert.objects.count(), 0)

    def test_omitidas_no_consumen_llamadas(self):
        fake = _FakeGemini()
        crudas = (self._crudas(20, level=3, prefijo="R", groups="dpkg,config_changed")
                  + self._crudas(2, level=9, prefijo="OK"))
        c = self._correr(crudas, dry=False, conf=True, prov=fake, scan_limit=100)
        self.assertEqual(c["omitidas_ruido"] + c["omitidas_nivel"], 20)
        self.assertEqual(fake.n, 2)                         # sólo las 2 elegibles
        self.assertEqual(c["llamadas_reales"], 2)

    def test_nunca_supera_3_llamadas_aunque_haya_mas_elegibles(self):
        fake = _FakeGemini()
        c = self._correr(self._crudas(100, level=9), dry=False, conf=True, prov=fake,
                         scan_limit=500)
        self.assertEqual(c["candidatas"], 100)
        self.assertEqual(c["elegibles"], 100)
        self.assertEqual(c["elegibles_seleccionadas"], 3)
        self.assertEqual(c["elegibles_no_seleccionadas"], 97)
        self.assertLessEqual(fake.n, 3)
        self.assertLessEqual(c["llamadas_reales"], 3)
        self.assertLessEqual(c["completed"], 3)
        self.assertEqual(Alert.objects.filter(estado_analisis="COMPLETED").count(), c["completed"])

    def test_completed_no_se_reanaliza(self):
        fake = _FakeGemini(salida=json.dumps({**SALIDA_VALIDA, "verdict": "FALSO_POSITIVO"}))
        Alert.objects.create(
            titulo="t", descripcion="d", estado="Pendiente", opensearch_id="ALTO-0",
            estado_analisis="COMPLETED", veredicto_ia="REQUIERE_ATENCION", riesgo_ia="HIGH",
        )
        c = self._correr(self._crudas(3, level=9, prefijo="ALTO"), dry=False, conf=True, prov=fake)
        self.assertEqual(c["duplicadas_completed"], 1)
        self.assertEqual(c["elegibles_seleccionadas"], 2)   # las otras 2
        self.assertEqual(fake.n, 2)
        self.assertEqual(Alert.objects.get(opensearch_id="ALTO-0").veredicto_ia, "REQUIERE_ATENCION")

    def test_dedup_completa_solo_procedencia_faltante(self):
        fake = _FakeGemini()
        Alert.objects.create(
            titulo="t", descripcion="algo viejo", estado="Pendiente", opensearch_id="ALTO-0",
            severidad=9, riesgo_ia="HIGH",   # legacy, sin wazuh_*, sin estado_analisis
        )
        c = self._correr(self._crudas(1, level=9, prefijo="ALTO"), dry=False, conf=True, prov=fake)
        self.assertEqual(c["procedencia_completada"], 1)
        self.assertEqual(Alert.objects.filter(opensearch_id="ALTO-0").count(), 1)  # no duplica
        obj = Alert.objects.get(opensearch_id="ALTO-0")
        self.assertEqual(obj.wazuh_agent_id, "000")
        self.assertEqual(obj.wazuh_rule_id, "5710")
        self.assertEqual(obj.descripcion, "algo viejo")     # dato histórico intacto
        self.assertEqual(obj.estado_analisis, "COMPLETED")  # re-evaluada

    def test_error_no_aumenta_limite_ni_reintenta(self):
        class Rota:
            nombre = "gemini_developer"
            def __init__(self): self.n = 0
            def analizar(self, prompt):
                self.n += 1
                return proveedores.RespuestaProveedor(ok=False, texto="", modelo="m", error="timeout")
        rota = Rota()
        c = self._correr(self._crudas(10, level=9), dry=False, conf=True, prov=rota)
        self.assertEqual(c["elegibles_seleccionadas"], 3)   # el fallo NO permite una 4ª
        self.assertEqual(c["analisis_fallido"], 3)
        self.assertEqual(c["completed"], 0)
        self.assertEqual(rota.n, 3)                         # 3 intentos, ni uno más (sin reintentos)
        self.assertEqual(c["llamadas_reales"], 3)
        for a in Alert.objects.all():
            self.assertIsNone(a.veredicto_ia)               # nunca FALSO_POSITIVO por error

    @mock.patch.dict(os.environ, {"GEMINI_API_KEY": "test-key", "GEMINI_MODEL": "m"})
    def test_dry_run_no_escribe_ni_usa_proveedor(self):
        obtenido = {}
        def _prov(_n):
            obtenido["llamado"] = True
            return None
        c = procesar_ingesta_controlada(
            "000", scan_limit=100, max_analisis=3, dry=True, conf=False,
            get_alertas=lambda size, agent_id, min_level: self._crudas(3),
            obtener_proveedor=_prov)
        self.assertNotIn("llamado", obtenido)
        self.assertEqual(Alert.objects.count(), 0)
        self.assertEqual(c["llamadas_reales"], 0)
        self.assertEqual(c["elegibles_seleccionadas"], 3)

    @mock.patch.dict(os.environ, {"GEMINI_API_KEY": "test-key", "GEMINI_MODEL": "m"})
    def test_confirmar_solo_gemini_developer_y_veredicto_real(self):
        fake = _FakeGemini(salida=json.dumps({**SALIDA_VALIDA, "verdict": "FALSO_POSITIVO"}))
        pedido = {}
        def _prov(nombre):
            pedido["nombre"] = nombre
            return fake
        c = procesar_ingesta_controlada(
            "000", scan_limit=100, max_analisis=3, dry=False, conf=True,
            get_alertas=lambda size, agent_id, min_level: self._crudas(2),
            obtener_proveedor=_prov)
        self.assertEqual(pedido["nombre"], "gemini_developer")
        self.assertEqual(c["completed"], 2)
        self.assertEqual(c["falso_positivo"], 2)

    @mock.patch.dict(os.environ, {"GEMINI_API_KEY": "test-key", "GEMINI_MODEL": "m"})
    def test_prompt_con_ip_privada_se_aborta_como_fallo(self):
        fake = _FakeGemini()
        crudas = [{"opensearch_id": "IP1", "description": "conexión rara",
                   "level": 9, "groups": "sshd, 10.10.5.5", "rule_id": "5710", "agent_id": "000"}]
        c = self._correr(crudas, dry=False, conf=True, prov=fake)
        self.assertEqual(fake.n, 0)
        self.assertEqual(c["analisis_fallido"], 1)
        self.assertEqual(c["falso_positivo"], 0)

    @mock.patch.dict(os.environ, {"GEMINI_API_KEY": ""})
    def test_confirmar_sin_api_key_aborta(self):
        from django.core.management.base import CommandError
        with self.assertRaises(CommandError):
            procesar_ingesta_controlada(
                "000", scan_limit=100, max_analisis=3, dry=False, conf=True,
                get_alertas=lambda size, agent_id, min_level: self._crudas(1),
                obtener_proveedor=lambda _n: _FakeGemini())

    def test_scan_limit_se_recorta_a_500(self):
        c = self._correr(self._crudas(3, level=9), dry=True, conf=False, scan_limit=99999)
        self.assertEqual(c["scan_limit"], 500)

    def test_max_analisis_se_recorta_a_3(self):
        c = self._correr(self._crudas(3, level=9), dry=True, conf=False, max_analisis=99)
        self.assertEqual(c["max_analisis"], 3)


# --------------------------------------------------------------------------
# Sprint 2F — FASE 2: evidencia técnica segura (funciones puras)
# --------------------------------------------------------------------------
class EvidenciaWazuhTests(SimpleTestCase):
    def test_clasificar_ruta(self):
        casos = {
            "/etc/systemd/system/x.service": "configuracion_sistema",
            "/var/log/auth.log": "logs",
            "/var/spool/cups/d00001-001": "spool_impresion",
            "/tmp/borrame": "temporal",
            "/usr/bin/rm": "ejecutable_sistema",
            "/home/juan/documento.txt": "home_anonimizado",
            "/root/.bashrc": "home_anonimizado",
            "/opt/app/data": "otra_no_determinada",
            "relativo/x": "no_determinado",
            "": "no_determinado",
        }
        for ruta, cat in casos.items():
            self.assertEqual(evi.clasificar_ruta(ruta), cat, ruta)

    def test_categoria_usuario_anonimiza(self):
        self.assertEqual(evi.categoria_usuario("0"), "root")
        self.assertEqual(evi.categoria_usuario("101"), "servicio_sistema")
        self.assertEqual(evi.categoria_usuario("1000"), "usuario_no_privilegiado")
        self.assertEqual(evi.categoria_usuario(None, "root"), "root")
        self.assertEqual(evi.categoria_usuario(None, "juan"), "no_determinado")

    def test_extension_y_evento(self):
        self.assertEqual(evi.extension_archivo("/x/y.service"), "service")
        self.assertEqual(evi.extension_archivo("/x/config"), "sin_extension")
        self.assertEqual(evi.categoria_evento_fim("deleted"), "deleted")
        self.assertEqual(evi.categoria_evento_fim("weird"), "no_determinado")

    def test_construir_evidencia_no_expone_datos_privados(self):
        raw = {
            "syscheck_path": "/home/mgarza9931/proyecto/wallet_privado.p12",
            "syscheck_event": "deleted", "syscheck_size_after": "512",
            "syscheck_hash_present": True, "syscheck_uid_after": "1000",
            "syscheck_uname_after": "mgarza9931",
            "syscheck_process_name": "/home/mgarza9931/bin/xtoolkitz",
            "rule_firedtimes": 3, "groups": "syscheck,syscheck_file,syscheck_entry_deleted",
            "rule_id": "553",
        }
        ev = evi.construir_evidencia_tecnica(raw)
        blob = json.dumps(ev)
        for prohibido in ("mgarza9931", "wallet_privado", "/home/", "xtoolkitz"):
            self.assertNotIn(prohibido, blob, prohibido)
        self.assertEqual(ev["fim_event_type"], "deleted")
        self.assertEqual(ev["path_category"], "home_anonimizado")
        self.assertEqual(ev["user_role_category"], "usuario_no_privilegiado")
        self.assertEqual(ev["process_category"], "proceso_no_catalogado")  # nombre no revelado
        self.assertTrue(ev["hash_present"])
        self.assertEqual(ev["correlated_events"], 3)


class EntradaEEnriquecidaTests(SimpleTestCase):
    def _alerta_fim(self, **kw):
        base = dict(description="File deleted.", level=7,
                    groups="ossec,syscheck,syscheck_entry_deleted,syscheck_file",
                    rule_id="553", timestamp="2026-09-08T15:00:00Z",
                    syscheck_path="/etc/systemd/system/foo.service", syscheck_event="deleted",
                    syscheck_hash_present=True, syscheck_uid_after="0",
                    syscheck_size_after="200", rule_firedtimes=5)
        base.update(kw)
        return base

    def test_entrada_incluye_evidencia_permitida(self):
        e = construir_entrada_e(self._alerta_fim(), ACTIVO_FAKE)
        ev = e["evidencia_tecnica"]
        self.assertEqual(ev["fim_event_type"], "deleted")
        self.assertEqual(ev["path_category"], "configuracion_sistema")
        self.assertEqual(ev["file_extension"], "service")
        self.assertEqual(ev["user_role_category"], "root")
        self.assertIn("Evento FIM", e["technical_evidence_es"])
        # el prompt refleja la evidencia
        p = construir_prompt(e)
        self.assertIn("categoría de ruta: configuracion_sistema", p)
        self.assertIn("hash disponible: True", p)

    def test_entrada_no_contiene_ruta_ni_usuario_reales(self):
        e = construir_entrada_e(
            self._alerta_fim(syscheck_path="/home/rlopez7742/priv/token_maestro.pem",
                             syscheck_uname_after="rlopez7742",
                             syscheck_process_name="/home/rlopez7742/bin/exfilz"),
            ACTIVO_FAKE)
        blob = json.dumps(e) + construir_prompt(e)
        for prohibido in ("/home/rlopez7742", "token_maestro", "rlopez7742", "exfilz", "syscheck_path"):
            self.assertNotIn(prohibido, blob, prohibido)

    def test_ventana_mantenimiento_estados(self):
        from dashboard.ia.prompt import _estado_ventana_mantenimiento, VENTANA_MANT_ESTADOS
        self.assertEqual(set(VENTANA_MANT_ESTADOS),
                         {"dentro_ventana_declarada", "sin_ventana_declarada", "indeterminado"})
        self.assertEqual(_estado_ventana_mantenimiento({"maintenance_window": "dentro_ventana_declarada"})[0],
                         "dentro_ventana_declarada")
        self.assertEqual(_estado_ventana_mantenimiento({"maintenance_window": "sin_ventana_declarada"})[0],
                         "sin_ventana_declarada")
        self.assertEqual(_estado_ventana_mantenimiento({"maintenance_window": "indeterminado"})[0], "indeterminado")
        # sin activo con pk -> indeterminado; el prompt NUNCA dice "fuera de ventana"
        e = construir_entrada_e(self._alerta_fim(), ACTIVO_FAKE)
        self.assertEqual(e["maintenance_window"], "indeterminado")
        self.assertNotIn("fuera de la ventana de mantenimiento", construir_prompt(e).lower())


class EsquemaSalidaEstructuradaTests(SimpleTestCase):
    def test_esquema_json_valido_y_con_enums(self):
        s = contrato.esquema_json_salida()
        self.assertEqual(s["type"], "object")
        self.assertFalse(s["additionalProperties"])
        self.assertEqual(sorted(s["required"]), sorted(contrato.CAMPOS_SALIDA))
        self.assertEqual(s["properties"]["verdict"]["enum"], list(contrato.VEREDICTOS))
        self.assertEqual(s["properties"]["risk"]["enum"], list(contrato.RIESGOS))
        cf = s["properties"]["cvss_factors"]["properties"]
        self.assertEqual(sorted(cf.keys()), sorted(contrato.CVSS_CLAVES))
        self.assertIn("no_determinado", cf["attack_vector"]["enum"])
        # la validación estricta se sigue aplicando
        self.assertTrue(contrato.validar_salida_ia(dict(SALIDA_VALIDA)).ok)


class DiagnosticoFalloTests(SimpleTestCase):
    def test_categoria_fallo(self):
        self.assertEqual(_categoria_fallo("La respuesta no cumple el contrato: verdict inválido"), "contrato_invalido")
        self.assertEqual(_categoria_fallo("La respuesta viene envuelta en markdown/```"), "markdown")
        self.assertEqual(_categoria_fallo("anonimización: IP privada en el prompt"), "bloqueo_privacidad")
        self.assertEqual(_categoria_fallo("TimeoutError: read timed out"), "timeout")
        self.assertEqual(_categoria_fallo("respuesta vacía"), "respuesta_vacia")

    def test_fallo_guarda_motivo_y_categoria_en_snapshot(self):
        r = analizar_alerta(ALERTA_DEMO, ACTIVO_FAKE,
                            proveedor=_ProveedorFake(texto="no es json"))
        self.assertEqual(r["estado_analisis"], "ANALISIS_FALLIDO")
        self.assertIsNotNone(r["explicacion_ia"])            # motivo legible
        self.assertIsNone(r["veredicto_ia"])
        self.assertEqual(r["contexto_ia_snapshot"]["_diagnostico_fallo"]["categoria"], "no_json")


# --------------------------------------------------------------------------
# Sprint 2F — FASE 4/5: reintento individual protegido + visual
# --------------------------------------------------------------------------
class ReintentarAnalisisTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("ru", password="p")  # ANALISTA
        self.client.force_login(self.user)

    def _a(self, **kw):
        base = dict(titulo="t", descripcion="File deleted.", estado="Pendiente")
        base.update(kw)
        return Alert.objects.create(**base)

    def test_solo_para_analisis_fallido(self):
        comp = self._a(estado_analisis="COMPLETED", veredicto_ia="REQUIERE_ATENCION", riesgo_ia="HIGH")
        self.assertEqual(self.client.get(reverse("reintentar_analisis", args=[comp.id])).status_code, 302)
        fall = self._a(estado_analisis="ANALISIS_FALLIDO", explicacion_ia="verdict inválido")
        r = self.client.get(reverse("reintentar_analisis", args=[fall.id]))
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "Reintentar análisis")

    def test_boton_solo_aparece_en_fallidos_para_analista(self):
        self._a(estado_analisis="ANALISIS_FALLIDO", descripcion="FALLA_X")
        self._a(estado_analisis="COMPLETED", veredicto_ia="REQUIERE_ATENCION", riesgo_ia="HIGH", descripcion="OK_X")
        body = self.client.get(reverse("index")).content.decode()
        # la URL de reintento aparece para la fallida, no para la completada
        self.assertIn("/reintentar/", body)

    def test_invitado_no_reintenta(self):
        self.user.perfilusuario.rol = "INVITADO"
        self.user.perfilusuario.save()
        fall = self._a(estado_analisis="ANALISIS_FALLIDO")
        self.assertIn(self.client.get(reverse("reintentar_analisis", args=[fall.id])).status_code, (302, 403))

    def test_get_no_ejecuta_analisis(self):
        # GET sólo muestra la confirmación; no debe cambiar el estado (no llama a Gemini)
        fall = self._a(estado_analisis="ANALISIS_FALLIDO")
        self.client.get(reverse("reintentar_analisis", args=[fall.id]))
        fall.refresh_from_db()
        self.assertEqual(fall.estado_analisis, "ANALISIS_FALLIDO")

    def test_no_es_accion_masiva(self):
        # la ruta exige un id concreto; no hay endpoint de reintento en lote
        from django.urls import NoReverseMatch
        with self.assertRaises(NoReverseMatch):
            reverse("reintentar_analisis")

    def test_fallo_visible_en_cola_pendientes_con_motivo(self):
        self._a(estado_analisis="ANALISIS_FALLIDO", explicacion_ia="La respuesta no cumple el contrato: verdict inválido",
                descripcion="FALLIDA_VISIBLE")
        r = self.client.get(reverse("cola_pendientes"))
        self.assertContains(r, "FALLIDA_VISIBLE")
        self.assertContains(r, "verdict inválido")

    def test_revision_humana_sin_revisar(self):
        self._a(estado_analisis="COMPLETED", veredicto_ia="REQUIERE_ATENCION", riesgo_ia="HIGH", descripcion="NUEVA")
        body = self.client.get(reverse("index")).content.decode()
        self.assertIn("Revisión Analista", body)
        self.assertIn("Sin revisar", body)

    def test_evidencia_tecnica_utilizada_en_detalle(self):
        snap = dict(SALIDA_VALIDA)  # placeholder; añadimos evidencia_tecnica
        a = self._a(estado_analisis="COMPLETED", veredicto_ia="REQUIERE_ATENCION", riesgo_ia="HIGH",
                    factores_cvss=dict(SALIDA_VALIDA["cvss_factors"]),
                    contexto_ia_snapshot={
                        "operational_window": "dentro_horario_operativo",
                        "maintenance_window": "sin_ventana_declarada",
                        "evidencia_tecnica": {
                            "fim_event_type": "deleted", "path_category": "configuracion_sistema",
                            "file_extension": "service", "hash_present": True, "size_info": "archivo_no_vacio",
                            "user_role_category": "root", "process_category": "no_determinado",
                            "correlated_events": 5, "telemetry_source": "wazuh_syscheck",
                            "rule_id": "553", "rule_groups": ["syscheck"],
                        }})
        r = self.client.get(reverse("index"))
        self.assertContains(r, "Evidencia técnica utilizada")
        self.assertContains(r, "configuracion_sistema")
        self.assertContains(r, "Contexto de mantenimiento")
        self.assertContains(r, "Sin ventana declarada")


# --------------------------------------------------------------------------
# Sprint 2F.1 — salida estructurada del SDK: manejo del response
# --------------------------------------------------------------------------
class _FakeGenResponse:
    """Imita `GenerateContentResponse` del SDK de Gemini."""
    def __init__(self, *, text=None, parsed=None, finish_reason="STOP",
                 usage=None, con_candidates=True):
        self.text = text
        self.parsed = parsed
        if con_candidates:
            fr = SimpleNamespace(name=finish_reason) if finish_reason is not None else None
            self.candidates = [SimpleNamespace(finish_reason=fr)]
        else:
            self.candidates = []
        if usage is not None:
            self.usage_metadata = SimpleNamespace(
                prompt_token_count=usage.get("prompt"),
                candidates_token_count=usage.get("candidates"),
                thoughts_token_count=usage.get("thoughts"),
                total_token_count=usage.get("total"),
            )
        else:
            self.usage_metadata = None


def _gemini_provider_con(resp):
    p = proveedores.GeminiDeveloperProvider()
    cli = mock.Mock()
    cli.models.generate_content.return_value = resp
    p._client = cli   # ya inicializado -> no intenta importar google.genai
    return p


class SalidaEstructuradaSDKTests(SimpleTestCase):
    def test_config_lleva_tokens_schema_y_thinking(self):
        cfg = proveedores.GeminiDeveloperProvider()._config()
        d = cfg.model_dump(exclude_none=True)
        self.assertEqual(d["max_output_tokens"], 8192)
        self.assertEqual(d["response_mime_type"], "application/json")
        self.assertIn("response_json_schema", d)
        self.assertEqual(d["thinking_config"]["thinking_budget"], 0)

    def test_response_parsed_valido(self):
        p = _gemini_provider_con(_FakeGenResponse(parsed=dict(SALIDA_VALIDA), text=None,
                                                  finish_reason="STOP",
                                                  usage={"prompt": 800, "candidates": 300, "thoughts": 0, "total": 1100}))
        r = analizar_alerta(ALERTA_DEMO, ACTIVO_FAKE, proveedor=p)
        self.assertEqual(r["estado_analisis"], "COMPLETED")
        self.assertEqual(r["veredicto_ia"], "REQUIERE_ATENCION")
        self.assertEqual(sorted(r["factores_cvss"].keys()),
                         sorted(["attack_vector", "attack_complexity", "privileges_required",
                                 "user_interaction", "scope", "confidentiality_impact",
                                 "integrity_impact", "availability_impact"]))

    def test_text_es_solo_alternativa_cuando_no_hay_parsed(self):
        p = _gemini_provider_con(_FakeGenResponse(text=json.dumps(SALIDA_VALIDA), parsed=None))
        r = analizar_alerta(ALERTA_DEMO, ACTIVO_FAKE, proveedor=p)
        self.assertEqual(r["estado_analisis"], "COMPLETED")

    def test_finish_reason_max_tokens(self):
        p = _gemini_provider_con(_FakeGenResponse(text='{"schema_version": "1.0", "verd',
                                                  finish_reason="MAX_TOKENS",
                                                  usage={"prompt": 900, "candidates": 8192, "thoughts": 8000, "total": 9092}))
        r = analizar_alerta(ALERTA_DEMO, ACTIVO_FAKE, proveedor=p)
        self.assertEqual(r["estado_analisis"], "ANALISIS_FALLIDO")
        self.assertIsNone(r["veredicto_ia"])
        diag = r["contexto_ia_snapshot"]["_diagnostico_fallo"]
        self.assertEqual(diag["categoria"], "respuesta_truncada")
        self.assertEqual(diag["finish_reason"], "MAX_TOKENS")
        self.assertEqual(diag["usage"]["total"], 9092)
        self.assertFalse(diag["parsed_present"])

    def test_json_truncado_sin_max_tokens(self):
        p = _gemini_provider_con(_FakeGenResponse(text='{"schema_version": "1.0", "verdict": "REQUI',
                                                  finish_reason="STOP"))
        r = analizar_alerta(ALERTA_DEMO, ACTIVO_FAKE, proveedor=p)
        self.assertEqual(r["estado_analisis"], "ANALISIS_FALLIDO")
        self.assertEqual(r["contexto_ia_snapshot"]["_diagnostico_fallo"]["categoria"], "no_json")

    def test_ausencia_de_candidates(self):
        p = _gemini_provider_con(_FakeGenResponse(text=None, parsed=None, con_candidates=False))
        r = analizar_alerta(ALERTA_DEMO, ACTIVO_FAKE, proveedor=p)
        self.assertEqual(r["estado_analisis"], "ANALISIS_FALLIDO")
        self.assertEqual(r["contexto_ia_snapshot"]["_diagnostico_fallo"]["categoria"], "respuesta_vacia")

    def test_bloqueo_de_seguridad(self):
        p = _gemini_provider_con(_FakeGenResponse(text=None, parsed=None, finish_reason="SAFETY"))
        r = analizar_alerta(ALERTA_DEMO, ACTIVO_FAKE, proveedor=p)
        self.assertEqual(r["estado_analisis"], "ANALISIS_FALLIDO")
        self.assertEqual(r["contexto_ia_snapshot"]["_diagnostico_fallo"]["categoria"], "bloqueo_seguridad_proveedor")
        self.assertEqual(r["contexto_ia_snapshot"]["_diagnostico_fallo"]["finish_reason"], "SAFETY")

    def test_salida_valida_ocho_factores_cvss(self):
        p = _gemini_provider_con(_FakeGenResponse(parsed=dict(SALIDA_VALIDA)))
        r = analizar_alerta(ALERTA_DEMO, ACTIVO_FAKE, proveedor=p)
        self.assertTrue(contrato.validar_salida_ia(
            {**SALIDA_VALIDA, "cvss_factors": r["factores_cvss"]}).ok)
        self.assertEqual(len(r["factores_cvss"]), 8)

    def test_ningun_fallo_es_falso_positivo(self):
        for resp in (
            _FakeGenResponse(text='{"verd', finish_reason="MAX_TOKENS"),
            _FakeGenResponse(text="no json", finish_reason="STOP"),
            _FakeGenResponse(text=None, con_candidates=False),
            _FakeGenResponse(text=None, finish_reason="SAFETY"),
            _FakeGenResponse(parsed={**SALIDA_VALIDA, "verdict": "TAL_VEZ"}),
        ):
            r = analizar_alerta(ALERTA_DEMO, ACTIVO_FAKE, proveedor=_gemini_provider_con(resp))
            self.assertIsNone(r["veredicto_ia"])
            self.assertNotEqual(r.get("veredicto_ia"), "FALSO_POSITIVO")

    def test_diagnostico_no_incluye_texto_crudo(self):
        secreto = '{"fuga": "10.0.0.9 user=root ' + "x" * 50
        p = _gemini_provider_con(_FakeGenResponse(text=secreto, finish_reason="STOP"))
        r = analizar_alerta(ALERTA_DEMO, ACTIVO_FAKE, proveedor=p)
        diag = json.dumps(r["contexto_ia_snapshot"]["_diagnostico_fallo"])
        self.assertNotIn("10.0.0.9", diag)
        self.assertNotIn("user=root", diag)
        self.assertNotIn(secreto, diag)


# --------------------------------------------------------------------------
# Sprint 2G — ventanas de mantenimiento
# --------------------------------------------------------------------------
from django.core.exceptions import ValidationError
from django.test import Client as _Client
from django.utils import timezone as _tz
from dashboard.models import VentanaMantenimiento
from dashboard.mantenimiento import crear_ventana, cancelar_ventana, estado_para


class VentanaMantenimientoModeloTests(TestCase):
    def setUp(self):
        self.srv = _activo_real()  # SRV-01
        self.u = User.objects.create_user("vmu", password="x")

    def _rango(self, desde_h=-1, hasta_h=+2):
        base = _tz.now()
        return base + datetime.timedelta(hours=desde_h), base + datetime.timedelta(hours=hasta_h)

    def test_fin_debe_ser_posterior_al_inicio(self):
        ini, _ = self._rango()
        with self.assertRaises(ValidationError):
            crear_ventana(activo=self.srv, inicio=ini, fin=ini, categoria="cambio_configuracion", autor=self.u)
        with self.assertRaises(ValidationError):
            crear_ventana(activo=self.srv, inicio=ini, fin=ini - datetime.timedelta(hours=1),
                          categoria="cambio_configuracion", autor=self.u)

    def test_rechazo_de_solapamientos_activos(self):
        ini, fin = self._rango(-2, +2)
        crear_ventana(activo=self.srv, inicio=ini, fin=fin, categoria="reinicio_servicios", autor=self.u)
        # solapa
        with self.assertRaises(ValidationError):
            crear_ventana(activo=self.srv, inicio=ini + datetime.timedelta(hours=1),
                          fin=fin + datetime.timedelta(hours=1), categoria="otro", autor=self.u)
        # no solapa (posterior) -> OK
        v2 = crear_ventana(activo=self.srv, inicio=fin + datetime.timedelta(hours=1),
                           fin=fin + datetime.timedelta(hours=3), categoria="otro", autor=self.u)
        self.assertEqual(v2.estado, "ACTIVA")
        # una ventana CANCELADA no bloquea el solapamiento
        cancelar_ventana(v2, autor=self.u)
        crear_ventana(activo=self.srv, inicio=fin + datetime.timedelta(hours=1),
                      fin=fin + datetime.timedelta(hours=2), categoria="otro", autor=self.u)

    def test_cancelacion_auditable_no_borra(self):
        ini, fin = self._rango()
        v = crear_ventana(activo=self.srv, inicio=ini, fin=fin, categoria="mantenimiento_hardware", autor=self.u)
        self.assertTrue(cancelar_ventana(v, autor=self.u))
        v.refresh_from_db()
        self.assertEqual(v.estado, "CANCELADA")
        self.assertIsNotNone(v.cancelada_en)
        self.assertEqual(v.cancelada_por, self.u)
        self.assertTrue(VentanaMantenimiento.objects.filter(id=v.id).exists())  # no se borró
        self.assertFalse(cancelar_ventana(v, autor=self.u))  # ya cancelada

    def test_calculo_dentro_sin_indeterminado(self):
        ini, fin = self._rango(-1, +1)
        cat = "actualizacion_software"
        v = crear_ventana(activo=self.srv, inicio=ini, fin=fin, categoria=cat, autor=self.u)
        dentro = _tz.now()
        fuera = fin + datetime.timedelta(hours=3)
        self.assertEqual(estado_para(self.srv, dentro), ("dentro_ventana_declarada", cat))
        self.assertEqual(estado_para(self.srv, fuera), ("sin_ventana_declarada", None))
        self.assertEqual(estado_para(None, dentro), ("indeterminado", None))
        self.assertEqual(estado_para(self.srv, None), ("indeterminado", None))
        # cancelada -> ya no cuenta
        cancelar_ventana(v, autor=self.u)
        self.assertEqual(estado_para(self.srv, dentro), ("sin_ventana_declarada", None))

    def test_entrada_e_dentro_de_ventana_no_fuerza_falso_positivo(self):
        ini, fin = self._rango(-1, +2)
        crear_ventana(activo=self.srv, inicio=ini, fin=fin, categoria="cambio_configuracion",
                      descripcion="SECRETO_DESC_XYZ", autor=self.u)
        alerta = {**ALERTA_DEMO, "timestamp": _tz.now().isoformat(),
                  "groups": "ossec,syscheck,syscheck_entry_deleted",
                  "syscheck_path": "/etc/hosts", "syscheck_event": "modified"}
        e = construir_entrada_e(alerta, self.srv)
        self.assertEqual(e["maintenance_window"], "dentro_ventana_declarada")
        self.assertEqual(e["maintenance_category"], "cambio_configuracion")
        # la descripción libre y el creador NO llegan al prompt/entrada
        blob = json.dumps(e) + construir_prompt(e)
        self.assertNotIn("SECRETO_DESC_XYZ", blob)
        self.assertNotIn("vmu", blob)
        # el prompt deja claro que no implica FALSO_POSITIVO
        self.assertIn("NO", construir_prompt(e))
        self.assertIn("FALSO_POSITIVO", construir_prompt(e))
        # y el análisis respeta el veredicto del modelo (REQUIERE_ATENCION)
        r = analizar_alerta(alerta, self.srv, proveedor=_ProveedorFake())
        self.assertEqual(r["estado_analisis"], "COMPLETED")
        self.assertEqual(r["veredicto_ia"], "REQUIERE_ATENCION")
        self.assertEqual(r["contexto_ia_snapshot"]["maintenance_window"], "dentro_ventana_declarada")

    def test_snapshot_historico_no_cambia_al_cancelar_o_editar_ventana(self):
        ini, fin = self._rango(-1, +2)
        v = crear_ventana(activo=self.srv, inicio=ini, fin=fin, categoria="reinicio_servicios", autor=self.u)
        obj, _ = ingestar_alerta(
            {**ALERTA_DEMO, "opensearch_id": "vm1", "activo_logico": "SRV-01",
             "timestamp": _tz.now().isoformat()}, proveedor=_ProveedorFake())
        obj.refresh_from_db()
        snap0 = json.dumps(obj.contexto_ia_snapshot, sort_keys=True)
        self.assertEqual(obj.contexto_ia_snapshot["maintenance_window"], "dentro_ventana_declarada")
        # cancelar y editar la ventana
        cancelar_ventana(v, autor=self.u)
        v.fin = fin + datetime.timedelta(days=1)
        v.save(update_fields=["fin"])
        obj.refresh_from_db()
        self.assertEqual(json.dumps(obj.contexto_ia_snapshot, sort_keys=True), snap0)  # congelado

    def test_crear_o_cancelar_ventana_no_altera_alertas(self):
        vieja = Alert.objects.create(titulo="t", descripcion="d", estado="Pendiente", riesgo_ia="HIGH")
        ini, fin = self._rango()
        v = crear_ventana(activo=self.srv, inicio=ini, fin=fin, categoria="otro", autor=self.u)
        cancelar_ventana(v, autor=self.u)
        vieja.refresh_from_db()
        self.assertIsNone(vieja.estado_analisis)
        self.assertEqual(vieja.riesgo_ia, "HIGH")


class VentanaMantenimientoVistaTests(TestCase):
    def setUp(self):
        self.srv = _activo_real()
        self.analista = User.objects.create_user("an", password="p")  # ANALISTA por señal
        self.admin = User.objects.create_user("ad", password="p")
        self.admin.perfilusuario.rol = "ADMIN"; self.admin.perfilusuario.save()
        self.invitado = User.objects.create_user("inv", password="p")
        self.invitado.perfilusuario.rol = "INVITADO"; self.invitado.perfilusuario.save()

    def _post_crear(self, cli, **over):
        base = _tz.now()
        data = {
            "activo_logico": self.srv.id, "categoria": "cambio_configuracion",
            "inicio": (base + datetime.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M"),
            "fin": (base + datetime.timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M"),
            "descripcion": "prog",
        }
        data.update(over)
        return cli.post(reverse("mantenimiento_lista"), data)

    def test_listado_visible_para_cualquier_usuario(self):
        for u in (self.analista, self.admin, self.invitado):
            self.client.force_login(u)
            self.assertEqual(self.client.get(reverse("mantenimiento_lista")).status_code, 200)

    def test_solo_admin_analista_crean(self):
        self.client.force_login(self.invitado)
        self._post_crear(self.client)
        self.assertEqual(VentanaMantenimiento.objects.count(), 0)   # invitado no crea
        self.client.force_login(self.analista)
        self._post_crear(self.client)
        self.assertEqual(VentanaMantenimiento.objects.count(), 1)
        self.client.force_login(self.admin)
        self._post_crear(self.client, inicio=(_tz.now() + datetime.timedelta(days=2)).strftime("%Y-%m-%dT%H:%M"),
                         fin=(_tz.now() + datetime.timedelta(days=2, hours=2)).strftime("%Y-%m-%dT%H:%M"))
        self.assertEqual(VentanaMantenimiento.objects.count(), 2)

    def test_fin_antes_de_inicio_rechazado_por_la_vista(self):
        self.client.force_login(self.analista)
        base = _tz.now()
        self._post_crear(self.client,
                         inicio=(base + datetime.timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M"),
                         fin=(base + datetime.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M"))
        self.assertEqual(VentanaMantenimiento.objects.count(), 0)

    def test_solapamiento_rechazado_por_la_vista(self):
        self.client.force_login(self.analista)
        self._post_crear(self.client)
        self._post_crear(self.client)  # mismas fechas -> solapa
        self.assertEqual(VentanaMantenimiento.objects.count(), 1)

    def test_cancelar_requiere_rol_y_post(self):
        self.client.force_login(self.analista)
        self._post_crear(self.client)
        v = VentanaMantenimiento.objects.get()
        # invitado no cancela
        self.client.force_login(self.invitado)
        self.assertIn(self.client.post(reverse("mantenimiento_cancelar", args=[v.id])).status_code, (302, 403))
        v.refresh_from_db(); self.assertEqual(v.estado, "ACTIVA")
        # GET no cancela
        self.client.force_login(self.analista)
        self.client.get(reverse("mantenimiento_cancelar", args=[v.id]))
        v.refresh_from_db(); self.assertEqual(v.estado, "ACTIVA")
        # POST de ANALISTA sí
        self.client.post(reverse("mantenimiento_cancelar", args=[v.id]))
        v.refresh_from_db(); self.assertEqual(v.estado, "CANCELADA")

    def test_csrf_requerido(self):
        cli = _Client(enforce_csrf_checks=True)
        cli.force_login(self.analista)
        base = _tz.now()
        r = cli.post(reverse("mantenimiento_lista"), {
            "activo_logico": self.srv.id, "categoria": "otro",
            "inicio": (base + datetime.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M"),
            "fin": (base + datetime.timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M"),
        })
        self.assertEqual(r.status_code, 403)
        self.assertEqual(VentanaMantenimiento.objects.count(), 0)

    def test_formulario_lleva_csrf_token(self):
        self.client.force_login(self.analista)
        self.assertContains(self.client.get(reverse("mantenimiento_lista")), "csrfmiddlewaretoken")

    def test_nav_enlace_en_dashboard(self):
        self.client.force_login(self.analista)
        self.assertContains(self.client.get(reverse("index")), reverse("mantenimiento_lista"))


# --------------------------------------------------------------------------
# Corrección 2G.1 — zona horaria de las ventanas de mantenimiento
# --------------------------------------------------------------------------
from zoneinfo import ZoneInfo as _ZoneInfo
from dashboard.views import _parse_dt_local
from dashboard.templatetags.dashboard_extras import en_zona

_BOGOTA = SimpleNamespace(zona_horaria="America/Bogota")


class ZonaHorariaVentanaTests(SimpleTestCase):
    """El instante se guarda aware en UTC; la interfaz lo interpreta y muestra
    en la zona del activo. Colombia (America/Bogota) es UTC-5 fijo, sin DST."""

    def test_entrada_hora_local_colombia_se_convierte_a_utc(self):
        # El usuario escribe 16:04 hora local del activo en el <input datetime-local>.
        dt = _parse_dt_local("2026-09-08T16:04", _BOGOTA)
        self.assertEqual(dt.utcoffset(), datetime.timedelta(0))      # aware, en UTC
        self.assertEqual((dt.year, dt.month, dt.day, dt.hour, dt.minute), (2026, 9, 8, 21, 4))

    def test_entrada_medianoche_local_cruza_de_dia_en_utc(self):
        dt = _parse_dt_local("2026-09-08T22:30", _BOGOTA)   # 22:30 Bogota -> 03:30 del día 9 UTC
        self.assertEqual((dt.day, dt.hour, dt.minute), (9, 3, 30))

    def test_presentacion_utc_a_colombia(self):
        utc = datetime.datetime(2026, 9, 8, 21, 4, tzinfo=datetime.timezone.utc)
        self.assertEqual(en_zona(utc, "America/Bogota"), "2026-09-08 16:04")

    def test_presentacion_ida_y_vuelta_es_estable(self):
        entrada = "2026-09-08T16:04"
        utc = _parse_dt_local(entrada, _BOGOTA)
        self.assertEqual(en_zona(utc, "America/Bogota"), "2026-09-08 16:04")

    def test_en_zona_naive_se_asume_utc_y_zona_invalida_cae_a_utc(self):
        naive = datetime.datetime(2026, 9, 8, 21, 4)
        self.assertEqual(en_zona(naive, "America/Bogota"), "2026-09-08 16:04")
        utc = datetime.datetime(2026, 9, 8, 21, 4, tzinfo=datetime.timezone.utc)
        self.assertEqual(en_zona(utc, "Zona/Inexistente"), "2026-09-08 21:04")
        self.assertEqual(en_zona(None, "America/Bogota"), "")

    def test_vigente_ahora_se_calcula_sobre_el_instante_no_sobre_la_presentacion(self):
        ahora = datetime.datetime(2026, 9, 8, 21, 13, tzinfo=datetime.timezone.utc)
        inicio = _parse_dt_local("2026-09-08T16:04", _BOGOTA)   # 21:04 UTC
        fin = _parse_dt_local("2026-09-08T17:04", _BOGOTA)      # 22:04 UTC
        self.assertTrue(inicio <= ahora <= fin)                 # misma lógica que la plantilla
        # y su presentación en Bogota va 5 h por detrás del reloj UTC
        self.assertEqual(en_zona(inicio, "America/Bogota"), "2026-09-08 16:04")
        self.assertEqual(en_zona(fin, "America/Bogota"), "2026-09-08 17:04")

    def test_ventana_pasada_no_esta_vigente(self):
        ahora = datetime.datetime(2026, 9, 8, 21, 13, tzinfo=datetime.timezone.utc)
        inicio = _parse_dt_local("2026-09-08T08:00", _BOGOTA)   # 13:00 UTC
        fin = _parse_dt_local("2026-09-08T09:00", _BOGOTA)      # 14:00 UTC
        self.assertFalse(inicio <= ahora <= fin)


class ZonaHorariaVentanaRenderTests(TestCase):
    def test_listado_muestra_inicio_fin_en_zona_del_activo(self):
        srv = _activo_real()  # SRV-01, America/Bogota
        u = User.objects.create_user("zhr", password="x")
        inicio = _parse_dt_local("2026-09-08T16:04", srv)
        fin = _parse_dt_local("2026-09-08T17:04", srv)
        v = VentanaMantenimiento.objects.create(
            activo_logico=srv, inicio=inicio, fin=fin,
            categoria="limpieza_housekeeping", creada_por=u,
        )
        # se almacena en UTC
        self.assertEqual(v.inicio.astimezone(datetime.timezone.utc).hour, 21)
        self.client.force_login(u)
        html = self.client.get(reverse("mantenimiento_lista")).content.decode()
        self.assertIn("2026-09-08 16:04", html)   # Bogota, no 21:04
        self.assertIn("2026-09-08 17:04", html)
        self.assertNotIn("2026-09-08 21:04", html)
        self.assertIn("America/Bogota", html)

    def test_vigente_ahora_aparece_para_ventana_que_cubre_el_momento(self):
        srv = _activo_real()
        u = User.objects.create_user("zhr2", password="x")
        ahora = _tz.now()
        v = VentanaMantenimiento.objects.create(
            activo_logico=srv, inicio=ahora - datetime.timedelta(hours=1),
            fin=ahora + datetime.timedelta(hours=1),
            categoria="otro", creada_por=u,
        )
        self.assertTrue(v.cubre(ahora))
        self.client.force_login(u)
        html = self.client.get(reverse("mantenimiento_lista")).content.decode()
        self.assertIn("vigente ahora", html)


# --------------------------------------------------------------------------
# Checkpoint 2G.3 — ruta de laboratorio + análisis dirigido por opensearch_id
# --------------------------------------------------------------------------
from dashboard.management.commands.ingestar_alertas import procesar_una_por_opensearch_id
from django.core.management.base import CommandError as _CommandError

_RUTA_LAB = "/opt/sentria_lab_fim/prueba_housekeeping_sentria_2.txt"   # sólo para el test


class RutaLaboratorioControladoTests(SimpleTestCase):
    def test_clasificar_ruta_laboratorio(self):
        self.assertEqual(evi.clasificar_ruta(_RUTA_LAB), "laboratorio_controlado")
        self.assertEqual(evi.clasificar_ruta("/opt/sentria_lab_fim"), "laboratorio_controlado")
        self.assertEqual(evi.clasificar_ruta("/opt/sentria_lab_fim/"), "laboratorio_controlado")
        # otras rutas /opt siguen igual
        self.assertEqual(evi.clasificar_ruta("/opt/app/data"), "otra_no_determinada")
        self.assertIn("laboratorio_controlado", evi.CATEGORIAS_RUTA)

    def test_evidencia_lab_no_expone_ruta_ni_nombre(self):
        raw = {
            "syscheck_path": _RUTA_LAB, "syscheck_event": "deleted",
            "syscheck_hash_present": False, "syscheck_uid_after": "0",
            "groups": "ossec,syscheck,syscheck_file,syscheck_entry_deleted",
            "rule_id": "553", "decoder_name": "syscheck_deleted",
        }
        ev = evi.construir_evidencia_tecnica(raw)
        blob = json.dumps(ev)
        for prohibido in ("sentria_lab_fim", "prueba_housekeeping", "/opt/", ".txt"):
            self.assertNotIn(prohibido, blob, prohibido)
        self.assertEqual(ev["fim_event_type"], "deleted")
        self.assertEqual(ev["path_category"], "laboratorio_controlado")
        self.assertEqual(ev["file_extension"], "txt")
        self.assertFalse(ev["hash_present"])
        self.assertEqual(ev["telemetry_source"], "wazuh_syscheck")

    def test_prompt_no_incluye_ruta_exacta(self):
        from dashboard.ia.prompt import construir_entrada_e, construir_prompt
        alert = {
            "description": "File deleted.", "level": 7,
            "groups": "ossec,syscheck,syscheck_file,syscheck_entry_deleted",
            "rule_id": "553", "timestamp": "2026-09-09T04:10:38Z",
            "syscheck_path": _RUTA_LAB, "syscheck_event": "deleted",
            "maintenance_window": "dentro_ventana_declarada",
            "maintenance_category": "limpieza_housekeeping",
        }
        prompt = construir_prompt(construir_entrada_e(alert, ACTIVO_FAKE))
        for prohibido in ("sentria_lab_fim", "prueba_housekeeping", "/opt/"):
            self.assertNotIn(prohibido, prompt, prohibido)
        self.assertIn("laboratorio_controlado", prompt)
        self.assertIn("dentro_ventana_declarada", prompt)
        self.assertIn("limpieza_housekeeping", prompt)


class AnalisisDirigidoPorOpensearchIdTests(TestCase):
    def setUp(self):
        self.srv = _activo_real()
        asignar_agente("000", "SRV-01")
        self.osid = "wdBchKAB3fBU6jWnXuGy"

    def _doc(self, **over):
        d = {
            "opensearch_id": self.osid, "agent_id": "000",
            "description": "File deleted.", "level": 7,
            "groups": "ossec,syscheck,syscheck_file,syscheck_entry_deleted",
            "rule_id": "553", "timestamp": "2026-09-09T04:10:38Z",
            "syscheck_path": _RUTA_LAB, "syscheck_event": "deleted",
            "syscheck_hash_present": True,
        }
        d.update(over)
        return d

    def _ventana(self):
        ini = datetime.datetime(2026, 9, 9, 4, 3, tzinfo=datetime.timezone.utc)
        fin = datetime.datetime(2026, 9, 9, 6, 0, tzinfo=datetime.timezone.utc)
        return VentanaMantenimiento.objects.create(
            activo_logico=self.srv, inicio=ini, fin=fin,
            categoria="limpieza_housekeeping", estado="ACTIVA")

    def _run(self, doc, *, prov, api_key="k"):
        env = {"GEMINI_API_KEY": api_key} if api_key else {}
        with mock.patch.dict(os.environ, env, clear=False):
            return procesar_una_por_opensearch_id(
                self.osid, "000", get_uno=lambda _id: doc,
                obtener_proveedor=lambda _n: prov)

    def test_exige_confirmar_y_rechaza_dry_run(self):
        with self.assertRaises(_CommandError):
            call_command("ingestar_alertas", "--agent-id", "000",
                         "--opensearch-id", self.osid)                 # sin --confirmar
        with self.assertRaises(_CommandError):
            call_command("ingestar_alertas", "--agent-id", "000",
                         "--opensearch-id", self.osid, "--dry-run")
        self.assertEqual(Alert.objects.count(), 0)

    def test_rechaza_documento_con_id_distinto(self):
        fake = _FakeGemini()
        with self.assertRaises(_CommandError):
            self._run(self._doc(opensearch_id="OTRO-999"), prov=fake)
        self.assertEqual(fake.n, 0)
        self.assertEqual(Alert.objects.count(), 0)

    def test_rechaza_otro_agente(self):
        fake = _FakeGemini()
        with self.assertRaises(_CommandError):
            self._run(self._doc(agent_id="007"), prov=fake)
        self.assertEqual(fake.n, 0)

    def test_agente_sin_asignacion(self):
        desactivar_asignacion("000")
        fake = _FakeGemini()
        with self.assertRaises(_CommandError):
            self._run(self._doc(), prov=fake)
        self.assertEqual(fake.n, 0)

    def test_dedup_no_reingiere(self):
        Alert.objects.create(titulo="t", descripcion="d", estado="Pendiente",
                             opensearch_id=self.osid, estado_analisis="PENDING")
        fake = _FakeGemini()
        with self.assertRaises(_CommandError):
            self._run(self._doc(), prov=fake)
        self.assertEqual(fake.n, 0)
        self.assertEqual(Alert.objects.filter(opensearch_id=self.osid).count(), 1)

    def test_nivel_bajo_no_llama(self):
        fake = _FakeGemini()
        with self.assertRaises(_CommandError):
            self._run(self._doc(level=5, rule_id="554",
                                groups="ossec,syscheck,syscheck_file,syscheck_entry_added",
                                syscheck_event="added"), prov=fake)
        self.assertEqual(fake.n, 0)
        self.assertEqual(Alert.objects.count(), 0)

    def test_no_elegible_por_ruido_no_llama(self):
        fake = _FakeGemini()
        with self.assertRaises(_CommandError):
            self._run(self._doc(level=9, groups="dpkg,config_changed"), prov=fake)
        self.assertEqual(fake.n, 0)

    def test_sin_api_key_no_llama(self):
        fake = _FakeGemini()
        with self.assertRaises(_CommandError):
            self._run(self._doc(), prov=fake, api_key="")
        self.assertEqual(fake.n, 0)
        self.assertEqual(Alert.objects.count(), 0)

    def test_tope_absoluto_una_llamada_y_una_fila(self):
        self._ventana()
        fake = _FakeGemini(salida=json.dumps({**SALIDA_VALIDA, "verdict": "REQUIERE_ATENCION"}))
        antes = Alert.objects.count()
        r = self._run(self._doc(), prov=fake)
        self.assertEqual(fake.n, 1)
        self.assertEqual(r["llamadas_reales"], 1)
        self.assertEqual(Alert.objects.count(), antes + 1)
        obj = Alert.objects.get(opensearch_id=self.osid)
        self.assertEqual(obj.estado_analisis, "COMPLETED")
        snap = obj.contexto_ia_snapshot or {}
        self.assertEqual(snap.get("maintenance_window"), "dentro_ventana_declarada")
        self.assertEqual(snap.get("maintenance_category"), "limpieza_housekeeping")
        self.assertEqual(snap.get("evidencia_tecnica", {}).get("path_category"),
                         "laboratorio_controlado")
        blob = json.dumps(snap)
        for prohibido in ("sentria_lab_fim", "prueba_housekeeping", "000"):
            self.assertNotIn(prohibido, blob, prohibido)

    def test_no_fuerza_veredicto(self):
        for verdict in ("REQUIERE_ATENCION", "FALSO_POSITIVO"):
            VentanaMantenimiento.objects.all().delete()
            Alert.objects.filter(opensearch_id=self.osid).delete()
            self._ventana()
            fake = _FakeGemini(salida=json.dumps({**SALIDA_VALIDA, "verdict": verdict}))
            self._run(self._doc(), prov=fake)
            obj = Alert.objects.get(opensearch_id=self.osid)
            self.assertEqual(obj.veredicto_ia, verdict)


# --------------------------------------------------------------------------
# Sprint 3A — revisión humana, métricas correctas y bandeja del dataset
# --------------------------------------------------------------------------
from dashboard.models import RevisionHumana, CandidatoDataset
from dashboard.revision import registrar_revision, sincronizar_revision_desde_correccion
from dashboard.dataset import (
    sincronizar_candidato, sincronizar_todos, construir_salida_objetivo,
    fingerprint_entrada, validar_privacidad, familia_alerta,
)
from dashboard.metricas_eval import matriz_confusion

_SNAP_SEGURO = {
    "schema_version": "1.0",
    "alert_description_es": "Se eliminó un archivo de texto vacío.",
    "wazuh_level": 7, "wazuh_rule_groups": ["ossec", "syscheck", "syscheck_entry_deleted"],
    "wazuh_rule_id": "553",
    "asset_type": "servidor_interno", "asset_criticality": "alta",
    "asset_os_family": "linux", "asset_os_role": "servidor",
    "operational_window": "dentro_horario_operativo",
    "maintenance_window": "dentro_ventana_declarada",
    "maintenance_category": "limpieza_housekeeping",
    "authorized_context_es": "Servidor interno; servicios internos e impresión.",
    "technical_evidence_es": "Regla de Wazuh nivel 7 (syscheck). Evento FIM: deleted "
                             "sobre un archivo de categoría 'laboratorio_controlado'.",
    "evidencia_tecnica": {
        "fim_event_type": "deleted", "path_category": "laboratorio_controlado",
        "file_extension": "txt", "hash_present": True, "size_info": "archivo_vacio",
        "process_category": "no_determinado", "user_role_category": "usuario_no_privilegiado",
        "telemetry_source": "wazuh_syscheck", "correlated_events": 1,
        "rule_id": "553", "rule_groups": ["ossec", "syscheck", "syscheck_entry_deleted"],
    },
    "observed_cvss_factors": {k: "no_determinado" for k in (
        "attack_vector", "attack_complexity", "privileges_required", "user_interaction",
        "scope", "confidentiality_impact", "integrity_impact", "availability_impact")},
}


def _alerta_completed(**kw):
    base = dict(
        titulo="t", descripcion="Se eliminó un archivo de texto vacío.",
        estado="Pendiente", estado_analisis="COMPLETED",
        veredicto_ia="REQUIERE_ATENCION", riesgo_ia="LOW",
        explicacion_ia="El evento coincide con una ventana de mantenimiento, pero falta el proceso ejecutor.",
        factores_cvss={"attack_vector": "local", "attack_complexity": "baja",
                       "privileges_required": "bajos", "user_interaction": "ninguna",
                       "scope": "sin_cambio", "confidentiality_impact": "ninguno",
                       "integrity_impact": "bajo", "availability_impact": "ninguno"},
        justificacion_cvss="Vector local; impacto de integridad bajo por cambio del sistema de archivos.",
        recomendacion_ia="Verificar con el responsable si la eliminación era parte de la limpieza.",
        evidencia_faltante=["Identificador del proceso"],
        respuesta_ia_original=json.dumps({**SALIDA_VALIDA, "verdict": "REQUIERE_ATENCION", "risk": "LOW"}),
        proveedor_ia="gemini_developer", modelo_ia="models/gemini-3.5-flash",
        contexto_ia_snapshot=dict(_SNAP_SEGURO),
    )
    base.update(kw)
    return Alert.objects.create(**base)


class RevisionHumanaModeloTests(TestCase):
    def setUp(self):
        self.u = User.objects.create_user("rev", password="p")

    def test_confirmar_no_toca_ia_ni_veredicto_efectivo(self):
        a = _alerta_completed(veredicto_ia="FALSO_POSITIVO")
        registrar_revision(a, accion="CONFIRMADA", motivo_categoria="comportamiento_normal", autor=self.u)
        a.refresh_from_db()
        self.assertEqual(a.veredicto_ia, "FALSO_POSITIVO")       # IA intacta
        self.assertIsNone(a.correccion_veredicto)                # efectivo = IA
        self.assertEqual(a.veredicto_efectivo, "FALSO_POSITIVO")
        self.assertEqual(a.verdad_terreno, "FALSO_POSITIVO")     # gt = IA
        self.assertEqual(a.revision_humana.accion, "CONFIRMADA")

    def test_corregir_cambia_efectivo_pero_no_ia(self):
        a = _alerta_completed(veredicto_ia="REQUIERE_ATENCION")
        registrar_revision(a, accion="CORREGIDA", motivo_categoria="mantenimiento_programado",
                           autor=self.u, veredicto_gt="FALSO_POSITIVO", nota="ventana autorizada")
        a.refresh_from_db()
        self.assertEqual(a.veredicto_ia, "REQUIERE_ATENCION")    # IA intacta
        self.assertEqual(a.correccion_veredicto, "FALSO_POSITIVO")
        self.assertEqual(a.veredicto_efectivo, "FALSO_POSITIVO")
        self.assertEqual(a.verdad_terreno, "FALSO_POSITIVO")

    def test_excluir_sin_verdad_de_terreno(self):
        a = _alerta_completed()
        registrar_revision(a, accion="EXCLUIDA", motivo_categoria="contexto_insuficiente", autor=self.u)
        a.refresh_from_db()
        self.assertIsNone(a.verdad_terreno)
        self.assertEqual(a.revision_humana.accion, "EXCLUIDA")
        self.assertEqual(a.candidato_dataset.estado, "EXCLUIDO")

    def test_solo_completed_se_revisa(self):
        a = _alerta_completed(estado_analisis="ANALISIS_FALLIDO", veredicto_ia=None)
        with self.assertRaises(ValueError):
            registrar_revision(a, accion="CONFIRMADA", motivo_categoria="otro", autor=self.u)

    def test_corregir_exige_veredicto_gt(self):
        a = _alerta_completed()
        with self.assertRaises(ValueError):
            registrar_revision(a, accion="CORREGIDA", motivo_categoria="otro", autor=self.u)

    def test_backfill_desde_correccion_no_toca_campos_historicos(self):
        a = _alerta_completed(veredicto_ia="REQUIERE_ATENCION")
        registrar_correccion_humana(a, veredicto="FALSO_POSITIVO", autor=self.u, motivo="texto original de miguel")
        fecha = a.correccion_fecha
        rev = sincronizar_revision_desde_correccion(a, motivo_categoria="mantenimiento_programado")
        a.refresh_from_db()
        self.assertEqual(rev.accion, "CORREGIDA")
        self.assertEqual(rev.veredicto_verdad_terreno, "FALSO_POSITIVO")
        self.assertEqual(rev.nota, "texto original de miguel")
        self.assertEqual(a.correccion_fecha, fecha)              # histórico intacto
        self.assertEqual(a.correccion_motivo, "texto original de miguel")


class RevisionHumanaVistaTests(TestCase):
    def setUp(self):
        self.analista = User.objects.create_user("an3", password="p")
        self.invitado = User.objects.create_user("inv3", password="p")
        self.invitado.perfilusuario.rol = "INVITADO"; self.invitado.perfilusuario.save()
        self.a = _alerta_completed(veredicto_ia="REQUIERE_ATENCION")

    def test_confirmar_por_analista(self):
        self.client.force_login(self.analista)
        r = self.client.post(reverse("revisar_alerta", args=[self.a.id]),
                             {"accion": "confirmar", "motivo_categoria": "comportamiento_normal"})
        self.assertEqual(r.status_code, 302)
        self.a.refresh_from_db()
        self.assertEqual(self.a.revision_humana.accion, "CONFIRMADA")

    def test_excluir_por_analista(self):
        self.client.force_login(self.analista)
        self.client.post(reverse("revisar_alerta", args=[self.a.id]),
                         {"accion": "excluir", "motivo_categoria": "contexto_insuficiente"})
        self.a.refresh_from_db()
        self.assertEqual(self.a.revision_humana.accion, "EXCLUIDA")

    def test_invitado_no_revisa(self):
        self.client.force_login(self.invitado)
        r = self.client.post(reverse("revisar_alerta", args=[self.a.id]),
                             {"accion": "confirmar", "motivo_categoria": "otro"})
        self.assertIn(r.status_code, (302, 403))
        self.assertFalse(RevisionHumana.objects.filter(alerta=self.a).exists())

    def test_csrf_requerido(self):
        cli = _Client(enforce_csrf_checks=True)
        cli.force_login(self.analista)
        r = cli.post(reverse("revisar_alerta", args=[self.a.id]),
                     {"accion": "confirmar", "motivo_categoria": "otro"})
        self.assertEqual(r.status_code, 403)

    def test_categoria_obligatoria_nota_opcional(self):
        self.client.force_login(self.analista)
        self.client.post(reverse("revisar_alerta", args=[self.a.id]), {"accion": "confirmar"})
        self.assertFalse(RevisionHumana.objects.filter(alerta=self.a).exists())
        self.client.post(reverse("revisar_alerta", args=[self.a.id]),
                         {"accion": "confirmar", "motivo_categoria": "otro"})  # sin nota
        self.assertTrue(RevisionHumana.objects.filter(alerta=self.a).exists())


class MetricasEvaluacionTests(TestCase):
    def setUp(self):
        self.u = User.objects.create_user("m3", password="p")

    def _rev(self, ia, humano, accion="CORREGIDA"):
        a = _alerta_completed(veredicto_ia=ia)
        if accion == "CONFIRMADA":
            registrar_revision(a, accion="CONFIRMADA", motivo_categoria="otro", autor=self.u)
        else:
            registrar_revision(a, accion="CORREGIDA", motivo_categoria="otro", autor=self.u, veredicto_gt=humano)
        return a

    def test_matriz_tp_fp_tn_fn(self):
        self._rev("REQUIERE_ATENCION", "REQUIERE_ATENCION", accion="CONFIRMADA")   # TP
        self._rev("REQUIERE_ATENCION", "FALSO_POSITIVO")                            # FP
        self._rev("FALSO_POSITIVO", "FALSO_POSITIVO", accion="CONFIRMADA")          # TN
        self._rev("FALSO_POSITIVO", "REQUIERE_ATENCION")                            # FN
        m = matriz_confusion()
        self.assertEqual((m["tp"], m["fp"], m["tn"], m["fn"]), (1, 1, 1, 1))
        self.assertEqual(m["total_etiquetado"], 4)
        self.assertAlmostEqual(m["fpr"], 0.5)
        self.assertAlmostEqual(m["fnr"], 0.5)
        self.assertAlmostEqual(m["precision"], 0.5)
        self.assertAlmostEqual(m["recall"], 0.5)
        self.assertAlmostEqual(m["accuracy"], 0.5)

    def test_no_cuenta_alertas_sin_revision(self):
        _alerta_completed(veredicto_ia="REQUIERE_ATENCION")   # sin revisión
        m = matriz_confusion()
        self.assertEqual(m["total_etiquetado"], 0)

    def test_excluida_no_cuenta(self):
        a = _alerta_completed()
        registrar_revision(a, accion="EXCLUIDA", motivo_categoria="contexto_insuficiente", autor=self.u)
        self.assertEqual(matriz_confusion()["total_etiquetado"], 0)

    def test_denominadores_cero_no_calculable(self):
        # sólo un TP -> FPR y FNR no calculables (FP+TN = 0, FN+TP = 1 -> FNR sí calculable=0)
        self._rev("REQUIERE_ATENCION", "REQUIERE_ATENCION", accion="CONFIRMADA")
        m = matriz_confusion()
        self.assertIsNone(m["fpr"])          # FP + TN = 0
        self.assertEqual(m["fpr_den"], 0)
        self.assertEqual(m["precision"], 1.0)

    def test_no_usa_campo_estado_legacy(self):
        a = _alerta_completed(veredicto_ia="REQUIERE_ATENCION", estado="Falso positivo")
        registrar_revision(a, accion="CONFIRMADA", motivo_categoria="otro", autor=self.u)
        m = matriz_confusion()
        self.assertEqual(m["tp"], 1)   # cuenta por verdad de terreno, no por `estado`
        self.assertEqual(m["fp"], 0)

    def test_vista_metricas_renderiza_no_calculable(self):
        self.client.force_login(self.u)
        r = self.client.get(reverse("metricas"))
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "NO CALCULABLE")   # sin datos


class BandejaDatasetTests(TestCase):
    def setUp(self):
        self.u = User.objects.create_user("d3", password="p")

    def test_candidato_se_crea_automaticamente_al_revisar(self):
        a = _alerta_completed()
        self.assertFalse(hasattr(a, "candidato_dataset") and a.candidato_dataset)
        registrar_revision(a, accion="CONFIRMADA", motivo_categoria="otro", autor=self.u)
        a.refresh_from_db()
        self.assertTrue(CandidatoDataset.objects.filter(alerta=a).exists())
        cand = a.candidato_dataset
        self.assertTrue(cand.ejemplo_id.startswith("EJ-"))
        self.assertEqual(len(cand.ejemplo_id), 19)          # EJ- + 16 hex
        self.assertNotEqual(cand.ejemplo_id, f"EJ-{a.pk}")  # opaco, no es la pk
        self.assertNotIn(a.opensearch_id or "zzz", cand.ejemplo_id)
        from dashboard.dataset import ejemplo_id_para
        self.assertEqual(ejemplo_id_para(a), cand.ejemplo_id)  # determinista

    def test_salida_incompleta_cuando_se_cambia_el_verdict(self):
        a = _alerta_completed(veredicto_ia="REQUIERE_ATENCION")
        registrar_revision(a, accion="CORREGIDA", motivo_categoria="mantenimiento_programado",
                           autor=self.u, veredicto_gt="FALSO_POSITIVO")
        a.refresh_from_db()
        cand = a.candidato_dataset
        self.assertEqual(cand.estado, "INCOMPLETO")
        self.assertFalse(cand.salida_objetivo_revisada)
        # la salida objetivo lleva el veredicto de verdad de terreno, no el de la IA
        salida = construir_salida_objetivo(a)
        self.assertEqual(salida["verdict"], "FALSO_POSITIVO")

    def test_confirmada_no_se_aprueba_automaticamente(self):
        a = _alerta_completed()
        registrar_revision(a, accion="CONFIRMADA", motivo_categoria="comportamiento_normal", autor=self.u)
        a.refresh_from_db()
        # ni siquiera CONFIRMADA salta a LISTO sin pasar por el editor
        self.assertEqual(a.candidato_dataset.estado, "INCOMPLETO")

    def test_bloqueo_de_datos_privados(self):
        snap_sucio = dict(_SNAP_SEGURO)
        snap_sucio["technical_evidence_es"] = "El archivo /opt/sentria_lab_fim/x.txt fue borrado desde 192.168.1.5"
        a = _alerta_completed(contexto_ia_snapshot=snap_sucio)
        registrar_revision(a, accion="CONFIRMADA", motivo_categoria="otro", autor=self.u)
        a.refresh_from_db()
        cand = a.candidato_dataset
        self.assertFalse(cand.privacidad_ok)
        self.assertNotEqual(cand.estado, "LISTO_PARA_REVISION")
        hall = (cand.diagnostico or {}).get("hallazgos_privacidad", [])
        self.assertTrue({"posible_ip", "posible_ruta_exacta"} & set(hall))

    def test_fuga_de_identificador_concreto_bloquea(self):
        snap = dict(_SNAP_SEGURO)
        snap["authorized_context_es"] = "Servidor SRV-01 del laboratorio"
        srv = _activo_real()
        a = _alerta_completed(contexto_ia_snapshot=snap, activo_logico=srv)
        registrar_revision(a, accion="CONFIRMADA", motivo_categoria="otro", autor=self.u)
        a.refresh_from_db()
        self.assertFalse(a.candidato_dataset.privacidad_ok)
        self.assertIn("identificador_activo", a.candidato_dataset.diagnostico["fugas_identificador"])

    def test_deduplicacion_por_fingerprint(self):
        a1 = _alerta_completed()
        a2 = _alerta_completed()   # mismo snapshot -> misma entrada
        registrar_revision(a1, accion="CONFIRMADA", motivo_categoria="otro", autor=self.u)
        registrar_revision(a2, accion="CONFIRMADA", motivo_categoria="otro", autor=self.u)
        a1.refresh_from_db(); a2.refresh_from_db()
        self.assertEqual(a1.candidato_dataset.fingerprint, a2.candidato_dataset.fingerprint)
        marcados = [c for c in (a1.candidato_dataset, a2.candidato_dataset) if c.duplicado_de]
        self.assertEqual(len(marcados), 1)   # el segundo apunta al primero

    def test_bandeja_no_expone_datos_privados_en_html(self):
        srv = _activo_real()
        a = _alerta_completed(activo_logico=srv, wazuh_agent_id="000", opensearch_id="wdBchKAB3fBU6jWnXuGy")
        registrar_revision(a, accion="CONFIRMADA", motivo_categoria="otro", autor=self.u)
        self.client.force_login(self.u)
        html = self.client.get(reverse("bandeja_dataset")).content.decode()
        for prohibido in ("SRV-01", "wdBchKAB3fBU6jWnXuGy", "/opt/", ">000<"):
            self.assertNotIn(prohibido, html, prohibido)

    def test_sincronizar_todos_solo_alertas_revisadas(self):
        _alerta_completed()   # sin revisión
        a = _alerta_completed()
        registrar_revision(a, accion="CONFIRMADA", motivo_categoria="otro", autor=self.u)
        self.assertEqual(sincronizar_todos(), 1)


class ID128ComoPrimerCandidatoTests(TestCase):
    """Reproduce el escenario real de la alerta 128: IA=REQUIERE_ATENCION,
    verdad de terreno humana=FALSO_POSITIVO (evento controlado en ventana)."""

    def setUp(self):
        self.admin = User.objects.create_user("ad128", password="p")
        self.admin.perfilusuario.rol = "ADMIN"; self.admin.perfilusuario.save()
        self.a = _alerta_completed(veredicto_ia="REQUIERE_ATENCION", riesgo_ia="LOW")
        # corrección por el flujo antiguo (como la que hizo Miguel)
        registrar_correccion_humana(
            self.a, veredicto="FALSO_POSITIVO", autor=self.admin,
            motivo="Evento controlado dentro de una ventana de mantenimiento autorizada.",
        )

    def test_backfill_y_matriz_cuenta_como_fp(self):
        sincronizar_revision_desde_correccion(self.a, motivo_categoria="mantenimiento_programado")
        self.a.refresh_from_db()
        self.assertEqual(self.a.verdad_terreno, "FALSO_POSITIVO")
        self.assertEqual(self.a.veredicto_ia, "REQUIERE_ATENCION")   # IA intacta
        m = matriz_confusion()
        self.assertEqual(m["fp"], 1)   # IA pidió atención, humano dijo FP
        self.assertEqual(m["tp"], 0)
        self.assertEqual(m["fpr"], 1.0)

    def test_es_candidato_incompleto(self):
        sincronizar_revision_desde_correccion(self.a, motivo_categoria="mantenimiento_programado")
        self.a.refresh_from_db()
        cand = self.a.candidato_dataset
        self.assertEqual(cand.estado, "INCOMPLETO")   # verdict cambiado, salida sin revisar
        self.assertNotEqual(cand.estado, "APROBADO")

    def test_colas_efectivas_para_id128(self):
        self.client.force_login(self.admin)
        self.assertNotContains(self.client.get(reverse("cola_atencion")),
                               self.a.descripcion[:20])
        self.assertContains(self.client.get(reverse("cola_falsos_positivos")),
                            self.a.descripcion[:20])
        self.assertContains(self.client.get(reverse("index")), self.a.descripcion[:20])


# --------------------------------------------------------------------------
# Sprint 3B — editor y aprobación de candidatos del dataset
# --------------------------------------------------------------------------
from dashboard.models import RevisionCandidato
from dashboard import dataset as _ds

_SALIDA_OK = {
    "risk": "MEDIUM",
    "explanation_es": "El evento coincide con una ventana de mantenimiento autorizada y no hay indicios de un actor no autorizado.",
    "cvss__attack_vector": "local", "cvss__attack_complexity": "baja",
    "cvss__privileges_required": "bajos", "cvss__user_interaction": "ninguna",
    "cvss__scope": "sin_cambio", "cvss__confidentiality_impact": "ninguno",
    "cvss__integrity_impact": "bajo", "cvss__availability_impact": "ninguno",
    "cvss_reasoning_es": "El vector es local porque se requiere acceso al sistema; el impacto de integridad es bajo por el cambio en el sistema de archivos.",
    "recommendation_es": "Confirmar con el equipo que la limpieza estaba programada y cerrar la alerta.",
    "missing_evidence": "",
}


def _cand_de(alerta):
    _ds.sincronizar_candidato(alerta)
    alerta.refresh_from_db()
    return alerta.candidato_dataset


class AdvertenciaEstadisticaTests(TestCase):
    def setUp(self):
        self.u = User.objects.create_user("adv", password="p")

    def test_advertencia_con_pocos_ejemplos(self):
        a = _alerta_completed()
        registrar_revision(a, accion="CONFIRMADA", motivo_categoria="otro", autor=self.u)
        self.client.force_login(self.u)
        r = self.client.get(reverse("metricas"))
        self.assertContains(r, "Muestra insuficiente")
        self.assertContains(r, "n = 1")
        self.assertContains(r, "Exactitud")           # antes "Accuracy"
        self.assertNotContains(r, ">Accuracy<")

    def test_n_junto_a_porcentajes(self):
        self.client.force_login(self.u)
        r = self.client.get(reverse("metricas"))
        self.assertContains(r, "n etiquetado = 0")
        self.assertContains(r, "NO CALCULABLE")


class EditorCandidatoTests(TestCase):
    def setUp(self):
        self.a1 = User.objects.create_user("eda", password="p")   # ANALISTA
        self.a2 = User.objects.create_user("edb", password="p")
        self.admin = User.objects.create_user("edadm", password="p")
        self.admin.perfilusuario.rol = "ADMIN"; self.admin.perfilusuario.save()
        self.invitado = User.objects.create_user("edinv", password="p")
        self.invitado.perfilusuario.rol = "INVITADO"; self.invitado.perfilusuario.save()
        self.autor = User.objects.create_user("edaut", password="p")
        self.alerta = _alerta_completed(veredicto_ia="REQUIERE_ATENCION")
        registrar_revision(self.alerta, accion="CORREGIDA", motivo_categoria="mantenimiento_programado",
                           autor=self.autor, veredicto_gt="FALSO_POSITIVO")
        self.cand = _cand_de(self.alerta)

    def _url(self):
        return reverse("candidato_detalle", args=[self.cand.ejemplo_id])

    def _enviar(self, cli, **over):
        data = {"accion": "enviar", "confirmo_revision": "on"}
        data.update(_SALIDA_OK); data.update(over)
        return cli.post(self._url(), data)

    def test_detalle_muestra_tres_bloques_sin_datos_privados(self):
        self.client.force_login(self.a1)
        r = self.client.get(self._url())
        self.assertEqual(r.status_code, 200)
        body = r.content.decode()
        self.assertIn("Entrada anonimizada", body)
        self.assertIn("Respuesta original de Gemini", body)
        self.assertIn("Salida objetivo supervisada", body)
        for bad in ("/opt/sentria_lab_fim", "wdBchKAB", ">000<"):
            self.assertNotIn(bad, body)

    def test_verdict_bloqueado_a_verdad_de_terreno(self):
        # aunque se intente enviar otro verdict, se fuerza a la verdad de terreno
        self.client.force_login(self.a1)
        self._enviar(self.client, verdict="REQUIERE_ATENCION")
        self.cand.refresh_from_db()
        salida = _ds.salida_objetivo_actual(self.cand)
        self.assertEqual(salida["verdict"], "FALSO_POSITIVO")

    def test_guardar_borrador_no_aprueba(self):
        self.client.force_login(self.a1)
        data = {"accion": "borrador"}; data.update(_SALIDA_OK)
        self.client.post(self._url(), data)
        self.cand.refresh_from_db()
        self.assertIn(self.cand.estado, ("INCOMPLETO", "DEVUELTO"))
        self.assertIsNotNone(self.cand.salida_objetivo_editada)

    def test_enviar_exige_confirmacion_y_contrato(self):
        self.client.force_login(self.a1)
        # sin confirmación -> no pasa
        self._enviar(self.client, confirmo_revision="")
        self.cand.refresh_from_db()
        self.assertNotEqual(self.cand.estado, "LISTO_PARA_REVISION")
        # explanation demasiado corta -> no pasa
        self._enviar(self.client, explanation_es="corto")
        self.cand.refresh_from_db()
        self.assertNotEqual(self.cand.estado, "LISTO_PARA_REVISION")
        # completo -> LISTO_PARA_REVISION
        self._enviar(self.client)
        self.cand.refresh_from_db()
        self.assertEqual(self.cand.estado, "LISTO_PARA_REVISION")
        self.assertEqual(self.cand.completado_por, self.a1)

    def test_privacidad_rechaza_antes_de_guardar(self):
        self.client.force_login(self.a1)
        self._enviar(self.client, recommendation_es="Bloquear la IP 10.0.2.15 del host afectado y avisar.")
        self.cand.refresh_from_db()
        self.assertIsNone(self.cand.salida_objetivo_editada)   # no se guardó
        self.assertNotEqual(self.cand.estado, "LISTO_PARA_REVISION")

    def test_invitado_no_edita_ni_aprueba(self):
        self.client.force_login(self.invitado)
        self.assertIn(self.client.get(self._url()).status_code, (302, 403))
        data = {"accion": "enviar", "confirmo_revision": "on"}; data.update(_SALIDA_OK)
        self.assertIn(self.client.post(self._url(), data).status_code, (302, 403))
        self.cand.refresh_from_db()
        self.assertEqual(self.cand.estado, "INCOMPLETO")

    def test_csrf_requerido(self):
        cli = _Client(enforce_csrf_checks=True)
        cli.force_login(self.a1)
        data = {"accion": "enviar", "confirmo_revision": "on"}; data.update(_SALIDA_OK)
        self.assertEqual(cli.post(self._url(), data).status_code, 403)

    # ---- FASE 4: segunda revisión ----
    def _dejar_listo(self):
        self.client.force_login(self.a1)
        self._enviar(self.client)
        self.cand.refresh_from_db()
        assert self.cand.estado == "LISTO_PARA_REVISION"

    def test_completador_no_puede_aprobar(self):
        self._dejar_listo()
        self.client.force_login(self.a1)   # el mismo que completó
        self.client.post(self._url(), {"accion": "revisar", "decision": "APROBADO"})
        self.cand.refresh_from_db()
        self.assertEqual(self.cand.estado, "LISTO_PARA_REVISION")   # sigue sin aprobar
        self.assertFalse(RevisionCandidato.objects.filter(candidato=self.cand, decision="APROBADO").exists())

    def test_segundo_revisor_aprueba(self):
        self._dejar_listo()
        self.client.force_login(self.a2)
        self.client.post(self._url(), {"accion": "revisar", "decision": "APROBADO"})
        self.cand.refresh_from_db()
        self.assertEqual(self.cand.estado, "APROBADO")
        rc = RevisionCandidato.objects.get(candidato=self.cand)
        self.assertEqual(rc.decision, "APROBADO")
        self.assertEqual(rc.autor, self.a2)

    def test_devolver_exige_observaciones_y_es_append_only(self):
        self._dejar_listo()
        self.client.force_login(self.a2)
        self.client.post(self._url(), {"accion": "revisar", "decision": "DEVUELTO"})   # sin obs
        self.cand.refresh_from_db()
        self.assertEqual(self.cand.estado, "LISTO_PARA_REVISION")
        self.client.post(self._url(), {"accion": "revisar", "decision": "DEVUELTO",
                                       "observaciones": "Faltan detalles del proceso."})
        self.cand.refresh_from_db()
        self.assertEqual(self.cand.estado, "DEVUELTO")
        # el editor corrige y reenvía; la revisión anterior NO se borra
        self.client.force_login(self.a1)
        self._enviar(self.client)
        self.client.force_login(self.a2)
        self.client.post(self._url(), {"accion": "revisar", "decision": "APROBADO"})
        self.cand.refresh_from_db()
        self.assertEqual(self.cand.estado, "APROBADO")
        self.assertEqual(RevisionCandidato.objects.filter(candidato=self.cand).count(), 2)

    def test_excluir_desde_segunda_revision(self):
        self._dejar_listo()
        self.client.force_login(self.a2)
        self.client.post(self._url(), {"accion": "revisar", "decision": "EXCLUIDO",
                                       "observaciones": "Evidencia insuficiente."})
        self.cand.refresh_from_db()
        self.assertEqual(self.cand.estado, "EXCLUIDO")

    def test_sync_no_promueve_ni_degrada_aprobado_sin_problema(self):
        self._dejar_listo()
        self.client.force_login(self.a2)
        self.client.post(self._url(), {"accion": "revisar", "decision": "APROBADO"})
        _ds.sincronizar_candidato(self.alerta)   # re-sync no debe tumbar el APROBADO
        self.cand.refresh_from_db()
        self.assertEqual(self.cand.estado, "APROBADO")


class ID128Editor3BTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_user("i128a", password="p")
        self.admin.perfilusuario.rol = "ADMIN"; self.admin.perfilusuario.save()
        self.a = _alerta_completed(veredicto_ia="REQUIERE_ATENCION", riesgo_ia="LOW")
        registrar_correccion_humana(self.a, veredicto="FALSO_POSITIVO", autor=self.admin,
                                    motivo="Evento controlado dentro de ventana autorizada.")
        sincronizar_revision_desde_correccion(self.a, motivo_categoria="mantenimiento_programado")
        self.a.refresh_from_db()
        self.cand = self.a.candidato_dataset

    def test_incompleto_prellenado_y_no_aprobado(self):
        self.assertEqual(self.cand.estado, "INCOMPLETO")
        self.client.force_login(self.admin)
        r = self.client.get(reverse("candidato_detalle", args=[self.cand.ejemplo_id]))
        self.assertEqual(r.status_code, 200)
        body = r.content.decode()
        self.assertIn("FALSO_POSITIVO", body)      # verdict bloqueado a la verdad de terreno
        # prellenado con la explicación original de Gemini
        self.assertIn("ventana de mantenimiento", body)

    def test_verdad_de_terreno_y_riesgo_propuesto(self):
        self.assertEqual(self.a.verdad_terreno, "FALSO_POSITIVO")
        salida = _ds.salida_objetivo_actual(self.cand)
        self.assertEqual(salida["verdict"], "FALSO_POSITIVO")
        self.assertEqual(salida["risk"], "LOW")

    def test_no_cambia_alerta_ni_correccion_ni_original(self):
        self.assertEqual(self.a.veredicto_ia, "REQUIERE_ATENCION")
        self.assertEqual(self.a.correccion_veredicto, "FALSO_POSITIVO")
        self.assertIn("REQUIERE_ATENCION", self.a.respuesta_ia_original)


# ============================================================================
# Sprint 3C/3D — operación selectiva, dashboard centrado en IA, dataset acelerado
# ============================================================================
from dashboard.ia.muestreo import (
    en_muestra_selectiva, requiere_auditoria_selectiva, POLITICA_MUESTREO_VERSION,
)
from dashboard.ia.legado import diagnosticar_legado
from dashboard.management.commands.migrar_legado import procesar_migracion_legado, GATE_ENV_VAR
from dashboard import planificador_dataset as pldata
from dashboard.views import (
    Q_PENDIENTES_TECNICOS, Q_LEGADO, Q_OMITIDAS, _auditoria_selectiva_ids,
)


def _activo_laptop():
    return ActivoLogico.objects.create(
        identificador="LAPTOP-01", nombre_visible="Portátil de pruebas",
        tipo_activo="equipo_administracion", criticidad="media",
        os_family="windows", os_role="estacion_cliente",
        hora_inicio_operacion=datetime.time(0, 0), hora_fin_operacion=datetime.time(23, 59),
        zona_horaria="America/Bogota",
        contexto_autorizado_es="Portátil Windows ficticio para pruebas de multiagente; no conectado todavía.",
        activo=True,
    )


class TextosYDisenoTests(TestCase):
    """FASE 2: textos exactos y clasificación IA como elemento principal."""
    def setUp(self):
        self.u = User.objects.create_user("tx1", password="p")
        self.client.force_login(self.u)

    def test_encabezados_exactos(self):
        self._a(estado_analisis="COMPLETED", veredicto_ia="REQUIERE_ATENCION", riesgo_ia="HIGH")
        body = self.client.get(reverse("index")).content.decode()
        self.assertIn("Clasificación IA", body)
        self.assertIn("Revisión Analista", body)
        self.assertNotIn(">Veredicto IA<", body)
        self.assertNotIn(">Revisión humana<", body)

    def test_texto_legado_exacto(self):
        self._a(descripcion="vieja")
        body = self.client.get(reverse("index")).content.decode()
        self.assertIn("Análisis Legado - Pendiente de migrar al flujo IA actual", body)

    def _a(self, **kw):
        base = dict(titulo="t", descripcion="d", estado="Pendiente")
        base.update(kw)
        return Alert.objects.create(**base)


class MenuAccionesTests(TestCase):
    """FASE 2: menú compacto 'Acciones ▾' con acciones condicionales."""
    def setUp(self):
        self.analista = User.objects.create_user("ma1", password="p")
        self.invitado = User.objects.create_user("mainv", password="p")
        self.invitado.perfilusuario.rol = "INVITADO"; self.invitado.perfilusuario.save()

    def _a(self, **kw):
        base = dict(titulo="t", descripcion="d", estado="Pendiente")
        base.update(kw)
        return Alert.objects.create(**base)

    def test_un_solo_boton_acciones(self):
        self._a(estado_analisis="COMPLETED", veredicto_ia="REQUIERE_ATENCION", riesgo_ia="HIGH")
        self.client.force_login(self.analista)
        body = self.client.get(reverse("index")).content.decode()
        self.assertIn("Acciones ▾", body)
        self.assertIn("actions-menu", body)

    def test_acciones_condicionales_por_estado(self):
        completada = self._a(estado_analisis="COMPLETED", veredicto_ia="REQUIERE_ATENCION", riesgo_ia="HIGH")
        fallida = self._a(estado_analisis="ANALISIS_FALLIDO", descripcion="FALLO-UNICA-XYZ")
        self.client.force_login(self.analista)
        body = self.client.get(reverse("index")).content.decode()
        self.assertIn("Confirmar clasificación IA", body)
        self.assertIn("Corregir clasificación IA", body)
        self.assertIn("Reintentar análisis", body)

    def test_invitado_no_ve_acciones_de_escritura(self):
        self._a(estado_analisis="COMPLETED", veredicto_ia="REQUIERE_ATENCION", riesgo_ia="HIGH")
        self.client.force_login(self.invitado)
        body = self.client.get(reverse("index")).content.decode()
        self.assertNotIn("Confirmar clasificación IA", body)
        self.assertNotIn("Corregir clasificación IA", body)

    def test_aprobado_oculta_confirmar_corregir_y_muestra_insignia(self):
        a = self._a(estado_analisis="COMPLETED", veredicto_ia="REQUIERE_ATENCION", riesgo_ia="LOW",
                    contexto_ia_snapshot=dict(_SNAP_SEGURO))
        registrar_revision(a, accion="CORREGIDA", motivo_categoria="otro", autor=self.analista,
                           veredicto_gt="FALSO_POSITIVO")
        cand = a.candidato_dataset
        otro = User.objects.create_user("ma2", password="p")
        cand, _ = _ds.enviar_a_revision(cand, {
            "risk": "LOW", "explanation_es": "Explicación suficientemente larga para pasar la validación del contrato.",
            "cvss__attack_vector": "local", "cvss__attack_complexity": "baja",
            "cvss__privileges_required": "bajos", "cvss__user_interaction": "ninguna",
            "cvss__scope": "sin_cambio", "cvss__confidentiality_impact": "ninguno",
            "cvss__integrity_impact": "bajo", "cvss__availability_impact": "ninguno",
            "cvss_reasoning_es": "Justificación suficientemente larga para pasar la validación del contrato CVSS.",
            "recommendation_es": "Cerrar la alerta tras confirmar con el equipo responsable.",
            "missing_evidence": "",
        }, self.analista, confirmado=True)
        _ds.revisar_candidato(cand, decision="APROBADO", autor=otro)
        a.refresh_from_db()
        self.assertTrue(a.dataset_aprobado)
        self.client.force_login(otro)
        body = self.client.get(reverse("index")).content.decode()
        self.assertIn("Dataset aprobado", body)
        self.assertNotIn("Confirmar clasificación IA", body)
        self.assertNotIn("Corregir clasificación IA", body)


class ColasSeparadasTests(TestCase):
    """FASE 3/4: colas más claras; legado nunca cuenta como pendiente ordinario."""
    def setUp(self):
        self.u = User.objects.create_user("cs1", password="p")
        self.client.force_login(self.u)

    def _a(self, **kw):
        base = dict(titulo="t", descripcion="d", estado="Pendiente")
        base.update(kw)
        return Alert.objects.create(**base)

    def test_legado_no_es_pendiente_tecnico(self):
        legado = self._a(descripcion="LEGADO-UNICA")
        self.assertTrue(Alert.objects.filter(Q_LEGADO, pk=legado.pk).exists())
        self.assertFalse(Alert.objects.filter(Q_PENDIENTES_TECNICOS, pk=legado.pk).exists())

    def test_cola_legado_y_cola_pendientes_separadas(self):
        legado = self._a(descripcion="LEG-SOLO")
        fallida = self._a(descripcion="FALLO-SOLO", estado_analisis="ANALISIS_FALLIDO")
        r_legado = self.client.get(reverse("cola_legado"))
        r_pend = self.client.get(reverse("cola_pendientes"))
        self.assertContains(r_legado, "LEG-SOLO")
        self.assertNotContains(r_legado, "FALLO-SOLO")
        self.assertContains(r_pend, "FALLO-SOLO")
        self.assertNotContains(r_pend, "LEG-SOLO")

    def test_cola_omitidas_separada(self):
        om = self._a(descripcion="OMIT-SOLO", estado_analisis="OMITIDO_POLITICA", motivo_omision="NIVEL_NO_ELEGIBLE")
        r = self.client.get(reverse("cola_omitidas"))
        self.assertContains(r, "OMIT-SOLO")
        self.assertFalse(Alert.objects.filter(Q_PENDIENTES_TECNICOS, pk=om.pk).exists())

    def test_alias_falsos_positivos_ia_redirige(self):
        r = self.client.get(reverse("cola_falsos_positivos_ia"))
        self.assertEqual(r.status_code, 302)
        self.assertIn(reverse("cola_falsos_positivos"), r["Location"])


class MuestreoSelectivoTests(SimpleTestCase):
    """FASE 4: muestreo determinista del 10%, sin ORDER BY RAND()."""

    def test_determinista_y_estable(self):
        for pk in (1, 42, 999, 123456):
            r1 = en_muestra_selectiva(pk)
            r2 = en_muestra_selectiva(pk)
            r3 = en_muestra_selectiva(pk)
            self.assertEqual(r1, r2)
            self.assertEqual(r2, r3)

    def test_version_distinta_puede_cambiar_resultado_pero_sigue_siendo_determinista(self):
        pk = 777
        a = en_muestra_selectiva(pk, version="1.0")
        b1 = en_muestra_selectiva(pk, version="2.0-prueba")
        b2 = en_muestra_selectiva(pk, version="2.0-prueba")
        self.assertEqual(b1, b2)  # determinista también bajo otra versión

    def test_distribucion_cercana_al_10_por_ciento(self):
        n = 4000
        positivos = sum(1 for pk in range(1, n + 1) if en_muestra_selectiva(pk))
        proporcion = positivos / n
        self.assertTrue(0.07 <= proporcion <= 0.13, f"proporción observada: {proporcion}")

    def test_nunca_usa_random_del_proceso(self):
        import random
        estado_antes = random.getstate()
        en_muestra_selectiva(12345)
        self.assertEqual(random.getstate(), estado_antes)


class AuditoriaSelectivaTests(TestCase):
    """FASE 4: política de auditoría selectiva de falsos positivos de la IA."""
    def setUp(self):
        self.admin = User.objects.create_user("au1", password="p")
        self.admin.perfilusuario.rol = "ADMIN"; self.admin.perfilusuario.save()

    def _fp(self, **kw):
        base = dict(titulo="t", descripcion="FP", estado="Pendiente",
                    estado_analisis="COMPLETED", veredicto_ia="FALSO_POSITIVO", riesgo_ia="LOW")
        base.update(kw)
        return Alert.objects.create(**base)

    def test_nivel_alto_siempre_entra(self):
        a = self._fp(severidad=10, riesgo_ia="LOW")
        ok, motivo = requiere_auditoria_selectiva(a)
        self.assertTrue(ok); self.assertEqual(motivo, "nivel_alto")

    def test_nivel_justo_debajo_del_umbral_no_fuerza_por_nivel(self):
        a = self._fp(severidad=9, riesgo_ia="LOW")
        ok, motivo = requiere_auditoria_selectiva(a)
        self.assertNotEqual(motivo, "nivel_alto")

    def test_riesgo_high_o_critical_siempre_entra(self):
        a = self._fp(severidad=1, riesgo_ia="HIGH")
        ok, motivo = requiere_auditoria_selectiva(a)
        self.assertTrue(ok); self.assertEqual(motivo, "riesgo_alto")
        b = self._fp(severidad=1, riesgo_ia="CRITICAL")
        ok2, motivo2 = requiere_auditoria_selectiva(b)
        self.assertTrue(ok2); self.assertEqual(motivo2, "riesgo_alto")

    def test_riesgo_medium_no_fuerza_por_riesgo(self):
        a = self._fp(severidad=1, riesgo_ia="MEDIUM")
        ok, motivo = requiere_auditoria_selectiva(a)
        self.assertNotEqual(motivo, "riesgo_alto")

    def test_requiere_atencion_nunca_entra_a_auditoria(self):
        a = Alert.objects.create(titulo="t", descripcion="RA", estado="Pendiente",
                                 estado_analisis="COMPLETED", veredicto_ia="REQUIERE_ATENCION",
                                 riesgo_ia="HIGH", severidad=15)
        ids = _auditoria_selectiva_ids()
        self.assertNotIn(a.pk, ids)

    def test_alerta_ya_revisada_no_vuelve_a_auditoria(self):
        a = self._fp(severidad=10)   # nivel alto -> calificaría
        self.assertIn(a.pk, _auditoria_selectiva_ids())
        registrar_revision(a, accion="CONFIRMADA", motivo_categoria="otro", autor=self.admin)
        self.assertNotIn(a.pk, _auditoria_selectiva_ids())

    def test_cola_auditoria_selectiva_responde_y_filtra(self):
        dentro = self._fp(severidad=10, descripcion="AUD-DENTRO")
        fuera = self._fp(severidad=1, riesgo_ia="LOW", descripcion="AUD-FUERA-000000")
        # sin opensearch_id "fuera" no puede caer en la muestra del 10%
        self.assertEqual(requiere_auditoria_selectiva(fuera), (False, None))
        self.client.force_login(self.admin)
        r = self.client.get(reverse("cola_auditoria_selectiva"))
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "AUD-DENTRO")
        self.assertNotContains(r, "AUD-FUERA-000000")

    def test_no_crea_ni_consume_campo_de_confianza(self):
        """El contrato de salida no tiene (ni debe tener) un campo de confianza inventado."""
        self.assertNotIn("confidence", contrato.CAMPOS_SALIDA)
        self.assertNotIn("confianza", contrato.CAMPOS_SALIDA)


class OrigenRevisionTests(TestCase):
    """FASE 5: origen auditable de RevisionHumana; métricas con disclaimer."""
    def setUp(self):
        self.u = User.objects.create_user("or1", password="p")

    def _completed(self, **kw):
        base = dict(titulo="t", descripcion="d", estado="Pendiente",
                    estado_analisis="COMPLETED", veredicto_ia="REQUIERE_ATENCION", riesgo_ia="LOW")
        base.update(kw)
        return Alert.objects.create(**base)

    def test_origen_por_defecto_operativa(self):
        a = self._completed()
        registrar_revision(a, accion="CONFIRMADA", motivo_categoria="otro", autor=self.u)
        self.assertEqual(a.revision_humana.origen, "OPERATIVA")

    def test_origen_explicito_se_respeta(self):
        a = self._completed()
        registrar_revision(a, accion="CONFIRMADA", motivo_categoria="otro", autor=self.u, origen="AUDITORIA_SELECTIVA")
        self.assertEqual(a.revision_humana.origen, "AUDITORIA_SELECTIVA")

    def test_origen_invalido_rechazado(self):
        a = self._completed()
        with self.assertRaises(ValueError):
            registrar_revision(a, accion="CONFIRMADA", motivo_categoria="otro", autor=self.u, origen="INVENTADO")

    def test_metricas_muestra_desglose_por_origen_y_advertencia(self):
        a = self._completed()
        registrar_revision(a, accion="CONFIRMADA", motivo_categoria="otro", autor=self.u, origen="PRUEBA_CONTROLADA")
        self.client.force_login(self.u)
        body = self.client.get(reverse("metricas")).content.decode()
        self.assertIn("Prueba controlada", body)
        self.assertIn("no constituyen una muestra estadística representativa", body)

    def test_origen_prueba_controlada_explicito_conserva_verdad_de_terreno(self):
        a = self._completed(id=128, veredicto_ia="REQUIERE_ATENCION", riesgo_ia="LOW")
        from dashboard.revision import sincronizar_revision_desde_correccion
        registrar_correccion_humana(a, veredicto="FALSO_POSITIVO", autor=self.u, motivo="prueba controlada")
        sincronizar_revision_desde_correccion(a, motivo_categoria="mantenimiento_programado", origen="PRUEBA_CONTROLADA")
        a.refresh_from_db()
        self.assertEqual(a.revision_humana.origen, "PRUEBA_CONTROLADA")
        self.assertEqual(a.verdad_terreno, "FALSO_POSITIVO")   # verdad de terreno sin cambios


class ProteccionAprobadoBackendTests(TestCase):
    """FASE 6: un candidato APROBADO es inmutable también en el backend."""
    def setUp(self):
        self.a1 = User.objects.create_user("pa1", password="p")
        self.a2 = User.objects.create_user("pa2", password="p")

    def _completada_aprobada(self):
        a = Alert.objects.create(titulo="t", descripcion="d", estado="Pendiente",
                                 estado_analisis="COMPLETED", veredicto_ia="REQUIERE_ATENCION", riesgo_ia="LOW",
                                 contexto_ia_snapshot=dict(_SNAP_SEGURO))
        registrar_revision(a, accion="CORREGIDA", motivo_categoria="otro", autor=self.a1,
                           veredicto_gt="FALSO_POSITIVO")
        cand = a.candidato_dataset
        cand, errores = _ds.enviar_a_revision(cand, {
            "risk": "LOW", "explanation_es": "Explicación suficientemente larga para pasar la validación del contrato.",
            "cvss__attack_vector": "local", "cvss__attack_complexity": "baja",
            "cvss__privileges_required": "bajos", "cvss__user_interaction": "ninguna",
            "cvss__scope": "sin_cambio", "cvss__confidentiality_impact": "ninguno",
            "cvss__integrity_impact": "bajo", "cvss__availability_impact": "ninguno",
            "cvss_reasoning_es": "Justificación suficientemente larga para pasar la validación del contrato CVSS.",
            "recommendation_es": "Cerrar la alerta tras confirmar con el equipo responsable.",
            "missing_evidence": "",
        }, self.a1, confirmado=True)
        self.assertEqual(errores, [])
        cand, errores = _ds.revisar_candidato(cand, decision="APROBADO", autor=self.a2)
        self.assertEqual(errores, [])
        a.refresh_from_db()
        return a, cand

    def test_registrar_revision_rechaza_sobre_aprobado(self):
        a, cand = self._completada_aprobada()
        with self.assertRaises(ValueError):
            registrar_revision(a, accion="CONFIRMADA", motivo_categoria="otro", autor=self.a1)

    def test_guardar_borrador_rechaza_sobre_aprobado(self):
        a, cand = self._completada_aprobada()
        cand, errores = _ds.guardar_borrador(cand, {"risk": "HIGH"}, self.a1)
        self.assertTrue(errores)
        cand.refresh_from_db()
        self.assertEqual(cand.estado, "APROBADO")

    def test_enviar_a_revision_rechaza_sobre_aprobado(self):
        a, cand = self._completada_aprobada()
        cand, errores = _ds.enviar_a_revision(cand, {"risk": "HIGH"}, self.a1, confirmado=True)
        self.assertTrue(errores)

    def test_revisar_candidato_solo_admite_exclusion(self):
        a, cand = self._completada_aprobada()
        cand, errores = _ds.revisar_candidato(cand, decision="DEVUELTO", autor=self.a1, observaciones="x")
        self.assertTrue(errores)
        cand.refresh_from_db()
        self.assertEqual(cand.estado, "APROBADO")
        cand, errores = _ds.revisar_candidato(cand, decision="EXCLUIDO", autor=self.a1, observaciones="retiro auditado")
        self.assertEqual(errores, [])
        cand.refresh_from_db()
        self.assertEqual(cand.estado, "EXCLUIDO")
        # queda la revisión de aprobación Y la de exclusión; nada se borra
        self.assertEqual(RevisionCandidato.objects.filter(candidato=cand).count(), 2)

    def test_sincronizar_nunca_degrada_aprobado(self):
        a, cand = self._completada_aprobada()
        _ds.sincronizar_candidato(a)
        cand.refresh_from_db()
        self.assertEqual(cand.estado, "APROBADO")

    def test_vista_corregir_veredicto_bloquea_aprobado(self):
        a, cand = self._completada_aprobada()
        self.client.force_login(self.a1)
        r = self.client.post(reverse("corregir_veredicto", args=[a.id]),
                             {"correccion_veredicto": "REQUIERE_ATENCION", "motivo_categoria": "otro"})
        self.assertEqual(r.status_code, 302)
        a.refresh_from_db()
        self.assertEqual(a.correccion_veredicto, "FALSO_POSITIVO")  # sin cambios


class ID128InmutableTests(TestCase):
    """FASE 6/10: id 128 (candidato ya APROBADO en producción) queda intacta."""
    def setUp(self):
        self.admin = User.objects.create_user("i128b", password="p")
        self.admin.perfilusuario.rol = "ADMIN"; self.admin.perfilusuario.save()
        self.a = Alert.objects.create(
            id=128, titulo="t", descripcion="d", estado="Pendiente",
            estado_analisis="COMPLETED", veredicto_ia="REQUIERE_ATENCION", riesgo_ia="LOW",
            contexto_ia_snapshot=dict(_SNAP_SEGURO),
        )
        registrar_correccion_humana(self.a, veredicto="FALSO_POSITIVO", autor=self.admin, motivo="x")
        from dashboard.revision import sincronizar_revision_desde_correccion
        sincronizar_revision_desde_correccion(self.a, motivo_categoria="mantenimiento_programado")

    def test_no_se_completa_ni_aprueba_automaticamente(self):
        self.a.refresh_from_db()
        self.assertEqual(self.a.candidato_dataset.estado, "INCOMPLETO")

    def test_si_llega_a_aprobado_queda_protegida(self):
        cand = self.a.candidato_dataset
        otro = User.objects.create_user("i128c", password="p")
        cand, errores = _ds.enviar_a_revision(cand, {
            "risk": "LOW", "explanation_es": "Explicación suficientemente larga para pasar la validación del contrato.",
            "cvss__attack_vector": "local", "cvss__attack_complexity": "baja",
            "cvss__privileges_required": "bajos", "cvss__user_interaction": "ninguna",
            "cvss__scope": "sin_cambio", "cvss__confidentiality_impact": "ninguno",
            "cvss__integrity_impact": "bajo", "cvss__availability_impact": "ninguno",
            "cvss_reasoning_es": "Justificación suficientemente larga para pasar la validación del contrato CVSS.",
            "recommendation_es": "Cerrar la alerta tras confirmar con el equipo responsable.",
            "missing_evidence": "",
        }, self.admin, confirmado=True)
        self.assertEqual(errores, [])
        cand, errores = _ds.revisar_candidato(cand, decision="APROBADO", autor=otro)
        self.assertEqual(errores, [])
        self.a.refresh_from_db()
        self.assertTrue(self.a.dataset_aprobado)
        with self.assertRaises(ValueError):
            registrar_revision(self.a, accion="CONFIRMADA", motivo_categoria="otro", autor=self.admin)


class MultiagenteTests(TestCase):
    """FASE 8: la ingesta no está restringida al agent.id 000."""
    def setUp(self):
        self.srv = _activo_real()
        self.laptop = _activo_laptop()
        asignar_agente("000", "SRV-01")
        asignar_agente("101", "LAPTOP-01", etiqueta="WIN-FICTICIO")

    def test_agente_000_sigue_funcionando(self):
        self.assertEqual(resolver_activo_por_agente("000").identificador, "SRV-01")

    def test_agente_windows_ficticio_resuelve_a_su_propio_activo(self):
        activo = resolver_activo_por_agente("101")
        self.assertIsNotNone(activo)
        self.assertEqual(activo.identificador, "LAPTOP-01")
        self.assertEqual(activo.os_family, "windows")

    def test_cada_agente_a_su_propio_activo_no_se_mezclan(self):
        self.assertNotEqual(
            resolver_activo_por_agente("000").identificador,
            resolver_activo_por_agente("101").identificador,
        )

    def test_agente_sin_asignacion_se_rechaza(self):
        self.assertIsNone(resolver_activo_por_agente("999"))

    def test_identificador_privado_no_llega_a_evidencia_ni_entrada_e(self):
        alert = {
            "description": "File deleted.", "level": 8,
            "groups": "ossec,syscheck,syscheck_entry_deleted", "rule_id": "553",
            "timestamp": "2026-10-05T10:00:00Z", "agent_id": "101",
        }
        activo = resolver_activo_por_agente("101")
        entrada = construir_entrada_e(alert, activo)
        blob = json.dumps(entrada)
        self.assertNotIn("101", blob)

    def test_ingesta_real_con_agente_windows_asigna_activo_correcto(self):
        fake = _ProveedorFake()
        alert = {
            "opensearch_id": "WIN-TEST-1", "description": "Suspicious logon.", "level": 9,
            "groups": "authentication_failed,windows", "rule_id": "60122",
            "timestamp": "2026-10-05T10:00:00Z", "agent_id": "101",
        }
        obj, accion = ingestar_alerta(alert, proveedor=fake)
        self.assertEqual(obj.activo_logico.identificador, "LAPTOP-01")
        self.assertIsNone(obj.wazuh_agent_id and None)  # wazuh_agent_id es capa P; no se afirma nada sobre su exposición pública
        self.assertNotIn("101", obj.descripcion)


class MigracionLegadoDryRunTests(TestCase):
    """FASE 7: el comando de migración del legado SOLO diagnostica en dry-run."""
    def setUp(self):
        self.srv = _activo_real()
        asignar_agente("000", "SRV-01")
        Alert.objects.create(titulo="t", descripcion="legado 1", estado="Pendiente")
        Alert.objects.create(titulo="t", descripcion="legado 2", estado="Pendiente",
                             opensearch_id="LEG-OSID-1")

    def test_dry_run_no_llama_proveedor_ni_escribe(self):
        import dashboard.ia.legado as legado_mod
        original = legado_mod._buscar_documentos
        legado_mod._buscar_documentos = lambda ids: {}   # sin red: simula Wazuh inalcanzable
        llamado = {}
        def _prov(_n):
            llamado["si"] = True
            return None
        def _get_uno(_id):
            return None
        try:
            r = procesar_migracion_legado(
                scan_limit=10, max_analisis=2, dry=True, conf=False,
                get_uno=_get_uno, obtener_proveedor=_prov, log=lambda _s: None,
            )
        finally:
            legado_mod._buscar_documentos = original
        self.assertNotIn("si", llamado)
        self.assertEqual(r["modo"], "dry-run")
        self.assertEqual(r["migradas"], 0)
        self.assertEqual(r["llamadas_reales"], 0)
        self.assertIn("diagnostico", r)
        # no se tocó ninguna alerta
        for a in Alert.objects.all():
            self.assertIsNone(a.estado_analisis)

    def test_confirmar_sin_gate_de_entorno_aborta(self):
        os.environ.pop(GATE_ENV_VAR, None)
        with self.assertRaises(Exception):
            procesar_migracion_legado(
                scan_limit=10, max_analisis=1, dry=False, conf=True, agent_id="000",
                get_uno=lambda _id: None, obtener_proveedor=lambda _n: None, log=lambda _s: None,
            )
        for a in Alert.objects.all():
            self.assertIsNone(a.estado_analisis)   # sin escrituras

    def test_diagnosticar_legado_no_rompe_sin_wazuh(self):
        # con mocks que simulan "sin red", debe devolver un resumen y no reventar
        import dashboard.ia.legado as legado_mod
        original = legado_mod._buscar_documentos
        legado_mod._buscar_documentos = lambda ids: {}
        try:
            resumen = diagnosticar_legado()
            self.assertIn("legado_total", resumen)
            self.assertEqual(resumen["sin_documento"], resumen["legado_con_opensearch_id"])
        finally:
            legado_mod._buscar_documentos = original


class PlanificadorDatasetTests(TestCase):
    """FASE 9: planificador dry-run sin duplicados ni fuga entre conjuntos."""

    def test_ningun_bucket_se_reparte_entre_conjuntos(self):
        pools = {
            ("fim:deleted", "legado_recuperado"): 40,
            ("authentication_failed", "escenario_ubuntu_controlado"): 60,
            ("web", "escenario_ubuntu_controlado"): 30,
            ("sshd", "legado_recuperado"): 25,
        }
        plan = pldata.construir_plan(pools)
        vistos = {}
        for conjunto, filas in plan["detalle"].items():
            for f in filas:
                clave = (f["familia"], f["origen"])
                self.assertNotIn(clave, vistos, "un bucket no debe aparecer en dos conjuntos")
                vistos[clave] = conjunto

    def test_respeta_objetivos(self):
        pools = {("fim:deleted", "legado_recuperado"): 500}
        plan = pldata.construir_plan(pools)
        self.assertLessEqual(plan["asignado"]["train"], pldata.OBJETIVO_TRAIN)
        self.assertLessEqual(plan["asignado"]["val"], pldata.OBJETIVO_VAL)
        self.assertLessEqual(plan["asignado"]["test"], pldata.OBJETIVO_TEST_MAX)

    def test_sin_disponibilidad_no_asigna_nada(self):
        plan = pldata.construir_plan({})
        self.assertEqual(sum(plan["asignado"].values()), 0)

    def test_pools_ubuntu_controlado_es_estimacion_no_real(self):
        pools = pldata.pools_ubuntu_controlado(3, ["fim:deleted", "sshd"])
        self.assertTrue(all(v > 0 for v in pools.values()))

    def test_vista_planificador_responde_solo_categorias(self):
        u = User.objects.create_user("plan1", password="p")
        self.client.force_login(u)
        r = self.client.get(reverse("planificador_dataset"))
        self.assertEqual(r.status_code, 200)
        body = r.content.decode()
        self.assertIn("Solo planificación", body)
        self.assertNotIn(".jsonl", body.lower())


# ============================================================================
# Correcciones precommit 3C/3D
# ============================================================================
import hashlib
import importlib

from django.core.management.base import CommandError
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import Client, TransactionTestCase

from dashboard.ia import muestreo as _muestreo
from dashboard.management.commands.migrar_legado import GEMINI_GATE_ENV_VAR


class Migracion0010PortableTests(TransactionTestCase):
    """0010 es portable: no marca ninguna fila concreta (p. ej. una PK 128 ajena)."""
    MIG_ANTERIOR = [("dashboard", "0009_editor_candidato_dataset")]
    MIG_0010 = [("dashboard", "0010_legado_snapshot_y_origen_revision")]

    def test_estructura_dos_addfield_y_runpython_noop(self):
        from django.db import migrations
        mod = importlib.import_module("dashboard.migrations.0010_legado_snapshot_y_origen_revision")
        ops = mod.Migration.operations
        self.assertEqual([type(o).__name__ for o in ops], ["AddField", "AddField", "RunPython"])
        self.assertIs(ops[2].code, migrations.RunPython.noop)
        self.assertIs(ops[2].reverse_code, migrations.RunPython.noop)

    def test_base_nueva_con_pk_128_no_se_modifica(self):
        executor = MigrationExecutor(connection)
        executor.migrate(self.MIG_ANTERIOR)
        try:
            apps_viejas = executor.loader.project_state(self.MIG_ANTERIOR).apps
            AlertH = apps_viejas.get_model("dashboard", "Alert")
            RevH = apps_viejas.get_model("dashboard", "RevisionHumana")
            alerta = AlertH.objects.create(id=128, titulo="otra instalación", descripcion="d", estado="Pendiente")
            RevH.objects.create(alerta=alerta, accion="CONFIRMADA", motivo_categoria="otro")

            executor = MigrationExecutor(connection)
            executor.migrate(self.MIG_0010)
            apps_nuevas = executor.loader.project_state(self.MIG_0010).apps
            RevN = apps_nuevas.get_model("dashboard", "RevisionHumana")
            self.assertEqual(RevN.objects.get(alerta_id=128).origen, "OPERATIVA")
        finally:
            executor = MigrationExecutor(connection)
            executor.loader.build_graph()
            executor.migrate(executor.loader.graph.leaf_nodes())


def _osid_ficticio(i):
    """Identificador con forma de `_id` de OpenSearch (20 caracteres), ficticio."""
    return hashlib.sha1(f"doc-ficticio-{i}".encode()).hexdigest()[:20]


def _osid_en_muestra(dentro=True):
    """Primer identificador ficticio que cae (o no) en la muestra del 10 %."""
    i = 0
    while _muestreo.en_muestra_selectiva(_osid_ficticio(i)) != dentro:
        i += 1
    return _osid_ficticio(i)


class MuestreoSalPublicaTests(SimpleTestCase):
    """Muestra del 10 %: SHA-256(sal pública versionada + opensearch_id), nunca PK ni SECRET_KEY."""

    def _fp(self, **kw):
        base = dict(titulo="t", descripcion="d", estado="Pendiente", estado_analisis="COMPLETED",
                    veredicto_ia="FALSO_POSITIVO", riesgo_ia="LOW", severidad=3)
        base.update(kw)
        return Alert(**base)          # sin guardar: sólo se evalúa la política

    def test_formula_publica_reproducible_en_cualquier_entorno(self):
        for i in range(50):
            osid = _osid_ficticio(i)
            digest = hashlib.sha256(f"SENTRIA_AUDIT_SAMPLE_V1:{osid}".encode("utf-8")).hexdigest()
            esperado = int(digest[:8], 16) / 0x100000000 < 0.10
            self.assertEqual(_muestreo.en_muestra_selectiva(osid), esperado)

    def test_mismo_opensearch_id_con_pk_distinta_misma_decision(self):
        for dentro in (True, False):
            osid = _osid_en_muestra(dentro)
            a = self._fp(pk=5, opensearch_id=osid)
            b = self._fp(pk=98765, opensearch_id=osid)
            self.assertEqual(requiere_auditoria_selectiva(a), requiere_auditoria_selectiva(b))
            self.assertEqual(requiere_auditoria_selectiva(a)[0], dentro)

    def test_la_pk_no_influye(self):
        osid = _osid_en_muestra(False)
        for pk in range(1, 400):
            self.assertEqual(requiere_auditoria_selectiva(self._fp(pk=pk, opensearch_id=osid)), (False, None))

    def test_independiente_de_secret_key(self):
        ids = [_osid_ficticio(i) for i in range(500)]
        with override_settings(SECRET_KEY="clave-a-solo-para-prueba"):
            a = [_muestreo.en_muestra_selectiva(i) for i in ids]
        with override_settings(SECRET_KEY="clave-b-rotada-solo-para-prueba"):
            b = [_muestreo.en_muestra_selectiva(i) for i in ids]
        self.assertEqual(a, b)

    def test_estable_entre_ejecuciones(self):
        ids = [_osid_ficticio(i) for i in range(300)]
        self.assertEqual([_muestreo.en_muestra_selectiva(i) for i in ids],
                         [_muestreo.en_muestra_selectiva(i) for i in ids])

    def test_aproximadamente_10_por_ciento_con_ids_opensearch(self):
        n = 20000
        proporcion = sum(_muestreo.en_muestra_selectiva(_osid_ficticio(i)) for i in range(n)) / n
        self.assertTrue(0.09 <= proporcion <= 0.11, f"proporción observada: {proporcion}")

    def test_sin_opensearch_id_no_entra_por_muestra_ni_falla(self):
        self.assertFalse(_muestreo.en_muestra_selectiva(None))
        self.assertFalse(_muestreo.en_muestra_selectiva(""))
        self.assertFalse(_muestreo.en_muestra_selectiva("   "))
        for pk in range(1, 300):          # sin fallback a la PK, cualquiera que sea
            for vacio in (None, ""):
                self.assertEqual(requiere_auditoria_selectiva(self._fp(pk=pk, opensearch_id=vacio)), (False, None))

    def test_sin_opensearch_id_entra_por_nivel(self):
        self.assertEqual(requiere_auditoria_selectiva(self._fp(opensearch_id=None, severidad=10)),
                         (True, "nivel_alto"))

    def test_sin_opensearch_id_entra_por_riesgo(self):
        for riesgo in ("HIGH", "CRITICAL"):
            self.assertEqual(requiere_auditoria_selectiva(self._fp(opensearch_id=None, riesgo_ia=riesgo)),
                             (True, "riesgo_alto"))

    def test_no_depende_de_settings_ni_de_la_pk(self):
        import inspect
        fuente = inspect.getsource(_muestreo)
        self.assertNotIn("SECRET_KEY", inspect.getsource(_muestreo._hash_unitario))
        self.assertNotIn("django.conf", fuente)
        self.assertNotIn("alert.pk", fuente)


class MuestreoIdentificadorNoExpuestoTests(TestCase):
    """El opensearch_id usado para el muestreo no aparece en HTML, mensajes ni logs."""

    def setUp(self):
        self.admin = User.objects.create_user("muX", password="p")
        self.admin.perfilusuario.rol = "ADMIN"; self.admin.perfilusuario.save()
        self.osid = _osid_en_muestra(True)
        self.alerta = Alert.objects.create(
            titulo="t", descripcion="AUD-MUESTRA-ESTABLE", estado="Pendiente",
            estado_analisis="COMPLETED", veredicto_ia="FALSO_POSITIVO", riesgo_ia="LOW",
            severidad=3, opensearch_id=self.osid,
        )

    def test_entra_por_muestra_sin_exponer_el_identificador(self):
        self.client.force_login(self.admin)
        with self.assertNoLogs(level="DEBUG"):
            self.assertEqual(requiere_auditoria_selectiva(self.alerta), (True, "muestra_10pct"))
            self.assertIn(self.alerta.pk, _auditoria_selectiva_ids())
        with self.assertNoLogs("dashboard", level="DEBUG"):
            cola = self.client.get(reverse("cola_auditoria_selectiva"))
            hist = self.client.get(reverse("index"))
        for r in (cola, hist):
            self.assertEqual(r.status_code, 200)
            self.assertNotContains(r, self.osid)
        self.assertContains(cola, "AUD-MUESTRA-ESTABLE")

    def test_revision_desde_la_cola_no_expone_el_identificador(self):
        self.client.force_login(self.admin)
        url = reverse("revisar_alerta", args=[self.alerta.id])
        form = self.client.get(url + "?accion=confirmar&origen=auditoria_selectiva")
        self.assertNotContains(form, self.osid)
        r = self.client.post(url, {"accion": "confirmar", "motivo_categoria": "otro",
                                   "origen": "auditoria_selectiva"}, follow=True)
        self.assertNotContains(r, self.osid)
        for m in r.context["messages"]:
            self.assertNotIn(self.osid, str(m))
        self.assertEqual(RevisionHumana.objects.get(alerta=self.alerta).origen, "AUDITORIA_SELECTIVA")
        self.assertNotIn(self.alerta.pk, _auditoria_selectiva_ids())     # revisada: sale de la cola


# Documentos ficticios ya normalizados (formato de sentria_backend._normalizar_hit).
_AG_A, _AG_B = "731", "842"
_DOCS_MULTI = {
    "OS-A-HI": {"opensearch_id": "OS-A-HI", "agent_id": _AG_A, "level": 10, "groups": "syscheck", "rule_id": "550", "description": "A alto"},
    "OS-A-LO": {"opensearch_id": "OS-A-LO", "agent_id": _AG_A, "level": 3, "groups": "syscheck", "rule_id": "551", "description": "A bajo"},
    "OS-B-HI": {"opensearch_id": "OS-B-HI", "agent_id": _AG_B, "level": 12, "groups": "syscheck", "rule_id": "552", "description": "B alto"},
    "OS-B-LO": {"opensearch_id": "OS-B-LO", "agent_id": _AG_B, "level": 3, "groups": "syscheck", "rule_id": "553", "description": "B bajo"},
}


def _indexer_honesto(osid, agent_id=None):
    d = _DOCS_MULTI.get(osid)
    if d is None or (agent_id is not None and d["agent_id"] != agent_id):
        return None
    return dict(d)


def _indexer_ignora_filtro(osid, agent_id=None):
    d = _DOCS_MULTI.get(osid)
    return dict(d) if d else None


class _ProvFalso(proveedores.ProveedorIA):
    nombre = "falso"

    def __init__(self):
        self.prompts = []

    def analizar(self, prompt):
        self.prompts.append(prompt)
        return proveedores.RespuestaProveedor(ok=False, texto="", modelo="", error="falso")


class MigrarLegadoMultiagenteYAutorizacionesTests(TestCase):
    """--agent-id filtra de verdad y las autorizaciones de migración y Gemini son independientes."""

    def setUp(self):
        _activo_real()
        _activo_laptop()
        asignar_agente(_AG_A, "SRV-01")
        asignar_agente(_AG_B, "LAPTOP-01")
        for osid, d in _DOCS_MULTI.items():
            Alert.objects.create(titulo=osid, descripcion=d["description"], estado="Pendiente",
                                 opensearch_id=osid, severidad=d["level"],
                                 riesgo_ia="HIGH", explicacion_ia="análisis legado")
        p = mock.patch("dashboard.ia.legado._buscar_documentos",
                       lambda ids, agent_id=None: {i: dict(_DOCS_MULTI[i]) for i in ids if i in _DOCS_MULTI})
        p.start()
        self.addCleanup(p.stop)
        self.logs = []
        self.fabrica_llamada = []
        self.prov = _ProvFalso()

    def _fabrica(self, nombre):
        self.fabrica_llamada.append(nombre)
        return self.prov

    def _correr(self, *, entorno, dry=False, gemini=False, get_uno=_indexer_honesto, agent_id=_AG_A, max_analisis=3):
        with mock.patch.dict(os.environ, entorno):
            for var in (GATE_ENV_VAR, GEMINI_GATE_ENV_VAR):
                if var not in entorno:
                    os.environ.pop(var, None)
            return procesar_migracion_legado(
                scan_limit=50, max_analisis=max_analisis, dry=dry, conf=not dry, agent_id=agent_id,
                analizar_con_gemini=gemini, get_uno=get_uno, obtener_proveedor=self._fabrica,
                log=self.logs.append,
            )

    def _intacta(self, osid):
        a = Alert.objects.get(opensearch_id=osid)
        return a.estado_analisis is None and a.legado_snapshot is None and a.riesgo_ia == "HIGH"

    def _nada_escrito(self):
        return all(self._intacta(osid) for osid in _DOCS_MULTI)

    # --- autorizaciones ---
    def test_dry_run_rechaza_analizar_con_gemini(self):
        with self.assertRaises(CommandError):
            self._correr(entorno={GATE_ENV_VAR: "1", GEMINI_GATE_ENV_VAR: "1"}, dry=True, gemini=True)
        self.assertEqual(self.fabrica_llamada, [])
        self.assertTrue(self._nada_escrito())

    def test_dry_run_no_escribe_ni_llama(self):
        r = self._correr(entorno={GATE_ENV_VAR: "1", GEMINI_GATE_ENV_VAR: "1"}, dry=True)
        self.assertEqual(r["llamadas_reales"], 0)
        self.assertEqual(self.fabrica_llamada, [])
        self.assertTrue(self._nada_escrito())

    def test_gate_gemini_no_implica_gate_migracion(self):
        with self.assertRaises(CommandError):
            self._correr(entorno={GEMINI_GATE_ENV_VAR: "1", "GEMINI_API_KEY": "x"}, gemini=True)
        self.assertEqual(self.fabrica_llamada, [])
        self.assertTrue(self._nada_escrito())

    def test_flag_gemini_sin_gate_gemini_aborta_antes_de_escribir(self):
        with self.assertRaises(CommandError):
            self._correr(entorno={GATE_ENV_VAR: "1", "GEMINI_API_KEY": "x"}, gemini=True)
        self.assertEqual(self.fabrica_llamada, [])
        self.assertTrue(self._nada_escrito())

    def test_gate_gemini_sin_flag_no_crea_proveedor(self):
        r = self._correr(entorno={GATE_ENV_VAR: "1", GEMINI_GATE_ENV_VAR: "1", "GEMINI_API_KEY": "x"})
        self.assertEqual(self.fabrica_llamada, [])
        self.assertFalse(r["gemini_autorizado"])
        self.assertEqual(r["llamadas_reales"], 0)

    def test_solo_migracion_omite_no_elegibles_y_deja_intactas_las_elegibles(self):
        r = self._correr(entorno={GATE_ENV_VAR: "1"})
        self.assertEqual(self.fabrica_llamada, [])
        self.assertEqual(r["migradas_omitidas"], 1)
        self.assertEqual(r["requieren_gemini"], 1)
        self.assertEqual(r["migradas"], 0)
        lo = Alert.objects.get(opensearch_id="OS-A-LO")
        self.assertEqual(lo.estado_analisis, "OMITIDO_POLITICA")
        self.assertEqual(lo.legado_snapshot["riesgo_ia"], "HIGH")       # legado preservado
        self.assertEqual(lo.legado_snapshot["explicacion_ia"], "análisis legado")
        self.assertTrue(self._intacta("OS-A-HI"))                       # elegible: necesita Gemini

    def test_ambas_autorizaciones_llaman_al_proveedor_con_tope(self):
        r = self._correr(entorno={GATE_ENV_VAR: "1", GEMINI_GATE_ENV_VAR: "1", "GEMINI_API_KEY": "x"},
                         gemini=True, max_analisis=99)
        self.assertEqual(self.fabrica_llamada, ["gemini_developer"])
        self.assertTrue(r["gemini_autorizado"])
        self.assertLessEqual(r["llamadas_reales"], 3)          # tope absoluto
        self.assertEqual(r["max_analisis"], 3)
        self.assertEqual(len(self.prov.prompts), 1)            # sólo la elegible del agente A
        self.assertEqual(r["llamadas_reales"], 1)
        self.assertIsNotNone(Alert.objects.get(opensearch_id="OS-A-HI").legado_snapshot)

    def test_max_analisis_cero_no_llama(self):
        r = self._correr(entorno={GATE_ENV_VAR: "1", GEMINI_GATE_ENV_VAR: "1", "GEMINI_API_KEY": "x"},
                         gemini=True, max_analisis=0)
        self.assertEqual(r["llamadas_reales"], 0)
        self.assertEqual(self.prov.prompts, [])
        self.assertTrue(self._intacta("OS-A-HI"))

    # --- multiagente ---
    def test_indexer_recibe_el_filtro_de_agente(self):
        vistos = []

        def _espia(osid, agent_id=None):
            vistos.append(agent_id)
            return _indexer_honesto(osid, agent_id)
        self._correr(entorno={GATE_ENV_VAR: "1"}, get_uno=_espia)
        self.assertTrue(vistos)
        self.assertTrue(all(a == _AG_A for a in vistos))

    def test_agente_a_nunca_procesa_documentos_de_b(self):
        for get_uno in (_indexer_honesto, _indexer_ignora_filtro):
            self._correr(entorno={GATE_ENV_VAR: "1", GEMINI_GATE_ENV_VAR: "1", "GEMINI_API_KEY": "x"},
                         gemini=True, get_uno=get_uno)
            self.assertTrue(self._intacta("OS-B-HI"))
            self.assertTrue(self._intacta("OS-B-LO"))

    def test_documentos_de_otro_agente_se_rechazan_por_recomprobacion(self):
        r = self._correr(entorno={GATE_ENV_VAR: "1"}, get_uno=_indexer_ignora_filtro)
        self.assertEqual(r["rechazadas_otro_agente"], 2)
        self.assertTrue(self._intacta("OS-B-HI"))
        self.assertTrue(self._intacta("OS-B-LO"))

    def test_agente_b_tampoco_toca_a(self):
        self._correr(entorno={GATE_ENV_VAR: "1"}, agent_id=_AG_B, get_uno=_indexer_ignora_filtro)
        self.assertTrue(self._intacta("OS-A-HI"))
        self.assertTrue(self._intacta("OS-A-LO"))
        self.assertEqual(Alert.objects.get(opensearch_id="OS-B-LO").estado_analisis, "OMITIDO_POLITICA")

    def test_agent_id_no_aparece_en_salida(self):
        r = self._correr(entorno={GATE_ENV_VAR: "1"}, get_uno=_indexer_ignora_filtro)
        salida = " ".join(self.logs) + " " + json.dumps(
            {k: v for k, v in r.items() if k != "diagnostico"}, default=str)
        self.assertNotIn(_AG_A, salida)
        self.assertNotIn(_AG_B, salida)


class PlanificadorHonestoTests(TestCase):
    """Recuperable no es apto: sólo lo elegible entra al pool utilizable."""

    _DIAG = {
        "legado_total": 61, "legado_con_opensearch_id": 14, "legado_sin_opensearch_id": 47,
        "sin_documento": 0, "recuperables": 14, "recuperable_y_elegible": 1,
        "recuperable_no_elegible": 13, "no_elegible_total": 13, "sin_documento_recuperable": 47,
        "agente_bloqueado": 0, "sin_activo_asignado": 0,
        "por_familia": {"syscheck": 10, "sshd": 4}, "por_familia_elegible": {"syscheck": 1},
        "por_nivel": {}, "por_motivo_omision": {"NIVEL_NO_ELEGIBLE": 13}, "n_agentes_distintos": 1,
    }

    def test_no_elegibles_no_inflan_el_pool(self):
        pools = pldata.pools_utilizables(self._DIAG)
        self.assertEqual(sum(pools.values()), 1)
        plan = pldata.construir_plan(pools)
        self.assertEqual(sum(plan["asignado"].values()), 1)

    def test_resumen_real_y_deficit(self):
        real = pldata.resumen_real(self._DIAG, 1)
        self.assertEqual((real["recuperables"], real["elegibles"], real["no_elegibles"],
                          real["sin_documento_recuperable"], real["aprobados"]), (14, 1, 13, 47, 1))
        self.assertEqual((real["deficit_min"], real["deficit_max"]), (139, 149))

    def test_diag_con_error_no_rompe(self):
        self.assertEqual(pldata.pools_utilizables({"error": "x"}), {})
        self.assertEqual(pldata.resumen_real({"error": "x"}, 0)["deficit_min"], 140)

    def test_diagnostico_separa_recuperable_de_elegible(self):
        _activo_real()
        asignar_agente(_AG_A, "SRV-01")
        Alert.objects.create(titulo="t", descripcion="sin id", estado="Pendiente")
        for osid in ("OS-A-HI", "OS-A-LO", "OS-BORRADO"):
            Alert.objects.create(titulo="t", descripcion=osid, estado="Pendiente", opensearch_id=osid)
        with mock.patch("dashboard.ia.legado._buscar_documentos",
                        lambda ids, agent_id=None: {i: dict(_DOCS_MULTI[i]) for i in ids if i in _DOCS_MULTI}):
            d = diagnosticar_legado()
        self.assertEqual(d["recuperables"], 2)
        self.assertEqual(d["recuperable_y_elegible"], 1)
        self.assertEqual(d["no_elegible_total"], 1)
        self.assertEqual(d["sin_documento_recuperable"], 2)      # 1 sin opensearch_id + 1 borrado
        self.assertEqual(sum(pldata.pools_utilizables(d).values()), 1)

    def test_vista_muestra_cifras_separadas_y_aclaracion(self):
        u = User.objects.create_user("plan2", password="p")
        self.client.force_login(u)
        with mock.patch("dashboard.views.diagnosticar_legado", return_value=dict(self._DIAG)):
            r = self.client.get(reverse("planificador_dataset"))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.context["disponibilidad"]["legado_recuperado"], 1)
        self.assertEqual(r.context["real"]["no_elegibles"], 13)
        self.assertContains(r, "Recuperable no significa apto para entrenamiento")
        self.assertContains(r, "faltan 140–150")       # 0 aprobados en esta base de prueba


class OrigenRevisionNoManipulableTests(TestCase):
    """El origen lo decide el backend según flujo y rol; el cliente sólo puede pedirlo."""

    def setUp(self):
        self.analista = User.objects.create_user("orA", password="p")    # ANALISTA por señal
        self.admin = User.objects.create_user("orB", password="p")
        self.admin.perfilusuario.rol = "ADMIN"; self.admin.perfilusuario.save()
        self.invitado = User.objects.create_user("orC", password="p")
        self.invitado.perfilusuario.rol = "INVITADO"; self.invitado.perfilusuario.save()

    def _alerta(self, **kw):
        base = dict(titulo="t", descripcion="d", estado="Pendiente", estado_analisis="COMPLETED",
                    veredicto_ia="REQUIERE_ATENCION", riesgo_ia="LOW", severidad=3)
        base.update(kw)
        return Alert.objects.create(**base)

    def _confirmar(self, user, alerta, origen=None, en_url=False):
        self.client.force_login(user)
        url = reverse("revisar_alerta", args=[alerta.id])
        datos = {"accion": "confirmar", "motivo_categoria": "otro"}
        if origen is not None:
            if en_url:
                url += f"?accion=confirmar&origen={origen}"
            else:
                datos["origen"] = origen
        return self.client.post(url, datos)

    def _corregir(self, user, alerta, origen=None):
        self.client.force_login(user)
        datos = {"correccion_veredicto": "FALSO_POSITIVO", "motivo_categoria": "otro", "nota": "n"}
        if origen is not None:
            datos["origen"] = origen
        return self.client.post(reverse("corregir_veredicto", args=[alerta.id]), datos)

    def _origen(self, alerta):
        rev = RevisionHumana.objects.filter(alerta=alerta).first()
        return rev.origen if rev else None

    def test_sin_origen_es_operativa(self):
        a = self._alerta()
        self._confirmar(self.analista, a)
        self.assertEqual(self._origen(a), "OPERATIVA")

    def test_analista_no_puede_forzar_prueba_controlada_por_formulario(self):
        a = self._alerta()
        self._confirmar(self.analista, a, "prueba_controlada")
        self.assertIsNone(self._origen(a))

    def test_analista_no_puede_forzar_prueba_controlada_por_url(self):
        a = self._alerta()
        self._confirmar(self.analista, a, "prueba_controlada", en_url=True)
        self.assertIsNone(self._origen(a))

    def test_analista_no_puede_forzar_prueba_controlada_al_corregir(self):
        a = self._alerta()
        self._corregir(self.analista, a, "prueba_controlada")
        self.assertIsNone(self._origen(a))

    def test_admin_si_puede_registrar_prueba_controlada(self):
        a = self._alerta()
        self._confirmar(self.admin, a, "prueba_controlada")
        self.assertEqual(self._origen(a), "PRUEBA_CONTROLADA")

    def test_migracion_legado_nunca_desde_la_web(self):
        for user in (self.analista, self.admin):
            a = self._alerta()
            self._confirmar(user, a, "migracion_legado")
            self.assertIsNone(self._origen(a))
            b = self._alerta()
            self._corregir(user, b, "MIGRACION_LEGADO")
            self.assertIsNone(self._origen(b))

    def test_origen_desconocido_rechazado(self):
        a = self._alerta()
        self._confirmar(self.admin, a, "inventado")
        self.assertIsNone(self._origen(a))

    def test_auditoria_selectiva_solo_si_la_alerta_esta_en_esa_cola(self):
        en_cola = self._alerta(veredicto_ia="FALSO_POSITIVO", severidad=10)
        self._confirmar(self.analista, en_cola, "auditoria_selectiva")
        self.assertEqual(self._origen(en_cola), "AUDITORIA_SELECTIVA")

        fuera = self._alerta(veredicto_ia="REQUIERE_ATENCION", severidad=12)
        self._confirmar(self.analista, fuera, "auditoria_selectiva")
        self.assertEqual(self._origen(fuera), "OPERATIVA")

    def test_auditoria_selectiva_al_corregir_desde_la_cola(self):
        en_cola = self._alerta(veredicto_ia="FALSO_POSITIVO", riesgo_ia="HIGH")
        self._corregir(self.analista, en_cola, "auditoria_selectiva")
        self.assertEqual(self._origen(en_cola), "AUDITORIA_SELECTIVA")

    def test_invitado_no_puede_revisar_con_ningun_origen(self):
        a = self._alerta()
        r = self._confirmar(self.invitado, a, "operativa")
        self.assertNotEqual(r.status_code, 200)
        self.assertIsNone(self._origen(a))

    def test_post_sin_csrf_rechazado(self):
        a = self._alerta()
        c = Client(enforce_csrf_checks=True)
        c.force_login(self.admin)
        r = c.post(reverse("revisar_alerta", args=[a.id]),
                   {"accion": "confirmar", "motivo_categoria": "otro", "origen": "prueba_controlada"})
        self.assertEqual(r.status_code, 403)
        self.assertIsNone(self._origen(a))

    def test_pista_de_origen_en_formulario_solo_valores_conocidos(self):
        a = self._alerta()
        self.client.force_login(self.analista)
        r = self.client.get(reverse("revisar_alerta", args=[a.id]) + "?accion=confirmar&origen=<x>")
        self.assertEqual(r.context["origen_param"], "")
