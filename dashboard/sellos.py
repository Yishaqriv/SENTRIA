"""
Sellos de integridad de las entradas y salidas del dataset (registros append-only).

Dos huellas con propósitos DISTINTOS (no intercambiables):

- Huella SEMÁNTICA (`dataset.fingerprint_entrada`, versión `semantica_v1`):
  sirve para DEDUPLICAR. Ignora metadatos (`schema_version`,
  `technical_evidence_es`, `evidencia_tecnica.correlated_events`) y se recalcula
  en cada sincronización. NO es un sello de integridad.

- Huella de INTEGRIDAD (`huella_integridad`, serialización `json_canonico_v1`):
  SHA-256 (hex) de la serialización canónica COMPLETA del objeto, sin excluir
  ninguna clave:
      json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
  codificada en UTF-8. Si la serialización cambia alguna vez, se crea una
  versión nueva; las huellas antiguas conservan la suya en `serializacion_version`.

Qué se sella y cuándo:
- `EntradaRevisada`: la entrada del candidato tal como la vio quien revisó,
  congelada al guardar el primer borrador; nunca se actualiza. Una re-congelación
  es explícita (motivo obligatorio) y crea otra versión enlazada con la anterior.
- `ConfirmacionBorrador`: al confirmar el borrador (`enviar_a_revision`) se sella
  la salida y se enlaza con la entrada revisada vigente.
- Al aprobar se exige que la entrada y la salida actuales coincidan con las
  confirmadas, y `RevisionCandidato` guarda ambas huellas.

Las entradas históricas (anteriores a estos sellos) NO se reconstruyen con el
código actual para presentarlas como la entrada revisada: el comando
`congelar_entradas` las clasifica por regla con un `origen` explícito.
"""
from __future__ import annotations

import hashlib
import json

from django.db import transaction

from .models import ConfirmacionBorrador, EntradaRevisada

SERIALIZACION_VERSION = "json_canonico_v1"

# Verificación heredada: huella COMPLETA usada antes de `semantica_v1`
# (commit 027c1e9): SHA-256 de la serialización canónica de la entrada
# seleccionada con la lista blanca de entonces (16 claves).
LEGADO_ALGORITMO = "completa_027c1e9"
LEGADO_SELECCION_VERSION = "lista_blanca_v1"
LEGADO_CLAVES = (
    "schema_version", "alert_description_es", "wazuh_level", "wazuh_rule_groups",
    "wazuh_rule_id", "asset_type", "asset_criticality", "asset_os_family",
    "asset_os_role", "operational_window", "maintenance_window",
    "maintenance_category", "authorized_context_es", "technical_evidence_es",
    "evidencia_tecnica", "observed_cvss_factors",
)

LIMITACION_SNAPSHOT_CONSERVADO = (
    "Entrada seleccionada del snapshot conservado. Coincide la huella semántica registrada en la "
    "última sincronización, que ignora metadatos: no demuestra que sea exactamente la entrada revisada."
)
LIMITACION_HUELLA_LEGADO = (
    "El snapshot actual coincide con la huella completa guardada por un algoritmo anterior en la última "
    "sincronización, previa o simultánea a la aprobación. No prueba el contenido exacto en el momento de "
    "aprobar. La salida no tiene huella tomada al aprobar: solo la protege la inmutabilidad del estado APROBADO."
)


def serializar_canonico(obj) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def huella_integridad(obj) -> str:
    """SHA-256 de la serialización canónica completa (`json_canonico_v1`)."""
    return hashlib.sha256(serializar_canonico(obj).encode("utf-8")).hexdigest()


def huella_legado(snapshot) -> str:
    """Huella completa del algoritmo anterior a `semantica_v1` sobre un snapshot."""
    snap = snapshot or {}
    return huella_integridad({k: snap[k] for k in LEGADO_CLAVES if k in snap})


def ultima_entrada(cand):
    return EntradaRevisada.objects.filter(candidato=cand).order_by("-version").first()


def ultima_confirmacion(cand):
    return ConfirmacionBorrador.objects.filter(candidato=cand).order_by("-creada_en", "-id").first()


def _difiere(registro, entrada, snapshot):
    """Motivos por los que la entrada actual no coincide con un registro congelado."""
    motivos = []
    if registro.entrada_sha256 != huella_integridad(entrada):
        motivos.append("la entrada")
    if registro.snapshot_sha256 != huella_integridad(snapshot or {}):
        motivos.append("el snapshot de origen")
    return motivos


def verificar_entrada(cand, entrada, snapshot):
    """Errores si la entrada actual no coincide con la última entrada congelada."""
    reg = ultima_entrada(cand)
    if reg is None:
        return []
    motivos = _difiere(reg, entrada, snapshot)
    if motivos:
        return [f"cambió {' y '.join(motivos)} desde su congelación (v{reg.version}, {reg.origen}): "
                "hace falta volver a congelarla explícitamente y revisar de nuevo"]
    return []


def _nueva_version(cand, anterior, entrada, snapshot, autor, *, origen, seleccion_version, motivo,
                   transformacion_id="", limitaciones=""):
    return EntradaRevisada.objects.create(
        candidato=cand, version=(anterior.version + 1) if anterior else 1, anterior=anterior,
        origen=origen, entrada=entrada,
        entrada_sha256=huella_integridad(entrada),
        snapshot_sha256=huella_integridad(snapshot or {}),
        serializacion_version=SERIALIZACION_VERSION,
        seleccion_version=seleccion_version,
        transformacion_id=transformacion_id, motivo=motivo, limitaciones=limitaciones,
        creada_por=getattr(autor, "username", "") or "",
    )


def asegurar_entrada_revisada(cand, entrada, snapshot, autor, *, seleccion_version):
    """
    Se llama al guardar o confirmar un borrador, DENTRO de la transacción del
    llamador y con la fila del candidato bloqueada. Devuelve (registro, errores).

    - Primera vez: congela la entrada como ENTRADA_REVISADA (v1).
    - Si la entrada o el snapshot cambiaron desde la última congelación: error
      (hace falta una re-congelación explícita).
    - Si la última versión es histórica (SNAPSHOT_CONSERVADO, HUELLA_LEGADO…) o ya
      tiene una confirmación, se crea una versión NUEVA enlazada: así una entrada
      histórica nunca pasa por revisada sin que alguien la revise ahora, y editar
      un borrador confirmado invalida esa confirmación aunque luego se recupere
      el mismo texto (la confirmación apunta a una versión que ya no es la vigente).
    Sin snapshot no se congela nada: las validaciones del candidato ya lo bloquean.
    """
    if not snapshot:
        return None, []
    reg = ultima_entrada(cand)
    if reg is None:
        return _nueva_version(cand, None, entrada, snapshot, autor, origen="ENTRADA_REVISADA",
                              seleccion_version=seleccion_version, motivo=""), []
    errores = verificar_entrada(cand, entrada, snapshot)
    if errores:
        return None, errores
    if reg.origen != "ENTRADA_REVISADA":
        motivo = f"Revisada en el editor sobre la entrada histórica v{reg.version} ({reg.origen})."
    elif ConfirmacionBorrador.objects.filter(entrada_revisada=reg).exists():
        motivo = f"Nuevo borrador tras la confirmación de la v{reg.version}: esa confirmación deja de valer."
    else:
        return reg, []
    return _nueva_version(cand, reg, entrada, snapshot, autor, origen="ENTRADA_REVISADA",
                          seleccion_version=seleccion_version, motivo=motivo), []


def recongelar_entrada(cand, entrada, snapshot, autor, *, motivo, seleccion_version,
                       origen="ENTRADA_REVISADA", transformacion_id="", limitaciones=""):
    """
    Nueva versión EXPLÍCITA y auditada de la entrada congelada (nunca automática).
    No toca la versión anterior: la enlaza. Nunca sustituye la entrada de un
    candidato APROBADO. Devuelve (registro, errores).
    """
    if not (motivo or "").strip():
        return None, ["hace falta un motivo para volver a congelar la entrada"]
    if origen == "DERIVADA" and not transformacion_id:
        return None, ["una entrada DERIVADA necesita el identificador de su transformación"]
    with transaction.atomic():
        bloqueado = type(cand).objects.select_for_update().get(pk=cand.pk)
        if bloqueado.estado == "APROBADO":
            return None, ["un candidato APROBADO es inmutable: no se puede sustituir su entrada"]
        reg = _nueva_version(bloqueado, ultima_entrada(bloqueado), entrada, snapshot, autor, origen=origen,
                             seleccion_version=seleccion_version, motivo=motivo.strip(),
                             transformacion_id=transformacion_id, limitaciones=limitaciones)
    return reg, []


def sellar_confirmacion(cand, registro_entrada, salida, autor):
    """Sella la salida confirmada y la enlaza con la entrada revisada vigente."""
    return ConfirmacionBorrador.objects.create(
        candidato=cand, entrada_revisada=registro_entrada, salida=salida,
        salida_sha256=huella_integridad(salida),
        serializacion_version=SERIALIZACION_VERSION,
        confirmada_por=getattr(autor, "username", "") or "",
    )


def verificar_para_aprobar(cand, entrada, snapshot, salida):
    """La entrada y la salida actuales deben coincidir con las confirmadas."""
    conf = ultima_confirmacion(cand)
    if conf is None:
        return ["no hay una confirmación sellada del borrador: hay que volver a enviarlo a revisión"]
    errores = []
    if conf.entrada_revisada.origen != "ENTRADA_REVISADA":
        errores.append("la confirmación no corresponde a una entrada revisada")
    vigente = ultima_entrada(cand)
    if vigente is None or vigente.pk != conf.entrada_revisada_id:
        errores.append("la entrada se volvió a congelar o el borrador se editó después de la confirmación: "
                       "hay que confirmar de nuevo")
    motivos = _difiere(conf.entrada_revisada, entrada, snapshot)
    if motivos:
        errores.append(f"cambió {' y '.join(motivos)} desde la confirmación")
    if conf.salida_sha256 != huella_integridad(salida):
        errores.append("la salida cambió desde la confirmación")
    return errores


def clasificar_historico(cand, entrada, snapshot, *, fingerprint_semantico, version_semantica):
    """
    Clasificación por REGLA (nunca por ID) de un candidato sin entrada congelada.
    Devuelve dict con origen, entrada a sellar, selección, algoritmo y limitaciones.
    No escribe nada.
    """
    if not snapshot:
        return {"origen": "NO_VERIFICABLE", "detalle": "sin snapshot congelado"}
    diag = cand.diagnostico or {}
    if not diag.get("fingerprint_version") and cand.fingerprint and cand.fingerprint == huella_legado(snapshot):
        entrada_legado = {k: snapshot[k] for k in LEGADO_CLAVES if k in snapshot}
        return {"origen": "HUELLA_LEGADO_VERIFICADA", "entrada": entrada_legado,
                "seleccion_version": LEGADO_SELECCION_VERSION, "algoritmo": LEGADO_ALGORITMO,
                "limitaciones": LIMITACION_HUELLA_LEGADO,
                "detalle": "huella completa del algoritmo anterior coincide con el snapshot"}
    if diag.get("fingerprint_version") == version_semantica and cand.fingerprint == fingerprint_semantico:
        if cand.estado == "APROBADO":
            return {"origen": "NO_VERIFICABLE",
                    "detalle": "APROBADO sin sello de aprobación: la huella semántica no basta"}
        return {"origen": "SNAPSHOT_CONSERVADO", "entrada": entrada, "algoritmo": version_semantica,
                "limitaciones": LIMITACION_SNAPSHOT_CONSERVADO,
                "detalle": "coincide la huella semántica registrada (no prueba la entrada exacta revisada)"}
    return {"origen": "NO_VERIFICABLE", "detalle": "ninguna huella registrada coincide con el snapshot actual"}
