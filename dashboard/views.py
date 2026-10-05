import csv
import datetime
import sys
import os
import time

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.exceptions import ValidationError
from django.core.paginator import Paginator
from django.http import HttpResponse
from django.db.models import Q
from django.utils import timezone

from usuarios.decorators import requiere_rol, usuario_tiene_rol

from .models import (
    Alert, ActivoLogico, VentanaMantenimiento, RevisionHumana, CandidatoDataset,
)
from .ia.ingesta import ingestar_lote, reanalizar_alerta
from .ia.persistencia import registrar_correccion_humana
from .ia.proveedores import nombre_proveedor_activo
from .mantenimiento import crear_ventana, cancelar_ventana
from .revision import registrar_revision, MOTIVOS as MOTIVOS_REVISION, RIESGOS as RIESGOS_REVISION
from . import dataset as ds
from .dataset import sincronizar_todos, vista_bandeja
from .metricas_eval import matriz_confusion, resumen_revisiones, resumen_por_origen
from .ia.contrato import CVSS_ENUMS, RIESGOS as CONTRATO_RIESGOS
from .ia.muestreo import requiere_auditoria_selectiva, POLITICA_MUESTREO_VERSION
from .ia.legado import diagnosticar_legado
from . import planificador_dataset as pd

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from sentria_backend import get_latest_alerts, get_alert_by_id

ESTADOS_VALIDOS = ['Pendiente', 'Revisada', 'Falso positivo']
RIESGOS_VALIDOS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
VEREDICTOS_VALIDOS = ['FALSO_POSITIVO', 'REQUIERE_ATENCION']
ANALISIS_VALIDOS = ['PENDING', 'COMPLETED', 'ANALISIS_FALLIDO', 'OMITIDO_POLITICA']
MOTIVOS_VALIDOS = ['SIN_CONTEXTO_ACTIVO', 'NIVEL_NO_ELEGIBLE', 'RUIDO_OPERATIVO', 'REGLA_EXCLUIDA']
REVISION_VALIDOS = ['sin_revisar', 'confirmada', 'corregida', 'excluida', 'con_verdad_terreno']
ORDEN_VALIDO    = ['timestamp', '-timestamp', 'severidad', '-severidad', 'riesgo_ia', '-riesgo_ia', 'estado', '-estado']

PAUSA_ENTRE_LLAMADAS_GEMINI = 4  # segundos, para no exceder la cuota de Gemini

# --- Q para el veredicto EFECTIVO (corrección humana si existe, si no el de la IA) ---
Q_EFECTIVO_ATENCION = (
    Q(correccion_veredicto='REQUIERE_ATENCION')
    | (Q(correccion_veredicto__isnull=True) & Q(veredicto_ia='REQUIERE_ATENCION'))
)
Q_EFECTIVO_FP = (
    Q(correccion_veredicto='FALSO_POSITIVO')
    | (Q(correccion_veredicto__isnull=True) & Q(veredicto_ia='FALSO_POSITIVO'))
)
Q_PENDIENTES = (
    Q(estado_analisis__in=['PENDING', 'OMITIDO_POLITICA', 'ANALISIS_FALLIDO'])
    | Q(estado_analisis__isnull=True)
)
# --- Colas más claras (3C/3D): separan lo que es trabajo pendiente REAL del
# analista de lo que no lo es (legado, omitido por política). ---
Q_PENDIENTES_TECNICOS = Q(estado_analisis__in=['PENDING', 'ANALISIS_FALLIDO'])
Q_OMITIDAS = Q(estado_analisis='OMITIDO_POLITICA')
Q_LEGADO = Q(estado_analisis__isnull=True)

# Origen auditable de una revisión: lo decide el BACKEND. El cliente sólo puede
# *pedir* uno (parámetro 'origen'); la petición se valida contra el flujo real
# y el rol. MIGRACION_LEGADO nunca se asigna desde la web: sólo el proceso de
# migración autorizado.
ORIGENES_PEDIBLES = ('operativa', 'auditoria_selectiva', 'prueba_controlada')


def _en_auditoria_selectiva(alerta):
    """True si la alerta está HOY en la cola de auditoría selectiva."""
    if alerta.estado_analisis != 'COMPLETED' or alerta.veredicto_ia != 'FALSO_POSITIVO':
        return False
    if RevisionHumana.objects.filter(alerta=alerta).exists():
        return False
    return requiere_auditoria_selectiva(alerta)[0]


def _resolver_origen(request, alerta):
    """
    -> (origen, error). Con `error`, la petición se rechaza sin registrar nada.
    - vacío / 'operativa'      -> OPERATIVA.
    - 'auditoria_selectiva'    -> AUDITORIA_SELECTIVA sólo si la alerta está
                                  realmente en esa cola; si ya no lo está
                                  (enlace viejo), OPERATIVA.
    - 'prueba_controlada'      -> sólo ADMIN; cualquier otro rol se rechaza.
    - cualquier otro valor (incluido 'migracion_legado') -> rechazado.
    """
    pedido = (request.POST.get('origen') or request.GET.get('origen') or '').strip().lower()
    if pedido in ('', 'operativa'):
        return 'OPERATIVA', None
    if pedido == 'auditoria_selectiva':
        return ('AUDITORIA_SELECTIVA' if _en_auditoria_selectiva(alerta) else 'OPERATIVA'), None
    if pedido == 'prueba_controlada':
        if usuario_tiene_rol(request.user, ['ADMIN']):
            return 'PRUEBA_CONTROLADA', None
        return None, "Solo un administrador puede registrar una revisión como prueba controlada."
    return None, "Origen de revisión no permitido desde el dashboard."


def _origen_param(request):
    """Pista de origen para el formulario (sólo valores conocidos; no decide nada)."""
    pedido = (request.GET.get('origen') or '').strip().lower()
    return pedido if pedido in ORIGENES_PEDIBLES else ''


def _auditoria_selectiva_ids():
    """PKs de FALSO_POSITIVO originales de la IA, sin revisión, que entran a la
    auditoría selectiva (nivel alto, riesgo alto o muestra estable del 10%)."""
    candidatas = Alert.objects.filter(
        estado_analisis='COMPLETED', veredicto_ia='FALSO_POSITIVO', revision_humana__isnull=True,
    ).only('id', 'severidad', 'riesgo_ia', 'opensearch_id')
    return [a.pk for a in candidatas if requiere_auditoria_selectiva(a)[0]]


def _aplicar_filtros(request, alertas):
    """Filtros GET compartidos por todas las colas y la exportación CSV."""
    riesgo    = request.GET.get('riesgo', '')
    estado    = request.GET.get('estado', '')
    veredicto = request.GET.get('veredicto', '')
    analisis  = request.GET.get('analisis', '')
    motivo    = request.GET.get('motivo', '')
    revision  = request.GET.get('revision', '')
    severidad = request.GET.get('severidad', '')
    busqueda  = request.GET.get('q', '').strip()
    orden     = request.GET.get('orden', '-timestamp')

    if riesgo in RIESGOS_VALIDOS:
        alertas = alertas.filter(riesgo_ia=riesgo)
    if estado in ESTADOS_VALIDOS:
        alertas = alertas.filter(estado=estado)
    if veredicto in VEREDICTOS_VALIDOS:
        alertas = alertas.filter(veredicto_ia=veredicto)
    if analisis in ANALISIS_VALIDOS:
        alertas = alertas.filter(estado_analisis=analisis)
    if motivo in MOTIVOS_VALIDOS:
        alertas = alertas.filter(motivo_omision=motivo)
    if revision in REVISION_VALIDOS:
        if revision == 'sin_revisar':
            alertas = alertas.filter(revision_humana__isnull=True)
        elif revision == 'confirmada':
            alertas = alertas.filter(revision_humana__accion='CONFIRMADA')
        elif revision == 'corregida':
            alertas = alertas.filter(revision_humana__accion='CORREGIDA')
        elif revision == 'excluida':
            alertas = alertas.filter(revision_humana__accion='EXCLUIDA')
        elif revision == 'con_verdad_terreno':
            alertas = alertas.filter(revision_humana__accion__in=['CONFIRMADA', 'CORREGIDA'])

    if severidad == 'alta':
        alertas = alertas.filter(severidad__gte=12)
    elif severidad == 'media':
        alertas = alertas.filter(severidad__gte=7, severidad__lt=12)
    elif severidad == 'baja':
        alertas = alertas.filter(severidad__lt=7)

    if busqueda:
        alertas = alertas.filter(descripcion__icontains=busqueda)

    alertas = alertas.order_by(orden if orden in ORDEN_VALIDO else '-timestamp')

    filtros = {
        'filtro_riesgo': riesgo, 'filtro_estado': estado, 'filtro_veredicto': veredicto,
        'filtro_analisis': analisis, 'filtro_motivo': motivo, 'filtro_revision': revision,
        'filtro_severidad': severidad, 'filtro_orden': orden, 'filtro_q': busqueda,
    }
    return alertas.select_related('activo_logico', 'revision_humana'), filtros


def _contadores():
    base = Alert.objects
    return {
        'total': base.count(),
        # Contadores "IA" -> resultado ORIGINAL de la IA
        'n_ia_atencion': base.filter(veredicto_ia='REQUIERE_ATENCION').count(),
        'n_ia_falso_positivo': base.filter(veredicto_ia='FALSO_POSITIVO').count(),
        # Contadores OPERATIVOS -> veredicto EFECTIVO (con corrección humana)
        'n_efectivo_atencion': base.filter(Q_EFECTIVO_ATENCION).count(),
        'n_efectivo_falso_positivo': base.filter(Q_EFECTIVO_FP).count(),
        # Estados de análisis
        'n_omitidas': base.filter(estado_analisis='OMITIDO_POLITICA').count(),
        'n_fallidas': base.filter(estado_analisis='ANALISIS_FALLIDO').count(),
        'n_pendientes_analisis': base.filter(
            Q(estado_analisis='PENDING') | Q(estado_analisis__isnull=True)
        ).count(),
        # Colas 3C/3D: el análisis legado NUNCA cuenta como pendiente ordinario.
        'n_pendientes_tecnicos': base.filter(Q_PENDIENTES_TECNICOS).count(),
        'n_legado': base.filter(Q_LEGADO).count(),
        'n_auditoria_selectiva': len(_auditoria_selectiva_ids()),
        # Riesgo IA
        'n_critical': base.filter(riesgo_ia='CRITICAL').count(),
        'n_high': base.filter(riesgo_ia='HIGH').count(),
        'n_medium': base.filter(riesgo_ia='MEDIUM').count(),
        'n_low': base.filter(riesgo_ia='LOW').count(),
        'n_pendiente': base.filter(estado='Pendiente').count(),
        # Revisión humana / verdad de terreno
        'n_sin_revisar': base.filter(estado_analisis='COMPLETED', revision_humana__isnull=True).count(),
        'n_revision_confirmada': base.filter(revision_humana__accion='CONFIRMADA').count(),
        'n_revision_corregida': base.filter(revision_humana__accion='CORREGIDA').count(),
        'n_revision_excluida': base.filter(revision_humana__accion='EXCLUIDA').count(),
        'n_candidatos_dataset': CandidatoDataset.objects.count(),
    }


def _render_cola(request, base_qs, *, cola, titulo, subtitulo):
    alertas, filtros = _aplicar_filtros(request, base_qs)

    paginator = Paginator(alertas, 20)
    page_obj = paginator.get_page(request.GET.get('page', 1))

    params = request.GET.copy()
    params.pop('page', None)

    contexto = {
        'page_obj': page_obj,
        'cola_activa': cola,
        'cola_titulo': titulo,
        'cola_subtitulo': subtitulo,
        'proveedor_activo': nombre_proveedor_activo(),
        'query_string': params.urlencode(),
    }
    contexto.update(_contadores())
    contexto.update(filtros)
    return render(request, 'dashboard/index.html', contexto)


@login_required
def cola_historial(request):
    return _render_cola(
        request, Alert.objects.all(),
        cola='historial', titulo='Historial completo',
        subtitulo='Todas las alertas registradas, con su clasificación de IA y sus correcciones.',
    )


@login_required
def cola_atencion(request):
    return _render_cola(
        request, Alert.objects.filter(Q_EFECTIVO_ATENCION),
        cola='atencion', titulo='Requiere atención',
        subtitulo='Veredicto efectivo = requiere atención (incluye correcciones humanas).',
    )


@login_required
def cola_falsos_positivos(request):
    return _render_cola(
        request, Alert.objects.filter(Q_EFECTIVO_FP),
        cola='fp', titulo='Falsos positivos',
        subtitulo='Veredicto EFECTIVO = falso positivo (corrección humana si existe, si no el de la IA). '
                  'La clasificación original de la IA sigue disponible con el filtro «veredicto».',
    )


@login_required
def cola_falsos_positivos_ia(request):
    """Alias seguro de la URL antigua `/falsos-positivos-ia/` -> cola de falsos
    positivos EFECTIVOS, conservando los parámetros GET."""
    destino = redirect('cola_falsos_positivos')
    qs = request.GET.urlencode()
    if qs:
        destino['Location'] = f"{destino['Location']}?{qs}"
    return destino


@login_required
def cola_pendientes(request):
    """Pendientes y fallidas: trabajo técnico REAL del analista. El análisis
    legado y lo omitido por política tienen sus propias colas (no son "trabajo
    pendiente ordinario")."""
    return _render_cola(
        request, Alert.objects.filter(Q_PENDIENTES_TECNICOS),
        cola='pendientes', titulo='Pendientes y fallidas',
        subtitulo='Pendientes de análisis y fallos de análisis del contrato IA actual. '
                  'No incluye análisis legado ni alertas omitidas por política (ver sus propias colas).',
    )


@login_required
def cola_omitidas(request):
    return _render_cola(
        request, Alert.objects.filter(Q_OMITIDAS),
        cola='omitidas', titulo='Omitidas por política',
        subtitulo='No se enviaron al modelo de IA (ruido confirmado, nivel no elegible, sin contexto de activo o regla excluida). '
                  'No son un fallo de análisis.',
    )


@login_required
def cola_legado(request):
    return _render_cola(
        request, Alert.objects.filter(Q_LEGADO),
        cola='legado', titulo='Análisis Legado - Pendiente de migrar al flujo IA actual',
        subtitulo='Son anteriores al contrato de IA (Sprint 2A+) y NO cuentan como trabajo pendiente ordinario del analista.',
    )


@login_required
def cola_auditoria_selectiva(request):
    """
    Auditoría selectiva de falsos positivos de la IA (política versionada,
    determinista — ver `dashboard.ia.muestreo`). El analista no revisa todos
    los FALSO_POSITIVO: sólo nivel alto, riesgo alto o una muestra estable del
    10%. Una alerta ya revisada desaparece de aquí automáticamente.
    """
    ids = _auditoria_selectiva_ids()
    return _render_cola(
        request, Alert.objects.filter(pk__in=ids),
        cola='auditoria_selectiva', titulo='Auditoría selectiva IA',
        subtitulo=f'Falsos positivos originales de la IA seleccionados por nivel ≥10, riesgo HIGH/CRITICAL, '
                  f'o una muestra estable del 10% (política v{POLITICA_MUESTREO_VERSION}, determinista, '
                  f'nunca ORDER BY RAND()). Una alerta ya revisada no vuelve a aparecer aquí.',
    )


@requiere_rol('ADMIN', 'ANALISTA')
def update_alerts(request):
    """
    Trae la(s) última(s) alerta(s) del indexador Wazuh y las procesa por el
    camino de ingesta completo (dedup -> activo -> política -> contrato).
    Una alerta con análisis fallido NO oculta la alerta.
    """
    try:
        raw_alerts = get_latest_alerts()
    except Exception as exc:
        messages.error(request, f"No se pudo consultar el indexador Wazuh: {exc}")
        return redirect('index')

    c = ingestar_lote(raw_alerts)

    if c['nuevas'] == 0 and c['recuperadas'] == 0:
        messages.info(request, "No hay alertas nuevas para importar.")
    else:
        messages.success(
            request,
            f"{c['nuevas']} alerta(s) nueva(s) y {c['recuperadas']} recuperada(s): "
            f"{c['analizadas']} analizada(s), {c['omitidas']} omitida(s) por política, "
            f"{c['fallidas']} con fallo de análisis. {c['duplicadas']} ya existente(s) sin cambios."
        )
    return redirect('index')


@requiere_rol('ADMIN')
def reclasificar_pendientes(request):
    resultado = reclasificar_alertas_pendientes()
    if resultado['total'] == 0:
        messages.info(request, "No hay alertas para reclasificar.")
    else:
        messages.success(
            request,
            f"Reclasificación: {resultado['analizadas']}/{resultado['total']} analizada(s), "
            f"{resultado['omitidas']} omitida(s), {resultado['fallidas']} sin disponibilidad."
        )
    return redirect('index')


def reclasificar_alertas_pendientes(pausa_segundos=PAUSA_ENTRE_LLAMADAS_GEMINI, proveedor=None):
    """
    Re-analiza con el contrato completo las alertas recuperables:
    PENDING, ANALISIS_FALLIDO, OMITIDO_POLITICA y las legacy sin
    `estado_analisis` con riesgo_ia PENDING/No disponible/UNKNOWN.

    NO toca COMPLETED. NO toca correcciones humanas. Re-resuelve el activo con
    las asignaciones vigentes y re-aplica la política vigente. El fallo de una
    alerta NO detiene el lote. `proveedor` se inyecta sólo en pruebas.
    """
    pendientes = Alert.objects.filter(
        Q(estado_analisis__in=['PENDING', 'ANALISIS_FALLIDO', 'OMITIDO_POLITICA'])
        | Q(estado_analisis__isnull=True, riesgo_ia__in=['PENDING', 'No disponible', 'UNKNOWN'])
    )
    total = pendientes.count()
    analizadas = omitidas = fallidas = 0
    for i, alerta in enumerate(pendientes):
        if i > 0 and pausa_segundos:
            time.sleep(pausa_segundos)
        try:
            accion = reanalizar_alerta(alerta, proveedor=proveedor)
        except Exception:
            fallidas += 1
            continue
        if accion == 'analizada':
            analizadas += 1
        elif accion == 'omitida':
            omitidas += 1
        else:
            fallidas += 1
    return {'total': total, 'analizadas': analizadas, 'omitidas': omitidas, 'fallidas': fallidas}


@requiere_rol('ADMIN', 'ANALISTA')
def corregir_veredicto(request, alert_id):
    """
    Corrección humana OPCIONAL y MOTIVADA del veredicto automático de la IA.

    - Sólo disponible cuando existe un análisis COMPLETED (contrato nuevo).
      Una alerta sin análisis nuevo NO puede clasificarse manualmente aquí.
    - Exige ADMIN/ANALISTA (decorador), POST + CSRF (formulario Django) y un
      motivo no vacío.
    - El veredicto original de la IA NUNCA se sobrescribe: la corrección vive
      en campos separados (`registrar_correccion_humana`).
    """
    alerta = get_object_or_404(Alert, id=alert_id)

    if not alerta.analisis_completado:
        messages.error(
            request,
            "Solo se puede corregir la clasificación de una alerta con análisis "
            "completado. Las alertas sin análisis nuevo no se clasifican a mano."
        )
        return redirect('index')

    if alerta.dataset_aprobado:
        messages.error(
            request,
            "Esta alerta ya tiene un candidato de dataset APROBADO: la verdad de terreno es "
            "inmutable. Para retirarla, use la exclusión auditada desde la ficha del candidato."
        )
        return redirect('index')

    if request.method == 'POST':
        correccion = request.POST.get('correccion_veredicto', '')
        categoria = request.POST.get('motivo_categoria', '')
        nota = request.POST.get('nota', request.POST.get('correccion_motivo', '')).strip()
        riesgo_rev = request.POST.get('riesgo_revisado', '') or None
        origen, error_origen = _resolver_origen(request, alerta)
        if error_origen:
            messages.error(request, error_origen)
            return redirect('index')
        if correccion not in VEREDICTOS_VALIDOS:
            messages.error(request, "Selecciona una clasificación de corrección válida.")
            return redirect('corregir_veredicto', alert_id=alerta.id)
        if categoria not in MOTIVOS_REVISION:
            messages.error(request, "Elige una categoría de motivo.")
            return redirect('corregir_veredicto', alert_id=alerta.id)
        if riesgo_rev is not None and riesgo_rev not in RIESGOS_REVISION:
            riesgo_rev = None
        try:
            registrar_revision(
                alerta, accion='CORREGIDA', motivo_categoria=categoria, autor=request.user,
                veredicto_gt=correccion, riesgo_revisado=riesgo_rev, nota=nota, origen=origen,
            )
        except ValueError as exc:
            messages.error(request, str(exc))
            return redirect('index')
        messages.success(
            request,
            f"Clasificación corregida a «{dict(Alert.VEREDICTO_CHOICES).get(correccion, correccion)}» "
            f"y registrada como verdad de terreno.")
        return redirect('index')

    return render(request, 'dashboard/corregir_veredicto.html', {
        'alerta': alerta,
        'motivos': RevisionHumana.MOTIVO_CHOICES,
        'riesgos': RevisionHumana.RIESGO_CHOICES,
        'origen_param': _origen_param(request),
    })


@requiere_rol('ADMIN', 'ANALISTA')
def revisar_alerta(request, alert_id):
    """
    Revisión humana de una alerta COMPLETED: CONFIRMAR el veredicto de la IA o
    EXCLUIR la alerta del dataset (para CORREGIR está `corregir_veredicto`).

    Registra estado de revisión, verdad de terreno, riesgo revisado, categoría
    del motivo, nota opcional, autor y fecha. NO sobrescribe los campos de la IA.
    """
    alerta = get_object_or_404(Alert, id=alert_id)
    if not alerta.analisis_completado:
        messages.error(request, "Solo se puede revisar una alerta con análisis completado.")
        return redirect('index')

    accion_param = (request.GET.get('accion') or request.POST.get('accion') or 'confirmar').lower()
    accion = 'EXCLUIDA' if accion_param.startswith('exclu') else 'CONFIRMADA'

    if alerta.dataset_aprobado:
        messages.error(
            request,
            "Esta alerta ya tiene un candidato de dataset APROBADO: la verdad de terreno es "
            "inmutable. Para retirarla, use la exclusión auditada desde la ficha del candidato."
        )
        return redirect('index')

    if request.method == 'POST':
        categoria = request.POST.get('motivo_categoria', '')
        nota = request.POST.get('nota', '').strip()
        riesgo_rev = request.POST.get('riesgo_revisado', '') or None
        origen, error_origen = _resolver_origen(request, alerta)
        if error_origen:
            messages.error(request, error_origen)
            return redirect('index')
        if categoria not in MOTIVOS_REVISION:
            messages.error(request, "Elige una categoría de motivo.")
            return redirect(f"{request.path}?accion={accion_param}")
        if riesgo_rev is not None and riesgo_rev not in RIESGOS_REVISION:
            riesgo_rev = None
        try:
            registrar_revision(
                alerta, accion=accion, motivo_categoria=categoria, autor=request.user,
                riesgo_revisado=riesgo_rev, nota=nota, origen=origen,
            )
        except ValueError as exc:
            messages.error(request, str(exc))
            return redirect('index')
        if accion == 'CONFIRMADA':
            messages.success(request, "Clasificación de la IA confirmada como verdad de terreno.")
        else:
            messages.success(request, "Alerta excluida del dataset (evidencia insuficiente).")
        return redirect('index')

    return render(request, 'dashboard/revisar_alerta.html', {
        'alerta': alerta, 'accion': accion,
        'motivos': RevisionHumana.MOTIVO_CHOICES,
        'riesgos': RevisionHumana.RIESGO_CHOICES,
        'origen_param': _origen_param(request),
    })


@requiere_rol('ADMIN', 'ANALISTA')
def reintentar_analisis(request, alert_id):
    """
    Reintento INDIVIDUAL del análisis de UNA alerta en ANALISIS_FALLIDO.
    Nunca es una acción masiva. ADMIN/ANALISTA, POST + CSRF, con confirmación.
    Recupera la evidencia técnica fresca de Wazuh antes de reanalizar. Un fallo
    sigue siendo ANALISIS_FALLIDO; no hay reintentos automáticos.
    """
    alerta = get_object_or_404(Alert, id=alert_id)
    if not alerta.analisis_fallido:
        messages.error(request, "Solo se puede reintentar una alerta con fallo de análisis.")
        return redirect('index')

    if request.method == 'POST':
        override = None
        if alerta.opensearch_id:
            try:
                override = get_alert_by_id(alerta.opensearch_id)
            except Exception:
                override = None
        try:
            accion = reanalizar_alerta(alerta, alert_override=override)
        except Exception as exc:
            messages.error(request, f"El reintento no pudo ejecutarse: {type(exc).__name__}")
            return redirect('index')
        if accion == 'analizada':
            messages.success(request, "Reintento: análisis completado.")
        elif accion == 'fallida':
            messages.warning(request, "Reintento: el análisis volvió a fallar; la alerta sigue en fallo de análisis.")
        else:
            messages.info(request, f"Reintento: {accion}.")
        return redirect('index')

    return render(request, 'dashboard/reintentar_analisis.html', {'alerta': alerta})


def _csv_safe(valor):
    """Protege la exportación CSV contra fórmulas (= + - @, tab, CR)."""
    s = '' if valor is None else str(valor)
    if s[:1] in ('=', '+', '-', '@', '\t', '\r'):
        return "'" + s
    return s


@requiere_rol('ADMIN', 'ANALISTA')
def exportar_csv(request):
    """Exporta las alertas actualmente filtradas como CSV (con los mismos filtros)."""
    alertas, _ = _aplicar_filtros(request, Alert.objects.all())

    response = HttpResponse(content_type='text/csv; charset=utf-8')
    response['Content-Disposition'] = 'attachment; filename="sentria_alertas.csv"'
    response.write('﻿')  # BOM para Excel

    writer = csv.writer(response)
    writer.writerow([
        'ID', 'Timestamp', 'Descripción', 'Severidad', 'Activo lógico', 'Tipo activo',
        'Criticidad', 'SO', 'Estado análisis', 'Motivo omisión', 'Clasificación IA (original)',
        'Riesgo IA', 'Explicación IA', 'Veredicto efectivo', 'Corrección (humano)',
        'Proveedor', 'Modelo', 'Estado triage', 'Fuente', 'Registrado en',
    ])
    for a in alertas:
        act = a.activo_logico
        writer.writerow([_csv_safe(v) for v in [
            a.id, a.timestamp or '', a.descripcion, a.severidad or '',
            act.identificador if act else '', act.tipo_activo if act else '',
            act.criticidad if act else '', act.os_family if act else '',
            a.estado_analisis or '', a.motivo_omision or '', a.veredicto_ia or '',
            a.riesgo_ia or '', a.explicacion_ia or '', a.veredicto_efectivo or '',
            a.correccion_veredicto or '', a.proveedor_ia or '', a.modelo_ia or '',
            a.estado, a.fuente, a.creado_en.strftime('%Y-%m-%d %H:%M:%S'),
        ]])
    return response


def _parse_dt_local(cadena, activo):
    """`YYYY-MM-DDTHH:MM` interpretado en la zona horaria del activo -> UTC aware."""
    if not cadena:
        return None
    try:
        naive = datetime.datetime.fromisoformat(cadena)
    except ValueError:
        return None
    try:
        from zoneinfo import ZoneInfo
        tz = ZoneInfo((getattr(activo, "zona_horaria", None)) or "America/Bogota")
    except Exception:
        tz = datetime.timezone.utc
    return naive.replace(tzinfo=tz).astimezone(datetime.timezone.utc)


@login_required
def mantenimiento_lista(request):
    """Ventanas de mantenimiento: listado (todos) + alta/baja (ADMIN/ANALISTA)."""
    puede_gestionar = usuario_tiene_rol(request.user, ['ADMIN', 'ANALISTA'])

    if request.method == 'POST':
        if not puede_gestionar:
            messages.error(request, "Solo ADMIN o ANALISTA pueden declarar mantenimientos.")
            return redirect('mantenimiento_lista')
        activo = ActivoLogico.objects.filter(id=(request.POST.get('activo_logico') or 0)).first()
        inicio = _parse_dt_local(request.POST.get('inicio'), activo)
        fin = _parse_dt_local(request.POST.get('fin'), activo)
        try:
            v = crear_ventana(
                activo=activo, inicio=inicio, fin=fin,
                categoria=request.POST.get('categoria', ''),
                descripcion=request.POST.get('descripcion', ''),
                autor=request.user,
            )
            messages.success(request, f"Ventana de mantenimiento creada para {v.activo_logico.identificador}.")
        except ValidationError as e:
            messages.error(request, " ".join(e.messages))
        return redirect('mantenimiento_lista')

    ventanas = VentanaMantenimiento.objects.select_related('activo_logico', 'creada_por', 'cancelada_por')
    return render(request, 'dashboard/mantenimiento.html', {
        'ventanas': ventanas,
        'activos': ActivoLogico.objects.filter(activo=True),
        'categorias': VentanaMantenimiento.CATEGORIA_CHOICES,
        'puede_gestionar': puede_gestionar,
        'ahora': timezone.now(),
    })


@requiere_rol('ADMIN', 'ANALISTA')
def mantenimiento_cancelar(request, ventana_id):
    v = get_object_or_404(VentanaMantenimiento, id=ventana_id)
    if request.method != 'POST':
        return redirect('mantenimiento_lista')
    if cancelar_ventana(v, autor=request.user):
        messages.success(request, "Ventana de mantenimiento cancelada (se conserva la auditoría).")
    else:
        messages.info(request, "La ventana ya estaba cancelada.")
    return redirect('mantenimiento_lista')


def _pct(x):
    return None if x is None else round(x * 100, 1)


@requiere_rol('ADMIN', 'ANALISTA')
def metricas(request):
    """
    Métricas del clasificador sobre VERDAD DE TERRENO humana. Clase positiva =
    REQUIERE_ATENCION. No se usa el campo `estado` legacy; no se cuentan alertas
    sin revisión humana.
    """
    m = matriz_confusion()
    rev = resumen_revisiones()
    origenes = resumen_por_origen()

    metricas_pct = {
        'fpr': _pct(m['fpr']), 'fnr': _pct(m['fnr']),
        'precision': _pct(m['precision']), 'recall': _pct(m['recall']),
        'accuracy': _pct(m['accuracy']),
    }
    n = m['total_etiquetado']
    n_no_representativo = sum(f['n'] for f in origenes if not f['representativo'])

    return render(request, 'dashboard/metricas.html', {
        'm': m,
        'metricas_pct': metricas_pct,
        'rev': rev,
        'origenes': origenes,
        'n_no_representativo': n_no_representativo,
        'n_etiquetado': n,
        'muestra_insuficiente': n < 30,
        'total_alertas': Alert.objects.count(),
        'n_completed': Alert.objects.filter(estado_analisis='COMPLETED').count(),
    })


@requiere_rol('ADMIN', 'ANALISTA')
def bandeja_dataset(request):
    """
    Bandeja del dataset de entrenamiento. Detecta automáticamente las alertas con
    revisión humana y construye/actualiza sus candidatos desde
    `contexto_ia_snapshot` + evidencia segura ya congelada. No se copian alertas
    a mano. No genera JSONL definitivo ni sube nada.
    """
    sincronizar_todos()
    filas = vista_bandeja()
    resumen = {
        'total': len(filas),
        'incompletos': sum(1 for f in filas if f['estado'] == 'INCOMPLETO'),
        'listos': sum(1 for f in filas if f['estado'] == 'LISTO_PARA_REVISION'),
        'devueltos': sum(1 for f in filas if f['estado'] == 'DEVUELTO'),
        'aprobados': sum(1 for f in filas if f['estado'] == 'APROBADO'),
        'excluidos': sum(1 for f in filas if f['estado'] == 'EXCLUIDO'),
        'con_privacidad_ok': sum(1 for f in filas if f['privacidad_ok']),
        'posibles_duplicados': sum(1 for f in filas if f['duplicado_de']),
    }
    return render(request, 'dashboard/bandeja_dataset.html', {
        'filas': filas, 'resumen': resumen,
    })


@requiere_rol('ADMIN', 'ANALISTA')
def planificador_dataset(request):
    """
    Planificador SOLO dry-run de la fábrica de escenarios acelerada (3C/3D,
    fase 9). No genera eventos, no llama a Gemini/Vertex, no escribe JSONL.
    Combina conteos y categorías YA seguras: legado recuperable (consulta de
    solo lectura a Wazuh), capacidad estimada de escenarios Ubuntu
    controlados, y el futuro agente Windows LAPTOP-01 (hoy en 0, pendiente).

    El plan sólo usa el pool UTILIZABLE (legado recuperable Y elegible). La
    capacidad estimada de laboratorio se muestra aparte y nunca se suma.
    """
    try:
        diag_legado = diagnosticar_legado()
    except Exception as exc:
        diag_legado = {"error": f"{type(exc).__name__}: no se pudo consultar Wazuh (solo lectura)"}

    n_linux = ActivoLogico.objects.filter(activo=True, os_family='linux').count()
    familias_legado = list((diag_legado or {}).get('por_familia', {}).keys()) or ['sin_grupo']
    capacidad_ubuntu_estimada = sum(pd.pools_ubuntu_controlado(n_linux, familias_legado).values())

    pools = pd.pools_utilizables(diag_legado)
    plan = pd.construir_plan(pools)
    disponibilidad = pd.resumen_por_origen(pools)
    real = pd.resumen_real(diag_legado, CandidatoDataset.objects.filter(estado='APROBADO').count())

    return render(request, 'dashboard/planificador_dataset.html', {
        'diag_legado': diag_legado,
        'disponibilidad': disponibilidad,
        'plan': plan,
        'real': real,
        'capacidad_ubuntu_estimada': capacidad_ubuntu_estimada,
        'n_linux': n_linux,
    })


@requiere_rol('ADMIN', 'ANALISTA')
def candidato_detalle(request, ejemplo_id):
    """
    Editor y doble revisión de un candidato del dataset.

    GET: 3 bloques — entrada anonimizada (solo lectura), respuesta original de
    Gemini (solo lectura, nunca modificable), salida objetivo supervisada
    (formulario editable, verdict bloqueado a la verdad de terreno).

    POST (`accion`): `borrador` (guardar) · `enviar` (validar y pasar a
    LISTO_PARA_REVISION) · `revisar` (2º revisor: aprobar / devolver / excluir).
    POST + CSRF + ADMIN/ANALISTA (decorador).
    """
    cand = get_object_or_404(
        CandidatoDataset.objects.select_related('alerta', 'alerta__revision_humana',
                                                'alerta__activo_logico', 'completado_por'),
        ejemplo_id=ejemplo_id,
    )
    alerta = cand.alerta
    ds.sincronizar_candidato(alerta)
    cand.refresh_from_db()

    if request.method == 'POST':
        accion = request.POST.get('accion', '')
        confirmado = request.POST.get('confirmo_revision') in ('on', 'true', '1')

        if accion == 'borrador':
            cand, errores = ds.guardar_borrador(cand, request.POST, request.user, confirmado=confirmado)
            _flash_errores(request, errores, "Borrador guardado.")
        elif accion == 'enviar':
            cand, errores = ds.enviar_a_revision(cand, request.POST, request.user, confirmado=confirmado)
            if errores:
                _flash_errores(request, errores, "")
            else:
                messages.success(request, "Candidato enviado a segunda revisión (LISTO_PARA_REVISION).")
        elif accion == 'revisar':
            decision = request.POST.get('decision', '')
            obs = request.POST.get('observaciones', '')
            cand, errores = ds.revisar_candidato(cand, decision=decision, autor=request.user, observaciones=obs)
            if errores:
                _flash_errores(request, errores, "")
            else:
                messages.success(request, f"Segunda revisión registrada: {decision}.")
        else:
            messages.error(request, "Acción no reconocida.")
        return redirect('candidato_detalle', ejemplo_id=ejemplo_id)

    entrada = ds.construir_entrada(alerta)
    original = ds.respuesta_original_gemini(alerta)
    salida = ds.salida_objetivo_actual(cand)
    gt = alerta.verdad_terreno
    ok_rev, errores_rev = ds.validar_para_revision(cand, salida)
    es_completador = bool(cand.completado_por_id and cand.completado_por_id == request.user.id)

    cvss_actual = salida.get('cvss_factors', {}) or {}
    cvss_rows = [
        {'clave': k, 'opciones': list(v), 'valor': cvss_actual.get(k, '')}
        for k, v in CVSS_ENUMS.items()
    ]

    return render(request, 'dashboard/candidato_detalle.html', {
        'cand': cand,
        'entrada_json': _json_pretty(entrada),
        'original_json': _json_pretty(original),
        'salida': salida,
        'cvss_rows': cvss_rows,
        'missing_evidence_text': "\n".join(salida.get('missing_evidence', []) or []),
        'verdad_terreno': gt,
        'riesgos': CONTRATO_RIESGOS,
        'ok_para_revision': ok_rev,
        'errores_revision': errores_rev,
        'es_completador': es_completador,
        'puede_segunda_revision': cand.estado in ('LISTO_PARA_REVISION', 'DEVUELTO', 'APROBADO'),
        'solo_exclusion': cand.estado == 'APROBADO',
        'revisiones': cand.revisiones.select_related('autor').all(),
    })


def _flash_errores(request, errores, ok_msg):
    if errores:
        for e in errores:
            messages.error(request, e)
    elif ok_msg:
        messages.success(request, ok_msg)


def _json_pretty(obj):
    import json as _j
    return _j.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True)
