from django.urls import path
from . import views
from .comparacion import views as comparacion

urlpatterns = [
    # Colas operativas separadas (Sprint 2B; reorganizadas en 3C/3D)
    path('',                          views.cola_historial,   name='index'),
    path('atencion/',                 views.cola_atencion,    name='cola_atencion'),
    path('falsos-positivos/',         views.cola_falsos_positivos,    name='cola_falsos_positivos'),
    path('falsos-positivos-ia/',      views.cola_falsos_positivos_ia, name='cola_falsos_positivos_ia'),  # alias -> redirección
    path('auditoria-selectiva/',      views.cola_auditoria_selectiva, name='cola_auditoria_selectiva'),
    path('pendientes/',               views.cola_pendientes,  name='cola_pendientes'),
    path('omitidas/',                 views.cola_omitidas,    name='cola_omitidas'),
    path('legado/',                   views.cola_legado,      name='cola_legado'),

    path('update_alerts',             views.update_alerts,  name='update_alerts'),
    path('exportar_csv',              views.exportar_csv,   name='exportar_csv'),
    path('alerta/<int:alert_id>/corregir/', views.corregir_veredicto, name='corregir_veredicto'),
    path('alerta/<int:alert_id>/revisar/',  views.revisar_alerta,     name='revisar_alerta'),
    path('alerta/<int:alert_id>/reintentar/', views.reintentar_analisis, name='reintentar_analisis'),
    path('mantenimiento/',            views.mantenimiento_lista,   name='mantenimiento_lista'),
    path('mantenimiento/<int:ventana_id>/cancelar/', views.mantenimiento_cancelar, name='mantenimiento_cancelar'),
    path('metricas/',                 views.metricas,       name='metricas'),
    path('dataset/',                  views.bandeja_dataset, name='bandeja_dataset'),
    path('dataset/sincronizar/',      views.sincronizar_dataset, name='sincronizar_dataset'),
    path('dataset/planificador/',     views.planificador_dataset, name='planificador_dataset'),
    path('dataset/<str:ejemplo_id>/', views.candidato_detalle, name='candidato_detalle'),
    path('reclasificar_pendientes',   views.reclasificar_pendientes, name='reclasificar_pendientes'),

    # Comparación de IA: solo el superusuario real (ver dashboard/comparacion/views.py)
    path('comparacion/', comparacion.comparacion, name='comparacion'),
    path('comparacion/ejecucion/<uuid:uuid>/', comparacion.comparacion_detalle, name='comparacion_detalle'),
    path('comparacion/grafica/<slug:tipo>.<slug:formato>', comparacion.comparacion_grafica,
         name='comparacion_grafica'),
    path('comparacion/grafica/<slug:tipo>/datos.csv', comparacion.comparacion_grafica_datos,
         name='comparacion_grafica_datos'),
    path('comparacion/grafica/<slug:tipo>/manifiesto.json', comparacion.comparacion_grafica_manifiesto,
         name='comparacion_grafica_manifiesto'),
    path('comparacion/resumen/datos.csv', comparacion.comparacion_resumen_datos, name='comparacion_resumen_datos'),
    path('comparacion/resumen/ficha.json', comparacion.comparacion_resumen_ficha, name='comparacion_resumen_ficha'),
    path('comparacion/resumen/<slug:tipo>.<slug:formato>', comparacion.comparacion_resumen_grafica,
         name='comparacion_resumen_grafica'),
    path('comparacion/exportar.csv', comparacion.comparacion_exportar_csv, name='comparacion_exportar_csv'),
    path('comparacion/exportar.json', comparacion.comparacion_exportar_json, name='comparacion_exportar_json'),
    path('comparacion/registrar-locales/', comparacion.comparacion_registrar_locales,
         name='comparacion_registrar_locales'),
    path('comparacion/importar/', comparacion.comparacion_importar, name='comparacion_importar'),
    path('comparacion/importar/confirmar/', comparacion.comparacion_importar_confirmar,
         name='comparacion_importar_confirmar'),
    path('comparacion/caso/<str:clave>/procedencia/', comparacion.comparacion_procedencia,
         name='comparacion_procedencia'),
]
