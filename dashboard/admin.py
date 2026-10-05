from django.contrib import admin

from .models import (
    ActivoLogico, Alert, AsignacionAgenteActivo, HistorialAsignacionAgente,
    VentanaMantenimiento,
)

# Campos del análisis IA: se muestran pero no se editan desde el admin
# (el veredicto original de la IA nunca se sobrescribe a mano).
# `wazuh_agent_id` es capa P: visible sólo aquí (admin), nunca editable.
_CAMPOS_IA = (
    "estado_analisis", "veredicto_ia", "factores_cvss", "justificacion_cvss",
    "recomendacion_ia", "evidencia_faltante", "respuesta_ia_original",
    "proveedor_ia", "modelo_ia", "analizado_en", "motivo_omision",
    "contexto_ia_snapshot", "wazuh_rule_id", "wazuh_rule_groups", "wazuh_agent_id",
)


@admin.register(ActivoLogico)
class ActivoLogicoAdmin(admin.ModelAdmin):
    list_display = ("identificador", "nombre_visible", "tipo_activo", "criticidad",
                    "os_family", "os_role", "activo")
    list_filter = ("tipo_activo", "criticidad", "os_family", "activo")
    search_fields = ("identificador", "nombre_visible")


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = (
        "id", "titulo", "severidad", "activo_logico", "estado_analisis",
        "veredicto_ia", "riesgo_ia", "correccion_veredicto", "estado",
    )
    list_filter = ("estado_analisis", "motivo_omision", "veredicto_ia", "riesgo_ia", "estado", "fuente")
    search_fields = ("titulo", "descripcion", "opensearch_id")
    raw_id_fields = ("activo_logico", "correccion_autor")
    readonly_fields = _CAMPOS_IA + ("creado_en",)


@admin.register(AsignacionAgenteActivo)
class AsignacionAgenteActivoAdmin(admin.ModelAdmin):
    """Capa privada (P): asignación ACTUAL agent.id -> ActivoLogico. Sólo superusuario."""
    list_display = ("agent_id", "etiqueta_privada", "activo_logico",
                    "creada_por", "creada_en", "actualizada_en")
    list_filter = ("activo_logico",)
    search_fields = ("agent_id", "etiqueta_privada", "nota")
    raw_id_fields = ("activo_logico", "creada_por")
    readonly_fields = ("creada_en", "actualizada_en")


@admin.register(HistorialAsignacionAgente)
class HistorialAsignacionAgenteAdmin(admin.ModelAdmin):
    """Capa privada (P): bitácora append-only de cambios de asignación. Sólo lectura."""
    list_display = ("registrado_en", "agent_id", "accion", "activo_identificador", "autor")
    list_filter = ("accion",)
    search_fields = ("agent_id", "activo_identificador", "nota")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(VentanaMantenimiento)
class VentanaMantenimientoAdmin(admin.ModelAdmin):
    list_display = ("activo_logico", "categoria", "inicio", "fin", "estado", "creada_por", "creada_en")
    list_filter = ("estado", "categoria", "activo_logico")
    search_fields = ("descripcion",)
    raw_id_fields = ("activo_logico", "creada_por", "cancelada_por")
    readonly_fields = ("creada_en", "cancelada_en")

    def has_delete_permission(self, request, obj=None):
        return False   # nunca se borran: se cancelan (auditoría)
