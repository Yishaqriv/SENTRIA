"""
Catálogo de los 12 activos LÓGICOS del café internet simulado (diseño del
checkpoint 1B). NO es una migración: `sembrar_activos_cafe()` es un mecanismo
explícito, idempotente y revisable que se ejecuta con `manage.py cargar_activos_cafe`
cuando MySQL esté activo.

Los activos son lógicos: no son 12 agentes ni 12 equipos. No contienen
agent.id, hostname ni IP.
"""
from __future__ import annotations

import datetime

_H_INI = datetime.time(8, 0)
_H_FIN = datetime.time(22, 0)
_TZ = "America/Bogota"

_CTX_ESTACION = (
    "Estación de uso público. Actividades autorizadas: navegación web, ofimática, "
    "juegos, descargas de software legítimo, inserción de USB para archivos propios "
    "e impresión ocasional. No autorizado: escalamiento de privilegios locales, "
    "instalación de software con persistencia, cambios de configuración del sistema."
)
_CTX_ADMIN = (
    "Equipo de administración/caja, operado por personal durante su turno. "
    "Autorizado: gestión de sesiones de clientes, tareas administrativas del local "
    "y comunicación con el servidor para impresión. No autorizado: uso fuera de "
    "horario sin ventana de mantenimiento, cambios de cuentas no registrados, "
    "ejecución de procesos no reconocidos."
)
_CTX_SRV = (
    "Servidor interno Ubuntu: servicios internos e impresión. Autorizado: "
    "recepción de trabajos de impresión, servicios internos programados y "
    "mantenimiento en ventana autorizada. No autorizado: conexiones salientes a "
    "destinos no catalogados, cambios de cuentas privilegiadas sin aprobación, "
    "ejecución de binarios no reconocidos."
)


def catalogo():
    """Devuelve la lista de dicts con los 12 activos lógicos. No toca la BD."""
    filas = []
    for i in range(1, 11):
        filas.append(dict(
            identificador=f"EP-{i:02d}",
            nombre_visible=f"Estación pública {i:02d}",
            tipo_activo="estacion_publica",
            criticidad="media",
            os_family="windows",
            os_role="estacion_cliente",
            hora_inicio_operacion=_H_INI,
            hora_fin_operacion=_H_FIN,
            zona_horaria=_TZ,
            contexto_autorizado_es=_CTX_ESTACION,
            activo=True,
        ))
    filas.append(dict(
        identificador="ADM-01",
        nombre_visible="Equipo de administración / caja",
        tipo_activo="equipo_administracion",
        criticidad="alta",
        os_family="windows",
        os_role="administracion",
        hora_inicio_operacion=_H_INI,
        hora_fin_operacion=_H_FIN,
        zona_horaria=_TZ,
        contexto_autorizado_es=_CTX_ADMIN,
        activo=True,
    ))
    filas.append(dict(
        identificador="SRV-01",
        nombre_visible="Servidor interno Ubuntu",
        tipo_activo="servidor_interno",
        criticidad="alta",
        os_family="linux",
        os_role="servidor",
        hora_inicio_operacion=datetime.time(0, 0),
        hora_fin_operacion=datetime.time(23, 59),
        zona_horaria=_TZ,
        contexto_autorizado_es=_CTX_SRV,
        activo=True,
    ))
    return filas


def sembrar_activos_cafe(*, dry_run=False):
    """
    Crea/actualiza los 12 activos de forma IDEMPOTENTE (por `identificador`).
    Nunca borra activos existentes. Devuelve (creados, actualizados, sin_cambios).
    """
    from dashboard.models import ActivoLogico

    creados = actualizados = iguales = 0
    for fila in catalogo():
        ident = fila["identificador"]
        obj = ActivoLogico.objects.filter(identificador=ident).first()
        if obj is None:
            if not dry_run:
                ActivoLogico.objects.create(**fila)
            creados += 1
            continue
        cambios = {k: v for k, v in fila.items()
                   if k != "identificador" and getattr(obj, k) != v}
        if cambios:
            if not dry_run:
                for k, v in cambios.items():
                    setattr(obj, k, v)
                obj.save(update_fields=list(cambios.keys()))
            actualizados += 1
        else:
            iguales += 1
    return creados, actualizados, iguales
