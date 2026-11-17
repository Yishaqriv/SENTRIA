"""
Ingesta continua ACOTADA de un único agente (ver dashboard/ia/continua.py). Pensado para un temporizador systemd
de usuario cada 15 min; cada ejecución es independiente y el estado vive en un directorio privado.

Uso (siempre con el entorno del servicio, vía el lanzador privado, que aporta los identificadores del despliegue):
  python manage.py ingesta_continua --estado-dir DIR --agente ID --nombre-agente NOMBRE --activo ACTIVO \
         --desde ISO8601 [--excluir OPENSEARCH_ID ...] --ensayo | --confirmar
  python manage.py ingesta_continua --estado-dir DIR --agente ID --ver-estado | --pausar | --reanudar
  --ensayo lee y clasifica sin IA ni escrituras; --confirmar hace hasta 2 invocaciones (límites conjuntos).
  --desde es el límite inicial EXPLÍCITO de cobertura (con zona horaria). Se persiste en la primera ejecución
  confirmada; después debe coincidir con el persistido. --confirmar exige SENTRIA_EXCLUSION_DIR (el mismo
  directorio que usa el dashboard) para la exclusión común por alerta.

Límites fijos de INVOCACIONES (no de dinero ni tokens): 2 por ejecución, 6 en cualquier ventana móvil de 60 min y 30
por día calendario de America/Bogota. Sin reintentos automáticos, sin proveedor de respaldo. Salida: JSON con
metadatos seguros (nunca alertas crudas, prompts, respuestas, claves ni mensajes de excepción).
"""
import datetime as dt
import json
import os
import sys

from django.core.management.base import BaseCommand, CommandError

from dashboard.ia import continua, exclusion, proveedores
from dashboard.ia.ingesta import ingestar_alerta
from dashboard.ia.politica import cargar_politica
from dashboard.ia.resolver import resolver_activo_por_agente
from dashboard.models import Alert

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../')))
import sentria_backend as B  # noqa: E402

def _buscar(query):
    r = B._consultar_indexador(query, timeout=30)
    r.raise_for_status()
    return r.json()


def _existentes(ids):
    ids = [i for i in ids if i]
    return set(Alert.objects.filter(opensearch_id__in=ids).values_list("opensearch_id", flat=True)) if ids else set()


def _proveedor():
    nombre = proveedores.nombre_proveedor_activo()
    prov = proveedores.obtener_proveedor(nombre)
    if prov is None:
        raise CommandError(f"Proveedor {nombre} no disponible.")
    return prov


def _desde(valor):
    if not valor:
        return None
    try:
        d = dt.datetime.fromisoformat(str(valor).replace("Z", "+00:00"))
    except ValueError:
        raise CommandError("--desde no es una fecha ISO 8601 válida.") from None
    if d.tzinfo is None:
        raise CommandError("--desde debe incluir zona horaria (p. ej. Z).")
    return d.astimezone(dt.timezone.utc)


class Command(BaseCommand):
    help = ("Ingesta continua acotada del agente configurado (límites de invocaciones fijos; sin reintentos "
            "automáticos).")

    def add_arguments(self, parser):
        parser.add_argument("--estado-dir", dest="estado_dir", required=True,
                            help="directorio PRIVADO (0700) del estado del trabajador; uno para producción y otro "
                                 "distinto para pruebas")
        parser.add_argument("--agente", required=True, help="agent.id de Wazuh (capa privada; lo aporta el lanzador)")
        parser.add_argument("--nombre-agente", dest="nombre_agente", help="agent.name exacto exigido (ensayo/confirmar)")
        parser.add_argument("--activo", help="identificador del ActivoLogico que debe resolver el agente (ensayo/confirmar)")
        parser.add_argument("--desde", help="límite inicial explícito de cobertura, ISO 8601 con zona (ensayo/confirmar)")
        parser.add_argument("--excluir", action="append", default=[],
                            help="opensearch_id que esta automatización nunca selecciona (repetible)")
        modo = parser.add_mutually_exclusive_group(required=True)
        for m in ("ensayo", "confirmar", "ver-estado", "pausar", "reanudar"):
            modo.add_argument(f"--{m}", dest=m.replace("-", "_"), action="store_true")

    def _trabajador(self, almacen, o):
        agente = o["agente"]
        return continua.Trabajador(
            almacen, agente=agente, nombre_agente=o["nombre_agente"], identificador_activo=o["activo"], buscar=_buscar,
            normalizar=B._normalizar_hit, existentes=_existentes, activo=lambda: resolver_activo_por_agente(agente),
            proveedor=_proveedor, ingestar=ingestar_alerta, politica=cargar_politica(),
            reloj=lambda: dt.datetime.now(dt.timezone.utc), excluidos=tuple(o["excluir"]), campos=B._SOURCE_FIELDS,
            desde=_desde(o.get("desde")))

    def _salida(self, obj):
        self.stdout.write(json.dumps(obj, ensure_ascii=False, sort_keys=True, default=str))

    def handle(self, *args, **o):
        if not os.path.isabs(o["estado_dir"]):
            raise CommandError("--estado-dir debe ser una ruta absoluta.")
        almacen = continua.Almacen(o["estado_dir"], o["agente"])
        ahora = dt.datetime.now(dt.timezone.utc)
        try:
            if o["ver_estado"]:
                return self._salida(self._trabajador(almacen, o).resumen_estado(almacen.leer(ahora), ahora))
            if o["pausar"]:
                return self._salida({"pausa": continua.pausar(almacen, ahora)})
            if o["reanudar"]:
                return self._salida({"pausa_retirada": continua.reanudar(almacen, ahora)})
            if not (o["nombre_agente"] and o["activo"]):
                raise CommandError("--ensayo y --confirmar exigen --nombre-agente y --activo.")
            if o["confirmar"] and not exclusion.configurado_explicitamente():
                raise CommandError("SENTRIA_EXCLUSION_DIR ausente: sin exclusión común con el dashboard no se ejecuta.")
            if o["confirmar"] and not os.environ.get("GEMINI_API_KEY") and \
                    proveedores.nombre_proveedor_activo() == "gemini_developer":
                raise CommandError("GEMINI_API_KEY ausente: no se ejecuta.")
            return self._salida(self._trabajador(almacen, o).ejecutar(ensayo=o["ensayo"]))
        except continua.OcupadoError as e:
            return self._salida({"resultado": "ocupado", "detalle": str(e)})
        except continua.EstadoError as e:
            raise CommandError(f"Estado: {e}")
        except CommandError:
            raise
        except Exception as e:      # sin traza ni mensaje: podrían incluir URL, cabeceras o datos de la alerta
            self._salida({"resultado": "error_inesperado", "tipo": type(e).__name__})
            raise CommandError(f"Error inesperado ({type(e).__name__}); detalle no mostrado.") from None
