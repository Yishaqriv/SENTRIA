"""
Revisión HUMANA de llamadas sin cerrar (marca persistente de `dashboard.ia.exclusion`). Nunca llama al proveedor.

  python manage.py revisar_incierto --listar
      Solo lectura: cada marca (clave, vía, alert_id, desde) con el estado actual de su fila (estado del análisis,
      fecha, si tiene `_medicion` y su `estado_llamada`). No modifica nada.
  python manage.py revisar_incierto --liberar CLAVE --motivo TEXTO --revisor NOMBRE
      Retira la marca de CLAVE (opensearch_id, o pk:<id> sin él) y deja un registro `.revisado` con el motivo. No envía
      nada: solo permite que una vía MANUAL vuelva a analizar el documento, como una llamada nueva y consciente.

Necesita el mismo SENTRIA_EXCLUSION_DIR que el dashboard y el trabajador (lo aporta el lanzador privado).
"""
import json

from django.core.management.base import BaseCommand, CommandError

from dashboard.ia import exclusion
from dashboard.models import Alert


def _fila(marca):
    clave, alert_id = marca.get("clave"), marca.get("alert_id")
    q = Alert.objects.none()
    if clave and not str(clave).startswith("pk:"):
        q = Alert.objects.filter(opensearch_id=clave)
    elif alert_id is not None:
        q = Alert.objects.filter(pk=alert_id)
    fila = q.first()
    if fila is None:
        return {"existe": False}
    med = (fila.contexto_ia_snapshot or {}).get("_medicion") if isinstance(fila.contexto_ia_snapshot, dict) else None
    return {"existe": True, "alert_id": fila.id, "estado_analisis": fila.estado_analisis,
            "analizado_en": fila.analizado_en, "tiene_medicion": isinstance(med, dict),
            "estado_llamada": (med or {}).get("estado_llamada")}


class Command(BaseCommand):
    help = "Revisión humana de llamadas sin cerrar: listar (solo lectura) o liberar con motivo. Nunca llama a la IA."

    def add_arguments(self, parser):
        modo = parser.add_mutually_exclusive_group(required=True)
        modo.add_argument("--listar", action="store_true")
        modo.add_argument("--liberar", metavar="CLAVE")
        parser.add_argument("--motivo")
        parser.add_argument("--revisor")

    def handle(self, *args, **o):
        if not exclusion.configurado_explicitamente():
            raise CommandError("SENTRIA_EXCLUSION_DIR ausente: no se puede revisar el directorio común.")
        try:
            if o["listar"]:
                salida = [dict(m, fila=_fila(m)) for m in exclusion.listar_inciertos()]
            else:
                if not (o.get("motivo") or "").strip() or not (o.get("revisor") or "").strip():
                    raise CommandError("--liberar exige --motivo y --revisor.")
                salida = {"liberado": exclusion.liberar_incierto(o["liberar"], o["motivo"], o["revisor"])}
        except FileNotFoundError:
            raise CommandError("No hay marca sin cerrar para esa clave.") from None
        except exclusion.ExclusionError as e:
            raise CommandError(str(e)) from None
        self.stdout.write(json.dumps(salida, ensure_ascii=False, sort_keys=True, default=str))
