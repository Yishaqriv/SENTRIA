"""
Alta / baja / consulta de asignaciones agent.id -> ActivoLogico (capa P).

Auditable y transaccional. NO se ejecuta por migración. Ejemplos:

    manage.py asignar_agente_activo --listar
    manage.py asignar_agente_activo --historial
    manage.py asignar_agente_activo --agent-id 000 --activo SRV-01 --etiqueta AGENT-01 \\
        --nota "Manager Linux del laboratorio"
    manage.py asignar_agente_activo --desactivar --agent-id 000

Sólo hay una asignación ACTUAL por agent.id (UNIQUE en la BD). Cada cambio queda
en `HistorialAsignacionAgente`. Un agent.id en IA_AGENTES_BLOQUEADOS se rechaza:
para asignarlo hay que retirarlo de esa lista de forma deliberada y auditada.
"""
from django.core.management.base import BaseCommand, CommandError

from dashboard.ia.resolver import asignar_agente, desactivar_asignacion
from dashboard.models import AsignacionAgenteActivo, HistorialAsignacionAgente


class Command(BaseCommand):
    help = "Gestiona el mapeo privado agent.id -> ActivoLogico (Sprint 2C)."

    def add_arguments(self, parser):
        parser.add_argument("--agent-id", dest="agent_id", default=None)
        parser.add_argument("--activo", dest="activo", default=None,
                            help="identificador lógico del activo (EP-01, SRV-01, ...)")
        parser.add_argument("--etiqueta", dest="etiqueta", default="")
        parser.add_argument("--nota", dest="nota", default="")
        parser.add_argument("--desactivar", action="store_true",
                            help="retira la asignación actual de --agent-id")
        parser.add_argument("--listar", action="store_true",
                            help="lista las asignaciones actuales")
        parser.add_argument("--historial", action="store_true",
                            help="lista el histórico de cambios (append-only)")

    def handle(self, *args, **o):
        if o["listar"]:
            filas = AsignacionAgenteActivo.objects.select_related("activo_logico")
            if not filas:
                self.stdout.write("Sin asignaciones actuales.")
                return
            for a in filas:
                self.stdout.write(
                    f"  {a.agent_id:>6}  ->  {a.activo_logico.identificador:<8}"
                    f"  ({a.etiqueta_privada or '-'})  desde {a.creada_en:%Y-%m-%d}"
                )
            return

        if o["historial"]:
            filas = HistorialAsignacionAgente.objects.all()[:200]
            if not filas:
                self.stdout.write("Historial vacío.")
                return
            for h in filas:
                self.stdout.write(
                    f"  {h.registrado_en:%Y-%m-%d %H:%M}  {h.agent_id:>6}  {h.accion:<12}"
                    f"  {h.activo_identificador}"
                )
            return

        if o["desactivar"]:
            if not o["agent_id"]:
                raise CommandError("--desactivar requiere --agent-id")
            n = desactivar_asignacion(o["agent_id"], nota=o["nota"])
            self.stdout.write(self.style.SUCCESS(
                f"{n} asignación(es) retirada(s) para el agente {o['agent_id']} "
                f"(registrado en el historial)."
            ))
            return

        if not (o["agent_id"] and o["activo"]):
            raise CommandError("Se requieren --agent-id y --activo (o usa --listar / --historial / --desactivar).")

        try:
            asign = asignar_agente(
                o["agent_id"], o["activo"], etiqueta=o["etiqueta"], nota=o["nota"],
            )
        except ValueError as e:
            raise CommandError(str(e))
        self.stdout.write(self.style.SUCCESS(
            f"Asignación actual: agente {asign.agent_id} -> {asign.activo_logico.identificador} "
            f"(cambio registrado en el historial)."
        ))
