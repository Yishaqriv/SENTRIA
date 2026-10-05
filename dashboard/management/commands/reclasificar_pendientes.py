from django.core.management.base import BaseCommand

from dashboard.views import PAUSA_ENTRE_LLAMADAS_GEMINI, reclasificar_alertas_pendientes


class Command(BaseCommand):
    help = (
        "Re-analiza con el contrato completo las alertas en ANALISIS_FALLIDO "
        "(y las legacy sin estado con riesgo PENDING/No disponible/UNKNOWN). "
        "No toca las COMPLETED ni las correcciones humanas."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            '--pausa', type=float, default=PAUSA_ENTRE_LLAMADAS_GEMINI,
            help=f"Segundos de pausa entre llamadas al proveedor (default: {PAUSA_ENTRE_LLAMADAS_GEMINI}).",
        )

    def handle(self, *args, **options):
        r = reclasificar_alertas_pendientes(pausa_segundos=options['pausa'])
        if r['total'] == 0:
            self.stdout.write(self.style.SUCCESS("No hay alertas para reclasificar."))
            return
        self.stdout.write(self.style.SUCCESS(
            f"Reclasificación: {r['analizadas']}/{r['total']} analizada(s), "
            f"{r['omitidas']} omitida(s), {r['fallidas']} sin disponibilidad."
        ))
