from django.core.management.base import BaseCommand

from dashboard.ia.activos_cafe import sembrar_activos_cafe


class Command(BaseCommand):
    help = (
        "Crea/actualiza de forma IDEMPOTENTE los 12 activos lógicos del café "
        "internet simulado (EP-01..EP-10, ADM-01, SRV-01). No borra nada. "
        "Ejecutar cuando MySQL esté activo; con --dry-run solo informa."
    )

    def add_arguments(self, parser):
        parser.add_argument("--dry-run", action="store_true", help="no escribe, solo informa")

    def handle(self, *args, **options):
        creados, actualizados, iguales = sembrar_activos_cafe(dry_run=options["dry_run"])
        prefijo = "[dry-run] " if options["dry_run"] else ""
        self.stdout.write(self.style.SUCCESS(
            f"{prefijo}Activos: {creados} creado(s), {actualizados} actualizado(s), "
            f"{iguales} sin cambios."
        ))
