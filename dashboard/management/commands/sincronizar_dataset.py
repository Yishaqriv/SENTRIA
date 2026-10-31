"""
Sincroniza la bandeja del dataset (Sprint 3A).

- Backfill: para alertas con `Alert.correccion_*` pero sin `RevisionHumana`
  (flujo antiguo), crea una revisión CORREGIDA SIN tocar los campos históricos.
- Sincroniza (crea/actualiza) el `CandidatoDataset` de cada alerta revisada.

No llama a Gemini, no genera eventos, no escribe JSONL, no sube nada.

Uso:
  python manage.py sincronizar_dataset --alert-id 128 --motivo mantenimiento_programado
  python manage.py sincronizar_dataset            # todas las revisadas
"""
from django.core.management.base import BaseCommand, CommandError

from dashboard.models import Alert
from dashboard.revision import (
    MOTIVOS, sincronizar_revision_desde_correccion,
)
from dashboard.dataset import sincronizar_candidato, sincronizar_todos


class Command(BaseCommand):
    help = "Backfill de RevisionHumana desde correccion_* + sincroniza CandidatoDataset."

    def add_arguments(self, parser):
        parser.add_argument('--alert-id', dest='alert_id', type=int, default=None,
                            help="limita la operación a una sola alerta")
        parser.add_argument('--motivo', dest='motivo', default='otro',
                            help=f"categoría de motivo para el backfill ({', '.join(MOTIVOS)})")

    def handle(self, *args, **o):
        motivo = o['motivo']
        if motivo not in MOTIVOS:
            raise CommandError(f"--motivo inválido. Opciones: {', '.join(MOTIVOS)}")

        if o['alert_id'] is not None:
            qs = Alert.objects.filter(id=o['alert_id'])
            if not qs.exists():
                raise CommandError(f"No existe la alerta id {o['alert_id']}.")
        else:
            qs = Alert.objects.all()

        backfilled = 0
        for a in qs.select_related('revision_humana', 'correccion_autor', 'activo_logico'):
            if getattr(a, 'revision_humana', None) is None and a.correccion_veredicto:
                rev = sincronizar_revision_desde_correccion(a, motivo_categoria=motivo)
                if rev is not None:
                    backfilled += 1
                    self.stdout.write(f"  backfill RevisionHumana(CORREGIDA) para alerta id {a.id}")

        if o['alert_id'] is not None:
            a = Alert.objects.select_related('revision_humana').get(id=o['alert_id'])
            cand = sincronizar_candidato(a)
            n = 1 if cand is not None else 0
        else:
            n = sincronizar_todos()

        self.stdout.write("")
        self.stdout.write(self.style.SUCCESS("=== Sincronización del dataset ==="))
        self.stdout.write(f"  revisiones creadas por backfill: {backfilled}")
        self.stdout.write(f"  candidatos sincronizados:        {n}")
