# Sprint 3B — editor y doble revisión de candidatos del dataset.
# ADITIVA: 3 AddField nullables en CandidatoDataset (salida_objetivo_editada,
# completado_por, completado_en), ensancha `estado` 16->24 + 2 estados nuevos
# (DEVUELTO / LISTO_PARA_REVISION), y `CreateModel RevisionCandidato` (append-only).
# No borra ni reescribe filas. Portable a MySQL 8.4.
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dashboard', '0008_candidatodataset_revisionhumana'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name='candidatodataset',
            name='completado_en',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='candidatodataset',
            name='completado_por',
            field=models.ForeignKey(blank=True, help_text='Quién dejó el candidato LISTO_PARA_REVISION. No puede ser quien lo apruebe.', null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='candidatos_completados', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='candidatodataset',
            name='salida_objetivo_editada',
            field=models.JSONField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='candidatodataset',
            name='estado',
            field=models.CharField(choices=[('INCOMPLETO', 'Incompleto'), ('LISTO_PARA_REVISION', 'Listo para revisión'), ('DEVUELTO', 'Devuelto con observaciones'), ('APROBADO', 'Aprobado'), ('EXCLUIDO', 'Excluido')], default='INCOMPLETO', max_length=24),
        ),
        migrations.AlterField(
            model_name='candidatodataset',
            name='salida_objetivo_revisada',
            field=models.BooleanField(default=False, help_text='El revisor confirmó que revisó riesgo, explicación, CVSS, recomendación y evidencia faltante.'),
        ),
        migrations.CreateModel(
            name='RevisionCandidato',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('decision', models.CharField(choices=[('APROBADO', 'Aprobado'), ('DEVUELTO', 'Devuelto con observaciones'), ('EXCLUIDO', 'Excluido')], max_length=12)),
                ('observaciones', models.TextField(blank=True, default='')),
                ('creada_en', models.DateTimeField(auto_now_add=True)),
                ('autor', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='revisiones_candidato', to=settings.AUTH_USER_MODEL)),
                ('candidato', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='revisiones', to='dashboard.candidatodataset')),
            ],
            options={
                'ordering': ['-creada_en', '-id'],
            },
        ),
    ]
