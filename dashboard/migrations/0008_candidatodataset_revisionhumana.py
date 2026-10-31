# Sprint 3A — revisión humana y bandeja del dataset.
# ADITIVA: sólo `CreateModel RevisionHumana` + `CreateModel CandidatoDataset`.
# No toca ninguna tabla ni fila existente. Portable a MySQL 8.4 (sin índices
# parciales ni CheckConstraint; JSONField nativo). Los campos `Alert.correccion_*`
# se conservan intactos.
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dashboard', '0007_ventana_mantenimiento'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='CandidatoDataset',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ejemplo_id', models.CharField(editable=False, max_length=40, unique=True)),
                ('fingerprint', models.CharField(blank=True, db_index=True, default='', max_length=64)),
                ('estado', models.CharField(choices=[('INCOMPLETO', 'Incompleto'), ('LISTO_REVISION', 'Listo para revisión'), ('APROBADO', 'Aprobado'), ('EXCLUIDO', 'Excluido')], default='INCOMPLETO', max_length=16)),
                ('salida_objetivo_revisada', models.BooleanField(default=False, help_text='El humano revisó riesgo, explicación, CVSS, recomendación y evidencia faltante.')),
                ('privacidad_ok', models.BooleanField(default=False)),
                ('duplicado_de', models.CharField(blank=True, default='', max_length=40)),
                ('diagnostico', models.JSONField(blank=True, help_text='Sanitizado: motivos de incompletitud, hallazgos de privacidad, duplicado.', null=True)),
                ('creado_en', models.DateTimeField(auto_now_add=True)),
                ('sincronizado_en', models.DateTimeField(auto_now=True)),
                ('alerta', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='candidato_dataset', to='dashboard.alert')),
            ],
            options={
                'ordering': ['-creado_en', '-id'],
            },
        ),
        migrations.CreateModel(
            name='RevisionHumana',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('accion', models.CharField(choices=[('CONFIRMADA', 'Confirmada (de acuerdo con la IA)'), ('CORREGIDA', 'Corregida (en desacuerdo con la IA)'), ('EXCLUIDA', 'Excluida del dataset (evidencia insuficiente)')], max_length=12)),
                ('veredicto_verdad_terreno', models.CharField(blank=True, choices=[('FALSO_POSITIVO', 'Falso positivo'), ('REQUIERE_ATENCION', 'Requiere atención')], help_text='Etiqueta de verdad de terreno. Null si la revisión es EXCLUIDA.', max_length=20, null=True)),
                ('riesgo_revisado', models.CharField(blank=True, choices=[('LOW', 'Bajo'), ('MEDIUM', 'Medio'), ('HIGH', 'Alto'), ('CRITICAL', 'Crítico')], max_length=10, null=True)),
                ('motivo_categoria', models.CharField(choices=[('actividad_autorizada', 'Actividad autorizada'), ('mantenimiento_programado', 'Mantenimiento programado'), ('comportamiento_normal', 'Comportamiento normal'), ('evidencia_amenaza', 'Evidencia de amenaza'), ('contexto_insuficiente', 'Contexto insuficiente'), ('otro', 'Otro')], max_length=30)),
                ('nota', models.TextField(blank=True, default='')),
                ('creada_en', models.DateTimeField(auto_now_add=True)),
                ('actualizada_en', models.DateTimeField(auto_now=True)),
                ('alerta', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='revision_humana', to='dashboard.alert')),
                ('autor', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='revisiones_humanas', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['-actualizada_en', '-id'],
            },
        ),
    ]
