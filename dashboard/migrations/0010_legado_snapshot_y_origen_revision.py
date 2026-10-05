# Sprint 3C/3D — origen auditable de RevisionHumana + snapshot del legado.
# ADITIVA: 2 AddField (Alert.legado_snapshot, RevisionHumana.origen) + 1
# RunPython NEUTRO (noop en ambos sentidos).
#
# PORTABILIDAD: esta migración NO marca ninguna fila concreta. Una versión
# anterior, nunca commiteada ni distribuida, marcaba la revisión de una alerta
# por su PK; esa PK sólo identifica la prueba controlada en la base local de
# laboratorio y en otra instalación podría ser una alerta distinta. Editar este
# archivo en el sitio es aceptable porque (1) aún no se ha publicado, (2) las
# operaciones de esquema son idénticas, así que la base que ya la aplicó queda
# en el mismo estado de esquema, y (3) esa base conserva el dato local ya
# escrito (origen PRUEBA_CONTROLADA). Etiquetar una revisión como prueba
# controlada es una decisión operativa, no de esquema.
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dashboard', '0009_editor_candidato_dataset'),
    ]

    operations = [
        migrations.AddField(
            model_name='alert',
            name='legado_snapshot',
            field=models.JSONField(blank=True, help_text='Copia de riesgo_ia/explicacion_ia/estado/severidad previos a migrar del flujo legado.', null=True),
        ),
        migrations.AddField(
            model_name='revisionhumana',
            name='origen',
            field=models.CharField(choices=[('PRUEBA_CONTROLADA', 'Prueba controlada (evento de laboratorio dirigido)'), ('OPERATIVA', 'Revisión operativa normal'), ('AUDITORIA_SELECTIVA', 'Auditoría selectiva de falsos positivos de la IA'), ('MIGRACION_LEGADO', 'Migración de una alerta del flujo legado')], default='OPERATIVA', help_text='Procedencia auditable de la revisión. No es una muestra estadística representativa salvo OPERATIVA en volumen suficiente.', max_length=20),
        ),
        migrations.RunPython(migrations.RunPython.noop, migrations.RunPython.noop),
    ]
