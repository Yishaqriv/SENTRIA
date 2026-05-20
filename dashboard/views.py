from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .models import Alert
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from sentria_backend import get_analyzed_alerts

alerts = []

@login_required
def index(request):
    alertas_db = Alert.objects.all().order_by('-creado_en')

    return render(request, 'dashboard/index.html', {
        'alerts': alertas_db
    })


@login_required
def update_alerts(request):
    global alerts
    alerts = get_analyzed_alerts()

    for alerta in alerts:
        timestamp_alerta = alerta.get('timestamp')

        if Alert.objects.filter(timestamp=timestamp_alerta).exists():
            continue

        riesgo = alerta.get('risk', 'No disponible')
        razon = alerta.get('reason', '')

        if '429' in razon:
            riesgo = 'No disponible'
            razon = 'Límite de Gemini alcanzado'

        Alert.objects.create(
            timestamp=timestamp_alerta,
            descripcion=alerta.get('description', ''),
            severidad=alerta.get('level', None),
            riesgo_ia=riesgo,
            explicacion_ia=razon,
            estado='Pendiente',
            fuente='Wazuh'
        )

    return redirect('index')
