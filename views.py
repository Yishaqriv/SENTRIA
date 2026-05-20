from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from sentria_backend import get_analyzed_alerts

@login_required
def dashboard(request):
    alerts = get_analyzed_alerts()
    return render(request, "dashboard.html", {"alerts": alerts})
