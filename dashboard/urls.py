from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('update_alerts', views.update_alerts, name='update_alerts'),
]

