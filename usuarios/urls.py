from django.urls import path
from . import views

urlpatterns = [
    path("", views.lista_usuarios, name="lista_usuarios"),
    path("crear/", views.crear_usuario, name="crear_usuario"),
    path("editar/<int:user_id>/", views.editar_usuario, name="editar_usuario"),
    path("eliminar/<int:user_id>/", views.eliminar_usuario, name="eliminar_usuario"),
]
