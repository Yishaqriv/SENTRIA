from django.contrib import messages
from django.contrib.auth.models import User
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test

from .forms import UsuarioCreateForm, UsuarioUpdateForm
from .models import PerfilUsuario

def es_admin_sentria(user):
    if not user.is_authenticated:
        return False

    if user.is_superuser:
        return True

    return hasattr(user, "perfilusuario") and user.perfilusuario.rol == "ADMIN"

@login_required
@user_passes_test(es_admin_sentria)
def lista_usuarios(request):
    usuarios = User.objects.all().order_by("-date_joined")
    return render(request, "usuarios/lista_usuarios.html", {
        "usuarios": usuarios
    })

@login_required
@user_passes_test(es_admin_sentria)
def crear_usuario(request):
    if request.method == "POST":
        form = UsuarioCreateForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Usuario creado correctamente.")
            return redirect("lista_usuarios")
    else:
        form = UsuarioCreateForm()

    return render(request, "usuarios/crear_usuario.html", {
        "form": form
    })

@login_required
@user_passes_test(es_admin_sentria)
def editar_usuario(request, user_id):
    usuario = get_object_or_404(User, id=user_id)
    perfil, created = PerfilUsuario.objects.get_or_create(usuario=usuario)

    if request.method == "POST":
        form = UsuarioUpdateForm(request.POST, instance=usuario, perfil=perfil)
        if form.is_valid():
            form.save()
            messages.success(request, "Usuario actualizado correctamente.")
            return redirect("lista_usuarios")
    else:
        form = UsuarioUpdateForm(instance=usuario, perfil=perfil)

    return render(request, "usuarios/editar_usuario.html", {
        "form": form,
        "usuario": usuario
    })

@login_required
@user_passes_test(es_admin_sentria)
def eliminar_usuario(request, user_id):
    usuario = get_object_or_404(User, id=user_id)

    if request.method == "POST":
        usuario.delete()
        messages.success(request, "Usuario eliminado correctamente.")
        return redirect("lista_usuarios")

    return render(request, "usuarios/eliminar_usuario.html", {
        "usuario": usuario
    })
