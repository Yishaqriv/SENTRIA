from django.contrib import messages
from django.contrib.auth.models import User
from django.shortcuts import render, redirect, get_object_or_404

from .decorators import requiere_rol
from .forms import UsuarioCreateForm, UsuarioUpdateForm
from .models import PerfilUsuario


@requiere_rol('ADMIN')
def lista_usuarios(request):
    usuarios = User.objects.all().order_by("-date_joined")
    return render(request, "usuarios/lista_usuarios.html", {
        "usuarios": usuarios
    })

@requiere_rol('ADMIN')
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

@requiere_rol('ADMIN')
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

@requiere_rol('ADMIN')
def eliminar_usuario(request, user_id):
    usuario = get_object_or_404(User, id=user_id)

    if request.method == "POST":
        usuario.delete()
        messages.success(request, "Usuario eliminado correctamente.")
        return redirect("lista_usuarios")

    return render(request, "usuarios/eliminar_usuario.html", {
        "usuario": usuario
    })
