from django import forms
from django.contrib.auth.models import User
from .models import PerfilUsuario


class UsuarioCreateForm(forms.ModelForm):
    password = forms.CharField(
        label="Contraseña",
        widget=forms.PasswordInput(attrs={"class": "form-control"})
    )

    rol = forms.ChoiceField(
        choices=PerfilUsuario.ROLES,
        widget=forms.Select(attrs={"class": "form-control"})
    )

    class Meta:
        model = User
        fields = ["username", "first_name", "last_name", "email", "password"]
        widgets = {
            "username": forms.TextInput(attrs={"class": "form-control"}),
            "first_name": forms.TextInput(attrs={"class": "form-control"}),
            "last_name": forms.TextInput(attrs={"class": "form-control"}),
            "email": forms.EmailInput(attrs={"class": "form-control"}),
        }

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password"])

        if commit:
            user.save()
            perfil = user.perfilusuario
            perfil.rol = self.cleaned_data["rol"]
            perfil.save()

        return user


class UsuarioUpdateForm(forms.ModelForm):
    rol = forms.ChoiceField(
        choices=PerfilUsuario.ROLES,
        widget=forms.Select(attrs={"class": "form-control"})
    )

    activo = forms.BooleanField(required=False)

    class Meta:
        model = User
        fields = ["username", "first_name", "last_name", "email", "is_active"]
        widgets = {
            "username": forms.TextInput(attrs={"class": "form-control"}),
            "first_name": forms.TextInput(attrs={"class": "form-control"}),
            "last_name": forms.TextInput(attrs={"class": "form-control"}),
            "email": forms.EmailInput(attrs={"class": "form-control"}),
        }

    def __init__(self, *args, **kwargs):
        self.perfil = kwargs.pop("perfil", None)
        super().__init__(*args, **kwargs)

        if self.perfil:
            self.fields["rol"].initial = self.perfil.rol
            self.fields["activo"].initial = self.perfil.activo

    def save(self, commit=True):
        user = super().save(commit=False)

        if commit:
            user.save()
            if self.perfil:
                self.perfil.rol = self.cleaned_data["rol"]
                self.perfil.activo = self.cleaned_data["activo"]
                self.perfil.save()

        return user
