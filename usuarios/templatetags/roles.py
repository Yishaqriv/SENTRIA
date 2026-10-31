from django import template

from usuarios.decorators import usuario_tiene_rol

register = template.Library()


@register.filter(name='tiene_rol')
def tiene_rol(user, roles_csv):
    """
    Uso en templates: {% load roles %} ... {% if request.user|tiene_rol:"ADMIN,ANALISTA" %}
    """
    if not user or not user.is_authenticated:
        return False
    roles_permitidos = [r.strip() for r in roles_csv.split(',')]
    return usuario_tiene_rol(user, roles_permitidos)
