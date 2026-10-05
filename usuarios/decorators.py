from django.contrib.auth.decorators import login_required, user_passes_test


def usuario_tiene_rol(user, roles_permitidos):
    """Superusuarios siempre pasan, como si tuvieran rol ADMIN."""
    if not user.is_authenticated:
        return False
    if user.is_superuser:
        return True
    return hasattr(user, 'perfilusuario') and user.perfilusuario.rol in roles_permitidos


def requiere_rol(*roles_permitidos):
    """
    Decorador de vistas: exige sesión iniciada y que el usuario tenga uno de
    los roles indicados (ADMIN / ANALISTA / INVITADO).

    Uso:
        @requiere_rol('ADMIN')
        @requiere_rol('ADMIN', 'ANALISTA')
    """
    def decorador(view_func):
        vista_protegida = user_passes_test(
            lambda user: usuario_tiene_rol(user, roles_permitidos)
        )(view_func)
        return login_required(vista_protegida)
    return decorador
