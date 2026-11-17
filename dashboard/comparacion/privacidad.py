"""
Revisión de privacidad de los datos de comparación que ENTRAN (importación) o SALEN (exportación) de una instancia.

Devuelve CATEGORÍAS, nunca el valor encontrado (los motivos se muestran y se guardan en el resumen del lote).
- Secretos: claves con aspecto de API key, cabeceras PEM, `password=`, cookies de sesión, nombres de campo de
  credenciales en cualquier nivel del registro (aunque el campo se fuese a ignorar: un archivo así no se acepta).
- Datos de red/personales: IPv4/IPv6, correos, URLs, rutas absolutas de sistema.
- Identificadores privados DE ESTA INSTANCIA: ids de documento del indexador, etiquetas privadas de agentes,
  identificadores de activos y nombres de usuario (estos últimos solo en campos de texto libre cortos).
"""
from __future__ import annotations

import ipaddress
import re

_SECRETOS = [
    ("posible_clave_api", re.compile(r"AIza[0-9A-Za-z_\-]{20,}|\bsk-[A-Za-z0-9_\-]{16,}|\bya29\.[0-9A-Za-z_\-]{20,}")),
    ("material_pem", re.compile(r"-----BEGIN [A-Z ]*(PRIVATE KEY|CERTIFICATE)-----")),
    ("asignacion_de_credencial", re.compile(
        r"(?i)\b(password|passwd|contrase(n|ñ)a|api[_-]?key|secret|token|bearer|authorization)\b\s*[:=]\s*\S+")),
    ("cookie_de_sesion", re.compile(r"(?i)\b(sessionid|csrftoken)\s*=")),
    ("variable_de_entorno_sensible", re.compile(
        r"\b(DB_PASSWORD|DJANGO_SECRET_KEY|GEMINI_API_KEY|WAZUH_[A-Z_]*PASS[A-Z_]*|SENTRIA_ENV_FILE)\b")),
]
_CLAVE_CREDENCIAL = re.compile(
    r"(?i)^(api[_-]?key|apikey|password|passwd|secret|secret_key|token|access_token|refresh_token|cookie|cookies|"
    r"credenciales?|credentials?|authorization|contrase(n|ñ)a|env|dotenv|private_key|clave_api)$")
_IPV4 = re.compile(r"(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\d.])")
_IPV6 = re.compile(r"(?<![0-9A-Za-z:.])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![0-9A-Za-z:])")
_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_URL = re.compile(r"(?i)\b(https?|ftp|file)://")
_RUTA = re.compile(r"(?i)(?<![A-Za-z0-9])(/home/|/root/|/etc/|/var/|/media/|/tmp/|/opt/|[a-z]:\\users\\)")
_TOKEN_ID = re.compile(r"[A-Za-z0-9_\-]{16,}")


def _ipv4_valida(m):
    try:
        ipaddress.IPv4Address(m.group(0))
        return True
    except ValueError:
        return False


def categorias_texto(texto: str) -> set[str]:
    hall = {nombre for nombre, rx in _SECRETOS if rx.search(texto)}
    if any(_ipv4_valida(m) for m in _IPV4.finditer(texto)):
        hall.add("posible_ip")
    for m in _IPV6.finditer(texto):              # «00:25:01» (hora) no es una IPv6 válida: se valida
        try:
            ipaddress.IPv6Address(m.group(0))
            hall.add("posible_ipv6")
            break
        except ValueError:
            pass
    if _EMAIL.search(texto):
        hall.add("posible_correo")
    if _URL.search(texto):
        hall.add("url")
    if _RUTA.search(texto):
        hall.add("ruta_de_sistema")
    return hall


class IdentificadoresPrivados:
    """Valores privados de ESTA instancia que no deben entrar ni salir en datos de comparación."""

    def __init__(self, ids_documento=(), palabras=(), usuarios=()):
        self.ids_documento = {x for x in ids_documento if x and len(x) >= 16}
        self.palabras = [re.compile(r"(?<![A-Za-z0-9_\-])" + re.escape(p) + r"(?![A-Za-z0-9_\-])")
                         for p in sorted({p for p in palabras if p and len(p) >= 4})]
        self.usuarios = [re.compile(r"(?<![A-Za-z0-9_\-])" + re.escape(u) + r"(?![A-Za-z0-9_\-])")
                         for u in sorted({u for u in usuarios if u and len(u) >= 4})]

    @classmethod
    def de_la_instancia(cls):
        from dashboard.models import ActivoLogico, Alert, AsignacionAgenteActivo
        from django.contrib.auth.models import User
        ids = Alert.objects.exclude(opensearch_id__isnull=True).values_list("opensearch_id", flat=True)
        palabras = list(AsignacionAgenteActivo.objects.exclude(etiqueta_privada="")
                        .values_list("etiqueta_privada", flat=True))
        palabras += list(ActivoLogico.objects.values_list("identificador", flat=True))
        usuarios = User.objects.values_list("username", flat=True)
        return cls(ids, palabras, usuarios)

    def categorias(self, texto: str, *, texto_libre_corto=False) -> set[str]:
        hall = set()
        if self.ids_documento and any(t in self.ids_documento for t in _TOKEN_ID.findall(texto)):
            hall.add("identificador_privado_de_documento")
        if any(rx.search(texto) for rx in self.palabras):
            hall.add("identificador_privado_de_activo_o_agente")
        if texto_libre_corto and any(rx.search(texto) for rx in self.usuarios):
            hall.add("nombre_de_usuario_de_la_instancia")
        return hall


def revisar_registro_crudo(obj, privados: IdentificadoresPrivados | None = None, _prof=0) -> set[str]:
    """Recorre TODO el registro recibido (claves y valores). Cualquier hallazgo rechaza el registro."""
    hall = set()
    if _prof > 6:
        return {"anidamiento_excesivo"}
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str) and _CLAVE_CREDENCIAL.match(k.strip()):
                hall.add("campo_de_credencial")
            hall |= revisar_registro_crudo(v, privados, _prof + 1)
            if isinstance(k, str):
                hall |= categorias_texto(k)
    elif isinstance(obj, list):
        for v in obj[:500]:
            hall |= revisar_registro_crudo(v, privados, _prof + 1)
    elif isinstance(obj, str):
        hall |= categorias_texto(obj)
        if privados is not None:
            hall |= privados.categorias(obj, texto_libre_corto=len(obj) <= 300)
    return hall
