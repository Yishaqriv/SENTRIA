"""
Anonimización RNF-03: enmascara IPs privadas, usuarios y hostnames del texto
antes de enviarlo al proveedor de IA.

Movido desde sentria_backend.py sin cambios de comportamiento; sentria_backend
lo re-exporta para compatibilidad con código y pruebas existentes.
"""
import ipaddress
import re

_PATRON_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")

_ETIQUETAS_USUARIO = r"(?:user(?:name)?|usuario|account\s*name|ruser|logname)"
_ETIQUETAS_HOST = r"(?:hostname|host\s*name|workstation\s*name|computer\s*name|computer|host|equipo|servidor)"


def _enmascarar_ips_privadas(texto):
    def reemplazo(match):
        ip = match.group(0)
        try:
            if ipaddress.ip_address(ip).is_private:
                return "[IP_PRIVADA]"
        except ValueError:
            pass
        return ip

    return _PATRON_IPV4.sub(reemplazo, texto)


def _enmascarar_por_etiqueta(texto, etiquetas, marcador):
    # forma "etiqueta: valor" / "etiqueta=valor"
    patron_separador = re.compile(
        rf"(?i)\b({etiquetas})\b(\s*[:=]\s*['\"]?)([A-Za-z0-9_.\-]{{2,64}})(['\"]?)"
    )
    texto = patron_separador.sub(
        lambda m: f"{m.group(1)}{m.group(2)}{marcador}{m.group(4)}", texto
    )

    # forma "etiqueta 'valor'" (sin separador, p. ej. "for user 'Administrator'")
    patron_comillas = re.compile(
        rf"(?i)\b({etiquetas})\b(\s+)(['\"])([^'\"]{{2,64}})(['\"])"
    )
    texto = patron_comillas.sub(
        lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}{marcador}{m.group(5)}", texto
    )

    return texto


def anonimizar_texto(texto):
    """Enmascara IPs privadas, usuarios y hostnames en `texto` (RNF-03)."""
    if not texto:
        return texto

    texto = _enmascarar_ips_privadas(texto)
    texto = _enmascarar_por_etiqueta(texto, _ETIQUETAS_USUARIO, "[USUARIO]")
    texto = _enmascarar_por_etiqueta(texto, _ETIQUETAS_HOST, "[HOSTNAME]")

    return texto
