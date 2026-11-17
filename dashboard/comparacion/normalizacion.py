"""
Normalización y validación de una ejecución de comparación (común al registro local y a la importación).

Reglas:
- Lo no medido es None (null), nunca 0. Tokens: enteros >= 0 (un booleano NO es un entero aquí). Tiempos: números
  finitos >= 0 y <= TIEMPO_MAX_S. NaN e infinitos se rechazan.
- Las huellas son 64 hex en minúsculas. Un UUID se acepta solo en forma canónica.
- Datos contradictorios se rechazan (p. ej. `sin_llamada` con latencia o tokens, COMPLETED sin llamada correcta,
  total menor que la entrada o la salida, duración del análisis menor que la latencia del proveedor).
- `huella_contenido` cubre SOLO los datos de la medición (no el origen, el lote ni el participante): la misma
  ejecución exportada e importada en otra instancia conserva la misma huella, y un cambio en cualquier dato medido
  produce un conflicto visible en vez de sobrescribir.
- `huella_observacion` = caso|proveedor|respuesta: solo SEÑALA que dos registros tienen la misma respuesta. No es
  identidad: dos repeticiones reales pueden repetir el texto. La identidad de una ejecución es su UUID.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import math
import re
import uuid as uuidlib

FORMATOS_ENTRADA = ("prompt_sentria", "exp-entrada-1")
ESTADOS_LLAMADA = ("ok", "error", "sin_llamada")
ESTADOS_ANALISIS = ("COMPLETED", "ANALISIS_FALLIDO")
ORIGENES = ("observada_local", "importada", "referencia")
PROCEDENCIAS = ("windows_natural", "web_natural", "web_historico_reproducido", "diagnostico_agente",
                "no_determinada")
EQUIVALENCIAS = ("equivalente", "variante", "incompatible", "no_verificada")
TIEMPO_MAX_S = 3600.0
TOKENS_MAX = 10_000_000
TEXTO_MAX = 65_536            # respuesta observada
OBS_MAX = 2_000

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_ETIQUETA = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:/()+-]{0,119}$")    # modelos, proveedores, motivos
_CODIGO = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,39}$")
_PARTICIPANTE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _-]{0,39}$")

# Campos medidos que entran en la huella de contenido (orden fijo).
CAMPOS_CONTENIDO = (
    "caso_clave", "repeticion", "proveedor", "modelo_solicitado", "modelo_informado", "parametros_sha256",
    "codigo_base_sha256", "codigo_ejecucion_sha256", "adaptador_sha256", "esquema_efectivo_sha256",
    "texto_enviado_sha256", "equivalencia", "inicio_utc", "definicion_tiempo", "latencia_proveedor_s",
    "duracion_analisis_s", "duracion_ejecucion_s", "tokens_entrada", "tokens_salida", "tokens_razonamiento",
    "tokens_total", "tokens_fuente", "estado_llamada", "estado_analisis", "categoria_error", "motivo_sin_llamada",
    "finish_reason", "codigo_http", "veredicto", "riesgo", "respuesta_sha256",
)


class DatoInvalido(ValueError):
    """Motivo de rechazo SANITIZADO: nombra el campo y la regla, nunca el valor recibido."""


def sha256_texto(texto: str) -> str:
    return hashlib.sha256(texto.encode("utf-8")).hexdigest()


def canonico(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def clave_caso(formato: str, entrada_sha256: str, esquema_sha256: str | None) -> str:
    return sha256_texto(f"caso|{formato}|{entrada_sha256}|{esquema_sha256 or '-'}")


def huella_observacion(caso_clave: str, proveedor: str, respuesta_sha256: str | None, uuid: str) -> str:
    # Sin respuesta no hay forma de reconocer la misma observación: la huella queda ligada al propio UUID.
    base = respuesta_sha256 or f"uuid:{uuid}"
    return sha256_texto(f"obs|{caso_clave}|{proveedor}|{base}")


def huella_contenido(datos: dict) -> str:
    sel = {k: datos.get(k) for k in CAMPOS_CONTENIDO}
    if isinstance(sel["inicio_utc"], dt.datetime):
        sel["inicio_utc"] = fecha_iso(sel["inicio_utc"])
    return hashlib.sha256(canonico(sel)).hexdigest()


# ------------------------------------------------------------------------------------------------ validadores
def hex64(v, campo, obligatorio=False):
    if v is None:
        if obligatorio:
            raise DatoInvalido(f"{campo}: obligatorio")
        return None
    if not isinstance(v, str) or not _HEX64.match(v):
        raise DatoInvalido(f"{campo}: debe ser SHA-256 (64 hex en minúsculas)")
    return v


def entero_tokens(v, campo):
    if v is None:
        return None
    if type(v) is not int:                     # rechaza bool, float, str
        raise DatoInvalido(f"{campo}: debe ser entero o null")
    if v < 0 or v > TOKENS_MAX:
        raise DatoInvalido(f"{campo}: fuera de rango")
    return v


def tiempo(v, campo):
    if v is None:
        return None
    if type(v) not in (int, float):
        raise DatoInvalido(f"{campo}: debe ser número o null")
    if not math.isfinite(v) or v < 0 or v > TIEMPO_MAX_S:
        raise DatoInvalido(f"{campo}: fuera de rango o no finito")
    return round(float(v), 3)


def etiqueta(v, campo, obligatorio=False, patron=_ETIQUETA):
    if v is None or v == "":
        if obligatorio:
            raise DatoInvalido(f"{campo}: obligatorio")
        return None
    if not isinstance(v, str) or not patron.match(v):
        raise DatoInvalido(f"{campo}: formato no admitido")
    return v


def opcion(v, campo, opciones, obligatorio=False):
    if v is None:
        if obligatorio:
            raise DatoInvalido(f"{campo}: obligatorio")
        return None
    if v not in opciones:
        raise DatoInvalido(f"{campo}: valor no admitido")
    return v


def fecha_utc(v, campo, ahora=None):
    if v is None:
        return None
    if not isinstance(v, str) or len(v) > 40:
        raise DatoInvalido(f"{campo}: debe ser ISO 8601 con zona")
    try:
        d = dt.datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        raise DatoInvalido(f"{campo}: debe ser ISO 8601 con zona") from None
    if d.tzinfo is None:
        raise DatoInvalido(f"{campo}: falta la zona horaria")
    d = d.astimezone(dt.timezone.utc)
    d = d.replace(microsecond=(d.microsecond // 1000) * 1000)          # milisegundos: igual en MySQL y SQLite
    ahora = ahora or dt.datetime.now(dt.timezone.utc)
    if d > ahora + dt.timedelta(days=1) or d.year < 2020:
        raise DatoInvalido(f"{campo}: fecha fuera de rango")
    return d


def fecha_iso(d):
    return None if d is None else d.astimezone(dt.timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z")


def uuid_canonico(v, campo="uuid"):
    if not isinstance(v, str):
        raise DatoInvalido(f"{campo}: obligatorio")
    try:
        u = uuidlib.UUID(v)
    except ValueError:
        raise DatoInvalido(f"{campo}: UUID no válido") from None
    if str(u) != v.lower() or u.int == 0:
        raise DatoInvalido(f"{campo}: UUID no canónico")
    return str(u)


_CLAVE_PARAM = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,59}$")
_CLAVE_SENSIBLE = re.compile(r"(?i)(api_?key|^key$|_key$|clave|^token$|_token$|access_?token|secret|password|"
                             r"contrasena|credencial|cookie|^auth|_auth|endpoint|url|ruta|path|archivo|project)")


def _param_valor(x, prof, cuenta):
    cuenta[0] += 1
    if cuenta[0] > 80:
        raise DatoInvalido("parametros: demasiados valores")
    if x is None or type(x) in (str, int, float, bool):
        if isinstance(x, float) and not math.isfinite(x):
            raise DatoInvalido("parametros: número no finito")
        if isinstance(x, str) and len(x) > 200:
            raise DatoInvalido("parametros: texto demasiado largo")
        return x
    if prof >= 3:
        raise DatoInvalido("parametros: anidamiento excesivo")
    if isinstance(x, list):
        if len(x) > 20:
            raise DatoInvalido("parametros: lista demasiado larga")
        return [_param_valor(y, prof + 1, cuenta) for y in x]
    if isinstance(x, dict):
        limpio = {}
        for k, y in x.items():
            if not isinstance(k, str) or not _CLAVE_PARAM.match(k):
                raise DatoInvalido("parametros: nombre de clave no admitido")
            if _CLAVE_SENSIBLE.search(k):
                raise DatoInvalido("parametros: clave con aspecto de credencial o ruta")
            limpio[k] = _param_valor(y, prof + 1, cuenta)
        return limpio
    raise DatoInvalido("parametros: tipo no admitido")


def parametros_seguros(v):
    """Parámetros del proveedor: objeto pequeño (hasta 3 niveles, 80 valores); sin claves de credenciales/rutas."""
    if v is None:
        return None, None
    if not isinstance(v, dict):
        raise DatoInvalido("parametros: debe ser un objeto")
    limpio = _param_valor(v, 0, [0])
    return limpio, hashlib.sha256(canonico(limpio)).hexdigest()


def texto_corto(v, campo, maximo=160):
    if v is None or v == "":
        return None
    if not isinstance(v, str) or len(v) > maximo or re.search(r"[\x00-\x1f\x7f]", v):
        raise DatoInvalido(f"{campo}: texto de hasta {maximo} caracteres sin controles")
    return v


def ejecucion(d: dict, *, ahora=None) -> dict:
    """Valida y normaliza una ejecución ya traducida a los nombres internos. -> dict listo para el modelo."""
    out = {}
    out["uuid"] = uuid_canonico(d.get("uuid"))
    out["caso_clave"] = hex64(d.get("caso_clave"), "caso_clave", obligatorio=True)
    rep = d.get("repeticion")
    if rep is not None and (type(rep) is not int or not 1 <= rep <= 10_000):
        raise DatoInvalido("repeticion: entero >= 1 o null")
    out["repeticion"] = rep
    out["proveedor"] = etiqueta(d.get("proveedor"), "proveedor", obligatorio=True)
    out["modelo_solicitado"] = etiqueta(d.get("modelo_solicitado"), "modelo_solicitado")
    out["modelo_informado"] = etiqueta(d.get("modelo_informado"), "modelo_informado")
    out["parametros"], psha = parametros_seguros(d.get("parametros"))
    if d.get("parametros_sha256") is not None and psha is not None and d["parametros_sha256"] != psha:
        raise DatoInvalido("parametros_sha256: no coincide con los parámetros")
    out["parametros_sha256"] = psha if psha is not None else hex64(d.get("parametros_sha256"), "parametros_sha256")
    for k in ("codigo_base_sha256", "codigo_ejecucion_sha256", "adaptador_sha256", "esquema_efectivo_sha256",
              "texto_enviado_sha256", "respuesta_sha256"):
        out[k] = hex64(d.get(k), k)
    out["equivalencia"] = opcion(d.get("equivalencia") or "no_verificada", "equivalencia", EQUIVALENCIAS)
    out["inicio_utc"] = fecha_utc(d.get("inicio_utc"), "inicio_utc", ahora)
    out["definicion_tiempo"] = texto_corto(d.get("definicion_tiempo"), "definicion_tiempo") or ""
    out["latencia_proveedor_s"] = tiempo(d.get("latencia_proveedor_s"), "latencia_proveedor_s")
    out["duracion_analisis_s"] = tiempo(d.get("duracion_analisis_s"), "duracion_analisis_s")
    out["duracion_ejecucion_s"] = tiempo(d.get("duracion_ejecucion_s"), "duracion_ejecucion_s")
    for k in ("tokens_entrada", "tokens_salida", "tokens_razonamiento", "tokens_total"):
        out[k] = entero_tokens(d.get(k), k)
    out["tokens_fuente"] = etiqueta(d.get("tokens_fuente"), "tokens_fuente")
    out["estado_llamada"] = opcion(d.get("estado_llamada"), "estado_llamada", ESTADOS_LLAMADA, obligatorio=True)
    out["estado_analisis"] = opcion(d.get("estado_analisis"), "estado_analisis", ESTADOS_ANALISIS)
    out["categoria_error"] = etiqueta(d.get("categoria_error"), "categoria_error")
    out["motivo_sin_llamada"] = etiqueta(d.get("motivo_sin_llamada"), "motivo_sin_llamada")
    out["finish_reason"] = etiqueta(d.get("finish_reason"), "finish_reason")
    http = d.get("codigo_http")
    if http is not None and (type(http) is not int or not 100 <= http <= 599):
        raise DatoInvalido("codigo_http: entero 100-599 o null")
    out["codigo_http"] = http
    out["veredicto"] = etiqueta(d.get("veredicto"), "veredicto")
    out["riesgo"] = etiqueta(d.get("riesgo"), "riesgo")
    resp = d.get("respuesta_observada")
    if resp is not None:
        if not isinstance(resp, str) or len(resp) > TEXTO_MAX:
            raise DatoInvalido("respuesta_observada: texto de hasta 64 KiB")
        if out["respuesta_sha256"] is not None and sha256_texto(resp) != out["respuesta_sha256"]:
            raise DatoInvalido("respuesta_sha256: no coincide con la respuesta")
        out["respuesta_sha256"] = out["respuesta_sha256"] or sha256_texto(resp)
    out["respuesta_observada"] = resp
    obs = d.get("observaciones") or ""
    if not isinstance(obs, str) or len(obs) > OBS_MAX:
        raise DatoInvalido("observaciones: texto de hasta 2000 caracteres")
    out["observaciones"] = obs

    # Coherencia: se rechaza lo contradictorio en lugar de «arreglarlo».
    if out["estado_llamada"] == "sin_llamada":
        if out["latencia_proveedor_s"] is not None or any(
                out[k] is not None for k in ("tokens_entrada", "tokens_salida", "tokens_razonamiento",
                                             "tokens_total", "modelo_informado", "codigo_http")):
            raise DatoInvalido("contradicción: sin_llamada con latencia, tokens, modelo informado o HTTP")
        if out["estado_analisis"] == "COMPLETED":
            raise DatoInvalido("contradicción: COMPLETED sin llamada")
    if out["estado_analisis"] == "COMPLETED" and out["estado_llamada"] != "ok":
        raise DatoInvalido("contradicción: COMPLETED con la llamada fallida")
    tot = out["tokens_total"]
    if tot is not None and any(out[k] is not None and out[k] > tot for k in ("tokens_entrada", "tokens_salida")):
        raise DatoInvalido("contradicción: tokens_total menor que la entrada o la salida")
    if (out["latencia_proveedor_s"] is not None and out["duracion_analisis_s"] is not None
            and out["duracion_analisis_s"] + 0.001 < out["latencia_proveedor_s"]):
        raise DatoInvalido("contradicción: duración del análisis menor que la latencia del proveedor")
    if out["estado_analisis"] != "COMPLETED" and (out["veredicto"] is not None or out["riesgo"] is not None):
        raise DatoInvalido("contradicción: veredicto o riesgo en un análisis no aceptado")
    return out


def caso(d: dict) -> dict:
    out = {}
    out["formato_entrada"] = opcion(d.get("formato_entrada"), "formato_entrada", FORMATOS_ENTRADA, obligatorio=True)
    out["entrada_sha256"] = hex64(d.get("entrada_sha256"), "entrada_sha256", obligatorio=True)
    out["esquema_sha256"] = hex64(d.get("esquema_sha256"), "esquema_sha256")
    out["contexto_sha256"] = hex64(d.get("contexto_sha256"), "contexto_sha256")
    out["codigo"] = etiqueta(d.get("codigo"), "codigo", patron=_CODIGO) or f"C-{out['entrada_sha256'][:10]}"
    out["procedencia"] = opcion(d.get("procedencia") or "no_determinada", "procedencia", PROCEDENCIAS)
    out["extension_web"] = etiqueta(d.get("extension_web"), "extension_web")
    desc = d.get("descripcion") or ""
    if not isinstance(desc, str) or len(desc) > 200:
        raise DatoInvalido("descripcion: texto de hasta 200 caracteres")
    out["descripcion"] = desc
    out["clave"] = clave_caso(out["formato_entrada"], out["entrada_sha256"], out["esquema_sha256"])
    if d.get("clave") is not None and d["clave"] != out["clave"]:
        raise DatoInvalido("clave del caso: no coincide con sus huellas")
    return out


def cabe_en_modelo(datos: dict, modelo) -> None:
    """Rechaza (como dato inválido) lo que no cabe en una columna: SQLite no limita la longitud y MySQL sí."""
    from django.db.models import CharField
    for campo in modelo._meta.concrete_fields:
        largo = campo.max_length if isinstance(campo, CharField) else None
        v = datos.get(campo.name)
        if largo and isinstance(v, str) and len(v) > largo:
            raise DatoInvalido(f"{campo.name}: supera {largo} caracteres")


def participante(v):
    return etiqueta(v, "participante", patron=_PARTICIPANTE) or ""
