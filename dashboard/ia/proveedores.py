"""
Abstracción configurable de proveedor de IA.

- gemini_developer : proveedor actual (Gemini Developer API con clave de API).
- vertex_tuned     : modelo ajustado en Vertex / Agent Platform (EXPERIMENTAL, desactivado por
                     defecto). Recibe la plantilla v1 + la entrada `exp-entrada-1` del piloto.
                     Sin configuración o sin credenciales devuelve una respuesta no disponible,
                     que el analizador convierte en ANALISIS_FALLIDO (nunca oculta la alerta,
                     nunca la marca FALSO_POSITIVO).

El cliente de red se crea de forma perezosa: importar este módulo no abre
ninguna conexión ni exige que exista una clave de API.
"""
from __future__ import annotations

import json
import os
import re
import socket
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class RespuestaProveedor:
    ok: bool
    texto: str           # texto crudo devuelto por el modelo (puede ser "")
    modelo: str
    error: str | None = None
    parsed: dict | None = None          # JSON ya deserializado por el SDK (response.parsed)
    finish_reason: str | None = None    # p. ej. "STOP", "MAX_TOKENS", "SAFETY"
    usage: dict | None = None           # conteos de tokens (prompt/candidates/thoughts/total)


class ProveedorIA(ABC):
    nombre = "abstracto"

    @abstractmethod
    def analizar(self, prompt: str) -> RespuestaProveedor:
        ...


class GeminiDeveloperProvider(ProveedorIA):
    nombre = "gemini_developer"

    def __init__(self):
        self._api_key = os.environ.get("GEMINI_API_KEY", "")
        self._modelo = os.environ.get("GEMINI_MODEL", "models/gemini-3.5-flash")
        self._client = None

    def _cliente(self):
        if self._client is None:
            from google import genai  # import perezoso
            self._client = genai.Client(api_key=self._api_key)
        return self._client

    def _config(self):
        from google.genai import types
        from .contrato import esquema_json_salida
        kwargs = dict(
            response_mime_type="application/json",     # nunca markdown
            response_json_schema=esquema_json_salida(),  # constriñe enums (verdict/risk/cvss)
            # Límite MUY holgado: el JSON del contrato ~700 tokens, pero un modelo
            # "thinking" gasta presupuesto en razonamiento antes de responder.
            max_output_tokens=8192,
            temperature=0.1,
            http_options=types.HttpOptions(timeout=60_000),   # ms; sin reintentos
        )
        # Desactiva el "thinking" si el SDK lo soporta: es una clasificación
        # determinista, no lo necesita, y evita truncar el JSON.
        try:
            kwargs["thinking_config"] = types.ThinkingConfig(thinking_budget=0)
        except Exception:
            pass
        try:
            return types.GenerateContentConfig(**kwargs)
        except Exception:
            kwargs.pop("thinking_config", None)
            return types.GenerateContentConfig(**kwargs)

    @staticmethod
    def _finish_reason(respuesta):
        try:
            fr = respuesta.candidates[0].finish_reason
            return getattr(fr, "name", None) or str(fr)
        except Exception:
            return None

    @staticmethod
    def _usage(respuesta):
        um = getattr(respuesta, "usage_metadata", None)
        if um is None:
            return None
        return {
            "prompt": getattr(um, "prompt_token_count", None),
            "candidates": getattr(um, "candidates_token_count", None),
            "thoughts": getattr(um, "thoughts_token_count", None),
            "total": getattr(um, "total_token_count", None),
        }

    @staticmethod
    def _parsed(respuesta):
        p = getattr(respuesta, "parsed", None)
        if isinstance(p, dict):
            return p
        # el SDK puede devolver un pydantic/objeto: intentar volcarlo a dict
        for attr in ("model_dump", "to_json_dict", "dict"):
            fn = getattr(p, attr, None)
            if callable(fn):
                try:
                    d = fn()
                    if isinstance(d, dict):
                        return d
                except Exception:
                    pass
        return None

    def analizar(self, prompt):
        try:
            cliente = self._cliente()
            respuesta = cliente.models.generate_content(
                model=self._modelo, contents=prompt, config=self._config())
            fr = self._finish_reason(respuesta)
            usage = self._usage(respuesta)
            parsed = self._parsed(respuesta)
            texto_bruto = getattr(respuesta, "text", None)
            texto = texto_bruto.strip() if isinstance(texto_bruto, str) else ""

            if fr and any(x in fr for x in ("SAFETY", "PROHIBITED", "BLOCKLIST", "SPII", "RECITATION")):
                return RespuestaProveedor(ok=False, texto="", modelo=self._modelo, parsed=None,
                                          finish_reason=fr, usage=usage,
                                          error=f"bloqueo de seguridad del proveedor (finish_reason={fr})")
            if fr and "MAX_TOKENS" in fr:
                return RespuestaProveedor(ok=False, texto=texto, modelo=self._modelo, parsed=parsed,
                                          finish_reason=fr, usage=usage,
                                          error="respuesta truncada por MAX_TOKENS")
            if parsed is None and not texto:
                return RespuestaProveedor(ok=False, texto="", modelo=self._modelo, parsed=None,
                                          finish_reason=fr, usage=usage,
                                          error=f"respuesta vacía (finish_reason={fr})")
            return RespuestaProveedor(ok=True, texto=texto, modelo=self._modelo, parsed=parsed,
                                      finish_reason=fr, usage=usage)
        except Exception as e:  # clave ausente, cuota, timeout, red, esquema, etc.
            return RespuestaProveedor(
                ok=False, texto="", modelo=self._modelo, error=f"{type(e).__name__}: {e}"
            )


_RE_ENDPOINT_VERTEX = re.compile(r"projects/[a-z0-9-]{1,63}/locations/(us|eu)/endpoints/[0-9]{1,30}")
_FR_BLOQUEO = ("SAFETY", "PROHIBITED", "BLOCKLIST", "SPII", "RECITATION")


class VertexTunedProvider(ProveedorIA):
    """
    Endpoint del modelo ajustado (`generateContent`) en la multirregión `us`/`eu`.

    - Solo actúa con IA_VERTEX_HABILITADO=1 y GEMINI_TUNED_ENDPOINT=projects/<p>/locations/<us|eu>/endpoints/<id>.
    - Autenticación: credenciales predeterminadas de aplicación de Google (ADC); nunca claves en el código.
    - Configuración de generación comprobada en el piloto: application/json, maxOutputTokens 8192 y
      thinkingLevel MINIMAL, sin temperatura ni esquema de respuesta.
    - UNA sola petición por análisis: sin reintentos ni proveedor alternativo.
    - Los errores nunca incluyen el token ni cabeceras.
    """
    nombre = "vertex_tuned"
    formato_entrada = "exp-entrada-1"       # el analizador le entrega la plantilla v1 + la entrada exportada
    valida_privacidad_salida = True         # el analizador valida además la privacidad de la respuesta
    TIMEOUT_S = 120
    GENERACION = {"responseMimeType": "application/json", "maxOutputTokens": 8192,
                  "thinkingConfig": {"thinkingLevel": "MINIMAL"}}

    def __init__(self):
        self._endpoint = os.environ.get("GEMINI_TUNED_ENDPOINT", "").strip()
        self._habilitado = os.environ.get("IA_VERTEX_HABILITADO", "").strip() == "1"
        self._modelo = self._endpoint or "vertex_tuned:no_configurado"

    def error_configuracion(self):
        if not self._habilitado:
            return "integración Vertex desactivada (IA_VERTEX_HABILITADO distinto de 1)"
        if not self._endpoint:
            return "configuración incompleta: falta GEMINI_TUNED_ENDPOINT"
        if not _RE_ENDPOINT_VERTEX.fullmatch(self._endpoint):
            return "configuración inválida: GEMINI_TUNED_ENDPOINT debe ser projects/<p>/locations/<us|eu>/endpoints/<id>"
        return None

    def url(self):
        region = _RE_ENDPOINT_VERTEX.fullmatch(self._endpoint).group(1)
        return f"https://aiplatform.{region}.rep.googleapis.com/v1/{self._endpoint}:generateContent"

    def cuerpo(self, texto):
        return {"contents": [{"role": "user", "parts": [{"text": texto}]}], "generationConfig": dict(self.GENERACION)}

    @staticmethod
    def _token():
        import google.auth                          # import perezoso
        import google.auth.transport.requests
        credenciales, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
        credenciales.refresh(google.auth.transport.requests.Request())
        return credenciales.token

    def _fallo(self, error, **kw):
        return RespuestaProveedor(ok=False, texto=kw.pop("texto", ""), modelo=self._modelo, error=error, **kw)

    def analizar(self, prompt):
        err = self.error_configuracion()
        if err:
            return self._fallo(err)
        try:
            token = self._token()
        except Exception as e:                      # sin ADC, sin permisos, sin red: un único intento
            return self._fallo(f"credenciales predeterminadas de aplicación no disponibles ({type(e).__name__})")
        peticion = urllib.request.Request(
            self.url(), data=json.dumps(self.cuerpo(prompt)).encode("utf-8"), method="POST",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(peticion, timeout=self.TIMEOUT_S) as r:
                datos = json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            estado = ""
            try:
                estado = str((json.loads(e.read().decode("utf-8", "replace")).get("error") or {}).get("status") or "")
            except Exception:
                pass
            return self._fallo(f"HTTP {e.code} del endpoint ajustado" + (f" ({estado[:40]})" if estado else ""))
        except (socket.timeout, TimeoutError):
            return self._fallo("timeout del endpoint ajustado")
        except Exception as e:
            return self._fallo(f"error de red o de respuesta ({type(e).__name__})")
        finally:
            token = None

        bloqueo = (datos.get("promptFeedback") or {}).get("blockReason")
        if bloqueo:
            return self._fallo(f"bloqueo de seguridad del proveedor (blockReason={bloqueo})")
        cand = (datos.get("candidates") or [{}])[0]
        fr = cand.get("finishReason")
        um = datos.get("usageMetadata") or {}
        usage = {"prompt": um.get("promptTokenCount"), "candidates": um.get("candidatesTokenCount"),
                 "thoughts": um.get("thoughtsTokenCount"), "total": um.get("totalTokenCount")}
        partes = (cand.get("content") or {}).get("parts") or []
        texto = "".join(p.get("text", "") for p in partes if isinstance(p, dict) and not p.get("thought")).strip()
        if fr and any(x in fr for x in _FR_BLOQUEO):
            return self._fallo(f"bloqueo de seguridad del proveedor (finish_reason={fr})", finish_reason=fr, usage=usage)
        if fr and "MAX_TOKENS" in fr:
            return self._fallo("respuesta truncada por MAX_TOKENS", texto=texto, finish_reason=fr, usage=usage)
        if not texto:
            return self._fallo(f"respuesta vacía (finish_reason={fr})", finish_reason=fr, usage=usage)
        return RespuestaProveedor(ok=True, texto=texto, modelo=self._modelo, parsed=None, finish_reason=fr, usage=usage)


PROVEEDORES = {
    "gemini_developer": GeminiDeveloperProvider,
    "vertex_tuned": VertexTunedProvider,
}
PROVEEDOR_POR_DEFECTO = "gemini_developer"


def nombre_proveedor_activo():
    return os.environ.get("IA_PROVIDER", PROVEEDOR_POR_DEFECTO)


def obtener_proveedor(nombre=None):
    """
    Devuelve una instancia de ProveedorIA, o None si el nombre no existe.
    None -> el analizador produce ANALISIS_FALLIDO (nunca oculta la alerta).
    """
    nombre = nombre or nombre_proveedor_activo()
    cls = PROVEEDORES.get(nombre)
    if cls is None:
        return None
    return cls()
