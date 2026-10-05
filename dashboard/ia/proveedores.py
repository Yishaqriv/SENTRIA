"""
Abstracción configurable de proveedor de IA.

- gemini_developer : proveedor actual (Gemini Developer API con clave de API).
- vertex_tuned     : reservado para el modelo ajustado (Vertex / Agent Platform).
                     Aún no implementado: devuelve una respuesta no disponible,
                     que el analizador convierte en ANALISIS_FALLIDO (nunca oculta
                     la alerta, nunca la marca FALSO_POSITIVO).

El cliente de red se crea de forma perezosa: importar este módulo no abre
ninguna conexión ni exige que exista una clave de API.
"""
from __future__ import annotations

import os
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


class VertexTunedProvider(ProveedorIA):
    nombre = "vertex_tuned"

    def __init__(self):
        self._modelo = os.environ.get("GEMINI_TUNED_ENDPOINT", "vertex_tuned:no_configurado")

    def analizar(self, prompt):
        return RespuestaProveedor(
            ok=False,
            texto="",
            modelo=self._modelo,
            error="Proveedor 'vertex_tuned' aún no implementado (migración a Vertex pendiente).",
        )


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
