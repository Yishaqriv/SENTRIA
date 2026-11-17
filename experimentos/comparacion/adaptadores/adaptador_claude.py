"""Adaptador de Anthropic (Claude) para el conjunto SENTRIA-PILOTO-COMP.

Se basa en herramientas/plantilla_adaptador.py y replica la configuración de gemini_developer:
un único turno con el texto EXACTO de entrada.txt, sin instrucción de sistema, temperatura 0.1,
8192 tokens de salida, timeout de 60 s, sin razonamiento extendido y CERO reintentos.

Cómo se pide el esquema común (CLAUDE_MODO):
  herramienta (por defecto): el esquema común COMPLETO, sin modificar, se envía como input_schema de una
      herramienta que Claude está obligado a usar (tool_choice). Así el modelo recibe exactamente el mismo
      esquema que Gemini y GPT y la huella declarada es la canónica. El proveedor no hace cumplir minLength,
      maxLength ni maxItems en este modo; los controles de SENTRIA validan la respuesta igual que con los demás.
      Nota para el documento: la definición de la herramienta suma tokens de entrada propios de este modo.
  json_schema: usa output_config.format (salida estructurada). La API de Claude rechaza (400) minLength,
      maxLength y maxItems, así que aquí se envía una COPIA sin esas claves y se declara la huella de lo que
      realmente se envió. El ejecutor marcará la ejecución como no equivalente: es lo honesto.

Uso (desde entrega_companeros_v2/):
    export ANTHROPIC_API_KEY=...
    export CLAUDE_MODEL=claude-haiku-5-5     # o el modelo exacto que se reporte
    python herramientas/adaptador_claude.py --humo        # 1 llamada de prueba, fuera del registro
    python herramientas/ejecutar_conjunto.py --codigo codigo/sentria --conjunto conjunto \
        --proveedor anthropic_claude --adaptador herramientas/adaptador_claude.py:ClaudeProveedor \
        --permitir-variable ANTHROPIC_API_KEY --permitir-variable CLAUDE_MODEL --ensayo

Variables opcionales: CLAUDE_TEMPERATURE=0.1 (none = no enviar), CLAUDE_MODO=herramienta|json_schema.
"""
import copy
import hashlib
import json
import os
import sys

if __name__ == "__main__":  # permite la prueba de humo sin el ejecutor
    _raiz = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "codigo", "sentria")
    sys.path.insert(0, os.path.abspath(_raiz))

from dashboard.ia.proveedores import ProveedorIA, RespuestaProveedor

NOMBRE_HERRAMIENTA = "registrar_clasificacion"
_NO_SOPORTADAS = ("minLength", "maxLength", "maxItems")


def _esquema():
    from dashboard.ia.contrato import esquema_json_salida
    return esquema_json_salida()


def _huella(esquema):
    canon = json.dumps(esquema, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def _sin_claves_no_soportadas(o):
    if isinstance(o, dict):
        return {k: _sin_claves_no_soportadas(v) for k, v in o.items() if k not in _NO_SOPORTADAS}
    if isinstance(o, list):
        return [_sin_claves_no_soportadas(v) for v in o]
    return o


class ClaudeProveedor(ProveedorIA):
    nombre = "anthropic_claude"

    def __init__(self):
        self._clave = os.environ.get("ANTHROPIC_API_KEY", "")
        self._modelo = os.environ.get("CLAUDE_MODEL", "modelo-sin-configurar")
        self._modo = os.environ.get("CLAUDE_MODO", "herramienta").strip().lower()
        t = os.environ.get("CLAUDE_TEMPERATURE", "0.1").strip().lower()
        self._temperatura = None if t in ("none", "") else float(t)
        self._client = None

    def _cliente(self):
        if self._client is None:
            import anthropic  # import perezoso
            # max_retries=0: el SDK reintenta por defecto; aquí se desactiva (una petición por llamada).
            self._client = anthropic.Anthropic(api_key=self._clave, max_retries=0, timeout=60.0)
        return self._client

    def _esquema_enviado(self):
        e = _esquema()
        return copy.deepcopy(e) if self._modo == "herramienta" else _sin_claves_no_soportadas(e)

    def parametros_medicion(self):
        return {"modo_esquema": self._modo,
                "esquema_salida_sha256": _huella(self._esquema_enviado()),
                "max_output_tokens": 8192, "temperature": self._temperatura, "timeout_ms": 60_000,
                "razonamiento_extendido": False, "instruccion_sistema": None, "reintentos_configurados": 0}

    def _peticion(self, prompt):
        kwargs = dict(model=self._modelo, max_tokens=8192,
                      messages=[{"role": "user", "content": prompt}])  # texto exacto, un único turno
        if self._temperatura is not None:
            kwargs["temperature"] = self._temperatura
        if self._modo == "herramienta":
            kwargs["tools"] = [{"name": NOMBRE_HERRAMIENTA,
                                "description": "Registra la clasificación de la alerta con el esquema de SENTRIA.",
                                "input_schema": self._esquema_enviado()}]
            kwargs["tool_choice"] = {"type": "tool", "name": NOMBRE_HERRAMIENTA}
        else:
            kwargs["output_config"] = {"format": {"type": "json_schema", "schema": self._esquema_enviado()}}
        return self._cliente().messages.create(**kwargs)

    @staticmethod
    def _usage(r):
        u = getattr(r, "usage", None)
        if u is None:
            return None
        ent, sal = getattr(u, "input_tokens", None), getattr(u, "output_tokens", None)
        total = ent + sal if isinstance(ent, int) and isinstance(sal, int) else None  # suma de lo informado
        return {"prompt": ent, "candidates": sal, "thoughts": None, "total": total}

    def _extraer(self, r):
        for b in getattr(r, "content", None) or []:
            if self._modo == "herramienta" and getattr(b, "type", None) == "tool_use":
                entrada = getattr(b, "input", None)
                if isinstance(entrada, dict):
                    return json.dumps(entrada, ensure_ascii=False), entrada
            if self._modo != "herramienta" and getattr(b, "type", None) == "text":
                texto = (b.text or "").strip()
                try:
                    return texto, json.loads(texto)
                except ValueError:
                    return texto, None
        return "", None

    def analizar(self, prompt):
        try:
            r = self._peticion(prompt)
            usage = self._usage(r)
            mv = getattr(r, "model", None)
            fr = getattr(r, "stop_reason", None)
            texto, parsed = self._extraer(r)
            if fr == "refusal":
                return RespuestaProveedor(ok=False, texto="", modelo=self._modelo, finish_reason=fr, usage=usage,
                                          modelo_respuesta=mv, error="negativa del proveedor (stop_reason=refusal)")
            if fr == "max_tokens":
                return RespuestaProveedor(ok=False, texto=texto, modelo=self._modelo, parsed=parsed,
                                          finish_reason=fr, usage=usage, modelo_respuesta=mv,
                                          error="salida truncada (stop_reason=max_tokens)")
            if not texto:
                return RespuestaProveedor(ok=False, texto="", modelo=self._modelo, finish_reason=fr, usage=usage,
                                          modelo_respuesta=mv, error=f"respuesta sin JSON (stop_reason={fr})")
            return RespuestaProveedor(ok=True, texto=texto, modelo=self._modelo, parsed=parsed,
                                      finish_reason=fr, usage=usage, modelo_respuesta=mv)
        except Exception as e:  # el ejecutor registra el fallo; no se reintenta
            return RespuestaProveedor(ok=False, texto="", modelo=self._modelo,
                                      error=f"{type(e).__name__}: {str(e)[:300]}",
                                      codigo_http=getattr(e, "status_code", None))


if __name__ == "__main__" and "--humo" in sys.argv:
    p = ClaudeProveedor()
    print("Parámetros:", json.dumps(p.parametros_medicion(), ensure_ascii=False))
    res = p.analizar("Prueba de conexión. Responde con el esquema indicado sobre una alerta ficticia: "
                     "evento de prueba sin riesgo en un equipo de laboratorio.")
    print("ok:", res.ok, "| error:", res.error, "| http:", res.codigo_http)
    print("modelo informado:", res.modelo_respuesta, "| stop:", res.finish_reason, "| tokens:", res.usage)
    print("texto:", (res.texto or "")[:500])
