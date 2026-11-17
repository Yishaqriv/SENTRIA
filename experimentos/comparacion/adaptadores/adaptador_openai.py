"""Adaptador de OpenAI (ChatGPT) para el conjunto SENTRIA-PILOTO-COMP.

Se basa en herramientas/plantilla_adaptador.py y replica la configuración de gemini_developer:
un único turno con el texto EXACTO de entrada.txt, sin instrucción de sistema, salida JSON con el
esquema común, temperatura 0.1, 8192 tokens de salida, timeout de 60 s y CERO reintentos.

Uso (desde entrega_companeros_v2/):
    export OPENAI_API_KEY=...            # tu clave, nunca en un archivo .env
    export OPENAI_MODEL=...              # modelo exacto que se va a reportar en el documento
    python herramientas/ejecutar_conjunto.py --codigo codigo/sentria --conjunto conjunto \
        --proveedor openai_chat --adaptador herramientas/adaptador_openai.py:OpenAIProveedor \
        --permitir-variable OPENAI_API_KEY --permitir-variable OPENAI_MODEL \
        --permitir-variable OPENAI_STRICT --ensayo

Prueba de humo FUERA del registro (1 llamada con un texto ficticio, no toca ningún caso):
    python herramientas/adaptador_openai.py --humo

Variables opcionales:
    OPENAI_STRICT=1 (por defecto): pide al proveedor que haga cumplir el esquema (structured outputs).
        Si el proveedor rechaza el esquema común en modo estricto, la prueba de humo lo muestra; en ese
        caso usar OPENAI_STRICT=0 (el esquema se envía igual, pero como guía) y DECLARARLO en el documento.
    OPENAI_TEMPERATURE=0.1 (por defecto). Algunos modelos de razonamiento no aceptan temperatura;
        con OPENAI_TEMPERATURE=none no se envía, y queda registrado así.
"""
import hashlib
import json
import os
import sys

if __name__ == "__main__":  # permite la prueba de humo sin el ejecutor
    _raiz = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "codigo", "sentria")
    sys.path.insert(0, os.path.abspath(_raiz))

from dashboard.ia.proveedores import ProveedorIA, RespuestaProveedor


def _esquema():
    from dashboard.ia.contrato import esquema_json_salida
    return esquema_json_salida()


def _huella(esquema):
    canon = json.dumps(esquema, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


class OpenAIProveedor(ProveedorIA):
    nombre = "openai_chat"

    def __init__(self):
        self._clave = os.environ.get("OPENAI_API_KEY", "")
        self._modelo = os.environ.get("OPENAI_MODEL", "modelo-sin-configurar")
        self._estricto = os.environ.get("OPENAI_STRICT", "1").strip() not in ("0", "false", "no")
        t = os.environ.get("OPENAI_TEMPERATURE", "0.1").strip().lower()
        self._temperatura = None if t in ("none", "") else float(t)
        self._client = None

    def _cliente(self):
        if self._client is None:
            from openai import OpenAI  # import perezoso
            # max_retries=0: el SDK de OpenAI reintenta por defecto; aquí se desactiva (una petición por llamada).
            self._client = OpenAI(api_key=self._clave, max_retries=0, timeout=60.0)
        return self._client

    def parametros_medicion(self):
        return {"response_format": "json_schema", "strict": self._estricto,
                "esquema_salida_sha256": _huella(_esquema()),
                "max_output_tokens": 8192, "temperature": self._temperatura, "timeout_ms": 60_000,
                "instruccion_sistema": None, "reintentos_configurados": 0}

    def _peticion(self, prompt):
        kwargs = dict(
            model=self._modelo,
            messages=[{"role": "user", "content": prompt}],  # texto exacto, un único turno
            response_format={"type": "json_schema",
                             "json_schema": {"name": "sentria_respuesta", "schema": _esquema(),
                                             "strict": self._estricto}},
            max_completion_tokens=8192,
        )
        if self._temperatura is not None:
            kwargs["temperature"] = self._temperatura
        return self._cliente().chat.completions.create(**kwargs)

    @staticmethod
    def _usage(r):
        u = getattr(r, "usage", None)
        if u is None:
            return None
        det = getattr(u, "completion_tokens_details", None)
        return {"prompt": getattr(u, "prompt_tokens", None),
                "candidates": getattr(u, "completion_tokens", None),
                "thoughts": getattr(det, "reasoning_tokens", None) if det is not None else None,
                "total": getattr(u, "total_tokens", None)}

    def analizar(self, prompt):
        try:
            r = self._peticion(prompt)
            usage = self._usage(r)
            mv = getattr(r, "model", None)
            choice = r.choices[0] if getattr(r, "choices", None) else None
            fr = getattr(choice, "finish_reason", None) if choice else None
            msg = getattr(choice, "message", None) if choice else None
            negativa = getattr(msg, "refusal", None) if msg else None
            texto = (getattr(msg, "content", None) or "").strip() if msg else ""
            if negativa:
                return RespuestaProveedor(ok=False, texto="", modelo=self._modelo, finish_reason=fr, usage=usage,
                                          modelo_respuesta=mv, error=f"negativa del proveedor: {negativa[:200]}")
            if not texto:
                return RespuestaProveedor(ok=False, texto="", modelo=self._modelo, finish_reason=fr, usage=usage,
                                          modelo_respuesta=mv, error=f"respuesta vacía (finish_reason={fr})")
            try:
                parsed = json.loads(texto)
            except ValueError:
                parsed = None
            if fr == "length":
                return RespuestaProveedor(ok=False, texto=texto, modelo=self._modelo, parsed=parsed,
                                          finish_reason=fr, usage=usage, modelo_respuesta=mv,
                                          error="salida truncada (finish_reason=length)")
            return RespuestaProveedor(ok=True, texto=texto, modelo=self._modelo, parsed=parsed,
                                      finish_reason=fr, usage=usage, modelo_respuesta=mv)
        except Exception as e:  # el ejecutor registra el fallo; no se reintenta
            return RespuestaProveedor(ok=False, texto="", modelo=self._modelo,
                                      error=f"{type(e).__name__}: {str(e)[:300]}",
                                      codigo_http=getattr(e, "status_code", None))


if __name__ == "__main__" and "--humo" in sys.argv:
    p = OpenAIProveedor()
    print("Parámetros:", json.dumps(p.parametros_medicion(), ensure_ascii=False))
    res = p.analizar("Prueba de conexión. Responde con el esquema indicado sobre una alerta ficticia: "
                     "evento de prueba sin riesgo en un equipo de laboratorio.")
    print("ok:", res.ok, "| error:", res.error, "| http:", res.codigo_http)
    print("modelo informado:", res.modelo_respuesta, "| finish:", res.finish_reason, "| tokens:", res.usage)
    print("texto:", (res.texto or "")[:500])
