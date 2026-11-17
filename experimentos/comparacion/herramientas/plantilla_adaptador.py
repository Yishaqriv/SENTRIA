"""PLANTILLA de adaptador para un proveedor que SENTRIA no implementa. Cópiala, complétala y úsala con
  python herramientas/ejecutar_conjunto.py ... --proveedor mi_proveedor --adaptador ruta/mi_adaptador.py:MiProveedor \
         --permitir-variable MI_PROVEEDOR_API_KEY ...
Reglas (las comprueba el ejecutor; si no se cumplen, el registro lo dice):
- Enviar EXACTAMENTE el texto recibido (entrada.txt), como un único turno, sin recortar ni reescribir.
- Pedir la salida JSON con el esquema común (conjunto/esquema_salida.json) y declarar su huella canónica en
  parametros_medicion()["esquema_salida_sha256"]; si no la declaras, la ejecución queda «no_verificada».
- UNA petición por llamada: sin reintentos ocultos (desactiva los del SDK) ni proveedor alternativo.
- Devolver los tokens y el modelo que informe el proveedor; si no los informa, None (nunca 0 inventado).
- La clave se lee de tu propio entorno (nunca de un archivo .env); el ejecutor solo deja pasar las variables que
  indiques con --permitir-variable.
"""
import os

from dashboard.ia.proveedores import ProveedorIA, RespuestaProveedor

ESQUEMA_CANONICO = "4c67891e7e608a4f564d580af6e916cc8eb1c3d701947d4fccd9b3bf546d78c2"


class MiProveedor(ProveedorIA):
    nombre = "mi_proveedor"

    def __init__(self):
        self._modelo = os.environ.get("MI_PROVEEDOR_MODELO", "modelo-sin-configurar")
        self._clave = os.environ.get("MI_PROVEEDOR_API_KEY", "")

    def parametros_medicion(self):
        return {"temperature": 0.1, "max_output_tokens": 8192, "reintentos_configurados": 0,
                "esquema_salida_sha256": ESQUEMA_CANONICO}

    def analizar(self, prompt):
        # Completar: UNA llamada al proveedor con `prompt` exacto y el esquema común; sin reintentos.
        # return RespuestaProveedor(ok=True, texto=texto_json, modelo=self._modelo, modelo_respuesta=modelo_informado,
        #                           usage={"prompt": n_in, "candidates": n_out, "thoughts": None, "total": n_total},
        #                           finish_reason=motivo, codigo_http=None)
        raise NotImplementedError("Completa analizar() con la llamada de tu proveedor")
