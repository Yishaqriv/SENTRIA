#!/usr/bin/env python3
"""
Ejecuta UN caso de comparación con UN proveedor y registra el resultado (registro_comparacion_v2). Nada se ejecuta solo.

  python ejecutar_caso.py --codigo ../../codigo/sentria --caso ../casos/CASO-WIN-01 --proveedor gemini_developer --ensayo
  python ejecutar_caso.py --codigo ../../codigo/sentria --caso ../casos/CASO-WIN-01 --proveedor gemini_developer \
         --repeticion 1 --registro ../registro/registro_resultados.jsonl --confirmar
  (adaptador propio, sin tocar proveedores.py)   ... --proveedor mi_proveedor --adaptador ruta/mi_adaptador.py:MiClase

--ensayo (por defecto, sin red): comprueba huellas del caso, que el código reconstruye EXACTAMENTE entrada.txt, si el
  adaptador representa la entrada y valida la respuesta de referencia como SENTRIA. Sin llamadas y sin registro.
--confirmar: UNA llamada con las credenciales de QUIEN lo ejecuta. Sin reintentos ni proveedor alternativo.

Aislamiento (v2): el proceso NO carga settings de SENTRIA ni .env, no usa base de datos ni indexador.
- Se niega si DJANGO_SETTINGS_MODULE está definido o si Django ya está configurado por otro proyecto.
- Vacía el entorno salvo variables básicas y las credenciales del proveedor elegido (más --permitir-variable).
- Trampa de auditoría: abrir un archivo `.env`, importar clientes de BD/configuración de SENTRIA o abrir la red fuera
  de la llamada confirmada lanza un error.
- Django solo se configura (sin BD, sin settings del proyecto) si el proveedor exige la validación de privacidad.
Registro v2: UUID estable por ejecución, huella del paquete base y, por separado, del código y del adaptador realmente
cargados, esquema efectivo y equivalencia (equivalente / variante / incompatible / no_verificada). Una excepción del
adaptador queda registrada como fallo de llamada (sin traza ni mensaje), con el tiempo medido y tokens null.
"""
import argparse
import datetime as dt
import hashlib
import importlib.util
import inspect
import json
import os
import re
import sys
import time
import uuid

REGISTRO_VERSION = "registro_comparacion_v2"
ND = None
ENTORNO_BASE = ("PATH", "HOME", "LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "TZ", "TMPDIR", "TEMP", "TMP", "SYSTEMROOT",
                "USERPROFILE", "APPDATA", "LOCALAPPDATA", "PYTHONIOENCODING")
CREDENCIALES = {
    "gemini_developer": ("GEMINI_API_KEY", "GEMINI_MODEL"),
    "vertex_tuned": ("GEMINI_TUNED_ENDPOINT", "IA_VERTEX_HABILITADO", "VERTEX_AUTENTICACION", "VERTEX_TOKEN_ARCHIVO",
                     "GOOGLE_APPLICATION_CREDENTIALS"),
}
MODULOS_PROHIBIDOS = ("MySQLdb", "pymysql", "dotenv", "sentria_project", "sentria_backend", "psycopg", "psycopg2")
DEFINICION_TIEMPO = "ejecutor v2: monotonic alrededor de analizar(); tiempo_total = proceso desde la preparación"
_RED = {"permitida": False}
_TRAMPA = {"instalada": False}


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def sha256_archivo(p):
    with open(p, "rb") as f:
        return sha256_bytes(f.read())


# ------------------------------------------------------------------------------------------------- aislamiento
def _auditar(evento, args):
    if evento == "open" and args and isinstance(args[0], (str, bytes, os.PathLike)):
        nombre = os.path.basename(os.fsdecode(args[0]))
        if nombre == ".env" or nombre.endswith(".env"):
            raise PermissionError("ejecutor aislado: lectura de .env bloqueada")
    elif evento == "import" and args and isinstance(args[0], str):
        if args[0].split(".")[0] in MODULOS_PROHIBIDOS:
            raise ImportError(f"ejecutor aislado: importación bloqueada ({args[0].split('.')[0]})")
    elif evento in ("socket.connect", "socket.getaddrinfo") and not _RED["permitida"]:
        raise PermissionError("ejecutor aislado: red bloqueada fuera de la llamada confirmada")


def aislar_proceso(proveedor, extra=()):
    if os.environ.get("DJANGO_SETTINGS_MODULE"):
        sys.exit("Rechazado: DJANGO_SETTINGS_MODULE está definido (otro proyecto). Ejecuta en un entorno limpio.")
    if "django" in sys.modules:
        from django.conf import settings
        if settings.configured:
            sys.exit("Rechazado: Django ya está configurado por otro proyecto en este proceso.")
    conservar = set(ENTORNO_BASE) | set(CREDENCIALES.get(proveedor, ())) | set(extra)
    for k in list(os.environ):
        if k not in conservar:
            del os.environ[k]
    if not _TRAMPA["instalada"]:
        sys.addaudithook(_auditar)
        _TRAMPA["instalada"] = True


def django_minimo():
    """Solo para validadores que dependen de modelos (privacidad de salida): sin BD ni settings del proyecto."""
    from django.conf import settings
    if not settings.configured:
        settings.configure(
            INSTALLED_APPS=["django.contrib.contenttypes", "django.contrib.auth", "dashboard", "usuarios"],
            DATABASES={}, USE_TZ=True, SECRET_KEY="ejecutor-aislado-sin-secreto",
            DEFAULT_AUTO_FIELD="django.db.models.BigAutoField")
        import django
        django.setup()


# --------------------------------------------------------------------------------------------------- caso
def cargar_caso(dir_caso):
    ficha = json.load(open(os.path.join(dir_caso, "ficha.json"), encoding="utf-8"))
    errores, datos = [], {}
    for nombre, meta in ficha["archivos"].items():
        b = open(os.path.join(dir_caso, nombre), "rb").read()
        datos[nombre] = b
        if sha256_bytes(b) != meta["sha256"]:
            errores.append(f"huella distinta: {nombre}")
    esq_b = open(os.path.normpath(os.path.join(dir_caso, ficha["esquema_salida"]["archivo"])), "rb").read()
    if sha256_bytes(esq_b) != ficha["esquema_salida"]["sha256_archivo"]:
        errores.append("huella distinta: esquema_salida.json (archivo)")
    canon = json.dumps(json.loads(esq_b), sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if sha256_bytes(canon) != ficha["esquema_salida"]["sha256_canonico"]:
        errores.append("huella distinta: esquema_salida.json (canónico)")
    return ficha, datos, errores


PROCEDENCIAS = ("windows_natural", "web_natural", "web_historico_reproducido", "diagnostico_agente", "no_determinada")


def procedencia_neutral(ficha):
    if ficha.get("procedencia_conjunto") in PROCEDENCIAS:          # fichas del conjunto: procedencia explícita
        return ficha["procedencia_conjunto"]
    tipo, proc = str(ficha.get("tipo", "")), str(ficha.get("procedencia", ""))
    if "web" in tipo:
        return "web_historico_reproducido" if "reproducido" in proc or "reproducido" in tipo else "web_natural"
    if "windows" in tipo:
        return "windows_natural"
    if "agente" in tipo or "diagnostico" in tipo:
        return "diagnostico_agente"
    return "no_determinada"


def _sanear(texto):
    """Error sin secretos ni rutas: sin claves con aspecto de API key, asignaciones de credenciales ni URLs."""
    t = re.sub(r"AIza[0-9A-Za-z_\-]{20,}", "[clave omitida]", str(texto or ""))
    t = re.sub(r"(?i)\b(bearer|api[_-]?key|token|password|secret)\b\s*[:=]?\s*\S+", r"\1 [omitido]", t)
    t = re.sub(r"(?i)\b(https?|ftp|file)://\S+", "[url omitida]", t)
    t = re.sub(r"(/home/|/root/|/etc/|[A-Za-z]:\\\\)\S*", "[ruta omitida]", t)
    return t[:200]


def validar_como_sentria(prov, respuesta, entrada_capa_e):
    """-> (estado_analisis, motivo|None, data|None). Mismo orden que dashboard/ia/analizador.py."""
    from dashboard.ia.contrato import parsear_json_estricto, validar_salida_ia
    from dashboard.ia.sustento import factores_sin_sustento
    if not respuesta.ok:
        return "ANALISIS_FALLIDO", f"proveedor: {_sanear(respuesta.error)}", None
    parsed = getattr(respuesta, "parsed", None)
    data, err = (parsed, None) if isinstance(parsed, dict) else parsear_json_estricto(respuesta.texto)
    if data is None:
        return "ANALISIS_FALLIDO", f"json_no_estricto: {_sanear(err)}", None
    v = validar_salida_ia(data)
    if not v.ok:
        return "ANALISIS_FALLIDO", "contrato: " + "; ".join(v.errores[:6]), data
    if getattr(prov, "valida_privacidad_salida", False):
        django_minimo()
        from dashboard.dataset import validar_privacidad
        ok, hallazgos = validar_privacidad(data)
        if not ok:
            return "ANALISIS_FALLIDO", f"privacidad: {hallazgos}", data
    if getattr(prov, "valida_sustento_impactos", True):
        sin = factores_sin_sustento(data, entrada_capa_e)
        if sin:
            return "ANALISIS_FALLIDO", "sustento: " + "; ".join(f"{x['factor']}={x['valor']}" for x in sin), data
    return "COMPLETED", None, data


def texto_para_proveedor(prov, entrada_txt, entrada_capa_e):
    from dashboard.ia.entrada_exportacion import CONTRATO_ENTRADA
    if getattr(prov, "formato_entrada", None) == CONTRATO_ENTRADA:
        django_minimo()                         # la exportación usa modelos registrados; sin BD ni settings
        from dashboard.ia.analizador import _entrada_modelo_ajustado
        texto, _traza = _entrada_modelo_ajustado(entrada_capa_e, prov)
        return texto, CONTRATO_ENTRADA
    return entrada_txt, "prompt_sentria"


# ------------------------------------------------------------------------------------------------- huellas
def huella_codigo_cargado(codigo):
    """Huella de los archivos del árbol de código REALMENTE importados por este proceso (no recorre .venv/.git)."""
    base = os.path.realpath(codigo)
    filas = set()
    for m in list(sys.modules.values()):
        f = getattr(m, "__file__", None)
        if not f:
            continue
        rf = os.path.realpath(f)
        if not rf.startswith(base + os.sep) or not rf.endswith(".py"):
            continue
        rel = os.path.relpath(rf, base).replace(os.sep, "/")
        if set(rel.split("/")) & {".venv", "venv", ".git", "__pycache__", "site-packages"}:
            continue
        filas.add((rel, sha256_archivo(rf)))
    texto = "".join(f"{h}  {r}\n" for r, h in sorted(filas))
    return sha256_bytes(texto.encode("utf-8")), len(filas)


def cargar_adaptador(especificacion):
    """`ruta.py:Clase` -> clase. El archivo es el adaptador del propio participante (se registra su huella)."""
    ruta, _, clase = especificacion.rpartition(":")
    if not ruta or not clase or not ruta.endswith(".py"):
        sys.exit("--adaptador debe ser RUTA.py:Clase")
    spec = importlib.util.spec_from_file_location("adaptador_participante", ruta)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return getattr(mod, clase), ruta


def equivalencia(representable, texto_sha, entrada_sha, esquema_efectivo, esquema_comun):
    if not representable:
        return "incompatible"
    if texto_sha != entrada_sha:
        return "variante"                       # el adaptador no envía el texto común exacto
    if esquema_efectivo is None:
        return "no_verificada"
    return "equivalente" if esquema_efectivo == esquema_comun else "variante"


def fila_registro(**kw):
    base = {k: ND for k in (
        "registro_version", "uuid", "fecha_utc", "caso", "procedencia", "repeticion", "grupo_entrada_sha256",
        "proveedor", "modelo_solicitado", "modelo_informado", "formato_entrada", "entrada_sha256",
        "texto_enviado_sha256", "capa_e_sha256", "esquema_sha256_archivo", "esquema_sha256_canonico",
        "esquema_efectivo_sha256", "equivalencia", "configuracion", "manifiesto_codigo_sha256",
        "codigo_ejecucion_sha256", "codigo_ejecucion_archivos", "adaptador_sha256", "estado_llamada",
        "estado_analisis", "motivo_fallo", "categoria_error", "codigo_http", "finish_reason", "tiempo_proveedor_s",
        "tiempo_total_s", "definicion_tiempo", "tokens_entrada", "tokens_salida", "tokens_razonamiento",
        "tokens_total", "tokens_fuente", "respuesta_archivo", "respuesta_sha256", "respuesta_observada", "veredicto",
        "riesgo", "error_sanitizado", "observaciones")}
    base.update(kw)
    return base


def _token(u, k):
    v = u.get(k) if isinstance(u, dict) else None
    return v if type(v) is int and v >= 0 else None


# ---------------------------------------------------------------------------------------------------- main
def main():
    t0 = time.monotonic()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--codigo", required=True, help="carpeta codigo/sentria del paquete")
    ap.add_argument("--caso", required=True)
    ap.add_argument("--proveedor", required=True, help="nombre en PROVEEDORES o el de tu adaptador")
    ap.add_argument("--adaptador", help="RUTA.py:Clase de un adaptador propio (se registra su huella)")
    ap.add_argument("--permitir-variable", action="append", default=[], help="variable de entorno que tu adaptador necesita")
    ap.add_argument("--repeticion", type=int, default=1)
    ap.add_argument("--registro", help="registro JSONL (obligatorio con --confirmar)")
    ap.add_argument("--observaciones", default=None)
    ap.add_argument("--conjunto", help="manifiesto_conjunto.json: registra el conjunto y exige que el caso pertenezca a él")
    modo = ap.add_mutually_exclusive_group()
    modo.add_argument("--ensayo", action="store_true")
    modo.add_argument("--confirmar", action="store_true")
    a = ap.parse_args()

    if a.confirmar and os.environ.get("SENTRIA_ENV_FILE"):
        sys.exit("Entorno de despliegue de SENTRIA detectado (SENTRIA_ENV_FILE): no se ejecuta. Usa tu propio entorno.")
    for v in a.permitir_variable:
        if not re.match(r"^[A-Z][A-Z0-9_]{1,59}$", v) or v.startswith(("DB_", "DJANGO_", "SENTRIA_", "WAZUH_")):
            sys.exit(f"--permitir-variable no admitida: {v}")
    aislar_proceso(a.proveedor, a.permitir_variable)
    ficha, datos, errores = cargar_caso(a.caso)
    if errores:
        sys.exit("El caso no supera la verificación de huellas: " + "; ".join(errores))
    ref_conjunto = None
    if a.conjunto:
        man = json.load(open(a.conjunto, encoding="utf-8"))
        claves_entrada = {c["entrada_sha256"] for c in man["casos"]}
        if ficha["archivos"]["entrada.txt"]["sha256"] not in claves_entrada:
            sys.exit("El caso no pertenece al conjunto indicado (por su huella de entrada).")
        ref_conjunto = {"codigo": man["codigo"], "version": man["version"], "manifiesto_sha256": man["manifiesto_sha256"]}
    sys.path.insert(0, os.path.abspath(a.codigo))
    from dashboard.ia.prompt import construir_prompt
    from dashboard.ia.proveedores import PROVEEDORES, RespuestaProveedor
    from dashboard.ia.entrada_exportacion import EntradaNoRepresentable

    entrada_txt = datos["entrada.txt"].decode("utf-8")
    capa_e = json.loads(datos["contexto_capa_e.json"])
    if construir_prompt(capa_e) != entrada_txt:
        sys.exit("El código no reconstruye exactamente entrada.txt desde contexto_capa_e.json: versión de código distinta.")
    if a.adaptador:
        cls, ruta_adaptador = cargar_adaptador(a.adaptador)
    else:
        cls = PROVEEDORES.get(a.proveedor)
        if cls is None:
            sys.exit(f"Proveedor no registrado: {a.proveedor}. Disponibles: {sorted(PROVEEDORES)} (o usa --adaptador)")
        ruta_adaptador = inspect.getsourcefile(cls) if inspect.isclass(cls) else None
    prov = cls()
    adaptador_sha = sha256_archivo(ruta_adaptador) if ruta_adaptador and os.path.isfile(ruta_adaptador) else ND
    modelo_solicitado = getattr(prov, "_modelo", ND)
    if isinstance(modelo_solicitado, str) and ("projects/" in modelo_solicitado or "://" in modelo_solicitado):
        # Un endpoint privado (proyecto/región) no viaja: se registra solo su huella corta.
        modelo_solicitado = "endpoint_privado:" + sha256_bytes(modelo_solicitado.encode("utf-8"))[:12]
    try:
        texto, formato = texto_para_proveedor(prov, entrada_txt, capa_e)
        representable, motivo_nr = True, None
    except EntradaNoRepresentable as e:
        texto, formato, representable, motivo_nr = None, "exp-entrada-1", False, _sanear(e)
    try:
        params = prov.parametros_medicion() if callable(getattr(prov, "parametros_medicion", None)) else None
    except Exception:
        params = None
    params = params if isinstance(params, dict) else None
    esquema_efectivo = (params or {}).get("esquema_salida_sha256")
    esquema_efectivo = esquema_efectivo if isinstance(esquema_efectivo, str) and re.match(r"^[0-9a-f]{64}$", esquema_efectivo) else None
    entrada_sha = ficha["archivos"]["entrada.txt"]["sha256"]
    texto_sha = sha256_bytes(texto.encode("utf-8")) if texto is not None else ND
    comun = dict(
        registro_version=REGISTRO_VERSION, uuid=str(uuid.uuid4()), caso=ficha["caso"],
        procedencia=procedencia_neutral(ficha), repeticion=a.repeticion, grupo_entrada_sha256=entrada_sha,
        proveedor=a.proveedor, modelo_solicitado=modelo_solicitado, formato_entrada=formato,
        entrada_sha256=entrada_sha, texto_enviado_sha256=texto_sha,
        capa_e_sha256=ficha["archivos"]["contexto_capa_e.json"]["sha256"],
        esquema_sha256_archivo=ficha["esquema_salida"]["sha256_archivo"],
        esquema_sha256_canonico=ficha["esquema_salida"]["sha256_canonico"],
        esquema_efectivo_sha256=esquema_efectivo,
        equivalencia=equivalencia(representable, texto_sha, entrada_sha, esquema_efectivo,
                                  ficha["esquema_salida"]["sha256_canonico"]),
        configuracion=params, manifiesto_codigo_sha256=ficha["codigo"]["manifiesto_codigo_sha256"],
        adaptador_sha256=adaptador_sha, definicion_tiempo=DEFINICION_TIEMPO, observaciones=a.observaciones,
        **({"conjunto": ref_conjunto} if ref_conjunto else {}))

    if not a.confirmar:
        ref_b = datos.get("respuesta_referencia_gemini.json")      # conjunto v2: los casos nuevos no traen referencia
        if ref_b is None:
            estado, motivo = "sin_referencia", "referencia de Gemini pendiente para este caso"
        else:
            estado, motivo, _ = validar_como_sentria(prov, RespuestaProveedor(ok=True, texto=ref_b.decode("utf-8"),
                                                                              modelo="referencia"), capa_e)
        cod, n = huella_codigo_cargado(a.codigo)
        print(json.dumps({"modo": "ensayo", "caso": ficha["caso"], "huellas": "ok", "entrada_reconstruida": "idéntica",
                          "proveedor": a.proveedor, "modelo_solicitado": modelo_solicitado, "formato": formato,
                          "representable": representable, "motivo_no_representable": motivo_nr,
                          "equivalencia": comun["equivalencia"], "codigo_ejecucion_sha256": cod,
                          "codigo_ejecucion_archivos": n, "adaptador_sha256": adaptador_sha,
                          "referencia_validada_como_sentria": estado, "motivo": motivo, "llamadas": 0},
                         ensure_ascii=False, indent=1))
        return

    if not a.registro:
        sys.exit("--confirmar exige --registro.")
    inicio = dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    if not representable:
        cod, n = huella_codigo_cargado(a.codigo)
        fila = fila_registro(**comun, fecha_utc=inicio, estado_llamada="sin_llamada", estado_analisis="ANALISIS_FALLIDO",
                             motivo_fallo=f"entrada_no_representable: {motivo_nr}", categoria_error="entrada_no_representable",
                             codigo_ejecucion_sha256=cod, codigo_ejecucion_archivos=n,
                             tiempo_total_s=round(time.monotonic() - t0, 3), tokens_fuente="no_disponible")
    else:
        respuesta, excepcion = None, None
        t_prov = time.monotonic()
        _RED["permitida"] = True
        try:
            respuesta = prov.analizar(texto)              # UNA llamada; sin reintentos ni alternativa
        except Exception as e:                            # noqa: BLE001 - se registra, no se repite
            excepcion = re.sub(r"[^A-Za-z0-9_]", "", type(e).__name__)[:60] or "Excepcion"
        finally:
            _RED["permitida"] = False
        tiempo_proveedor = round(time.monotonic() - t_prov, 3)
        if excepcion is not None:
            estado, motivo, data = "ANALISIS_FALLIDO", "excepcion_del_adaptador", None
            u, llamada, cat = {}, "error", f"excepcion_adaptador:{excepcion}"
        else:
            estado, motivo, data = validar_como_sentria(prov, respuesta, capa_e)
            u = getattr(respuesta, "usage", None) or {}
            llamada = "ok" if respuesta.ok else "error"
            http = getattr(respuesta, "codigo_http", None)
            cat = None if respuesta.ok else (f"http_{http}" if type(http) is int else "error_informado_por_proveedor")
            if respuesta.ok and estado != "COMPLETED":
                cat = (motivo or "").split(":", 1)[0] or "validacion"
        texto_resp = (getattr(respuesta, "texto", None) or "") if respuesta is not None else ""
        nombre = ND
        if respuesta is not None:
            dir_resp = os.path.join(os.path.dirname(os.path.abspath(a.registro)), "respuestas")
            os.makedirs(dir_resp, exist_ok=True)
            nombre = f"{ficha['caso']}_{re.sub(r'[^A-Za-z0-9_.-]', '_', a.proveedor)}_r{a.repeticion}_{inicio.replace(':', '')}.txt"
            with open(os.path.join(dir_resp, nombre), "w", encoding="utf-8", newline="") as f:
                f.write(texto_resp)
        cod, n = huella_codigo_cargado(a.codigo)
        mv = getattr(respuesta, "modelo_respuesta", None)
        http = getattr(respuesta, "codigo_http", None)
        fila = fila_registro(
            **comun, fecha_utc=inicio, estado_llamada=llamada, estado_analisis=estado, motivo_fallo=motivo,
            categoria_error=cat, codigo_http=http if type(http) is int else ND,
            finish_reason=getattr(respuesta, "finish_reason", ND) if respuesta is not None else ND,
            modelo_informado=mv if isinstance(mv, str) else ND,
            codigo_ejecucion_sha256=cod, codigo_ejecucion_archivos=n,
            tiempo_proveedor_s=tiempo_proveedor, tiempo_total_s=round(time.monotonic() - t0, 3),
            tokens_entrada=_token(u, "prompt"), tokens_salida=_token(u, "candidates"),
            tokens_razonamiento=_token(u, "thoughts"), tokens_total=_token(u, "total"),
            tokens_fuente="usage_del_proveedor" if u else "no_disponible",
            respuesta_archivo=f"respuestas/{nombre}" if nombre else ND,
            respuesta_sha256=sha256_bytes(texto_resp.encode("utf-8")) if respuesta is not None else ND,
            respuesta_observada=texto_resp if respuesta is not None and len(texto_resp) <= 65536 else ND,
            veredicto=(data or {}).get("verdict") if estado == "COMPLETED" else ND,
            riesgo=(data or {}).get("risk") if estado == "COMPLETED" else ND,
            error_sanitizado=_sanear(respuesta.error) if respuesta is not None and not respuesta.ok else ND)
    with open(a.registro, "a", encoding="utf-8") as f:
        f.write(json.dumps(fila, ensure_ascii=False, sort_keys=True) + "\n")
    print(json.dumps({k: fila[k] for k in ("uuid", "caso", "proveedor", "estado_llamada", "estado_analisis",
                                            "categoria_error", "tiempo_proveedor_s", "tokens_total",
                                            "modelo_informado", "equivalencia")}, ensure_ascii=False))


if __name__ == "__main__":
    main()
