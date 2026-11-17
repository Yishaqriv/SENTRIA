"""
Exportación e importación de resultados de comparación entre instancias de SENTRIA (sin conexión entre ellas).

Formatos de ENTRADA (lista cerrada; se detectan por su contenido, nunca por el nombre del archivo):
- `sentria_comparacion` versión 1: documento JSON exportado por esta pantalla (casos + ejecuciones con UUID y
  huella de contenido verificable).
- `registro_comparacion_v2`: líneas JSONL del ejecutor independiente (comparacion/herramientas/ejecutar_caso.py),
  con UUID, huellas del código/adaptador realmente usados y equivalencia declarada.
- `registro_comparacion_v1`: líneas del ejecutor v1 y de `referencia_observada.jsonl` (sin UUID). Su UUID es
  DETERMINISTA (uuid5 de la línea canónica): importar la misma línea dos veces da el mismo UUID.

Garantías: el archivo solo se interpreta como JSON (nunca pickle/YAML ni código), no se abren rutas ni URLs que
contenga, no se llama a ningún proveedor; lo ya existente no se modifica (mismo UUID y mismo contenido = existente;
mismo UUID y distinto contenido = conflicto rechazado); un caso desconocido requiere confirmación expresa; los datos
privados o sensibles rechazan el registro completo.

Identidad (v2): la idempotencia se basa SOLO en el UUID de la ejecución. Dos ejecuciones con UUID estables distintos
son dos mediciones aunque su respuesta sea idéntica (una repetición puede repetir el texto). Una coincidencia de
respuesta no demuestra que sean la misma ejecución: si uno de los registros tiene identidad DERIVADA (línea v1 sin UUID),
no se puede probar ni descartar que lo sean, así que el registro queda «ambigua»: no se fusiona ni se importa salvo
decisión expresa (y entonces se guarda como ejecución separada).
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import uuid as uuidlib

from django.db import IntegrityError, transaction

from dashboard.models import CasoComparacion, EjecucionComparacion, LoteImportacionComparacion

from . import conjuntos as CJ
from . import normalizacion as N
from .privacidad import IdentificadoresPrivados, categorias_texto, revisar_registro_crudo

FORMATO_DOC = "sentria_comparacion"
VERSION_DOC = 1
MAX_BYTES = 1024 * 1024
MAX_REGISTROS = 2000
NS_REGISTRO_V1 = uuidlib.UUID("6f1d3c52-2b7e-5a51-9c8e-3a7f0e4b9d21")   # espacio de nombres fijo del formato
VERSION_EXPORTADOR = "comparacion_v1"


class ArchivoInvalido(ValueError):
    """El archivo completo se rechaza (motivo sanitizado)."""


# ----------------------------------------------------------------------------------------------------- lectura
def _sin_duplicadas(pares):
    d = {}
    for k, v in pares:
        if k in d:
            raise ArchivoInvalido("clave JSON repetida en un objeto (datos contradictorios)")
        d[k] = v
    return d


def _no_finito(_):
    raise ArchivoInvalido("número JSON no finito (NaN o infinito)")


def _json(texto):
    try:
        return json.loads(texto, object_pairs_hook=_sin_duplicadas, parse_constant=_no_finito)
    except ArchivoInvalido:
        raise
    except (ValueError, RecursionError):
        raise ArchivoInvalido("JSON mal formado") from None


def leer(contenido: bytes) -> tuple[str, list[dict], list[dict]]:
    """-> (formato, casos_crudos, registros_crudos). Solo interpreta JSON. El bloque «conjunto» opcional de un
    documento se obtiene con `leer_conjunto`."""
    return _leer(contenido)[:3]


def leer_conjunto(contenido: bytes):
    return _leer(contenido)[3]


def _leer(contenido: bytes):
    if len(contenido) > MAX_BYTES:
        raise ArchivoInvalido(f"archivo mayor de {MAX_BYTES // 1024} KiB")
    try:
        texto = contenido.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ArchivoInvalido("el archivo no es UTF-8") from None
    if "\x00" in texto:
        raise ArchivoInvalido("el archivo contiene bytes nulos")
    t = texto.strip()
    if not t:
        raise ArchivoInvalido("archivo vacío")
    if t.startswith("{") and "\n{" not in t:
        doc = _json(t)
        if isinstance(doc, dict) and "formato" in doc:
            if doc.get("formato") != FORMATO_DOC or doc.get("version") != VERSION_DOC:
                raise ArchivoInvalido("formato o versión de documento no admitidos")
            casos, ejs = doc.get("casos"), doc.get("ejecuciones")
            if not isinstance(casos, list) or not isinstance(ejs, list):
                raise ArchivoInvalido("el documento debe tener las listas «casos» y «ejecuciones»")
            if len(ejs) > MAX_REGISTROS or len(casos) > MAX_REGISTROS:
                raise ArchivoInvalido(f"más de {MAX_REGISTROS} registros")
            return FORMATO_DOC, casos, ejs, doc.get("conjunto")
    lineas = [x for x in t.splitlines() if x.strip()]
    if len(lineas) > MAX_REGISTROS:
        raise ArchivoInvalido(f"más de {MAX_REGISTROS} registros")
    regs = [_json(x) for x in lineas]
    versiones = {r.get("registro_version") if isinstance(r, dict) else None for r in regs}
    if versiones == {"registro_comparacion_v2"}:
        return "registro_comparacion_v2", [], regs, None
    if versiones == {"registro_comparacion_v1"}:
        return "registro_comparacion_v1", [], regs, None
    raise ArchivoInvalido("formato no reconocido: se admite el documento exportado por SENTRIA o el registro "
                          "JSONL del ejecutor (v1 o v2), sin mezclar versiones")


# ----------------------------------------------------------------------------------------------- traducción
def _categoria_v1(motivo):
    if not isinstance(motivo, str) or not motivo:
        return None
    pref = motivo.split(":", 1)[0].strip().lower().replace(" ", "_")
    return pref if re.match(r"^[a-z][a-z0-9_]{0,59}$", pref) else "no_clasificada"


def _desde_registro(r: dict, version: str) -> tuple[dict, dict]:
    """Línea del ejecutor -> (caso, ejecución) con nombres internos (sin validar aún)."""
    caso = {"codigo": r.get("caso"), "formato_entrada": r.get("formato_entrada"),
            "entrada_sha256": r.get("entrada_sha256"), "esquema_sha256": r.get("esquema_sha256_canonico"),
            "contexto_sha256": r.get("capa_e_sha256"),
            "procedencia": r.get("procedencia") if r.get("procedencia") in N.PROCEDENCIAS else None}
    llamada = {"fallida": "error"}.get(r.get("estado_llamada"), r.get("estado_llamada"))
    fecha = r.get("fecha_utc")
    obs = r.get("observaciones") or ""
    if isinstance(fecha, str) and re.match(r"^\d{4}-\d{2}-\d{2}$", fecha):      # v1: solo la fecha, sin hora
        obs = (f"[fecha declarada {fecha}; hora no registrada] " + obs).strip()
        fecha = None
    params = r.get("configuracion") if isinstance(r.get("configuracion"), dict) else None
    ej = {
        "repeticion": r.get("repeticion"), "proveedor": r.get("proveedor"),
        "modelo_solicitado": r.get("modelo_solicitado"), "modelo_informado": r.get("modelo_informado"),
        "parametros": params, "codigo_base_sha256": r.get("manifiesto_codigo_sha256"),
        "codigo_ejecucion_sha256": r.get("codigo_ejecucion_sha256"), "adaptador_sha256": r.get("adaptador_sha256"),
        "esquema_efectivo_sha256": r.get("esquema_efectivo_sha256"),
        "texto_enviado_sha256": r.get("texto_enviado_sha256"),
        "equivalencia": r.get("equivalencia") or "no_verificada", "inicio_utc": fecha,
        "definicion_tiempo": r.get("definicion_tiempo") or (
            "ejecutor v1: monotonic alrededor de analizar()" if version.endswith("v1") else None),
        "latencia_proveedor_s": r.get("tiempo_proveedor_s"), "duracion_analisis_s": None,
        "duracion_ejecucion_s": r.get("tiempo_total_s"),
        "tokens_entrada": r.get("tokens_entrada"), "tokens_salida": r.get("tokens_salida"),
        "tokens_razonamiento": r.get("tokens_razonamiento"), "tokens_total": r.get("tokens_total"),
        "tokens_fuente": (r.get("tokens_fuente") or "").split(" ", 1)[0] or None,
        "estado_llamada": llamada, "estado_analisis": r.get("estado_analisis"),
        "categoria_error": r.get("categoria_error") or _categoria_v1(r.get("motivo_fallo")),
        "motivo_sin_llamada": "entrada_no_representable" if llamada == "sin_llamada" else None,
        "finish_reason": r.get("finish_reason"), "codigo_http": r.get("codigo_http"),
        "veredicto": r.get("veredicto"), "riesgo": r.get("riesgo"),
        "respuesta_sha256": r.get("respuesta_sha256"), "respuesta_observada": r.get("respuesta_observada"),
        "observaciones": obs,
    }
    if version == "registro_comparacion_v1":
        ej["uuid"] = str(uuidlib.uuid5(NS_REGISTRO_V1, hashlib.sha256(N.canonico(r)).hexdigest()))
        decl = r.get("observaciones") if isinstance(r.get("observaciones"), str) else ""
        ej["origen"] = "referencia" if decl.lower().startswith("referencia observada") else "importada"
    else:
        ej["uuid"] = r.get("uuid")
        ej["origen"] = "importada"
    return caso, ej


# ----------------------------------------------------------------------------------------- vista previa
def analizar(contenido: bytes, *, privados: IdentificadoresPrivados | None = None, ahora=None) -> dict:
    """Clasifica cada registro SIN escribir nada. -> dict serializable (se muestra y se guarda en el resumen)."""
    formato, casos_crudos, regs, bloque_cj = _leer(contenido)
    privados = privados if privados is not None else IdentificadoresPrivados.de_la_instancia()
    casos_doc = {}
    for c in casos_crudos:
        if not isinstance(c, dict):
            raise ArchivoInvalido("cada caso debe ser un objeto")
        hall = revisar_registro_crudo(c, privados)
        if hall:
            raise ArchivoInvalido("un caso contiene datos no admitidos: " + ", ".join(sorted(hall)))
        try:
            cn = N.caso(c)
        except N.DatoInvalido as e:
            raise ArchivoInvalido(f"caso no válido: {e}") from None
        casos_doc[cn["clave"]] = cn
    conjunto = None
    if bloque_cj is not None:
        hall = revisar_registro_crudo(bloque_cj, privados)
        if hall:
            raise ArchivoInvalido("el conjunto contiene datos no admitidos: " + ", ".join(sorted(hall)))
        try:
            conjunto = CJ.validar_bloque(bloque_cj, casos_doc)
        except CJ.ConjuntoInvalido as e:
            raise ArchivoInvalido(str(e)) from None
    filas, uuids_vistos, obs_en_archivo = [], set(), {}
    for i, r in enumerate(regs, 1):
        fila = {"n": i, "resultado": None, "motivo": None, "uuid": None, "caso_clave": None, "codigo": None}
        filas.append(fila)
        if not isinstance(r, dict):
            fila.update(resultado="rechazada", motivo="el registro no es un objeto")
            continue
        hall = revisar_registro_crudo(r, privados)
        if hall:
            fila.update(resultado="rechazada", motivo="datos no admitidos: " + ", ".join(sorted(hall)))
            continue
        try:
            if formato == FORMATO_DOC:
                caso_d = casos_doc.get(r.get("caso_clave"))
                if caso_d is None:
                    raise N.DatoInvalido("caso_clave: no está en la lista de casos del documento")
                ej_crudo = {k: v for k, v in r.items() if k not in ("origen_medicion", "participante",
                                                                     "huella_contenido", "texto_omitido",
                                                                     "identidad_derivada")}
                derivada = r.get("identidad_derivada", False)
                if type(derivada) is not bool:
                    raise N.DatoInvalido("identidad_derivada: debe ser booleano")
                origen_decl = r.get("origen_medicion")
                if origen_decl not in N.ORIGENES:
                    raise N.DatoInvalido("origen_medicion: valor no admitido")
                ej = N.ejecucion(ej_crudo, ahora=ahora)
                if N.huella_contenido(ej) != r.get("huella_contenido"):
                    raise N.DatoInvalido("huella_contenido: no coincide con los datos (archivo alterado)")
                origen = "referencia" if origen_decl == "referencia" else "importada"
                part = N.participante(r.get("participante"))
            else:
                caso_c, ej_c = _desde_registro(r, formato)
                caso_d = N.caso(caso_c)
                if r.get("conjunto") is not None:
                    motivo_cj = CJ.referencia_valida(r.get("conjunto"), caso_d["clave"])
                    if motivo_cj:
                        raise N.DatoInvalido(motivo_cj)
                origen = ej_c.pop("origen")
                origen_decl = formato
                derivada = formato == "registro_comparacion_v1"
                ej = N.ejecucion({**ej_c, "caso_clave": caso_d["clave"]}, ahora=ahora)
                part = ""
        except N.DatoInvalido as e:
            fila.update(resultado="rechazada", motivo=str(e))
            continue
        try:
            N.cabe_en_modelo(caso_d, CasoComparacion)
            N.cabe_en_modelo(ej, EjecucionComparacion)
        except N.DatoInvalido as e:
            fila.update(resultado="rechazada", motivo=str(e))
            continue
        fila.update(uuid=ej["uuid"], caso_clave=caso_d["clave"], codigo=caso_d["codigo"])
        if ej["uuid"] in uuids_vistos:
            fila.update(resultado="rechazada", motivo="UUID repetido dentro del archivo")
            continue
        uuids_vistos.add(ej["uuid"])
        contenido_h = N.huella_contenido(ej)
        existente = EjecucionComparacion.objects.filter(uuid=ej["uuid"]).only("huella_contenido").first()
        if existente is not None:
            if existente.huella_contenido == contenido_h:
                fila.update(resultado="existente", motivo="mismo UUID y mismo contenido: no se duplica")
            else:
                fila.update(resultado="conflicto", motivo="mismo UUID con datos distintos: se rechaza sin "
                                                          "sobrescribir")
            continue
        obs = N.huella_observacion(caso_d["clave"], ej["proveedor"], ej["respuesta_sha256"], ej["uuid"])
        avisos, ambigua = [], False
        if ej["respuesta_sha256"]:
            previas = list(EjecucionComparacion.objects.filter(huella_observacion=obs)
                           .values_list("identidad_derivada", flat=True)) + obs_en_archivo.get(obs, [])
            if previas and (derivada or any(previas)):
                ambigua = True
                avisos.append("misma respuesta que otra ejecución y sin identidad compartida demostrable (formato "
                              "v1): no se fusiona ni se importa salvo decisión expresa")
            elif previas:
                avisos.append("misma respuesta que otra ejecución con UUID distinto: se conserva como repetición")
        caso_existe = CasoComparacion.objects.filter(clave=caso_d["clave"]).exists()
        if not caso_existe and CasoComparacion.objects.filter(codigo=caso_d["codigo"]).exists():
            avisos.append("hay un caso con el mismo nombre y otras huellas: se tratará como caso distinto")
        obs_en_archivo.setdefault(obs, []).append(derivada)
        fila.update(resultado="ambigua" if ambigua else ("nueva" if caso_existe else "caso_nuevo"),
                    motivo="; ".join(avisos) or None, _caso=caso_d, _ej=ej, _origen=origen,
                    _origen_decl=origen_decl, _participante=part, _obs=obs, _contenido=contenido_h,
                    _derivada=derivada, _caso_existe=caso_existe)
    recuento = {}
    for f in filas:
        recuento[f["resultado"]] = recuento.get(f["resultado"], 0) + 1
    return {"formato": formato, "total": len(filas), "recuento": recuento, "filas": filas, "_conjunto": conjunto,
            "_casos_doc": casos_doc,
            "conjunto": None if conjunto is None else {k: conjunto[k] for k in ("codigo", "version", "estado",
                                                                                "manifiesto_sha256")}
            | {"n_casos": len(conjunto["claves"])}}


def resumen_publico(analisis: dict) -> dict:
    """Vista previa sin los datos internos (para plantilla, sesión y lote)."""
    return {"formato": analisis["formato"], "total": analisis["total"], "recuento": analisis["recuento"],
            "conjunto": analisis.get("conjunto"),
            "filas": [{k: v for k, v in f.items() if not k.startswith("_")} for f in analisis["filas"]]}


def confirmar(contenido: bytes, *, nombre: str, usuario, participante: str = "",
              registrar_casos_nuevos: bool = False, importar_ambiguas: bool = False,
              ahora=None) -> LoteImportacionComparacion:
    """Vuelve a analizar el MISMO contenido y escribe solo lo nuevo, en UNA transacción. Idempotente.
    El lote (append-only) se inserta ya con su resumen final; si otra importación escribe a la vez el mismo UUID,
    se deshace todo y se reanaliza una vez (lo ajeno pasa a «existente»), sin duplicar ni sobrescribir."""
    participante = N.participante(participante)
    for intento in range(2):
        analisis = analizar(contenido, ahora=ahora)
        crear, casos_nuevos_ok = [], set()
        for f in analisis["filas"]:
            if f["resultado"] not in ("nueva", "caso_nuevo", "ambigua"):
                continue
            if f["resultado"] == "ambigua" and not importar_ambiguas:
                f.update(resultado="omitida", motivo="ambigua: no se importó (sin decisión expresa)")
            elif not f["_caso_existe"] and f["_caso"]["clave"] not in casos_nuevos_ok and not registrar_casos_nuevos:
                f.update(resultado="omitida", motivo="caso nuevo no confirmado")
            else:
                f["resultado"] = "importada" if f["resultado"] != "ambigua" else "importada_como_separada"
                casos_nuevos_ok.add(f["_caso"]["clave"])
                crear.append(f)
        pub = resumen_publico(analisis)
        pub["recuento"] = {}
        for f in pub["filas"]:
            pub["recuento"][f["resultado"]] = pub["recuento"].get(f["resultado"], 0) + 1
        pub["filas"] = pub["filas"][:500]
        pub["creadas"] = len(crear)
        pub["decisiones"] = {"registrar_casos_nuevos": registrar_casos_nuevos, "importar_ambiguas": importar_ambiguas}
        cj = analisis.get("_conjunto")
        prevision = None
        if cj:
            from dashboard.models import ConjuntoComparacion
            faltan = [c for c in cj["claves"] if not CasoComparacion.objects.filter(clave=c).exists()]
            if ConjuntoComparacion.objects.filter(manifiesto_sha256=cj["manifiesto_sha256"]).exists():
                prevision, motivo = "existente", None
            elif faltan and not registrar_casos_nuevos:
                prevision, motivo = "omitido", "el conjunto tiene casos nuevos y no se confirmó registrarlos"
            else:
                prevision, motivo = "creado", None
            pub["conjunto"] = dict(pub.get("conjunto") or {}, resultado=prevision, motivo=motivo)
        try:
            with transaction.atomic():
                lote = LoteImportacionComparacion.objects.create(
                    uuid=uuidlib.uuid4(), archivo_sha256=hashlib.sha256(contenido).hexdigest(),
                    archivo_nombre=_nombre_seguro(nombre), archivo_bytes=len(contenido),
                    formato=analisis["formato"], participante=participante, resumen=pub, importado_por=usuario)
                for f in crear:
                    caso_d = f["_caso"]
                    caso, _ = CasoComparacion.objects.get_or_create(
                        clave=caso_d["clave"], defaults={**caso_d, "origen_registro": "importado"})
                    ej = dict(f["_ej"])
                    ej.pop("caso_clave")
                    EjecucionComparacion.objects.create(
                        caso=caso, origen_medicion=f["_origen"], origen_declarado=f["_origen_decl"],
                        participante=f["_participante"] or participante, huella_observacion=f["_obs"],
                        huella_contenido=f["_contenido"], identidad_derivada=f["_derivada"], lote=lote,
                        registrado_por=usuario, **ej)
                if cj and prevision == "creado":
                    for clave in cj["claves"]:              # casos del conjunto aún sin ejecuciones en el archivo
                        if not CasoComparacion.objects.filter(clave=clave).exists():
                            CasoComparacion.objects.create(**analisis["_casos_doc"][clave], origen_registro="importado")
                    estado, _ = CJ.crear(cj)
                    if estado != "creado":
                        raise IntegrityError("el conjunto no se pudo crear como se previó")
            return lote
        except IntegrityError:
            if intento:
                raise


def _nombre_seguro(nombre):
    base = re.split(r"[\\/]", str(nombre or ""))[-1]
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base)[:120]
    return base or "archivo"


# ---------------------------------------------------------------------------------------------- exportación
def exportar(ejecuciones, *, filtros: dict, privados: IdentificadoresPrivados | None = None, conjunto=None) -> dict:
    """Documento `sentria_comparacion` v1. Sin ids de BD, usuarios, lote ni vínculo con alertas locales. Con
    `conjunto`, añade el bloque del conjunto congelado y TODOS sus casos (también los que aún no tienen ejecuciones)."""
    privados = privados if privados is not None else IdentificadoresPrivados.de_la_instancia()
    casos, salida = {}, []
    bloque = None
    if conjunto is not None:
        bloque, casos_cj = CJ.bloque_exportable(conjunto)
        for c in casos_cj:
            casos[c["clave"]] = {"clave": c["clave"], "codigo": c["codigo"], "formato_entrada": c["formato_entrada"],
                                 "entrada_sha256": c["entrada_sha256"], "esquema_sha256": c["esquema_sha256"],
                                 "contexto_sha256": c["contexto_sha256"], "extension_web": None,
                                 "procedencia": c["procedencia"], "descripcion": ""}
    for e in ejecuciones.select_related("caso"):
        c = e.caso
        if c.clave in casos and bloque is not None:
            pass                                    # descripción congelada del conjunto (no la editable)
        else:
            casos[c.clave] = {"clave": c.clave, "codigo": c.codigo, "formato_entrada": c.formato_entrada,
                              "entrada_sha256": c.entrada_sha256, "esquema_sha256": c.esquema_sha256,
                              "contexto_sha256": c.contexto_sha256, "extension_web": c.extension_web,
                              "procedencia": c.procedencia, "descripcion": c.descripcion}
        d = {k: getattr(e, k) for k in N.CAMPOS_CONTENIDO if k not in ("caso_clave",)}
        d["uuid"] = str(e.uuid)
        d["caso_clave"] = c.clave
        d["inicio_utc"] = N.fecha_iso(e.inicio_utc)
        d["parametros"] = e.parametros
        d["respuesta_observada"] = e.respuesta_observada
        d["observaciones"] = e.observaciones
        omitido = []
        for campo in ("respuesta_observada", "observaciones"):
            v = d[campo]
            if v and (categorias_texto(v) or privados.categorias(v, texto_libre_corto=campo == "observaciones")):
                d[campo] = None if campo == "respuesta_observada" else ""
                omitido.append(campo)
        d["texto_omitido"] = omitido or None
        d["origen_medicion"] = e.origen_medicion
        d["identidad_derivada"] = e.identidad_derivada
        d["participante"] = e.participante
        d["huella_contenido"] = e.huella_contenido
        salida.append(d)
    cuerpo = {"casos": sorted(casos.values(), key=lambda x: x["clave"]),
              "ejecuciones": sorted(salida, key=lambda x: x["uuid"])}
    return {"formato": FORMATO_DOC, "version": VERSION_DOC, "exportador": VERSION_EXPORTADOR,
            "generado_utc": N.fecha_iso(dt.datetime.now(dt.timezone.utc)),
            "filtros": filtros, "aviso": "Uso del equipo. Las huellas comprueban integridad, no autentican al "
                                         "proveedor. Sin llamadas a la IA.",
            **cuerpo, **({"conjunto": bloque} if bloque else {}),
            "huella_documento": hashlib.sha256(N.canonico(cuerpo)).hexdigest()}
