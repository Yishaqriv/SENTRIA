"""
Conjuntos comunes congelados de casos (p. ej. un piloto comparativo). Se crean SOLO al importar un documento que
trae el bloque «conjunto» (el mismo formato de intercambio del apartado), nunca al abrir una página.

Manifiesto (huella SHA-256 del JSON canónico): código, versión, descripción, reglas y la lista EXACTA de casos con su
huella (clave = formato|entrada|esquema), entrada, esquema, contexto, procedencia y código visible. La pertenencia se
resuelve por la clave del caso, nunca por el nombre visible. Mismo código y versión con otro manifiesto = conflicto.
"""
from __future__ import annotations

import hashlib
import re

from django.db import transaction

from dashboard.models import CasoComparacion, ConjuntoCaso, ConjuntoComparacion

from . import normalizacion as N

_CODIGO = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,39}$")
CAMPOS_CASO = ("clave", "codigo", "entrada_sha256", "esquema_sha256", "formato_entrada", "contexto_sha256",
               "procedencia")

REGLA_AGREGACION = ("Cada caso pesa igual: primero se promedian (media) las mediciones disponibles de las "
                    "repeticiones de cada caso, después se calculan la media y la mediana entre casos. Las ejecuciones "
                    "sin medición no cuentan como cero: se informan como faltantes. Los tokens se resumen como total "
                    "observado y promedio por ejecución medida; el razonamiento no se suma a salida ni a total. Solo se "
                    "comparan series con condiciones verificadas (equivalente) sobre los casos que todas cubren.")


class ConjuntoInvalido(ValueError):
    pass


def caso_para_manifiesto(c) -> dict:
    get = (lambda k: c.get(k)) if isinstance(c, dict) else (lambda k: getattr(c, k))
    return {k: get(k) for k in CAMPOS_CASO}


def huella_manifiesto(codigo, version, descripcion, reglas, casos) -> str:
    cuerpo = {"codigo": codigo, "version": version, "descripcion": descripcion, "reglas": reglas,
              "casos": sorted((caso_para_manifiesto(c) for c in casos), key=lambda x: x["clave"])}
    return hashlib.sha256(N.canonico(cuerpo)).hexdigest()


def _reglas_seguras(r):
    if not isinstance(r, dict) or len(r) > 20:
        raise ConjuntoInvalido("reglas: objeto de hasta 20 claves")
    for k, v in r.items():
        if not isinstance(k, str) or not re.match(r"^[a-z][a-z0-9_]{0,59}$", k):
            raise ConjuntoInvalido("reglas: nombre de clave no admitido")
        vals = v if isinstance(v, list) else [v]
        if len(vals) > 30 or any(not (x is None or type(x) in (str, int, float, bool)) for x in vals):
            raise ConjuntoInvalido("reglas: solo valores simples o listas cortas")
        if any(isinstance(x, str) and (len(x) > 800 or re.search(r"[\x00-\x08\x0b-\x1f]", x)) for x in vals):
            raise ConjuntoInvalido("reglas: texto demasiado largo o con controles")
    return r


def validar_bloque(bloque, casos_doc: dict) -> dict:
    """Bloque «conjunto» de un documento -> dict normalizado. `casos_doc`: clave -> caso normalizado del documento."""
    if not isinstance(bloque, dict):
        raise ConjuntoInvalido("conjunto: debe ser un objeto")
    codigo, version = bloque.get("codigo"), bloque.get("version")
    if not isinstance(codigo, str) or not _CODIGO.match(codigo):
        raise ConjuntoInvalido("conjunto: código no admitido")
    if type(version) is not int or not 1 <= version <= 1000:
        raise ConjuntoInvalido("conjunto: versión entera de 1 a 1000")
    desc = bloque.get("descripcion") or ""
    if not isinstance(desc, str) or len(desc) > 300:
        raise ConjuntoInvalido("conjunto: descripción de hasta 300 caracteres")
    reglas = _reglas_seguras(bloque.get("reglas") or {})
    claves = bloque.get("casos")
    if not isinstance(claves, list) or not claves or len(claves) > 500 or len(set(claves)) != len(claves):
        raise ConjuntoInvalido("conjunto: lista de casos vacía, demasiado larga o repetida")
    faltan = [c for c in claves if c not in casos_doc]
    if faltan:
        raise ConjuntoInvalido("conjunto: hay casos sin su descripción en el documento")
    casos = [casos_doc[c] for c in claves]
    sha = huella_manifiesto(codigo, version, desc, reglas, casos)
    if bloque.get("manifiesto_sha256") != sha:
        raise ConjuntoInvalido("conjunto: la huella del manifiesto no coincide (archivo alterado)")
    previo = ConjuntoComparacion.objects.filter(codigo=codigo, version=version).first()
    if previo is not None and previo.manifiesto_sha256 != sha:
        raise ConjuntoInvalido("conjunto en conflicto: ya existe esa versión con otro manifiesto (no se modifica; "
                               "una ampliación debe ser otra versión)")
    return {"codigo": codigo, "version": version, "descripcion": desc, "reglas": reglas, "claves": claves,
            "casos_manifiesto": [caso_para_manifiesto(c) for c in casos],
            "manifiesto_sha256": sha, "estado": "existente" if previo else "nuevo"}


def crear(bloque: dict):
    """Crea el conjunto (dentro de la transacción de la importación) si todos sus casos existen. -> (estado, motivo)."""
    if ConjuntoComparacion.objects.filter(manifiesto_sha256=bloque["manifiesto_sha256"]).exists():
        return "existente", None
    casos = {c.clave: c for c in CasoComparacion.objects.filter(clave__in=bloque["claves"])}
    if len(casos) != len(bloque["claves"]):
        return "omitido", "faltan casos del conjunto en esta instancia (confirma también los casos nuevos)"
    with transaction.atomic():
        cj = ConjuntoComparacion.objects.create(
            codigo=bloque["codigo"], version=bloque["version"], descripcion=bloque["descripcion"],
            reglas=bloque["reglas"], casos_manifiesto=bloque["casos_manifiesto"],
            manifiesto_sha256=bloque["manifiesto_sha256"])
        for i, clave in enumerate(bloque["claves"], 1):
            ConjuntoCaso.objects.create(conjunto=cj, caso=casos[clave], orden=i)
    return "creado", None


def referencia_valida(ref, clave_caso) -> str | None:
    """Referencia {codigo, version, manifiesto_sha256} de una línea del ejecutor -> motivo de rechazo o None."""
    if not isinstance(ref, dict):
        return "conjunto: debe ser un objeto"
    cj = ConjuntoComparacion.objects.filter(codigo=ref.get("codigo"), version=ref.get("version")).first()
    if cj is None:
        return "conjunto desconocido en esta instancia: importa primero el documento del conjunto"
    if cj.manifiesto_sha256 != ref.get("manifiesto_sha256"):
        return "conjunto: la huella del manifiesto no coincide con la registrada"
    if not cj.miembros.filter(caso__clave=clave_caso).exists():
        return "el caso no pertenece al conjunto declarado"
    return None


def bloque_exportable(cj) -> tuple[dict, list]:
    """-> (bloque «conjunto», descripciones CONGELADAS de sus casos en orden). Se exporta lo congelado, no el estado
    actual editable de cada caso, para que la huella del manifiesto se pueda verificar al importar."""
    casos = list(cj.casos_manifiesto)
    return ({"codigo": cj.codigo, "version": cj.version, "descripcion": cj.descripcion, "reglas": cj.reglas,
             "casos": [c["clave"] for c in casos], "manifiesto_sha256": cj.manifiesto_sha256}, casos)


def identificador(cj) -> str:
    return cj.manifiesto_sha256[:16]
