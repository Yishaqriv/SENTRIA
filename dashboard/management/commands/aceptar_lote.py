"""
Revisión consolidada por lote (modo REVISOR_UNICO_LOTE; ver dashboard/lotes.py).

1) Preparar la propuesta de manifiesto (SOLO LECTURA; en MySQL, sesión READ ONLY):
     manage.py aceptar_lote --preparar --ejemplos casos.json --manifiesto-salida manifiesto.json
   `casos.json`: lista de ejemplo_id (o {"ejemplos": [...]}). La selección es del lote, no del código.
   Informa caso por caso de lo que impide aceptarlo (p. ej. falta la confirmación sellada).

2) Validar la aceptación (dry-run por defecto, sin escrituras):
     manage.py aceptar_lote --manifiesto manifiesto.json --lista lista.json --referencia "..." --autor miguel
   Escritura (todo o nada), solo con SENTRIA_ACEPTAR_LOTE_AUTORIZADO=1 y --escribir, y con el modo activo.
Los archivos de salida y los logs son nuevos y nunca se sobrescriben.
"""
import datetime
import json
import os

from django.contrib.auth.models import User
from django.core.management.base import BaseCommand, CommandError
from django.db import connection

from dashboard import lotes


def _leer(ruta):
    with open(ruta, encoding="utf-8") as fh:
        return json.load(fh)


def _escribir(ruta, datos):
    if os.path.exists(ruta):
        raise CommandError(f"{ruta} ya existe: no se sobrescribe")
    with open(ruta, "x", encoding="utf-8") as fh:
        json.dump(datos, fh, ensure_ascii=False, indent=1)
    os.chmod(ruta, 0o600)


class Command(BaseCommand):
    help = "Prepara, valida o acepta un lote en modo REVISOR_UNICO_LOTE (dry-run por defecto)."

    def add_arguments(self, parser):
        parser.add_argument("--preparar", action="store_true")
        parser.add_argument("--ejemplos", default="")
        parser.add_argument("--manifiesto-salida", dest="manifiesto_salida", default="")
        parser.add_argument("--manifiesto", default="")
        parser.add_argument("--lista", default="")
        parser.add_argument("--referencia", default="")
        parser.add_argument("--autor", default="")
        parser.add_argument("--escribir", action="store_true")
        parser.add_argument("--log", default="")

    def handle(self, *args, **o):
        if not o["escribir"] and connection.vendor == "mysql":
            with connection.cursor() as cur:
                cur.execute("SET SESSION TRANSACTION READ ONLY")
        if o["preparar"]:
            if not (o["ejemplos"] and o["manifiesto_salida"]):
                raise CommandError("--preparar exige --ejemplos y --manifiesto-salida")
            datos = _leer(o["ejemplos"])
            ids = datos["ejemplos"] if isinstance(datos, dict) else datos
            m = lotes.preparar_manifiesto(ids)
            m["generado_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
            m["modo_vigente"] = "REVISOR_UNICO_LOTE" if lotes.modo_activo() else "DOBLE"
            _escribir(o["manifiesto_salida"], m)
            motivos = {}
            for errs in m["problemas"].values():
                for e in errs:
                    motivos[e] = motivos.get(e, 0) + 1
            self.stdout.write(f"preparar: {m['n_casos']} casos | válido={m['valido']} | con problemas={len(m['problemas'])} | "
                              f"motivos={motivos} | modo vigente={m['modo_vigente']}")
            return
        if not (o["manifiesto"] and o["lista"] and o["autor"]):
            raise CommandError("hace falta --manifiesto, --lista y --autor (o --preparar)")
        autor = User.objects.filter(username=o["autor"]).first()
        if autor is None:
            raise CommandError("el responsable no existe")
        manifiesto, lista = _leer(o["manifiesto"]), _leer(o["lista"])
        if o["escribir"]:
            if os.environ.get("SENTRIA_ACEPTAR_LOTE_AUTORIZADO") != "1":
                raise CommandError("--escribir exige SENTRIA_ACEPTAR_LOTE_AUTORIZADO=1")
            lote, errores = lotes.aceptar_lote(manifiesto, autor, lista, o["referencia"])
            resultado = {"modo": "escritura", "aceptado": lote is not None, "errores": errores,
                         "lote": lote.manifiesto_sha256 if lote else None, "n_casos": lote.n_casos if lote else 0}
        else:
            generales, por_caso = lotes.validar_aceptacion(manifiesto, autor, lista, o["referencia"])
            resultado = {"modo": "dry-run", "aceptable": not generales and not por_caso,
                         "errores_generales": generales, "errores_por_caso": por_caso}
        if o["log"]:
            _escribir(o["log"], resultado)
        self.stdout.write(json.dumps(resultado, ensure_ascii=False)[:2000])
