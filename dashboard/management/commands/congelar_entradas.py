"""
Congela por REGLA (nunca por ID) las entradas de los candidatos históricos.

Por defecto es un DRY-RUN: en MySQL abre la sesión en modo READ ONLY y no
escribe nada. Si la migración de los sellos todavía no está aplicada, simula
que no hay registros previos y lo indica.

    manage.py congelar_entradas                       # dry-run
    manage.py congelar_entradas --log /ruta/log.json  # dry-run con log nuevo (no sobrescribe)
    SENTRIA_CONGELAR_AUTORIZADO=1 manage.py congelar_entradas --escribir --autor <usuario>

Clasificación (`dashboard.sellos.clasificar_historico`):
- HUELLA_LEGADO_VERIFICADA: la huella guardada es del algoritmo anterior a
  `semantica_v1` y coincide con el snapshot. No prueba el contenido exacto al aprobar.
- SNAPSHOT_CONSERVADO: candidato no aprobado con borrador cuya huella semántica
  registrada coincide. No prueba que sea exactamente la entrada revisada.
- NO_VERIFICABLE: no coincide ninguna huella (bloquea la exportación).
- SIN_BORRADOR: no se congela; se congelará al guardar su primer borrador.
Nunca modifica candidatos, snapshots, salidas ni revisiones: solo inserta sellos.
`--autor` (ADMIN activo) queda como `creada_por`: es quien ejecuta la congelación,
no quien revisó o aprobó originalmente. Un histórico nunca se registra como ENTRADA_REVISADA.
"""
import datetime
import json
import os
from collections import Counter

from django.core.management.base import BaseCommand, CommandError
from django.db import connection, transaction

from dashboard import dataset as ds
from dashboard import sellos
from dashboard.models import CandidatoDataset, EntradaRevisada


class Command(BaseCommand):
    help = "Congela por regla las entradas de los candidatos históricos (dry-run por defecto)."

    def add_arguments(self, parser):
        parser.add_argument("--escribir", action="store_true",
                            help="inserta los sellos (exige SENTRIA_CONGELAR_AUTORIZADO=1 y --autor)")
        parser.add_argument("--autor", default="")
        parser.add_argument("--log", default="", help="ruta de un log JSON nuevo (nunca se sobrescribe)")

    def handle(self, *args, **o):
        escribir = o["escribir"]
        if escribir and os.environ.get("SENTRIA_CONGELAR_AUTORIZADO") != "1":
            raise CommandError("--escribir exige SENTRIA_CONGELAR_AUTORIZADO=1")
        if escribir and not o["autor"]:
            raise CommandError("--escribir exige --autor")
        if escribir:
            from django.contrib.auth.models import User
            from usuarios.decorators import usuario_tiene_rol
            operador = User.objects.filter(username=o["autor"]).first()
            if operador is None or not operador.is_active or not usuario_tiene_rol(operador, ["ADMIN"]):
                raise CommandError("--autor debe ser un usuario activo con rol ADMIN")
        if o["log"] and os.path.exists(o["log"]):
            raise CommandError("el log ya existe: no se sobrescribe")
        if not escribir and connection.vendor == "mysql":
            with connection.cursor() as cur:
                cur.execute("SET SESSION TRANSACTION READ ONLY")
        tabla = EntradaRevisada._meta.db_table in connection.introspection.table_names()
        if escribir and not tabla:
            raise CommandError("la migración de los sellos no está aplicada")

        resultados, cuenta = [], Counter()
        candidatos = (CandidatoDataset.objects.exclude(estado="EXCLUIDO")
                      .select_related("alerta").order_by("alerta_id"))
        for cand in candidatos:
            a = cand.alerta
            entrada, snap = ds.construir_entrada(a), ds._snapshot(a)
            fila = {"alerta": a.pk, "estado": cand.estado, "schema_version": snap.get("schema_version")}
            previa = sellos.ultima_entrada(cand) if tabla else None
            if previa is not None:
                errores = sellos.verificar_entrada(cand, entrada, snap)
                fila.update({"resultado": "DISCREPANCIA" if errores else "YA_CONGELADA",
                             "origen": previa.origen, "version": previa.version})
            elif cand.estado != "APROBADO" and not cand.salida_objetivo_editada:
                fila.update({"resultado": "SIN_BORRADOR", "origen": None})
            else:
                c = sellos.clasificar_historico(
                    cand, entrada, snap,
                    fingerprint_semantico=ds.fingerprint_entrada(entrada) if entrada else "",
                    version_semantica=ds.FINGERPRINT_VERSION)
                fila.update({"resultado": "A_CONGELAR" if c["origen"] != "NO_VERIFICABLE" else "NO_VERIFICABLE",
                             "origen": c["origen"], "detalle": c["detalle"]})
                if escribir and c["origen"] != "NO_VERIFICABLE":
                    with transaction.atomic():
                        CandidatoDataset.objects.select_for_update().get(pk=cand.pk)   # bloqueo, sin escribir en la fila
                        if sellos.ultima_entrada(cand) is not None:
                            raise CommandError(f"el candidato de la alerta {a.pk} se congeló durante la ejecución")
                        e = c["entrada"]
                        EntradaRevisada.objects.create(
                            candidato=cand, version=1, anterior=None, origen=c["origen"], entrada=e,
                            entrada_sha256=sellos.huella_integridad(e),
                            snapshot_sha256=sellos.huella_integridad(snap),
                            serializacion_version=sellos.SERIALIZACION_VERSION,
                            seleccion_version=c.get("seleccion_version", ds.ENTRADA_SELECCION_VERSION),
                            algoritmo_verificacion=c["algoritmo"], limitaciones=c["limitaciones"],
                            motivo=("Congelación histórica por regla (congelar_entradas). `creada_por` es quien "
                                    "ejecutó esta congelación; no se le atribuye la revisión ni la aprobación originales."),
                            creada_por=o["autor"],
                        )
                    fila["resultado"] = "CONGELADA"
            cuenta[(fila["resultado"], fila.get("origen"))] += 1
            resultados.append(fila)

        resumen = {f"{r}:{og}" if og else r: n for (r, og), n in sorted(cuenta.items(), key=str)}
        salida = {"generado_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                  "modo": "escritura" if escribir else "dry-run",
                  "tabla_sellos_presente": tabla, "candidatos": len(resultados),
                  "resumen": resumen, "detalle": resultados}
        if o["log"]:
            with open(o["log"], "x", encoding="utf-8") as fh:
                json.dump(salida, fh, ensure_ascii=False, indent=1)
            os.chmod(o["log"], 0o600)
        if not tabla:
            self.stdout.write("AVISO: la tabla de sellos no existe (migración no aplicada); se simula sin registros previos.")
        self.stdout.write(f"{salida['modo']}: {len(resultados)} candidatos | {resumen}")
