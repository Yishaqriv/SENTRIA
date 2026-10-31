"""
Revisión consolidada por lote (DECISIONES.md, enmienda 2026-10-07), modo REVISOR_UNICO_LOTE.

Un único revisor humano acepta EXPLÍCITAMENTE un lote de candidatos ya revisados
y confirmados. El modo predeterminado sigue siendo DOBLE: sin activar este modo,
`aceptar_lote` no aprueba nada, y la autoaprobación caso a caso
(`dataset.revisar_candidato`) sigue prohibida en cualquier modo.

Garantías:
- La selección de casos pertenece al MANIFIESTO del lote (nunca a reglas del
  código ni a excepciones por ID). El manifiesto fija, por caso, la confirmación
  sellada vigente y las huellas de entrada y salida; su huella
  (`manifiesto_sha256`, serialización `json_canonico_v1`) queda sellada en la
  aceptación, junto a la lista resumida y la declaración metodológica.
- Aceptar verifica permisos, confirmaciones vigentes y sellos dentro de UNA
  transacción con las filas bloqueadas. Una sola discrepancia impide aprobar
  el lote entero.
- Editar tras confirmar crea una versión nueva de la entrada (sellos.py): la
  confirmación deja de ser la vigente y cualquier manifiesto anterior queda
  inválido; hay que volver a confirmar y preparar un manifiesto nuevo.
- Después de aceptado, no se pueden añadir, sustituir ni modificar casos:
  lote e items son inmutables y los items solo se crean aquí.
"""
from __future__ import annotations

from django.conf import settings
from django.db import connection, transaction

from . import sellos
from .dataset import _snapshot, construir_entrada, salida_objetivo_actual, validar_para_revision
from .models import AceptacionLote, AceptacionLoteItem, CandidatoDataset, RevisionCandidato

MODO = "REVISOR_UNICO_LOTE"

DECLARACION = (
    "Aprobado por revisión consolidada: un único anotador humano (Miguel) con apoyo no vinculante de IA. "
    "No hay acuerdo entre revisores ni medida de acuerdo. No se realizó re-etiquetado ciego. La verdad de "
    "los casos de prueba controlada procede de manifiestos de laboratorio de un único operador; la de los "
    "casos operativos es juicio del revisor sin confirmación externa. Los ejemplos aprobados en este modo "
    "se identifican como tales en el dataset."
)

LISTA_RESUMIDA = (
    ("revisados_en_revision_referenciada",
     "Todos los casos se revisaron en la revisión referenciada, sobre la entrada que vio el modelo, con su decisión registrada."),
    ("etiquetas_sostenidas_por_la_entrada",
     "Etiquetas y riesgos se sostienen con la entrada; ninguna justificación procede de manifiestos ni de conocimiento externo."),
    ("textos_sin_afirmaciones_no_demostradas",
     "Los textos no convierten un fallo o un «no consta» en un hecho; las recomendaciones diagnostican antes de modificar."),
    ("privacidad_validada",
     "La validación automática de privacidad es correcta en todos los casos."),
    ("ia_no_vinculante",
     "El apoyo de IA fue no vinculante y las discrepancias las resolvió el revisor, con registro."),
    ("pendientes_fuera_del_lote",
     "Los casos con decisión pendiente están fuera del lote."),
)
CLAVES_LISTA = tuple(k for k, _ in LISTA_RESUMIDA)


def modo_activo() -> bool:
    return getattr(settings, "SENTRIA_MODO_REVISION", "DOBLE") == MODO


def huella_manifiesto(items) -> str:
    return sellos.huella_integridad(sorted(items, key=lambda x: x["ejemplo_id"]))


def _tabla_items_existe() -> bool:
    return AceptacionLoteItem._meta.db_table in connection.introspection.table_names()


def _comprobar_caso(cand, item=None, *, autor_id=None, tabla_items=True):
    """Errores de un caso para entrar en un lote. Si `item` viene del manifiesto, debe coincidir con lo vigente."""
    errores = []
    if cand.estado != "LISTO_PARA_REVISION":
        errores.append(f"estado {cand.estado}: falta la confirmación sellada (enviar a revisión)")
    conf = sellos.ultima_confirmacion(cand)
    if conf is None:
        errores.append("sin confirmación sellada")
        return errores, None
    entrada, snap, salida = construir_entrada(cand.alerta), _snapshot(cand.alerta), salida_objetivo_actual(cand)
    errores += sellos.verificar_para_aprobar(cand, entrada, snap, salida)
    ok, err_rev = validar_para_revision(cand, salida)
    if not ok:
        errores += err_rev
    if autor_id is not None and cand.completado_por_id != autor_id:
        errores.append("lo confirmó otra persona: el responsable del lote debe ser quien confirmó")
    if tabla_items and AceptacionLoteItem.objects.filter(candidato=cand).exists():
        errores.append("ya pertenece a un lote aceptado")
    vigente = {"ejemplo_id": cand.ejemplo_id, "confirmacion_id": conf.pk, "entrada_revisada_id": conf.entrada_revisada_id,
               "entrada_sha256": conf.entrada_revisada.entrada_sha256, "salida_sha256": conf.salida_sha256}
    if item is not None and any(item.get(k) != v for k, v in vigente.items()):
        errores.append("el manifiesto no coincide con la confirmación vigente (se editó o se reconfirmó después): "
                       "hay que preparar un manifiesto nuevo")
    return errores, vigente


def preparar_manifiesto(ejemplo_ids):
    """
    SOLO LECTURA. Construye la propuesta de manifiesto para los casos indicados e
    informa, caso por caso, de lo que impide aceptarlo (p. ej. falta confirmar).
    """
    ids = list(ejemplo_ids)
    problemas, items = {}, []
    if len(set(ids)) != len(ids):
        problemas["_lote"] = ["el lote repite casos"]
    tabla = _tabla_items_existe()
    existentes = {c.ejemplo_id: c for c in CandidatoDataset.objects.filter(ejemplo_id__in=ids).select_related("alerta")}
    for eid in ids:
        cand = existentes.get(eid)
        if cand is None:
            problemas[eid] = ["no existe"]
            continue
        errores, vigente = _comprobar_caso(cand, tabla_items=tabla)
        if errores:
            problemas[eid] = errores
        if vigente is not None:
            items.append({**vigente, "completado_por_id": cand.completado_por_id})
    valido = not problemas and bool(items)
    return {"items": items, "problemas": problemas, "valido": valido, "n_casos": len(ids),
            "manifiesto_sha256": huella_manifiesto([_sin_completador(i) for i in items]) if valido else None,
            "serializacion_version": sellos.SERIALIZACION_VERSION}


def _sin_completador(item):
    return {k: v for k, v in item.items() if k != "completado_por_id"}


def _validar_peticion(manifiesto, autor, lista, referencia, declaracion):
    from usuarios.decorators import usuario_tiene_rol
    errores = []
    if not modo_activo():
        errores.append("el modo REVISOR_UNICO_LOTE no está activo (modo vigente: DOBLE)")
    if not (getattr(autor, "is_active", False) and usuario_tiene_rol(autor, ["ADMIN"])):
        errores.append("el responsable debe ser un usuario activo con rol ADMIN")
    if not isinstance(lista, dict) or set(lista) != set(CLAVES_LISTA) or not all(v is True for v in lista.values()):
        errores.append("la lista de comprobación debe responder afirmativamente sus 6 puntos exactos")
    if declaracion != DECLARACION:
        errores.append("la declaración metodológica no es la aprobada")
    if not (referencia or "").strip():
        errores.append("falta la referencia de la revisión consolidada")
    items = [_sin_completador(i) for i in (manifiesto or {}).get("items", [])]
    if not items:
        errores.append("el manifiesto no tiene casos")
    if len({i["ejemplo_id"] for i in items}) != len(items):
        errores.append("el manifiesto repite casos")
    if (manifiesto or {}).get("manifiesto_sha256") != huella_manifiesto(items):
        errores.append("la huella del manifiesto no corresponde a su contenido")
    return errores, items


def validar_aceptacion(manifiesto, autor, lista, referencia, declaracion=DECLARACION):
    """Dry-run SIN bloqueos ni escrituras: devuelve (errores_generales, errores_por_caso)."""
    generales, items = _validar_peticion(manifiesto, autor, lista, referencia, declaracion)
    por_caso = {}
    tabla = _tabla_items_existe()
    cands = {c.ejemplo_id: c for c in CandidatoDataset.objects.filter(
        ejemplo_id__in=[i["ejemplo_id"] for i in items]).select_related("alerta")}
    for item in items:
        cand = cands.get(item["ejemplo_id"])
        errs = ["no existe"] if cand is None else _comprobar_caso(
            cand, item, autor_id=getattr(autor, "pk", None), tabla_items=tabla)[0]
        if errs:
            por_caso[item["ejemplo_id"]] = errs
    return generales, por_caso


def aceptar_lote(manifiesto, autor, lista, referencia, declaracion=DECLARACION):
    """
    Acepta el lote y aprueba TODOS sus casos, o ninguno. Una sola transacción con
    las filas bloqueadas; cualquier discrepancia devuelve los errores sin escribir.
    Devuelve (lote, errores).
    """
    generales, items = _validar_peticion(manifiesto, autor, lista, referencia, declaracion)
    if generales:
        return None, generales
    with transaction.atomic():
        ids = [i["ejemplo_id"] for i in items]
        cands = {c.ejemplo_id: c for c in CandidatoDataset.objects.select_for_update()
                 .filter(ejemplo_id__in=ids).select_related("alerta").order_by("pk")}
        errores = []
        for item in items:
            cand = cands.get(item["ejemplo_id"])
            errs = ["no existe"] if cand is None else _comprobar_caso(cand, item, autor_id=autor.pk)[0]
            errores += [f"{item['ejemplo_id']}: {e}" for e in errs]
        if errores:
            return None, ["no se aprueba ningún caso del lote: " + "; ".join(errores)]
        lote = AceptacionLote.objects.create(
            modo=MODO, responsable=autor.username, responsable_id=autor.pk, declaracion=declaracion,
            lista_comprobacion=lista, lista_sha256=sellos.huella_integridad(lista),
            referencia_revision=referencia.strip(), manifiesto_sha256=manifiesto["manifiesto_sha256"],
            n_casos=len(items), serializacion_version=sellos.SERIALIZACION_VERSION,
        )
        for item in items:
            cand = cands[item["ejemplo_id"]]
            fila = AceptacionLoteItem(lote=lote, candidato=cand, confirmacion_id=item["confirmacion_id"],
                                      entrada_revisada_id=item["entrada_revisada_id"],
                                      entrada_sha256=item["entrada_sha256"], salida_sha256=item["salida_sha256"])
            fila._desde_aceptar_lote = True
            fila.save()
            RevisionCandidato.objects.create(
                candidato=cand, decision="APROBADO", autor=autor,
                observaciones=f"Aceptación del lote {lote.manifiesto_sha256[:12]} (revisión consolidada).",
                entrada_sha256=item["entrada_sha256"], salida_sha256=item["salida_sha256"],
                serializacion_version=sellos.SERIALIZACION_VERSION, modo_revision=MODO, aceptacion_lote=lote,
            )
            cand.estado = "APROBADO"
            cand.save(update_fields=["estado", "sincronizado_en"])
    return lote, []


def verificar_lote(lote):
    """SOLO LECTURA: el lote aceptado sigue íntegro (sin casos añadidos, sustituidos ni alterados)."""
    items = [{"ejemplo_id": i.candidato.ejemplo_id, "confirmacion_id": i.confirmacion_id,
              "entrada_revisada_id": i.entrada_revisada_id, "entrada_sha256": i.entrada_sha256,
              "salida_sha256": i.salida_sha256} for i in lote.items.select_related("candidato")]
    errores = []
    if len(items) != lote.n_casos:
        errores.append("el número de casos no coincide con el aceptado")
    if huella_manifiesto(items) != lote.manifiesto_sha256:
        errores.append("el contenido no coincide con el manifiesto sellado")
    if sellos.huella_integridad(lote.lista_comprobacion) != lote.lista_sha256:
        errores.append("la lista de comprobación no coincide con su sello")
    if lote.declaracion != DECLARACION:
        errores.append("la declaración no es la aprobada")
    return errores
