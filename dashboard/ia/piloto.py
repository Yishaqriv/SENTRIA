"""
Registro PERSISTENTE del piloto acotado (`ingestar_alertas --piloto`).

Un archivo privado (600, fuera del repositorio) con una línea JSON por evento:
  - `inicio`: agente, proveedor, tope total y `inicio_utc` (sólo cuentan alertas con fecha >= inicio_utc);
  - `intento`: se escribe y se sincroniza a disco ANTES de cada llamada al modelo, así que una llamada fallida,
    interrumpida o con error de red también cuenta. Desde la deduplicación lleva `texto_sha256` (SHA-256 del texto
    exacto enviado); los intentos anteriores no lo tienen y no se les inventa;
  - `duplicada`: alerta cuyo texto ya se envió (intento registrado o fila del proveedor en MySQL) o ya apareció en la
    misma ejecución. No es un intento: no llama al modelo ni consume el tope. Una sola vez por alerta;
  - `resultado`: id de la fila y estado del análisis, después de guardar.

Garantías:
  - Crear el registro es una acción explícita (`crear`, O_EXCL): relanzar el comando nunca lo reinicia y una
    ejecución sin registro se rechaza en vez de empezar de cero.
  - Un candado exclusivo impide dos ejecuciones simultáneas sobre el mismo registro.
  - Nunca guarda `opensearch_id`, prompts ni respuestas: sólo una huella del `opensearch_id`.
  - Material de DESARROLLO: las huellas de los intentos identifican alertas que nunca pueden ir a una prueba final.

Prueba controlada (`crear_experimento`): un registro PROPIO, con el mismo formato y las mismas garantías, para analizar
alertas de una prueba documentada con el mismo proveedor. Su cabecera declara `clase_material: prueba_controlada`, el
experimento, sus sesiones UTC y sus reglas. Nunca vale como registro natural ni al revés. La fila analizada lleva en el
snapshot `_experimento` (procedencia), que por sí sola NO justifica nada: el piloto natural solo la deja fuera de su
contabilidad si `justificar_fila_experimento` la vincula con una sesión de la reserva SELLADA que declara ese
experimento, con la cabecera exacta de su registro y con el intento que ese registro anotó antes de la llamada.

Reserva explícita (`ManifiestoReserva`): cada ejecución exige el manifiesto privado de reserva (episodios
agente × días UTC y, si las hay, sesiones reservadas agente × intervalo UTC), verifica su sello
`json_canonico_v1` contra el sello esperado que se indica al lanzar, excluye lo reservado y deja constancia de la
versión y la huella usadas.
"""
from __future__ import annotations

import datetime
import fcntl
import hashlib
import json
import os
import re
import stat

from .proveedores import _RAIZ_REPOSITORIO

VERSION_REGISTRO = "piloto-1"
TOPE_TOTAL_MAX = 30


class RegistroPilotoError(RuntimeError):
    """Registro del piloto ausente, inseguro, inconsistente o agotado."""


def huella_opensearch_id(opensearch_id):
    return hashlib.sha256(f"SENTRIA-PILOTO|{opensearch_id}".encode("utf-8")).hexdigest()[:24]


def _ahora():
    return datetime.datetime.now(datetime.timezone.utc)


def _validar_ruta(ruta, *, debe_existir, que="registro del piloto"):
    if not ruta or not os.path.isabs(ruta):
        raise RegistroPilotoError(f"la ruta del {que} debe ser absoluta")
    real = os.path.realpath(ruta)
    if real == _RAIZ_REPOSITORIO or real.startswith(_RAIZ_REPOSITORIO + os.sep):
        raise RegistroPilotoError(f"el {que} no puede estar dentro del repositorio")
    if not debe_existir:
        return
    try:
        st = os.lstat(ruta)
    except OSError:
        if que == "registro del piloto":
            raise RegistroPilotoError(
                "no existe el registro del piloto: créalo explícitamente con --iniciar-piloto") from None
        raise RegistroPilotoError(f"no existe el {que}") from None
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise RegistroPilotoError(f"el {que} debe ser un archivo regular (no un enlace)")
    if st.st_uid != os.getuid():
        raise RegistroPilotoError(f"el {que} pertenece a otro usuario")
    if st.st_mode & 0o077:
        raise RegistroPilotoError(f"permisos inseguros en el {que} (se exige 600)")


def crear(ruta, *, agente, proveedor, tope_total, ahora=None):
    """Crea el registro (falla si ya existe). `inicio_utc` = ahora: sólo cuentan alertas posteriores."""
    _validar_ruta(ruta, debe_existir=False)
    tope_total = int(tope_total)
    if not 1 <= tope_total <= TOPE_TOTAL_MAX:
        raise RegistroPilotoError(f"el tope total del piloto debe estar entre 1 y {TOPE_TOTAL_MAX}")
    cabecera = {"tipo": "inicio", "version": VERSION_REGISTRO, "agente": str(agente), "proveedor": str(proveedor),
                "tope_total": tope_total, "inicio_utc": (ahora or _ahora()).isoformat(),
                "clase_material": "desarrollo"}     # sus alertas no pueden formar parte de una prueba final
    return _escribir_cabecera(ruta, cabecera)


CLASE_PRUEBA_CONTROLADA = "prueba_controlada"
_RE_EXPERIMENTO = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,39}")
_RE_REGLA = re.compile(r"\d{1,7}")


def _intervalo(ini, fin):
    ini = datetime.datetime.fromisoformat(str(ini).replace("Z", "+00:00"))
    fin = datetime.datetime.fromisoformat(str(fin).replace("Z", "+00:00"))
    if ini.tzinfo is None or fin.tzinfo is None or fin <= ini:
        raise ValueError("intervalo UTC no válido")
    return ini, fin


def crear_experimento(ruta, *, agente, proveedor, tope_total, experimento, sesiones, reglas, plan_sello, ahora=None):
    """
    Crea el registro de una PRUEBA CONTROLADA (falla si ya existe). `sesiones`: [(inicio, fin)] UTC con zona;
    `reglas`: rule.id previstos; `plan_sello`: SHA-256 del plan sellado. Mismas garantías que el registro natural.
    """
    _validar_ruta(ruta, debe_existir=False, que="registro del experimento")
    tope_total = int(tope_total)
    if not 1 <= tope_total <= TOPE_TOTAL_MAX:
        raise RegistroPilotoError(f"el tope total del experimento debe estar entre 1 y {TOPE_TOTAL_MAX}")
    if not _RE_EXPERIMENTO.fullmatch(str(experimento or "")):
        raise RegistroPilotoError("identificador de experimento no válido")
    if not _RE_SELLO.fullmatch(str(plan_sello or "")):
        raise RegistroPilotoError("el sello del plan debe ser un SHA-256 completo (64 hex)")
    reglas = sorted({str(r).strip() for r in (reglas or [])})
    if not reglas or not all(_RE_REGLA.fullmatch(r) for r in reglas):
        raise RegistroPilotoError("el experimento exige al menos una regla prevista (rule.id numérico)")
    try:
        ses = [_intervalo(i, f) for i, f in (sesiones or [])]
    except (TypeError, ValueError):
        raise RegistroPilotoError("sesiones del experimento no válidas (inicio < fin, ISO con zona)") from None
    if not ses:
        raise RegistroPilotoError("el experimento exige al menos una sesión")
    cabecera = {"tipo": "inicio", "version": VERSION_REGISTRO, "agente": str(agente), "proveedor": str(proveedor),
                "tope_total": tope_total, "inicio_utc": (ahora or _ahora()).isoformat(),
                "clase_material": CLASE_PRUEBA_CONTROLADA, "experimento": str(experimento),
                "sesiones": [{"inicio_utc": i.isoformat(), "fin_utc": f.isoformat()} for i, f in ses],
                "reglas": reglas, "plan_sello": str(plan_sello)}
    return _escribir_cabecera(ruta, cabecera)


def momento_de_reserva(valor):
    """
    ÚNICA definición de hora con la que el piloto natural y las pruebas controladas sitúan una alerta en días,
    sesiones de reserva y sesiones de experimento: la hora de RECEPCIÓN en Wazuh (`@timestamp`; es el `timestamp`
    de la alerta normalizada por `sentria_backend` y lo que guarda `Alert.timestamp`), en UTC. Se usa igual al
    seleccionar candidatas naturales, al admitir un caso del experimento y al justificar su fila después.
    No es la hora original de un evento de Windows (`prompt.hora_del_evento`), que solo sirve para el horario y la
    ventana de la ENTRADA del modelo. Sin hora válida -> None (la reserva la trata como reservada; el experimento
    la rechaza).
    """
    from .prompt import _parsear_ts            # perezoso: evita dependencias circulares
    m = _parsear_ts(valor)
    if m is None:
        return None
    return (m.replace(tzinfo=datetime.timezone.utc) if m.tzinfo is None else m).astimezone(datetime.timezone.utc)


def huella_linea_cabecera(linea):
    """SHA-256 de la línea de cabecera tal como está escrita (sin el salto de línea final)."""
    return hashlib.sha256(linea.rstrip("\n").encode("utf-8")).hexdigest()


def _escribir_cabecera(ruta, cabecera):
    try:
        fd = os.open(ruta, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise RegistroPilotoError("el registro del piloto ya existe: no se reinicia") from None
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(json.dumps(cabecera, ensure_ascii=False) + "\n")
        f.flush()
        os.fsync(f.fileno())
    return cabecera


class RegistroPiloto:
    """Registro abierto con candado exclusivo durante toda la ejecución. Usar como context manager."""

    def __init__(self, ruta):
        _validar_ruta(ruta, debe_existir=True)
        self.ruta = ruta
        self._f = open(ruta, "a+", encoding="utf-8")
        try:
            fcntl.flock(self._f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self._f.close()
            raise RegistroPilotoError("otra ejecución del piloto tiene el registro abierto") from None
        self._f.seek(0)
        lineas = [l for l in self._f.read().splitlines() if l.strip()]
        try:
            eventos = [json.loads(l) for l in lineas]
        except ValueError:
            self.cerrar()
            raise RegistroPilotoError("registro del piloto corrupto (línea no JSON)") from None
        if not eventos or eventos[0].get("tipo") != "inicio" or eventos[0].get("version") != VERSION_REGISTRO:
            self.cerrar()
            raise RegistroPilotoError("registro del piloto sin cabecera válida")
        self.cabecera = eventos[0]
        self.huella_cabecera = huella_linea_cabecera(lineas[0])
        self.intentos = [e for e in eventos[1:] if e.get("tipo") == "intento"]
        self._duplicadas = {e.get("alerta") for e in eventos[1:] if e.get("tipo") == "duplicada"}
        self.inicio_utc = datetime.datetime.fromisoformat(self.cabecera["inicio_utc"])
        self._pendiente = None
        self._texto_esperado = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.cerrar()

    def cerrar(self):
        if not self._f.closed:
            fcntl.flock(self._f.fileno(), fcntl.LOCK_UN)
            self._f.close()

    @property
    def agente(self):
        return self.cabecera["agente"]

    @property
    def proveedor(self):
        return self.cabecera["proveedor"]

    @property
    def tope_total(self):
        return int(self.cabecera["tope_total"])

    @property
    def clase_material(self):
        return self.cabecera.get("clase_material", "desarrollo")

    @property
    def es_experimento(self):
        return self.clase_material == CLASE_PRUEBA_CONTROLADA

    @property
    def experimento(self):
        return self.cabecera.get("experimento")

    @property
    def reglas(self):
        return set(self.cabecera.get("reglas") or [])

    def sesiones(self):
        """Experimento: [(inicio, fin)] UTC de su cabecera."""
        return [_intervalo(x["inicio_utc"], x["fin_utc"]) for x in self.cabecera.get("sesiones") or []]

    def en_sesion(self, momento):
        """Experimento: True si `momento` (ver `momento_de_reserva`) cae en una de las sesiones de su cabecera."""
        momento = momento_de_reserva(momento)
        if momento is None:
            return False
        for x in self.cabecera.get("sesiones") or []:
            ini, fin = _intervalo(x["inicio_utc"], x["fin_utc"])
            if ini <= momento <= fin:
                return True
        return False

    @property
    def usados(self):
        return len(self.intentos)

    @property
    def restantes(self):
        return max(0, self.tope_total - self.usados)

    def huellas_intentadas(self):
        return {e.get("alerta") for e in self.intentos}

    def textos_intentados(self):
        """SHA-256 de los textos de los intentos que lo registraron (los antiguos no lo tienen: no se inventa)."""
        return {e["texto_sha256"] for e in self.intentos if e.get("texto_sha256")}

    def _escribir(self, evento):
        self._f.write(json.dumps(evento, ensure_ascii=False) + "\n")
        self._f.flush()
        os.fsync(self._f.fileno())

    def preparar(self, opensearch_id, texto_sha256=None):
        """Alerta a la que se atribuirá el próximo intento y SHA del texto seleccionado para ella."""
        self._pendiente = huella_opensearch_id(opensearch_id)
        self._texto_esperado = texto_sha256

    def registrar_intento(self, texto_sha256=None):
        """
        Se llama justo ANTES de enviar al modelo, con el SHA-256 del texto que se va a enviar. Lanza (y no se llama)
        si el tope total está agotado, si el texto no es el seleccionado o si ese texto ya tiene un intento.
        """
        if self.restantes <= 0:
            raise RegistroPilotoError("tope total del piloto agotado")
        if self._texto_esperado and texto_sha256 != self._texto_esperado:
            raise RegistroPilotoError("el texto a enviar no coincide con el seleccionado")
        if texto_sha256 and texto_sha256 in self.textos_intentados():
            raise RegistroPilotoError("ese texto ya tiene un intento registrado")
        evento = {"tipo": "intento", "n": self.usados + 1, "alerta": self._pendiente, "utc": _ahora().isoformat()}
        if texto_sha256:
            evento["texto_sha256"] = texto_sha256
        self._escribir(evento)
        self.intentos.append(evento)

    def registrar_duplicada(self, opensearch_id, *, texto_sha256, previo):
        """Constancia de una alerta no enviada por repetir un texto (`previo`: de dónde consta). Una vez por alerta."""
        alerta = huella_opensearch_id(opensearch_id)
        if alerta in self._duplicadas:
            return False
        self._escribir({"tipo": "duplicada", "alerta": alerta, "texto_sha256": texto_sha256, "previo": previo,
                        "utc": _ahora().isoformat()})
        self._duplicadas.add(alerta)
        return True

    def registrar_ejecucion(self, reserva, *, modo):
        """Deja constancia, antes de cualquier llamada, de la versión y la huella del manifiesto de reserva usado."""
        self._escribir({"tipo": "ejecucion", "modo": modo, "reserva_version": reserva.version,
                        "reserva_sello": reserva.sello, "utc": _ahora().isoformat()})

    def registrar_ejecucion_experimento(self, opensearch_id, *, modo):
        """Experimento: constancia, antes de cualquier llamada, de la alerta dirigida (solo su huella)."""
        self._escribir({"tipo": "ejecucion", "modo": modo, "experimento": self.experimento,
                        "alerta": huella_opensearch_id(opensearch_id), "utc": _ahora().isoformat()})

    def registrar_resultado(self, opensearch_id, *, alert_id, estado_analisis):
        self._escribir({"tipo": "resultado", "alerta": huella_opensearch_id(opensearch_id), "alert_id": alert_id,
                        "estado_analisis": estado_analisis, "utc": _ahora().isoformat()})

    def comprobar_coherencia(self, alertas_del_proveedor):
        """
        `alertas_del_proveedor`: opensearch_id de las filas de MySQL analizadas por el proveedor del piloto para su
        agente desde `inicio_utc`. Todas deben figurar como intento: si falta alguna, el registro se reinició o se
        analizó por otra vía, y el piloto no continúa.
        """
        intentadas = self.huellas_intentadas()
        faltan = [o for o in alertas_del_proveedor if huella_opensearch_id(o) not in intentadas]
        if faltan:
            raise RegistroPilotoError(
                f"registro del piloto incoherente con MySQL: {len(faltan)} análisis del proveedor sin intento registrado")


_RE_SELLO = re.compile(r"[0-9a-f]{64}")


def _destino_vinculo(ruta, cabecera_sha256):
    """Identidad del registro al que apunta una sesión vinculada: ruta real + huella exacta de su cabecera."""
    return os.path.realpath(ruta), cabecera_sha256


def sesiones_ambiguas(sesiones_experimento):
    """
    Criterio ÚNICO de ambigüedad de las sesiones vinculadas a experimentos. Lo aplica `ManifiestoReserva` al cargarse,
    de modo que la validación previa del experimento (`_vinculo_experimento`) y la justificación posterior de la
    fila (`justificar_fila_experimento`) nunca pueden ver la misma reserva de forma distinta.
    Ambigua = dos sesiones del MISMO agente y experimento que se solapan o se tocan (límites incluidos, igual que
    las comprobaciones de hora) y apuntan a registros o cabeceras distintos. -> lista de pares conflictivos.
    """
    conflictos = []
    for i, a in enumerate(sesiones_experimento):
        for b in sesiones_experimento[i + 1:]:
            if a[0] == b[0] and a[3] == b[3] and a[1] <= b[2] and b[1] <= a[2] \
                    and _destino_vinculo(a[4], a[5]) != _destino_vinculo(b[4], b[5]):
                conflictos.append((a, b))
    return conflictos


_RE_DIA = re.compile(r"\d{4}-\d{2}-\d{2}")


class ManifiestoReserva:
    """
    Manifiesto privado de reserva: `{"cuerpo": {...}, "sello_json_canonico_v1": "<sha256>"}`.
    - `cuerpo.episodios`: lista de `{"agente": "...", "dias": ["AAAA-MM-DD", ...]}` (días UTC).
    - `cuerpo.sesiones` (opcional): lista de `{"agente": "...", "inicio_utc": ISO, "fin_utc": ISO}`.
    El sello debe coincidir con el `json_canonico_v1` del cuerpo Y con el sello esperado indicado al lanzar: un
    manifiesto editado (aunque se recalcule su sello) o sustituido no se acepta.
    """

    def __init__(self, ruta, sello_esperado):
        from dashboard.sellos import serializar_canonico
        if not _RE_SELLO.fullmatch(str(sello_esperado or "")):
            raise RegistroPilotoError("el sello esperado de la reserva debe ser un SHA-256 completo (64 hex)")
        _validar_ruta(ruta, debe_existir=True, que="manifiesto de reserva")
        try:
            with open(ruta, encoding="utf-8") as f:
                doc = json.load(f)
            cuerpo = doc["cuerpo"]
            sello = doc["sello_json_canonico_v1"]
        except Exception:
            raise RegistroPilotoError("manifiesto de reserva ilegible o sin cuerpo/sello") from None
        calculado = hashlib.sha256(serializar_canonico(cuerpo).encode("utf-8")).hexdigest()
        if sello != calculado:
            raise RegistroPilotoError("el sello del manifiesto de reserva no coincide con su contenido")
        if sello != sello_esperado:
            raise RegistroPilotoError("el manifiesto de reserva no es la versión esperada (sello distinto)")
        self.sello = sello
        self.version = f"{cuerpo.get('tipo', 'sin_tipo')}:{cuerpo.get('fecha', 'sin_fecha')}"
        self._dias, self._sesiones, self._sesiones_experimento = set(), [], []
        try:
            for e in cuerpo["episodios"]:
                for d in e["dias"]:
                    if not _RE_DIA.fullmatch(str(d)):
                        raise ValueError
                    self._dias.add((str(e["agente"]), str(d)))
            for x in cuerpo.get("sesiones") or []:
                ini, fin = _intervalo(x["inicio_utc"], x["fin_utc"])
                self._sesiones.append((str(x["agente"]), ini, fin))
                vinculo = [k for k in ("experimento", "registro", "registro_cabecera_sha256") if k in x]
                if vinculo:     # sesión de una prueba controlada: los tres campos o ninguno
                    if len(vinculo) != 3 or not _RE_EXPERIMENTO.fullmatch(str(x["experimento"])) \
                            or not os.path.isabs(str(x["registro"])) \
                            or not _RE_SELLO.fullmatch(str(x["registro_cabecera_sha256"])):
                        raise ValueError
                    self._sesiones_experimento.append(
                        (str(x["agente"]), ini, fin, str(x["experimento"]), str(x["registro"]),
                         str(x["registro_cabecera_sha256"])))
        except Exception:
            raise RegistroPilotoError("estructura del manifiesto de reserva no válida (episodios/sesiones)") from None
        if sesiones_ambiguas(self._sesiones_experimento):
            raise RegistroPilotoError("reserva ambigua: sesiones solapadas del mismo agente y experimento apuntan a "
                                      "registros o cabeceras distintos")
        self.n_episodios = len(cuerpo["episodios"])
        self.n_sesiones = len(self._sesiones)

    def sesiones_vinculadas(self, agente, experimento):
        """[(inicio, fin, ruta_registro, cabecera_sha256)] de las sesiones selladas de ese experimento y agente."""
        return [(ini, fin, ruta, sha) for a, ini, fin, e, ruta, sha in self._sesiones_experimento
                if a == str(agente) and e == str(experimento)]

    def reservada(self, agente, momento):
        """True si (agente, momento UTC) cae en un episodio o una sesión reservados. Sin fecha: se trata como reservada."""
        m = momento_de_reserva(momento)
        if m is None:
            return True
        agente = str(agente)
        if (agente, m.date().isoformat()) in self._dias:
            return True
        return any(a == agente and ini <= m <= fin for a, ini, fin in self._sesiones)


def leer_registro_experimento(ruta, cabecera_sha256):
    """
    Lectura (candado compartido, sin escribir) del registro de una prueba controlada declarado en la reserva.
    Exige permisos 600 y propietario, que su cabecera sea EXACTAMENTE la sellada y que sea de clase prueba_controlada.
    -> (cabecera, intentos).
    """
    _validar_ruta(ruta, debe_existir=True, que="registro del experimento")
    with open(ruta, encoding="utf-8") as f:
        try:
            fcntl.flock(f.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB)
        except OSError:
            raise RegistroPilotoError("el registro del experimento está en uso por otra ejecución") from None
        try:
            lineas = [l for l in f.read().splitlines() if l.strip()]
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    if not lineas or huella_linea_cabecera(lineas[0]) != cabecera_sha256:
        raise RegistroPilotoError("la cabecera del registro del experimento no es la sellada en la reserva")
    try:
        eventos = [json.loads(l) for l in lineas]
    except ValueError:
        raise RegistroPilotoError("registro del experimento corrupto (línea no JSON)") from None
    cab = eventos[0]
    if cab.get("tipo") != "inicio" or cab.get("clase_material") != CLASE_PRUEBA_CONTROLADA:
        raise RegistroPilotoError("el registro declarado no es de una prueba controlada")
    return cab, [e for e in eventos[1:] if e.get("tipo") == "intento"]


def justificar_fila_experimento(reserva, *, agente, proveedor, opensearch_id, momento, snapshot, huellas_naturales):
    """
    ¿Puede el piloto NATURAL dejar fuera de su contabilidad esta fila del proveedor? Solo si TODO se cumple:
      1. el snapshot trae `_experimento` (clase prueba_controlada) con la huella de ESTA alerta;
      2. la alerta no figura como intento natural;
      3. su hora cae en una sesión de la reserva SELLADA que declara ese experimento, para este agente;
      4. el registro declarado en esa sesión tiene exactamente la cabecera sellada (experimento, agente y proveedor
         iguales, y la misma sesión en su cabecera);
      5. ese registro anotó, antes de la llamada, el intento `n` de la marca para esta alerta y con el SHA del texto
         que el snapshot dice haber enviado.
    Devuelve el identificador del experimento; si algo falla, lanza RegistroPilotoError (la marca sola no basta).
    """
    marca = (snapshot or {}).get("_experimento") if isinstance(snapshot, dict) else None
    if not isinstance(marca, dict) or marca.get("clase") != CLASE_PRUEBA_CONTROLADA:
        raise RegistroPilotoError("la fila no trae una procedencia de prueba controlada válida")
    huella = huella_opensearch_id(opensearch_id)
    if marca.get("alerta") != huella:
        raise RegistroPilotoError("la procedencia no corresponde a esta alerta")
    if huella in huellas_naturales:
        raise RegistroPilotoError("la alerta figura a la vez como intento natural y como prueba controlada")
    m = momento_de_reserva(momento)
    if m is None:
        raise RegistroPilotoError("la fila no tiene hora: no puede situarse en una sesión")
    exp = str(marca.get("experimento") or "")
    sesiones = [x for x in reserva.sesiones_vinculadas(agente, exp) if x[0] <= m <= x[1]]
    if not sesiones:
        raise RegistroPilotoError("la fila no cae en una sesión sellada de la reserva para ese experimento")
    if len({_destino_vinculo(x[2], x[3]) for x in sesiones}) != 1:      # imposible tras `sesiones_ambiguas`
        raise RegistroPilotoError("reserva ambigua: sesiones solapadas del mismo agente y experimento apuntan a "
                                  "registros o cabeceras distintos")
    ini, fin, ruta, cab_sha = sesiones[0]
    if marca.get("registro_cabecera_sha256") != cab_sha:
        raise RegistroPilotoError("la procedencia apunta a otro registro de experimento")
    cab, intentos = leer_registro_experimento(ruta, cab_sha)
    if (cab.get("experimento"), str(cab.get("agente")), cab.get("proveedor")) != (exp, str(agente), proveedor):
        raise RegistroPilotoError("el registro del experimento es de otro experimento, agente o proveedor")
    if not any(_intervalo(x["inicio_utc"], x["fin_utc"]) == (ini, fin) for x in cab.get("sesiones") or []):
        raise RegistroPilotoError("la sesión sellada en la reserva no figura en la cabecera del experimento")
    texto = ((snapshot.get("_entrada_modelo") or {}).get("texto_enviado_sha256"))
    ok = [e for e in intentos if e.get("n") == marca.get("intento") and e.get("alerta") == huella
          and texto and e.get("texto_sha256") == texto]
    if len(ok) != 1:
        raise RegistroPilotoError("el registro del experimento no tiene el intento previo de esta alerta con ese texto")
    return exp
