"""
Registro PERSISTENTE del piloto acotado (`ingestar_alertas --piloto`).

Un archivo privado (600, fuera del repositorio) con una línea JSON por evento:
  - `inicio`: agente, proveedor, tope total y `inicio_utc` (sólo cuentan alertas con fecha >= inicio_utc);
  - `intento`: se escribe y se sincroniza a disco ANTES de cada llamada al modelo, así que una llamada fallida,
    interrumpida o con error de red también cuenta;
  - `resultado`: id de la fila y estado del análisis, después de guardar.

Garantías:
  - Crear el registro es una acción explícita (`crear`, O_EXCL): relanzar el comando nunca lo reinicia y una
    ejecución sin registro se rechaza en vez de empezar de cero.
  - Un candado exclusivo impide dos ejecuciones simultáneas sobre el mismo registro.
  - Nunca guarda `opensearch_id`, prompts ni respuestas: sólo una huella del `opensearch_id`.
  - Material de DESARROLLO: las huellas de los intentos identifican alertas que nunca pueden ir a una prueba final.

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
        self.intentos = [e for e in eventos[1:] if e.get("tipo") == "intento"]
        self.inicio_utc = datetime.datetime.fromisoformat(self.cabecera["inicio_utc"])
        self._pendiente = None

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
    def usados(self):
        return len(self.intentos)

    @property
    def restantes(self):
        return max(0, self.tope_total - self.usados)

    def huellas_intentadas(self):
        return {e.get("alerta") for e in self.intentos}

    def _escribir(self, evento):
        self._f.write(json.dumps(evento, ensure_ascii=False) + "\n")
        self._f.flush()
        os.fsync(self._f.fileno())

    def preparar(self, opensearch_id):
        """Alerta a la que se atribuirá el próximo intento."""
        self._pendiente = huella_opensearch_id(opensearch_id)

    def registrar_intento(self):
        """Se llama justo ANTES de enviar al modelo. Si el tope total está agotado, lanza (no se llama)."""
        if self.restantes <= 0:
            raise RegistroPilotoError("tope total del piloto agotado")
        evento = {"tipo": "intento", "n": self.usados + 1, "alerta": self._pendiente, "utc": _ahora().isoformat()}
        self._escribir(evento)
        self.intentos.append(evento)

    def registrar_ejecucion(self, reserva, *, modo):
        """Deja constancia, antes de cualquier llamada, de la versión y la huella del manifiesto de reserva usado."""
        self._escribir({"tipo": "ejecucion", "modo": modo, "reserva_version": reserva.version,
                        "reserva_sello": reserva.sello, "utc": _ahora().isoformat()})

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
        self._dias, self._sesiones = set(), []
        try:
            for e in cuerpo["episodios"]:
                for d in e["dias"]:
                    if not _RE_DIA.fullmatch(str(d)):
                        raise ValueError
                    self._dias.add((str(e["agente"]), str(d)))
            for x in cuerpo.get("sesiones") or []:
                ini = datetime.datetime.fromisoformat(str(x["inicio_utc"]).replace("Z", "+00:00"))
                fin = datetime.datetime.fromisoformat(str(x["fin_utc"]).replace("Z", "+00:00"))
                if ini.tzinfo is None or fin.tzinfo is None or fin <= ini:
                    raise ValueError
                self._sesiones.append((str(x["agente"]), ini, fin))
        except Exception:
            raise RegistroPilotoError("estructura del manifiesto de reserva no válida (episodios/sesiones)") from None
        self.n_episodios = len(cuerpo["episodios"])
        self.n_sesiones = len(self._sesiones)

    def reservada(self, agente, momento):
        """True si (agente, momento UTC) cae en un episodio o una sesión reservados. Sin fecha: se trata como reservada."""
        if momento is None:
            return True
        m = momento.astimezone(datetime.timezone.utc)
        agente = str(agente)
        if (agente, m.date().isoformat()) in self._dias:
            return True
        return any(a == agente and ini <= m <= fin for a, ini, fin in self._sesiones)
