"""
Exclusión común por alerta entre TODAS las vías que pueden invocar al proveedor para el mismo documento: ingesta
nueva, recuperación/reanálisis (reintento individual, reclasificación, «Actualizar») y el trabajador de ingesta
continua.

Mecanismo: un `flock` exclusivo y NO bloqueante sobre un archivo por clave (SHA-256 del `opensearch_id`, o de la
clave primaria si la fila no lo tiene) en un directorio privado compartido por el dashboard y el trabajador.
- Es atómico entre procesos y entre hilos (cada adquisición abre su propio descriptor), lo libera el SO si el
  proceso muere y no usa transacciones SQL (no hay transacción abierta durante la llamada de red).
- No destructivo: si otra vía tiene la clave, se lanza `AnalisisEnCursoError` sin tocar la fila ni llamar.
- No reentrante a propósito: una segunda adquisición de la misma clave en el mismo hilo es un error de
  programación (`ReentradaError`), no un «ocupado» silencioso.
- Los archivos de bloqueo no se borran (borrarlos abriría una carrera); son vacíos y uno por alerta analizada.

Marca PERSISTENTE de llamada sin cerrar (`<sha>.incierto`, mismo directorio): se escribe (fsync) justo antes del
análisis que puede invocar al proveedor y solo se retira cuando el resultado, correcto o fallido, ya está guardado
en la fila. Si el proceso muere entre medias, la marca queda: ninguna vía (trabajador, «Actualizar», reintento,
reclasificación, ingesta manual) vuelve a enviar ese documento (`AnalisisInciertoError`), sin tocar la fila ni
consumir llamada, hasta que una persona lo revise y la libere explícitamente (`liberar_incierto`, comando
`revisar_incierto`). Liberar no envía nada: deja un registro `.revisado` con el motivo.

Directorio: `SENTRIA_EXCLUSION_DIR` (ruta absoluta; el lanzador privado fija la MISMA para el dashboard y el
trabajador, en almacenamiento persistente para que las marcas sobrevivan al reinicio). Sin la variable:
`<tmp>/sentria-exclusion-<uid>` (solo pruebas/desarrollo: un /tmp que se vacía al arrancar NO conserva las marcas).
Debe ser del usuario, sin enlaces y sin permisos para grupo u otros; si no es utilizable se lanza `ExclusionError` y
no se llama al proveedor.
"""
from __future__ import annotations

import datetime as dt
import errno
import fcntl
import hashlib
import json
import os
import stat
import tempfile
import threading
from contextlib import contextmanager

VARIABLE_DIR = "SENTRIA_EXCLUSION_DIR"
_local = threading.local()


class AnalisisEnCursoError(RuntimeError):
    """Otra vía está analizando este mismo documento: no se llama, no se modifica la fila."""


class ExclusionError(RuntimeError):
    """El directorio de exclusión no existe o no es seguro: no se llama al proveedor."""


class ReentradaError(RuntimeError):
    """Adquisición anidada de la misma clave en el mismo hilo (error de programación)."""


class AnalisisInciertoError(RuntimeError):
    """Una llamada anterior de este documento pudo ejecutarse y no quedó cerrada: requiere revisión humana. No se
    reenvía, no se modifica la fila y no se consume llamada."""


def directorio():
    d = os.environ.get(VARIABLE_DIR) or os.path.join(tempfile.gettempdir(), f"sentria-exclusion-{os.getuid()}")
    if not os.path.isabs(d):
        raise ExclusionError(f"{VARIABLE_DIR} debe ser una ruta absoluta")
    return d


def configurado_explicitamente():
    return bool(os.environ.get(VARIABLE_DIR))


def _preparar(d):
    try:
        os.makedirs(d, mode=0o700, exist_ok=True)
        st = os.lstat(d)
    except OSError as e:
        raise ExclusionError(f"directorio de exclusión no utilizable ({type(e).__name__})") from None
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise ExclusionError("el directorio de exclusión debe ser del usuario, sin enlaces y sin permisos para "
                             "grupo u otros")


def comprobar():
    """Comprobación previa (trabajador): el directorio de exclusión existe o se crea y es seguro."""
    _preparar(directorio())


def clave_de_fila(alerta):
    osid = getattr(alerta, "opensearch_id", None)
    if osid:
        return str(osid)
    return f"pk:{alerta.pk}" if getattr(alerta, "pk", None) is not None else None


def _activas():
    if not hasattr(_local, "claves"):
        _local.claves = set()
    return _local.claves


@contextmanager
def exclusion_analisis(clave):
    """Sección exclusiva para `clave` (str). Sin clave (alerta nueva sin `opensearch_id`) no hay nada que excluir."""
    if not clave:
        yield
        return
    clave = str(clave)
    if clave in _activas():
        raise ReentradaError("adquisición anidada de la exclusión de la misma alerta")
    d = directorio()
    _preparar(d)
    ruta = os.path.join(d, hashlib.sha256(clave.encode("utf-8")).hexdigest() + ".lock")
    try:
        fd = os.open(ruta, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except OSError as e:
        raise ExclusionError(f"archivo de exclusión no utilizable ({type(e).__name__})") from None
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as e:
            if e.errno in (errno.EAGAIN, errno.EACCES):
                raise AnalisisEnCursoError("otra vía está analizando esta alerta; no se llama") from None
            raise ExclusionError(f"bloqueo no disponible ({type(e).__name__})") from None
        _activas().add(clave)
        try:
            yield
        finally:
            _activas().discard(clave)
    finally:
        os.close(fd)            # libera el flock


# --------------------------------------------------------------------------- llamadas sin cerrar (persistente)
def _nombre(clave):
    return hashlib.sha256(str(clave).encode("utf-8")).hexdigest()


def _fsync_dir(d):
    fd = os.open(d, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def comprobar_no_incierto(clave):
    """Lanza AnalisisInciertoError si `clave` tiene una llamada sin cerrar. Sin clave no hay nada que comprobar."""
    if not clave:
        return
    d = directorio()
    _preparar(d)
    if os.path.lexists(os.path.join(d, _nombre(clave) + ".incierto")):
        raise AnalisisInciertoError("una llamada anterior de esta alerta pudo ejecutarse y no quedó cerrada: "
                                    "requiere revisión; no se reenvía")


def abrir_llamada(clave, via, alert_id=None):
    """Escribe de forma duradera la marca de llamada sin cerrar ANTES del análisis. -> ruta (o None sin clave).
    Si ya existe -> AnalisisInciertoError; si no puede escribirse -> ExclusionError (no se llama)."""
    if not clave:
        return None
    d = directorio()
    _preparar(d)
    ruta = os.path.join(d, _nombre(clave) + ".incierto")
    datos = {"clave": str(clave), "via": via, "alert_id": alert_id, "pid": os.getpid(),
             "desde_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")}
    try:
        fd = os.open(ruta, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except FileExistsError:
        raise AnalisisInciertoError("una llamada anterior de esta alerta pudo ejecutarse y no quedó cerrada: "
                                    "requiere revisión; no se reenvía") from None
    except OSError as e:
        raise ExclusionError(f"no se pudo registrar la llamada ({type(e).__name__}); no se llama") from None
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(datos, f, ensure_ascii=False, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        _fsync_dir(d)
    except OSError as e:
        raise ExclusionError(f"no se pudo registrar la llamada ({type(e).__name__}); no se llama") from None
    return ruta


def cerrar_llamada(ruta):
    """Retira la marca. Solo se llama cuando el resultado (correcto o fallido) ya está guardado en la fila."""
    if ruta:
        os.unlink(ruta)
        _fsync_dir(os.path.dirname(ruta))


def listar_inciertos():
    """-> lista de marcas sin cerrar (dict con clave, vía, alert_id, pid, desde_utc). Solo lectura."""
    d = directorio()
    if not os.path.isdir(d):
        return []
    _preparar(d)
    out = []
    for nombre in sorted(os.listdir(d)):
        if nombre.endswith(".incierto"):
            try:
                with open(os.path.join(d, nombre), encoding="utf-8") as f:
                    out.append(json.load(f))
            except (OSError, ValueError):
                out.append({"clave": None, "archivo": nombre, "ilegible": True})
    return out


def liberar_incierto(clave, motivo, revisor):
    """Decisión HUMANA tras revisar: retira la marca (no envía nada) y deja un registro `.revisado` con el motivo.
    Después, una vía manual podrá volver a analizar el documento (una llamada nueva y consciente)."""
    if not str(motivo or "").strip() or not str(revisor or "").strip():
        raise ValueError("liberar exige motivo y revisor")
    d = directorio()
    _preparar(d)
    ruta = os.path.join(d, _nombre(clave) + ".incierto")
    with open(ruta, encoding="utf-8") as f:              # FileNotFoundError si no hay marca
        datos = json.load(f)
    datos["revision"] = {"motivo": str(motivo).strip(), "revisor": str(revisor).strip(),
                         "liberado_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")}
    sello = datos["revision"]["liberado_utc"].replace(":", "").replace("-", "")
    registro = os.path.join(d, f"{_nombre(clave)}.revisado.{sello}")
    fd = os.open(registro, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(datos, f, ensure_ascii=False, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.unlink(ruta)
    _fsync_dir(d)
    return datos
