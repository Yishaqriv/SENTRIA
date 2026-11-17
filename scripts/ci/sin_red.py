"""Ejecuta un script Python (argv[1:]) con una guarda de auditoría que BLOQUEA toda conexión de red que no sea
loopback o socket UNIX, y registra cada intento en el archivo indicado por SIN_RED_INFORME (JSON). Sin dependencias."""
import ipaddress, json, os, runpy, sys
INTENTOS = []

def _loopback(host):
    try:
        return ipaddress.ip_address(str(host).split("%")[0]).is_loopback
    except ValueError:
        return str(host) in ("localhost",)

def _hook(ev, args):
    if ev == "socket.connect":
        addr = args[1]
        if isinstance(addr, tuple) and not _loopback(addr[0]):
            INTENTOS.append({"evento": ev, "destino": str(addr[0])})
            raise ConnectionRefusedError("red bloqueada en la prueba aislada")
    elif ev == "socket.getaddrinfo":
        if not _loopback(args[0]) and args[0] is not None:
            INTENTOS.append({"evento": ev, "destino": str(args[0])})
            raise OSError("resolución bloqueada en la prueba aislada")

def _informe():
    p = os.environ.get("SIN_RED_INFORME")
    if p:
        with open(p, "w", encoding="utf-8") as f:
            json.dump({"intentos_bloqueados": len(INTENTOS), "destinos": sorted({i["destino"] for i in INTENTOS})}, f)

import atexit
atexit.register(_informe)
sys.addaudithook(_hook)
sys.argv = sys.argv[1:]
sys.path.insert(0, os.path.dirname(os.path.abspath(sys.argv[0])))
runpy.run_path(sys.argv[0], run_name="__main__")
