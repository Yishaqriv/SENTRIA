#!/usr/bin/env python3
"""Prueba SIN RED del ejecutor (v2): ejecuta test_ejecutor.py (proveedores falsos, entorno hostil, trampa de .env,
excepción del adaptador, cambio de adaptador/código). Cero llamadas reales.
Uso: python probar_ejecutor_sin_red.py --codigo ../../codigo/sentria"""
import argparse, os, subprocess, sys
AQUI = os.path.dirname(os.path.abspath(__file__))
ap = argparse.ArgumentParser(); ap.add_argument("--codigo", required=True); ap.add_argument("--salida", help="(v1; ya no se usa)")
a = ap.parse_args()
env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.environ.get("HOME", AQUI),
       "EJECUTOR_CODIGO": os.path.abspath(a.codigo)}
sys.exit(subprocess.run([sys.executable, "-m", "unittest", "-v", "test_ejecutor"], cwd=AQUI, env=env).returncode)
