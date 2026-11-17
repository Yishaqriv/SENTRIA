#!/usr/bin/env python3
"""
Ejecuta el CONJUNTO común congelado con UN proveedor: una invocación por caso y repetición, sin reintentos, con un
presupuesto explícito de llamadas. Cada llamada la hace ejecutar_caso.py en un proceso aislado (mismo aislamiento:
sin settings de SENTRIA, sin .env, credenciales propias).

  python ejecutar_conjunto.py --codigo ../codigo/sentria --conjunto ../conjunto --proveedor gemini_developer --ensayo
  python ejecutar_conjunto.py --codigo ../codigo/sentria --conjunto ../conjunto --proveedor gemini_developer \
         --repeticiones 1 --max-llamadas 9 --registro ../registro/registro_resultados.jsonl --confirmar

- --ensayo: valida cada caso sin red (huellas, reconstrucción exacta, representabilidad); 0 llamadas.
- --confirmar: exige --max-llamadas >= casos × repeticiones (si no, no empieza). Lo ya registrado para el mismo
  conjunto, caso, proveedor y repetición se SALTA (reanudar no repite llamadas). Un fallo NO se reintenta: queda
  registrado; para volver a intentarlo hay que usar otra repetición de forma expresa.
- El registro resultante (registro_comparacion_v2, con el conjunto, el caso por huella y la repetición) se importa
  tal cual en «Comparación de IA» (Importar → vista previa → confirmar).
"""
import argparse
import json
import os
import subprocess
import sys

AQUI = os.path.dirname(os.path.abspath(__file__))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--codigo", required=True)
    ap.add_argument("--conjunto", required=True, help="carpeta del conjunto (manifiesto_conjunto.json y casos/)")
    ap.add_argument("--proveedor", required=True)
    ap.add_argument("--adaptador")
    ap.add_argument("--permitir-variable", action="append", default=[])
    ap.add_argument("--repeticiones", type=int, default=1)
    ap.add_argument("--max-llamadas", type=int)
    ap.add_argument("--registro")
    modo = ap.add_mutually_exclusive_group()
    modo.add_argument("--ensayo", action="store_true")
    modo.add_argument("--confirmar", action="store_true")
    a = ap.parse_args()
    man_ruta = os.path.join(a.conjunto, "manifiesto_conjunto.json")
    man = json.load(open(man_ruta, encoding="utf-8"))
    casos = [c["codigo"] for c in man["casos"]]
    if not 1 <= a.repeticiones <= 20:
        sys.exit("--repeticiones entre 1 y 20")
    plan = [(r, c) for r in range(1, a.repeticiones + 1) for c in casos]
    if a.confirmar:
        if not a.registro:
            sys.exit("--confirmar exige --registro.")
        if a.max_llamadas is None or a.max_llamadas < len(plan):
            sys.exit(f"Presupuesto insuficiente o no indicado: el plan son {len(plan)} llamadas como máximo "
                     f"({len(casos)} casos × {a.repeticiones} repeticiones). Indica --max-llamadas {len(plan)} o más.")
    hechos = set()
    if a.registro and os.path.exists(a.registro):
        for linea in open(a.registro, encoding="utf-8"):
            try:
                d = json.loads(linea)
            except ValueError:
                continue
            if (d.get("conjunto") or {}).get("manifiesto_sha256") == man["manifiesto_sha256"] and d.get("proveedor") == a.proveedor:
                hechos.add((d.get("repeticion"), d.get("grupo_entrada_sha256")))
    entrada_por_codigo = {c["codigo"]: c["entrada_sha256"] for c in man["casos"]}
    resumen = {"modo": "confirmar" if a.confirmar else "ensayo", "conjunto": f"{man['codigo']} v{man['version']}",
               "plan": len(plan), "saltados_ya_registrados": 0, "invocaciones": 0, "errores": 0}
    for rep, codigo in plan:
        if a.confirmar and (rep, entrada_por_codigo[codigo]) in hechos:
            resumen["saltados_ya_registrados"] += 1
            continue
        args = [sys.executable, "-I", os.path.join(AQUI, "ejecutar_caso.py"), "--codigo", a.codigo,
                "--caso", os.path.join(a.conjunto, "casos", codigo), "--proveedor", a.proveedor,
                "--conjunto", man_ruta, "--repeticion", str(rep)]
        if a.adaptador:
            args += ["--adaptador", a.adaptador]
        for v in a.permitir_variable:
            args += ["--permitir-variable", v]
        args += ["--confirmar", "--registro", a.registro] if a.confirmar else ["--ensayo"]
        r = subprocess.run(args, capture_output=True, text=True, env=os.environ.copy())
        if r.returncode != 0:
            resumen["errores"] += 1
            print(f"[{codigo} r{rep}] detenido: {(r.stderr.strip().splitlines() or ['sin detalle'])[-1][:200]}")
            break                                       # un rechazo del ejecutor detiene todo (sin reintentos)
        if a.confirmar:
            resumen["invocaciones"] += 1
        try:
            d = json.loads(r.stdout)
            linea = (f"representable={d.get('representable')} condiciones={d.get('equivalencia')} "
                     f"referencia_validada={d.get('referencia_validada_como_sentria')} llamadas={d.get('llamadas')}")
        except ValueError:
            linea = (r.stdout.strip().splitlines() or [""])[-1][:240]
        print(f"[{codigo} r{rep}] {linea}")
    print(json.dumps(resumen, ensure_ascii=False))
    sys.exit(1 if resumen["errores"] else 0)


if __name__ == "__main__":
    main()
