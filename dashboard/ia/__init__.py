"""
Módulo de análisis de alertas con IA (Sprint 2A).

Estructura:
- anonimizacion.py : enmascarado RNF-03 (IP privadas, usuarios, hostnames).
- contrato.py      : enums y validación estricta de la salida JSON (contrato 1C).
- prompt.py        : construcción de la entrada (capa E) y del prompt.
- proveedores.py   : abstracción configurable de proveedor (gemini_developer / vertex_tuned).
- analizador.py    : orquestación -> resultado normalizado o ANALISIS_FALLIDO.
- persistencia.py  : escritura en el modelo Alert respetando la inmutabilidad del veredicto IA.

Ningún import de este paquete crea clientes de red al importarse: el cliente
del proveedor se construye de forma perezosa en el primer uso.
"""
