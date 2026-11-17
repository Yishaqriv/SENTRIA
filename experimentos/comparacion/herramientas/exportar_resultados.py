"""Vista local HTML y CSV de resultados ya registrados (registro v1 o v2 del ejecutor). Solo biblioteca estandar; sin IA,
sin Django, sin red ni BD. Es una tabla exportada para abrir en navegador/Excel; la pantalla principal de comparacion
es el apartado «Comparacion de IA» de SENTRIA (importando el mismo registro)."""
import argparse,csv,hashlib,html,io,json,math
from pathlib import Path

COLUMNS=[('caso','Caso'),('repeticion','Repeticion'),('proveedor','Proveedor'),('modelo_solicitado','Modelo solicitado'),
 ('modelo_informado','Modelo informado'),('estado_llamada','Estado llamada'),('estado_analisis','Estado analisis'),
 ('tiempo_proveedor_s','Tiempo proveedor (s)'),('tiempo_total_s','Tiempo total registrado (s)'),('tokens_entrada','Tokens entrada'),
 ('tokens_salida','Tokens salida'),('tokens_razonamiento','Tokens razonamiento'),('tokens_total','Tokens total'),
 ('veredicto','Clasificacion'),('riesgo','Riesgo'),('grupo_entrada_sha256','SHA256 de entrada'),
 ('equivalencia','Equivalencia'),('categoria_error','Categoria de error'),('uuid','UUID')]
TOKENS={'tokens_entrada','tokens_salida','tokens_razonamiento','tokens_total'}
TIMES={'tiempo_proveedor_s','tiempo_total_s'}

def value(row,key):
    v=row.get(key)
    if key in TOKENS:return v if type(v) is int and v>=0 else None
    if key in TIMES:return v if type(v) in (int,float) and math.isfinite(v) and v>=0 else None
    if v is None:return None
    return str(v) if isinstance(v,(str,int,float,bool)) else None

def display(v):return 'No disponible' if v is None else str(v)

def safe_csv(v):
    text=display(v)
    return "'"+text if text.lstrip().startswith(('=','+','-','@')) else text

def render(records,source_hash):
    rows=[[value(row,key) for key,_ in COLUMNS] for row in records]
    out=io.StringIO(newline='');writer=csv.writer(out,delimiter=';',lineterminator='\n')
    writer.writerow([title for _,title in COLUMNS])
    for row in rows:writer.writerow([safe_csv(v) for v in row])
    head=''.join('<th>'+html.escape(title)+'</th>' for _,title in COLUMNS)
    body=''.join('<tr>'+''.join('<td>'+html.escape(display(v),quote=True)+'</td>' for v in row)+'</tr>' for row in rows)
    measured=sum(value(r,'tiempo_proveedor_s') is not None for r in records)
    providers={str(r.get('proveedor')) for r in records if r.get('proveedor')}
    groups={str(r.get('grupo_entrada_sha256') or r.get('entrada_sha256')) for r in records if r.get('grupo_entrada_sha256') or r.get('entrada_sha256')}
    notice='Solo hay un proveedor: esta vista aun no permite una comparacion entre proveedores.' if len(providers)<=1 else 'Comparar proveedores sobre el mismo caso y la misma huella de entrada.'
    page='''<!doctype html><html lang="es"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SENTRIA · resultados de pruebas</title><style>
body{font:15px system-ui,sans-serif;color:#e8edf8;background:#10182b;margin:32px}h1{font-size:25px;margin-bottom:8px}
p{line-height:1.6;max-width:1050px}.cards{display:flex;gap:14px;flex-wrap:wrap;margin:24px 0}.card{padding:16px 22px;background:#1b2945;border-radius:10px}
.card strong{font-size:24px;display:block}.scroll{overflow:auto;border:1px solid #405272;border-radius:10px}table{border-collapse:collapse;width:100%;font-size:13px}
th,td{padding:13px;text-align:left;border-bottom:1px solid #334563;vertical-align:top}th{background:#263754;white-space:nowrap}td{max-width:280px;overflow-wrap:anywhere}
.note{color:#b7c6e0}code{overflow-wrap:anywhere}.tag{color:#a5d9c3}footer{margin-top:24px;font-size:12px;color:#a9b6cb}</style>
<h1>SENTRIA · resultados de pruebas</h1><p>Vista de registros existentes. No realiza llamadas a la IA, no consulta bases de datos y no modifica SENTRIA.</p>
<div class="cards"><div class="card"><strong>COUNT</strong>ejecuciones registradas</div><div class="card"><strong>GROUPS</strong>entradas diferentes por huella</div>
<div class="card"><strong>MEASURED / COUNT</strong>con tiempo del proveedor</div></div>
<p class="tag">NOTICE</p><div class="scroll"><table><thead><tr>HEAD</tr></thead><tbody>BODY</tbody></table></div>
<p class="note">«No disponible» significa que el dato no se midio o no fue informado; no equivale a cero.
Los tokens proceden de cada proveedor y sus tokenizadores pueden diferir. Tiempo del proveedor y tiempo total se mantienen separados; su alcance depende del ejecutor registrado.
Modelo solicitado e informado pueden ser distintos. No se estiman costes sin tarifas verificadas. Las respuestas observadas no son verdad de terreno.</p>
<p class="note">Los casos historicos reproducidos se mantienen identificados en la ficha de cada caso. Esta tabla es una instantanea: hay que regenerarla despues de registrar nuevas pruebas.</p>
<footer>Registro fuente SHA256: <code>HASH</code>. Uso interno del equipo.</footer></html>'''
    for key,text in [('COUNT',str(len(records))),('GROUPS',str(len(groups))),('MEASURED',str(measured)),('NOTICE',html.escape(notice)),('HASH',html.escape(source_hash)),('HEAD',head),('BODY',body)]:page=page.replace(key,text)
    return page.encode('utf-8'),b'\xef\xbb\xbf'+out.getvalue().encode('utf-8')

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--registro',required=True);ap.add_argument('--salida',required=True,help='prefijo de archivos .html y .csv; no se sobrescriben')
    args=ap.parse_args();source=Path(args.registro);raw=source.read_bytes()
    def invalid(_):raise ValueError('Numero JSON no finito')
    records=[json.loads(line,parse_constant=invalid) for line in raw.decode('utf-8-sig').splitlines() if line.strip()]
    if any(not isinstance(r,dict) for r in records):raise ValueError('Cada registro debe ser un objeto JSON')
    page,csv_data=render(records,hashlib.sha256(raw).hexdigest());prefix=Path(args.salida)
    targets=[(prefix.with_suffix('.html'),page),(prefix.with_suffix('.csv'),csv_data)]
    if any(p.exists() for p,_ in targets):raise FileExistsError('Elegir otro prefijo: no se sobrescriben reportes anteriores')
    prefix.parent.mkdir(parents=True,exist_ok=True)
    for p,data in targets:
        with p.open('xb') as f:f.write(data)
    print(json.dumps({'records':len(records),'provider_time_available':sum(value(r,'tiempo_proveedor_s') is not None for r in records),'html':str(targets[0][0]),'csv':str(targets[1][0]),'ai_calls':0},ensure_ascii=True))

if __name__=='__main__':main()
