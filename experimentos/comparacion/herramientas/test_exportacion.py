import csv,io,json,unittest
from exportar_resultados import render,value

class ExportTests(unittest.TestCase):
    def test_realistic_measures_and_missing(self):
        rows=[{'caso':'WEB','proveedor':'gemini','tokens_entrada':1702,'tokens_salida':430,'tokens_total':2132,'tiempo_proveedor_s':5.22},
              {'caso':'WIN','proveedor':'gemini','tokens_total':None,'tiempo_proveedor_s':None}]
        page,data=render(rows,'a'*64)
        table=list(csv.reader(io.StringIO(data.decode('utf-8-sig')),delimiter=';'))
        self.assertEqual(table[1][7],'5.22');self.assertEqual(table[1][12],'2132');self.assertEqual(table[2][12],'No disponible')
        self.assertIn(b'1702',page);self.assertIn(b'1 / 2',page)
    def test_escape_html_and_csv_formulas(self):
        page,data=render([{'caso':'<script>alert(1)</script>','proveedor':'=1+1'}],'b'*64)
        self.assertNotIn(b'<script>',page);self.assertIn(b'&lt;script&gt;',page)
        table=list(csv.reader(io.StringIO(data.decode('utf-8-sig')),delimiter=';'))
        self.assertEqual(table[1][2],"'=1+1")
    def test_invalid_measures_are_not_zero(self):
        for bad in (True,-1,'20',{},float('nan')):self.assertIsNone(value({'tokens_total':bad},'tokens_total'))
        self.assertIsNone(value({'tiempo_proveedor_s':float('inf')},'tiempo_proveedor_s'))
        self.assertEqual(value({'tokens_total':0},'tokens_total'),0)
    def test_only_allowed_fields_exported(self):
        page,data=render([{'caso':'test','secret_extra':'SECRET_NO_EXPORTAR','configuracion':{'api_key':'SECRET_NO_EXPORTAR'}}],'c'*64)
        self.assertNotIn(b'SECRET_NO_EXPORTAR',page+data)

    def test_registro_v2_muestra_equivalencia_y_uuid(self):
        u='0b7f6c1e-1b2a-4c3d-9e8f-0123456789ab'
        page,data=render([{'registro_version':'registro_comparacion_v2','uuid':u,'caso':'CASO-WEB-01','proveedor':'p',
                           'equivalencia':'variante','categoria_error':'excepcion_adaptador:RuntimeError','tokens_total':None}],'d'*64)
        table=list(csv.reader(io.StringIO(data.decode('utf-8-sig')),delimiter=';'))
        self.assertEqual(table[1][-3:],['variante','excepcion_adaptador:RuntimeError',u])
        self.assertEqual(table[1][12],'No disponible')

if __name__=='__main__':unittest.main()
