from django.db import models

class Alert(models.Model):
    timestamp = models.DateTimeField(null=True, blank=True)
    titulo = models.CharField(max_length=255)
    descripcion = models.TextField()
    severidad = models.IntegerField(null=True, blank=True)

    riesgo_ia = models.CharField(max_length=100, blank=True, null=True)
    explicacion_ia = models.TextField(blank=True, null=True)

    estado = models.CharField(max_length=50, default="Pendiente")
    fuente = models.CharField(max_length=100, default="Wazuh")

    creado_en = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.titulo
