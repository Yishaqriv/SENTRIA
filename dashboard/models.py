from django.db import models

from dashboard.ia.alcance import ALCANCE_CHOICES, NO_DECLARADO


class ActivoLogico(models.Model):
    """
    Activo LÓGICO del laboratorio (café internet simulado). No es un equipo
    físico ni un agente de Wazuh: es contexto experimental configurable.
    Nunca contiene agent.id, hostname ni IP.
    """
    TIPO_CHOICES = [
        ("estacion_publica", "Estación pública"),
        ("equipo_administracion", "Equipo de administración"),
        ("servidor_interno", "Servidor interno"),
    ]
    CRITICIDAD_CHOICES = [
        ("media", "Media"),
        ("alta", "Alta"),
    ]
    OS_FAMILY_CHOICES = [
        ("windows", "Windows"),
        ("linux", "Linux"),
        ("otro", "Otro"),
        ("no_determinado", "No determinado"),
    ]
    OS_ROLE_CHOICES = [
        ("estacion_cliente", "Estación cliente"),
        ("administracion", "Administración"),
        ("servidor", "Servidor"),
    ]

    identificador = models.CharField(max_length=20, unique=True)   # EP-01, ADM-01, SRV-01
    nombre_visible = models.CharField(max_length=120)
    tipo_activo = models.CharField(max_length=30, choices=TIPO_CHOICES)
    criticidad = models.CharField(max_length=10, choices=CRITICIDAD_CHOICES)
    os_family = models.CharField(max_length=20, choices=OS_FAMILY_CHOICES, default="no_determinado")
    os_role = models.CharField(max_length=20, choices=OS_ROLE_CHOICES)
    hora_inicio_operacion = models.TimeField()
    hora_fin_operacion = models.TimeField()
    zona_horaria = models.CharField(max_length=64, default="America/Bogota")
    contexto_autorizado_es = models.TextField()
    activo = models.BooleanField(default=True)
    creado_en = models.DateTimeField(auto_now_add=True)
    actualizado_en = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["identificador"]
        verbose_name = "activo lógico"
        verbose_name_plural = "activos lógicos"

    def __str__(self):
        return f"{self.identificador} · {self.nombre_visible}"


class AsignacionAgenteActivo(models.Model):
    """
    CAPA PRIVADA (P) — Sprint 2C. Asignación **ACTUAL** de un agente físico de
    Wazuh (`agent.id`) a un `ActivoLogico`. Hay como mucho UNA fila por
    `agent.id`: la unicidad la garantiza la BASE DE DATOS con un índice
    `UNIQUE(agent_id)` normal — soportado por MySQL, MariaDB y SQLite por igual
    (sin `UniqueConstraint` condicional, que MySQL/MariaDB no garantizan).

    El `agent.id` vive EXCLUSIVAMENTE aquí, en `HistorialAsignacionAgente` y en
    `Alert.wazuh_agent_id`: nunca entra al prompt, al `contexto_ia_snapshot`, a
    la explicación, al dashboard del analista, al CSV ni a la respuesta de la IA.

    Reglas (ver INFORME_2C_CORRECCIONES_PREMYSQL):
    - Las asignaciones se crean/cambian a mano (`manage.py asignar_agente_activo`
      o admin), NUNCA por migración. El cambio es transaccional
      (`asignar_agente()`): actualiza esta fila y añade una entrada al historial.
    - Cambiar la asignación NO altera análisis históricos: una alerta ya
      `COMPLETED` conserva su `activo_logico` y su snapshot; sólo las alertas no
      `COMPLETED` se vuelven a resolver en una reingesta/reanálisis.
    - Un `agent.id` en `IA_AGENTES_BLOQUEADOS` (settings) no se asigna ni se
      resuelve. Para habilitarlo hay que retirarlo de esa lista de forma
      deliberada y auditada.
    """
    agent_id = models.CharField(max_length=32, unique=True)     # agent.id de Wazuh, p. ej. "000"
    etiqueta_privada = models.CharField(max_length=64, blank=True, default="")  # p. ej. "AGENT-01"
    activo_logico = models.ForeignKey(
        ActivoLogico, on_delete=models.PROTECT, related_name="asignacion_agente"
    )
    nota = models.TextField(blank=True, default="")
    creada_por = models.ForeignKey(
        "auth.User", null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    creada_en = models.DateTimeField(auto_now_add=True)
    actualizada_en = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["agent_id"]
        verbose_name = "asignación agente→activo (actual, privada)"
        verbose_name_plural = "asignaciones agente→activo (actuales, privadas)"

    def __str__(self):
        # Sólo se muestra en el admin (acceso de superusuario).
        return f"{self.etiqueta_privada or self.agent_id} → {self.activo_logico.identificador}"


class HistorialAsignacionAgente(models.Model):
    """
    CAPA PRIVADA (P) — Bitácora **append-only** de los cambios de asignación
    agente→activo. Ilimitada; nunca se edita ni se borra. `activo_identificador`
    es una instantánea inmutable (texto), así el histórico sigue siendo legible
    aunque después se elimine el `ActivoLogico`.
    """
    ACCIONES = [
        ("asignada", "Asignada por primera vez"),
        ("reemplazada", "Reemplazada por otra asignación"),
        ("desactivada", "Desactivada (agente sin activo)"),
    ]
    agent_id = models.CharField(max_length=32)
    activo_identificador = models.CharField(max_length=20)      # snapshot inmutable
    activo_logico = models.ForeignKey(
        ActivoLogico, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    accion = models.CharField(max_length=12, choices=ACCIONES)
    etiqueta_privada = models.CharField(max_length=64, blank=True, default="")
    nota = models.TextField(blank=True, default="")
    autor = models.ForeignKey(
        "auth.User", null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    registrado_en = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-registrado_en", "-id"]
        verbose_name = "cambio de asignación agente→activo (histórico)"
        verbose_name_plural = "cambios de asignación agente→activo (histórico)"

    def __str__(self):
        return f"{self.agent_id} {self.accion} {self.activo_identificador} @ {self.registrado_en:%Y-%m-%d}"


class VentanaMantenimiento(models.Model):
    """
    Ventana de mantenimiento AUTORIZADO sobre un `ActivoLogico` (Sprint 2G).

    Es contexto declarado por un analista: sirve para que la IA distinga una
    actividad esperada de una potencial amenaza. Estar DENTRO de una ventana
    NO convierte la alerta en FALSO_POSITIVO automáticamente — la IA conserva
    la decisión y pondera la evidencia técnica.

    Nunca contiene `agent.id`, hostname, IP, credenciales ni datos privados.
    Al prompt sólo llegan el ESTADO calculado y la CATEGORÍA controlada; la
    descripción libre, el creador y la auditoría se quedan fuera.
    """
    CATEGORIA_CHOICES = [
        ("actualizacion_software", "Actualización de software / parches"),
        ("cambio_configuracion", "Cambio de configuración"),
        ("mantenimiento_hardware", "Mantenimiento de hardware"),
        ("respaldo_restauracion", "Respaldo / restauración"),
        ("reinicio_servicios", "Reinicio de servicios"),
        ("limpieza_housekeeping", "Limpieza / housekeeping"),
        ("otro", "Otro (ver descripción)"),
    ]
    ESTADO_CHOICES = [
        ("ACTIVA", "Activa"),
        ("CANCELADA", "Cancelada"),
    ]

    activo_logico = models.ForeignKey(
        ActivoLogico, on_delete=models.PROTECT, related_name="ventanas_mantenimiento"
    )
    inicio = models.DateTimeField()
    fin = models.DateTimeField()
    categoria = models.CharField(max_length=30, choices=CATEGORIA_CHOICES)
    # Entrada 1.3: tipo de operación autorizada (categoría cerrada). Las ventanas anteriores quedan `no_declarado`.
    alcance_operacion = models.CharField(max_length=40, choices=ALCANCE_CHOICES, default=NO_DECLARADO)
    descripcion = models.CharField(max_length=280, blank=True, default="")
    creada_por = models.ForeignKey(
        "auth.User", null=True, blank=True, on_delete=models.SET_NULL,
        related_name="ventanas_mantenimiento_creadas",
    )
    creada_en = models.DateTimeField(auto_now_add=True)
    estado = models.CharField(max_length=10, choices=ESTADO_CHOICES, default="ACTIVA")
    cancelada_en = models.DateTimeField(null=True, blank=True)
    cancelada_por = models.ForeignKey(
        "auth.User", null=True, blank=True, on_delete=models.SET_NULL,
        related_name="ventanas_mantenimiento_canceladas",
    )

    class Meta:
        ordering = ["-inicio", "-id"]
        verbose_name = "ventana de mantenimiento"
        verbose_name_plural = "ventanas de mantenimiento"
        constraints = [
            models.CheckConstraint(
                condition=models.Q(fin__gt=models.F("inicio")),
                name="vm_fin_posterior_a_inicio",
            ),
        ]

    def __str__(self):
        return (f"{self.activo_logico.identificador} · {self.get_categoria_display()} · "
                f"{self.inicio:%Y-%m-%d %H:%M}→{self.fin:%H:%M} ({self.estado})")

    @property
    def activa(self):
        return self.estado == "ACTIVA"

    def cubre(self, momento):
        """True si `momento` (datetime aware) cae dentro de la ventana activa."""
        return self.estado == "ACTIVA" and self.inicio <= momento <= self.fin


class Alert(models.Model):
    # --- Enums del contrato IA ---
    ESTADO_ANALISIS_CHOICES = [
        ("PENDING", "Pendiente de análisis"),
        ("COMPLETED", "Análisis completado"),
        ("ANALISIS_FALLIDO", "Fallo de análisis"),
        ("OMITIDO_POLITICA", "Omitido por política"),
    ]
    MOTIVO_OMISION_CHOICES = [
        ("SIN_CONTEXTO_ACTIVO", "Sin contexto de activo"),
        ("NIVEL_NO_ELEGIBLE", "Nivel Wazuh no elegible"),
        ("RUIDO_OPERATIVO", "Ruido operativo confirmado"),
        ("REGLA_EXCLUIDA", "Regla o grupo excluido"),
    ]
    VEREDICTO_CHOICES = [
        ("FALSO_POSITIVO", "Falso positivo"),
        ("REQUIERE_ATENCION", "Requiere atención"),
    ]

    opensearch_id = models.CharField(max_length=255, unique=True, null=True, blank=True)
    timestamp = models.DateTimeField(null=True, blank=True)
    titulo = models.CharField(max_length=255)
    descripcion = models.TextField()
    severidad = models.IntegerField(null=True, blank=True)

    riesgo_ia = models.CharField(max_length=100, blank=True, null=True)
    explicacion_ia = models.TextField(blank=True, null=True)

    estado = models.CharField(max_length=50, default="Pendiente")
    fuente = models.CharField(max_length=100, default="Wazuh")

    veredicto_ia_correcto = models.BooleanField(null=True, blank=True)

    creado_en = models.DateTimeField(auto_now_add=True)

    # ------------------------------------------------------------------
    # Contrato IA (Sprint 2A). Todos nullables: las alertas anteriores a
    # este sprint los tienen en null y se siguen mostrando sin cambios.
    # ------------------------------------------------------------------
    estado_analisis = models.CharField(
        max_length=20, choices=ESTADO_ANALISIS_CHOICES, null=True, blank=True
    )
    veredicto_ia = models.CharField(
        max_length=20, choices=VEREDICTO_CHOICES, null=True, blank=True
    )
    factores_cvss = models.JSONField(null=True, blank=True)
    justificacion_cvss = models.TextField(null=True, blank=True)
    recomendacion_ia = models.TextField(null=True, blank=True)
    evidencia_faltante = models.JSONField(null=True, blank=True)
    respuesta_ia_original = models.TextField(null=True, blank=True)
    proveedor_ia = models.CharField(max_length=50, null=True, blank=True)
    modelo_ia = models.CharField(max_length=120, null=True, blank=True)
    analizado_en = models.DateTimeField(null=True, blank=True)

    # ------------------------------------------------------------------
    # Contexto del activo (Sprint 2B).
    # ------------------------------------------------------------------
    activo_logico = models.ForeignKey(
        ActivoLogico,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="alertas",
    )
    # Instantánea INMUTABLE del contexto que usó la IA. Cambiar el activo
    # después NO altera la explicación histórica de una alerta ya analizada.
    contexto_ia_snapshot = models.JSONField(null=True, blank=True)
    motivo_omision = models.CharField(
        max_length=30, choices=MOTIVO_OMISION_CHOICES, null=True, blank=True
    )
    # Datos de Wazuh que se conservan tal cual (no van al prompt salvo groups/id).
    wazuh_rule_id = models.CharField(max_length=16, null=True, blank=True)
    wazuh_rule_groups = models.JSONField(null=True, blank=True)

    # CAPA PRIVADA (P) — Sprint 2C. `agent.id` físico de Wazuh que originó la
    # alerta. Se conserva SÓLO para poder re-resolver el activo lógico si la
    # asignación cambia después (reingesta/reanálisis de alertas no COMPLETED).
    # NUNCA se renderiza en el dashboard, ni se exporta a CSV, ni entra al
    # prompt / contexto_ia_snapshot / explicación / respuesta de la IA.
    wazuh_agent_id = models.CharField(max_length=32, null=True, blank=True)

    # ------------------------------------------------------------------
    # Corrección humana: separada del resultado original de la IA, que
    # NUNCA se sobrescribe. Se conservan autor, fecha y motivo.
    # ------------------------------------------------------------------
    correccion_veredicto = models.CharField(
        max_length=20, choices=VEREDICTO_CHOICES, null=True, blank=True
    )
    correccion_autor = models.ForeignKey(
        "auth.User",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="correcciones_alertas",
    )
    correccion_fecha = models.DateTimeField(null=True, blank=True)
    correccion_motivo = models.TextField(null=True, blank=True)

    # ------------------------------------------------------------------
    # Migración segura del legado (Sprint 3C/3D, aditivo). Antes de aplicar el
    # contrato de IA actual a una alerta legado (`estado_analisis` NULL), su
    # `riesgo_ia`/`explicacion_ia`/`estado`/`severidad` ANTERIORES se copian
    # aquí. Así la migración nunca pierde ni sobrescribe sin respaldo el
    # análisis legado histórico, aunque reutilice los mismos campos.
    # ------------------------------------------------------------------
    legado_snapshot = models.JSONField(
        null=True, blank=True,
        help_text="Copia de riesgo_ia/explicacion_ia/estado/severidad previos a migrar del flujo legado.",
    )

    def __str__(self):
        return self.titulo

    # --- Ayudas de presentación (no tocan la base de datos) ---
    @property
    def tiene_correccion_humana(self):
        return bool(self.correccion_veredicto)

    @property
    def veredicto_efectivo(self):
        """Veredicto vigente: la corrección humana si existe, si no el de la IA."""
        return self.correccion_veredicto or self.veredicto_ia

    @property
    def analisis_fallido(self):
        return self.estado_analisis == "ANALISIS_FALLIDO"

    @property
    def analisis_completado(self):
        return self.estado_analisis == "COMPLETED"

    @property
    def analisis_legado(self):
        """
        Alerta anterior al contrato de IA (Sprint 2A+): `estado_analisis` NULL.
        Su `riesgo_ia`/`explicacion_ia` provienen del flujo antiguo y NO siguen
        el contrato nuevo (CVSS, veredicto binario, evidencia). No se reinterpretan.
        """
        return self.estado_analisis is None

    @property
    def omitido_por_politica(self):
        return self.estado_analisis == "OMITIDO_POLITICA"

    @property
    def verdad_terreno(self):
        """
        Etiqueta de VERDAD DE TERRENO (ground truth): existe SÓLO tras una
        revisión humana CONFIRMADA o CORREGIDA. `None` si no hay revisión, o si
        la revisión excluyó la alerta del dataset.
        """
        rev = getattr(self, "revision_humana", None)
        if rev is None or rev.accion not in ("CONFIRMADA", "CORREGIDA"):
            return None
        return rev.veredicto_verdad_terreno

    @property
    def estado_revision(self):
        rev = getattr(self, "revision_humana", None)
        return rev.accion if rev is not None else "SIN_REVISAR"

    @property
    def dataset_aprobado(self):
        """True si el candidato del dataset de esta alerta está APROBADO (inmutable, 3C/3D)."""
        cand = getattr(self, "candidato_dataset", None)
        return cand is not None and cand.estado == "APROBADO"


class RevisionHumana(models.Model):
    """
    Revisión humana de una alerta ya analizada. Fuente de la VERDAD DE TERRENO
    para métricas y dataset. NUNCA toca los campos originales de la IA
    (`veredicto_ia`, `riesgo_ia`, `explicacion_ia`, `factores_cvss`, ...).

    Los campos `Alert.correccion_*` se conservan por compatibilidad (colas y
    veredicto efectivo); una revisión CORREGIDA los actualiza, CONFIRMADA/EXCLUIDA
    no cambian el veredicto efectivo.
    """
    ACCION_CHOICES = [
        ("CONFIRMADA", "Confirmada (de acuerdo con la IA)"),
        ("CORREGIDA", "Corregida (en desacuerdo con la IA)"),
        ("EXCLUIDA", "Excluida del dataset (evidencia insuficiente)"),
    ]
    # Origen auditable de la revisión (Sprint 3C/3D, aditivo). No cambia la
    # verdad de terreno ni los valores de la matriz: es sólo procedencia, para
    # que /metricas/ pueda advertir cuándo una cifra no es una muestra
    # estadística representativa (p. ej. una única prueba controlada).
    ORIGEN_CHOICES = [
        ("PRUEBA_CONTROLADA", "Prueba controlada (evento de laboratorio dirigido)"),
        ("OPERATIVA", "Revisión operativa normal"),
        ("AUDITORIA_SELECTIVA", "Auditoría selectiva de falsos positivos de la IA"),
        ("MIGRACION_LEGADO", "Migración de una alerta del flujo legado"),
    ]
    MOTIVO_CHOICES = [
        ("actividad_autorizada", "Actividad autorizada"),
        ("mantenimiento_programado", "Mantenimiento programado"),
        ("comportamiento_normal", "Comportamiento normal"),
        ("evidencia_amenaza", "Evidencia de amenaza"),
        ("contexto_insuficiente", "Contexto insuficiente"),
        ("otro", "Otro"),
    ]
    RIESGO_CHOICES = [
        ("LOW", "Bajo"), ("MEDIUM", "Medio"), ("HIGH", "Alto"), ("CRITICAL", "Crítico"),
    ]

    alerta = models.OneToOneField(
        "Alert", on_delete=models.CASCADE, related_name="revision_humana"
    )
    accion = models.CharField(max_length=12, choices=ACCION_CHOICES)
    veredicto_verdad_terreno = models.CharField(
        max_length=20, choices=Alert.VEREDICTO_CHOICES, null=True, blank=True,
        help_text="Etiqueta de verdad de terreno. Null si la revisión es EXCLUIDA.",
    )
    riesgo_revisado = models.CharField(
        max_length=10, choices=RIESGO_CHOICES, null=True, blank=True
    )
    motivo_categoria = models.CharField(max_length=30, choices=MOTIVO_CHOICES)
    origen = models.CharField(
        max_length=20, choices=ORIGEN_CHOICES, default="OPERATIVA",
        help_text="Procedencia auditable de la revisión. No es una muestra estadística representativa "
                  "salvo OPERATIVA en volumen suficiente.",
    )
    nota = models.TextField(blank=True, default="")
    autor = models.ForeignKey(
        "auth.User", null=True, blank=True, on_delete=models.SET_NULL,
        related_name="revisiones_humanas",
    )
    creada_en = models.DateTimeField(auto_now_add=True)
    actualizada_en = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-actualizada_en", "-id"]

    def __str__(self):
        return f"Revisión {self.accion} de alerta {self.alerta_id}"

    @property
    def tiene_verdad_terreno(self):
        return (self.accion in ("CONFIRMADA", "CORREGIDA")
                and self.veredicto_verdad_terreno in ("FALSO_POSITIVO", "REQUIERE_ATENCION"))


class CandidatoDataset(models.Model):
    """
    Candidato SUPERVISADO para el dataset de entrenamiento. Se construye
    AUTOMÁTICAMENTE desde `Alert.contexto_ia_snapshot` (capa E ya congelada y
    anonimizada) + `RevisionHumana`. No se copian alertas a mano.

    La salida objetivo parte de la respuesta de Gemini; si el humano cambió el
    veredicto y no revisó riesgo/explicación/CVSS/recomendación/evidencia
    faltante, el candidato queda INCOMPLETO. APROBADO nunca es automático.
    """
    ESTADO_CHOICES = [
        ("INCOMPLETO", "Incompleto"),
        ("LISTO_PARA_REVISION", "Listo para revisión"),
        ("DEVUELTO", "Devuelto con observaciones"),
        ("APROBADO", "Aprobado"),
        ("EXCLUIDO", "Excluido"),
    ]

    alerta = models.OneToOneField(
        "Alert", on_delete=models.CASCADE, related_name="candidato_dataset"
    )
    ejemplo_id = models.CharField(max_length=40, unique=True, editable=False)
    fingerprint = models.CharField(max_length=64, db_index=True, blank=True, default="")
    estado = models.CharField(max_length=24, choices=ESTADO_CHOICES, default="INCOMPLETO")
    salida_objetivo_revisada = models.BooleanField(
        default=False,
        help_text="El revisor confirmó que revisó riesgo, explicación, CVSS, recomendación y evidencia faltante.",
    )
    # Borrador editable de la salida objetivo supervisada. `None` = todavía se usa
    # la salida derivada automáticamente (respuesta de Gemini con el verdict = verdad de terreno).
    salida_objetivo_editada = models.JSONField(null=True, blank=True)
    completado_por = models.ForeignKey(
        "auth.User", null=True, blank=True, on_delete=models.SET_NULL,
        related_name="candidatos_completados",
        help_text="Quién dejó el candidato LISTO_PARA_REVISION. No puede ser quien lo apruebe.",
    )
    completado_en = models.DateTimeField(null=True, blank=True)
    privacidad_ok = models.BooleanField(default=False)
    duplicado_de = models.CharField(max_length=40, blank=True, default="")
    diagnostico = models.JSONField(
        null=True, blank=True,
        help_text="Sanitizado: motivos de incompletitud, hallazgos de privacidad, duplicado.",
    )
    creado_en = models.DateTimeField(auto_now_add=True)
    sincronizado_en = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-creado_en", "-id"]

    def __str__(self):
        return f"Candidato {self.ejemplo_id} ({self.estado})"


class RevisionCandidato(models.Model):
    """
    Segunda revisión (append-only) de un `CandidatoDataset`. Quien completa el
    borrador NO puede aprobarlo: se exige un segundo ADMIN/ANALISTA. No se borran
    ni sobrescriben revisiones anteriores.
    """
    DECISION_CHOICES = [
        ("APROBADO", "Aprobado"),
        ("DEVUELTO", "Devuelto con observaciones"),
        ("EXCLUIDO", "Excluido"),
    ]
    candidato = models.ForeignKey(
        "CandidatoDataset", on_delete=models.CASCADE, related_name="revisiones"
    )
    decision = models.CharField(max_length=12, choices=DECISION_CHOICES)
    autor = models.ForeignKey(
        "auth.User", null=True, blank=True, on_delete=models.SET_NULL,
        related_name="revisiones_candidato",
    )
    observaciones = models.TextField(blank=True, default="")
    # Huellas de integridad (`sellos.huella_integridad`) de la entrada y la salida
    # en el momento de la decisión. Vacías en revisiones anteriores a los sellos.
    entrada_sha256 = models.CharField(max_length=64, blank=True, default="")
    salida_sha256 = models.CharField(max_length=64, blank=True, default="")
    serializacion_version = models.CharField(max_length=32, blank=True, default="")
    # Modo con el que se tomó la decisión y, si fue por lote, la aceptación que la originó.
    MODO_CHOICES = [("DOBLE", "Doble revisión"), ("REVISOR_UNICO_LOTE", "Revisión consolidada por lote")]
    modo_revision = models.CharField(max_length=24, choices=MODO_CHOICES, default="DOBLE")
    aceptacion_lote = models.ForeignKey(
        "AceptacionLote", null=True, blank=True, on_delete=models.PROTECT, related_name="revisiones"
    )
    creada_en = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-creada_en", "-id"]

    def __str__(self):
        return f"Revisión {self.decision} de {self.candidato.ejemplo_id}"


class _SoloInsercionQuerySet(models.QuerySet):
    def update(self, **kwargs):
        raise ValueError("registro inmutable: no se puede actualizar")

    def delete(self):
        raise ValueError("registro inmutable: no se puede borrar")


class _RegistroInmutable(models.Model):
    """Base append-only: se inserta una vez y nunca se actualiza ni se borra."""
    objects = _SoloInsercionQuerySet.as_manager()

    class Meta:
        abstract = True

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValueError("registro inmutable: no se puede actualizar")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValueError("registro inmutable: no se puede borrar")


class EntradaRevisada(_RegistroInmutable):
    """
    Entrada de un candidato CONGELADA (append-only, ver `dashboard/sellos.py`).
    Cada re-congelación crea otra versión enlazada con la anterior; ninguna se
    sobrescribe. `origen` distingue lo verificado de lo conservado o derivado.
    """
    ORIGEN_CHOICES = [
        ("ENTRADA_REVISADA", "Entrada revisada: congelada al guardar el borrador"),
        ("SNAPSHOT_CONSERVADO", "Histórico: snapshot conservado; solo coincide la huella semántica"),
        ("HUELLA_LEGADO_VERIFICADA", "Histórico: coincide una huella completa de un algoritmo anterior"),
        ("DERIVADA", "Derivada por una transformación explícita (no es la original)"),
        ("NO_VERIFICABLE", "No verificable"),
    ]
    candidato = models.ForeignKey(
        "CandidatoDataset", on_delete=models.PROTECT, related_name="entradas_revisadas"
    )
    version = models.PositiveIntegerField()
    anterior = models.OneToOneField(
        "self", null=True, blank=True, on_delete=models.PROTECT, related_name="siguiente"
    )
    origen = models.CharField(max_length=32, choices=ORIGEN_CHOICES)
    entrada = models.JSONField()
    entrada_sha256 = models.CharField(max_length=64)
    snapshot_sha256 = models.CharField(max_length=64)
    serializacion_version = models.CharField(max_length=32)
    seleccion_version = models.CharField(max_length=32)
    algoritmo_verificacion = models.CharField(max_length=40, blank=True, default="")
    transformacion_id = models.CharField(max_length=60, blank=True, default="")
    motivo = models.TextField(blank=True, default="")
    limitaciones = models.TextField(blank=True, default="")
    # Texto (no FK): un registro inmutable no puede quedar alterado al borrar un usuario.
    creada_por = models.CharField(max_length=150, blank=True, default="")
    creada_en = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["candidato_id", "version"]
        constraints = [
            models.UniqueConstraint(fields=["candidato", "version"], name="entrada_revisada_version_unica"),
        ]

    def __str__(self):
        return f"Entrada v{self.version} ({self.origen}) de {self.candidato_id}"


class ConfirmacionBorrador(_RegistroInmutable):
    """Salida confirmada al enviar a revisión, enlazada con la entrada revisada vigente."""
    candidato = models.ForeignKey(
        "CandidatoDataset", on_delete=models.PROTECT, related_name="confirmaciones"
    )
    entrada_revisada = models.ForeignKey(
        "EntradaRevisada", on_delete=models.PROTECT, related_name="confirmaciones"
    )
    salida = models.JSONField()
    salida_sha256 = models.CharField(max_length=64)
    serializacion_version = models.CharField(max_length=32)
    confirmada_por = models.CharField(max_length=150, blank=True, default="")
    creada_en = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["candidato_id", "creada_en", "id"]

    def __str__(self):
        return f"Confirmación de {self.candidato_id} ({self.creada_en:%Y-%m-%d %H:%M})"


class AceptacionLote(_RegistroInmutable):
    """
    Aceptación EXPLÍCITA e inmutable de un lote en modo REVISOR_UNICO_LOTE
    (ver `dashboard/lotes.py`). Identifica al humano responsable, conserva la
    declaración metodológica y sella la lista resumida y el manifiesto exacto
    del lote (casos, confirmaciones y huellas).
    """
    modo = models.CharField(max_length=24)
    responsable = models.CharField(max_length=150)          # texto: un registro inmutable no depende de la FK
    responsable_id = models.PositiveIntegerField()
    declaracion = models.TextField()
    lista_comprobacion = models.JSONField()
    lista_sha256 = models.CharField(max_length=64)
    referencia_revision = models.TextField()
    manifiesto_sha256 = models.CharField(max_length=64, unique=True)
    n_casos = models.PositiveIntegerField()
    serializacion_version = models.CharField(max_length=32)
    creada_en = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["creada_en", "id"]

    def __str__(self):
        return f"Lote {self.manifiesto_sha256[:12]} ({self.n_casos} casos, {self.responsable})"


class AceptacionLoteItem(_RegistroInmutable):
    """Caso de un lote aceptado. Solo lo crea `lotes.aceptar_lote`, en la misma transacción que el lote."""
    lote = models.ForeignKey("AceptacionLote", on_delete=models.PROTECT, related_name="items")
    candidato = models.ForeignKey("CandidatoDataset", on_delete=models.PROTECT, related_name="items_lote")
    confirmacion = models.ForeignKey("ConfirmacionBorrador", on_delete=models.PROTECT, related_name="items_lote")
    entrada_revisada = models.ForeignKey("EntradaRevisada", on_delete=models.PROTECT, related_name="items_lote")
    entrada_sha256 = models.CharField(max_length=64)
    salida_sha256 = models.CharField(max_length=64)

    class Meta:
        ordering = ["lote_id", "id"]
        constraints = [
            # Un candidato solo puede aceptarse en un lote, y un lote no repite casos.
            models.UniqueConstraint(fields=["candidato"], name="lote_item_candidato_unico"),
        ]

    def save(self, *args, **kwargs):
        if not getattr(self, "_desde_aceptar_lote", False):
            raise ValueError("los casos de un lote solo se crean al aceptarlo: no se pueden añadir después")
        super().save(*args, **kwargs)
