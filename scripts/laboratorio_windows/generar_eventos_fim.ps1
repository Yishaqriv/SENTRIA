<#
.SYNOPSIS
    Generador SEGURO y reproducible de eventos FIM sinteticos para el
    laboratorio Windows de SENTRIA (activo logico LAPTOP-01).

.DESCRIPTION
    Crea, modifica y elimina archivos de texto SINTETICOS exclusivamente dentro
    del directorio aislado de laboratorio, para que Wazuh (FIM en tiempo real)
    produzca alertas reales. Cada escenario es una prueba controlada autorizada:
    la verdad esperada es FALSO_POSITIVO.

      - Creacion                   -> control de politica (nivel 5, no elegible).
      - Modificacion / eliminacion -> eventos objetivo (nivel 7).
      - En los escenarios 'modified' la eliminacion final es LIMPIEZA
        (tambien produce un evento nivel 7 y queda registrada como tal).

    Por defecto es un DRY-RUN: solo muestra el plan. Para operar exige -Confirmar.

    Salvaguardas:
      - Raiz FIJA (no parametrizable). Se rechaza si no existe, no es un
        directorio, es un punto de reanalisis/enlace o no esta vacia; y se
        revalida antes de cada operacion destructiva.
      - Cada ruta se normaliza y se rechaza si sale de la raiz.
      - Los archivos se crean en modo exclusivo (nunca se sobrescribe uno ajeno).
      - Solo se borran los archivos exactos creados por ESTA ejecucion, uno a uno.
      - Maximo 30 escenarios; intervalo minimo 10 s (por defecto 20 s).
      - Se detiene en el primer error, lo anota en el manifiesto, limpia
        unicamente sus propios archivos y guarda el manifiesto en todo caso.
      - Sin red, sin credenciales, sin cambios de sistema, sin procesos externos.
      - El manifiesto (capa privada) se escribe fuera del directorio monitorizado,
        en %LOCALAPPDATA%\SENTRIA\manifiestos_fim, nunca en el repositorio.

.EXAMPLE
    .\generar_eventos_fim.ps1 -Escenarios 3
    (dry-run: muestra el plan, no toca nada)

.EXAMPLE
    .\generar_eventos_fim.ps1 -Escenarios 3 -Confirmar
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 30)]
    [int] $Escenarios = 3,

    [ValidateRange(10, 600)]
    [int] $IntervaloSegundos = 20,

    [switch] $Confirmar
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Constantes (no parametrizables)
# ---------------------------------------------------------------------------
$SchemaVersion   = '1.1'
$LabRoot         = 'C:\SENTRIA-LAB'
$MaxEscenarios   = 30
$IntervaloMinimo = 10
$ManifestRel     = 'SENTRIA\manifiestos_fim'

$Tipos       = @('modified', 'deleted')
$Extensiones = @('txt', 'csv', 'json', 'md')
$Tamanos     = [ordered]@{ vacio = 0; pequeno = 256; mediano = 32768 }
$ModosCambio = @('aumento', 'reduccion', 'mismo_tamano')

if ($Escenarios -gt $MaxEscenarios) { throw "Maximo $MaxEscenarios escenarios por ejecucion." }
if ($IntervaloSegundos -lt $IntervaloMinimo) { throw "El intervalo minimo es $IntervaloMinimo s." }

# ---------------------------------------------------------------------------
# Validaciones de ruta
# ---------------------------------------------------------------------------
function Assert-RaizLaboratorio {
    if (-not (Test-Path -LiteralPath $LabRoot -PathType Container)) {
        throw 'La raiz del laboratorio no existe o no es un directorio.'
    }
    $item = Get-Item -LiteralPath $LabRoot -Force
    if ([int]($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'La raiz del laboratorio es un punto de reanalisis o enlace: se rechaza.'
    }
    $resuelta = [System.IO.Path]::GetFullPath($LabRoot).TrimEnd('\')
    if (-not [string]::Equals($resuelta, $LabRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'La raiz del laboratorio no se resuelve a si misma.'
    }
}

function Get-RutaSegura([string] $Nombre) {
    if ($Nombre -notmatch '^f_[0-9a-f]{12}\.[a-z]{2,4}$') {
        throw 'Nombre de archivo no permitido.'
    }
    $completa = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($LabRoot, $Nombre))
    $prefijo = $LabRoot.TrimEnd('\') + '\'
    if (-not $completa.StartsWith($prefijo, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'La ruta resultante escapa de la raiz del laboratorio.'
    }
    $padre = [System.IO.Path]::GetDirectoryName($completa)
    if (-not [string]::Equals($padre, $LabRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Solo se permiten archivos directamente bajo la raiz del laboratorio.'
    }
    return $completa
}

function Assert-ArchivoPropio([string] $Ruta, [hashtable] $Creados) {
    # Antes de CADA operacion destructiva: la raiz sigue siendo valida (no se
    # sustituyo por un enlace) y el archivo es propio, regular y directo.
    Assert-RaizLaboratorio
    if (-not $Creados.ContainsKey($Ruta)) { throw 'El archivo no fue creado por esta ejecucion.' }
    $padre = [System.IO.Path]::GetDirectoryName([System.IO.Path]::GetFullPath($Ruta))
    if (-not [string]::Equals($padre, $LabRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'El archivo no esta directamente bajo la raiz del laboratorio.'
    }
    $item = Get-Item -LiteralPath $Ruta -Force
    if ($item.PSIsContainer) { throw 'Se esperaba un archivo, no un directorio.' }
    if ([int]($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'El archivo es un punto de reanalisis o enlace: se rechaza.'
    }
}

# ---------------------------------------------------------------------------
# Contenido sintetico (sin secretos, sin datos personales)
# ---------------------------------------------------------------------------
function Get-BytesSinteticos([int] $Bytes, [int] $Variante) {
    # La coma evita que PowerShell desenrolle el arreglo (un arreglo vacio
    # llegaria al llamador como $null).
    if ($Bytes -le 0) { return ,([byte[]]::new(0)) }
    $linea = "SENTRIA laboratorio controlado - contenido sintetico - variante $Variante`n"
    $sb = New-Object System.Text.StringBuilder
    while ($sb.Length -lt $Bytes) { [void] $sb.Append($linea) }
    $texto = $sb.ToString().Substring(0, $Bytes)
    return ,([System.Text.Encoding]::ASCII.GetBytes($texto))
}

function New-ArchivoSintetico([string] $Ruta, [int] $Bytes) {
    # CreateNew: falla si el archivo ya existe; nunca sobrescribe.
    $fs = [System.IO.File]::Open($Ruta, [System.IO.FileMode]::CreateNew,
                                 [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $b = Get-BytesSinteticos $Bytes 0
        if ($b.Length -gt 0) { $fs.Write($b, 0, $b.Length) }
    } finally { $fs.Dispose() }
}

function Set-ContenidoSintetico([string] $Ruta, [int] $Bytes, [int] $Variante) {
    $fs = [System.IO.File]::Open($Ruta, [System.IO.FileMode]::Open,
                                 [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $fs.SetLength(0)
        $b = Get-BytesSinteticos $Bytes $Variante
        if ($b.Length -gt 0) { $fs.Write($b, 0, $b.Length) }
    } finally { $fs.Dispose() }
}

function Remove-ArchivoPropio([string] $Ruta, [hashtable] $Creados) {
    Assert-ArchivoPropio $Ruta $Creados
    [System.IO.File]::Delete($Ruta)
    $Creados.Remove($Ruta)
}

# ---------------------------------------------------------------------------
# Plan determinista y balanceado (cubre las 24 combinaciones antes de repetir)
# ---------------------------------------------------------------------------
function Get-Plan([int] $N) {
    $plan = @()
    $k = 0
    for ($i = 0; $i -lt $N; $i++) {
        $tipo = $Tipos[$i % 2]
        $tamano = @($Tamanos.Keys)[$i % 3]
        $ext = $Extensiones[[int](($i + [math]::Floor($i / 6)) % 4)]
        $modo = $null
        if ($tipo -eq 'modified') {
            $modo = if ($tamano -eq 'vacio') { 'aumento' } else { $ModosCambio[$k % 3] }
            $k++
        }
        $plan += [pscustomobject]@{ indice = $i; tipo = $tipo; extension = $ext; tamano = $tamano; modo_cambio = $modo }
    }
    return $plan
}

function Get-BytesModificacion([string] $Tamano, [string] $Modo) {
    $base = $Tamanos[$Tamano]
    switch ($Modo) {
        'aumento'      { return [int][math]::Max(64, $base * 2) }
        'reduccion'    { return [int][math]::Floor($base / 2) }
        'mismo_tamano' { return [int]$base }
    }
    throw 'Modo de cambio desconocido.'
}

function New-IdOpaco { return [System.Guid]::NewGuid().ToString('N').Substring(0, 12) }

# ISO 8601 en UTC con offset explicito, p. ej. 2026-10-05T22:42:07.123+00:00
function Get-AhoraUtc { return [System.DateTimeOffset]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffzzz') }

# ---------------------------------------------------------------------------
# Dry-run (por defecto)
# ---------------------------------------------------------------------------
$plan = @(Get-Plan $Escenarios)
$intervalos = ($plan | ForEach-Object { if ($_.tipo -eq 'modified') { 3 } else { 2 } } | Measure-Object -Sum).Sum
$duracion = [math]::Round(($intervalos * $IntervaloSegundos) / 60, 1)
$nObjetivo = $Escenarios
$nLimpieza = @($plan | Where-Object { $_.tipo -eq 'modified' }).Count

Write-Host 'SENTRIA - generador FIM del laboratorio Windows'
Write-Host ("  escenarios: {0} (max {1}) | intervalo: {2} s | duracion aprox.: {3} min" -f $Escenarios, $MaxEscenarios, $IntervaloSegundos, $duracion)
Write-Host '  por operacion:'; $plan | Group-Object tipo      | ForEach-Object { Write-Host ("    {0}: {1}" -f $_.Name, $_.Count) }
Write-Host '  por extension:'; $plan | Group-Object extension | ForEach-Object { Write-Host ("    {0}: {1}" -f $_.Name, $_.Count) }
Write-Host '  por tamano:';    $plan | Group-Object tamano    | ForEach-Object { Write-Host ("    {0}: {1}" -f $_.Name, $_.Count) }
Write-Host ("  eventos esperados: {0} creacion (nivel 5, control) + {1} objetivo (nivel 7) + {2} limpieza (nivel 7)" -f $Escenarios, $nObjetivo, $nLimpieza)

if (-not $Confirmar) {
    Write-Host 'DRY-RUN: no se creo, modifico ni borro ningun archivo y no se escribio manifiesto. Usa -Confirmar para ejecutar.'
    return
}

# ---------------------------------------------------------------------------
# Ejecucion real (solo con -Confirmar)
# ---------------------------------------------------------------------------
Assert-RaizLaboratorio
if (@(Get-ChildItem -LiteralPath $LabRoot -Force).Count -gt 0) {
    throw 'La raiz del laboratorio no esta vacia: vaciala manualmente antes de ejecutar.'
}

if (-not $env:LOCALAPPDATA) { throw 'LOCALAPPDATA no esta definido.' }
$manifestDir = Join-Path $env:LOCALAPPDATA $ManifestRel
$manifestDirFull = [System.IO.Path]::GetFullPath($manifestDir)
if ($manifestDirFull.StartsWith($LabRoot.TrimEnd('\') + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'El manifiesto no puede quedar dentro del directorio monitorizado.'
}
New-Item -ItemType Directory -Path $manifestDirFull -Force | Out-Null

$runId = New-IdOpaco
$manifestPath = Join-Path $manifestDirFull ("fim_{0}.json" -f $runId)
$manifest = [ordered]@{
    schema_version    = $SchemaVersion
    run_id            = $runId
    activo_logico     = 'LAPTOP-01'
    iniciado_utc      = Get-AhoraUtc
    finalizado_utc    = $null
    intervalo_s       = $IntervaloSegundos
    exito             = $false
    error             = $null
    escenarios        = @()
}

function Save-Manifiesto {
    $json = $manifest | ConvertTo-Json -Depth 8
    [System.IO.File]::WriteAllText($manifestPath, $json, (New-Object System.Text.UTF8Encoding($false)))
}

# rol: control_politica (creacion, nivel 5) | objetivo (evento que se quiere
# etiquetar) | limpieza (eliminacion final de un escenario modified) |
# limpieza_por_error (eliminacion tras un fallo).
function Add-Operacion($Escenario, [string] $Operacion, [string] $EventoEsperado, [int] $NivelEsperado,
                       [string] $Rol, [bool] $Exito = $true, [string] $Detalle = $null) {
    $Escenario.operaciones += [ordered]@{
        operacion             = $Operacion
        rol                   = $Rol
        evento_fim_esperado   = $EventoEsperado
        nivel_wazuh_esperado  = $NivelEsperado
        timestamp_utc         = Get-AhoraUtc
        exito                 = $Exito
        error                 = $Detalle
    }
    Save-Manifiesto
}

$creados = @{}          # ruta exacta -> escenario propietario (capa privada)
$escActual = $null
$opActual = $null       # operacion en curso, para dejar traza si falla
Save-Manifiesto
try {
    foreach ($p in $plan) {
        $escenarioId = New-IdOpaco
        $nombre = "f_{0}.{1}" -f $escenarioId, $p.extension
        $ruta = Get-RutaSegura $nombre
        $esc = [ordered]@{
            scenario_id              = $escenarioId
            tipo                     = $p.tipo
            extension                = $p.extension
            categoria_tamano         = $p.tamano
            modo_cambio              = $p.modo_cambio
            verdad_esperada          = 'FALSO_POSITIVO'
            origen                   = 'PRUEBA_CONTROLADA'
            motivo                   = 'prueba_controlada_autorizada'
            motivo_categoria_sentria = 'actividad_autorizada'
            operaciones              = @()
            exito                    = $false
            # CAPA PRIVADA: relacion inequivoca escenario <-> archivo, solo para
            # correlacion local. Nunca va a la evidencia de la IA ni al dataset.
            privado_no_exportable    = [ordered]@{ capa = 'P'; nombre_archivo = $nombre; ruta = $ruta }
        }
        $manifest.escenarios += $esc
        $escActual = $esc

        $opActual = @('crear', 'added', 5, 'control_politica')
        Assert-RaizLaboratorio
        New-ArchivoSintetico $ruta $Tamanos[$p.tamano]
        $creados[$ruta] = $esc
        Add-Operacion $esc 'crear' 'added' 5 'control_politica'
        Start-Sleep -Seconds $IntervaloSegundos

        if ($p.tipo -eq 'modified') {
            $opActual = @('modificar', 'modified', 7, 'objetivo')
            Assert-ArchivoPropio $ruta $creados
            Set-ContenidoSintetico $ruta (Get-BytesModificacion $p.tamano $p.modo_cambio) ($p.indice + 1)
            Add-Operacion $esc 'modificar' 'modified' 7 'objetivo'
            Start-Sleep -Seconds $IntervaloSegundos
        }

        $rolEliminar = if ($p.tipo -eq 'deleted') { 'objetivo' } else { 'limpieza' }
        $opActual = @('eliminar', 'deleted', 7, $rolEliminar)
        Remove-ArchivoPropio $ruta $creados
        Add-Operacion $esc 'eliminar' 'deleted' 7 $rolEliminar
        $opActual = $null
        $esc.exito = $true
        Save-Manifiesto
        Start-Sleep -Seconds $IntervaloSegundos
    }
    $manifest.exito = $true
}
catch {
    $manifest.error = $_.Exception.Message
    if ($null -ne $escActual -and $null -ne $opActual) {
        Add-Operacion $escActual $opActual[0] $opActual[1] $opActual[2] $opActual[3] $false $manifest.error
    }
    # Limpieza: SOLO los archivos exactos creados por esta ejecucion que sigan existiendo.
    foreach ($r in @($creados.Keys)) {
        $dueno = $creados[$r]
        try {
            if (Test-Path -LiteralPath $r -PathType Leaf) {
                Remove-ArchivoPropio $r $creados
                Add-Operacion $dueno 'eliminar' 'deleted' 7 'limpieza_por_error'
            }
        } catch {
            $manifest.error += ' | limpieza incompleta'
            Add-Operacion $dueno 'eliminar' 'deleted' 7 'limpieza_por_error' $false $_.Exception.Message
        }
    }
}
finally {
    $manifest.finalizado_utc = Get-AhoraUtc
    Save-Manifiesto
}

$ok = @($manifest.escenarios | Where-Object { $_.exito }).Count
$restantes = @(Get-ChildItem -LiteralPath $LabRoot -Force).Count
Write-Host ("Resultado: {0}/{1} escenarios completos | archivos restantes en el laboratorio: {2} | exito: {3}" -f $ok, $Escenarios, $restantes, $manifest.exito)
Write-Host ("Manifiesto local: %LOCALAPPDATA%\{0}\fim_{1}.json" -f $ManifestRel, $runId)
if (-not $manifest.exito) { exit 1 }
