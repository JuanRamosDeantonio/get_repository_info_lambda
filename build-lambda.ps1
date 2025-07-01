# Script PowerShell para empaquetar función AWS Lambda con compresión óptima, validación, control de tamaño y logging persistente

# Configuración de PowerShell para mejor manejo de errores
$ErrorActionPreference = "Stop"

# Obtener ruta raíz del proyecto
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Preparar estructura de logs
$LogMessages = @()

# Variables globales para manejo de rutas
$BuildDir = $null
$PublicDir = $null
$zipPath = $null

# Función de logging con timestamp y persistencia
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = 'INFO'
    )
    $time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $log = "$time [$Level] - $Message"
    Write-Host $log
    $script:LogMessages += $log
}

# Función para validar disponibilidad de .NET Framework
function Test-DotNetFramework {
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        return $true
    }
    catch {
        return $false
    }
}

# Función para limpiar directorios de forma segura
function Remove-DirectorySafe {
    param([string]$Path)
    
    if ([string]::IsNullOrEmpty($Path)) {
        return
    }
    
    if (Test-Path $Path) {
        try {
            Remove-Item -Recurse -Force $Path -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 100
        }
        catch {
            Write-Log -Message "ADVERTENCIA: No se pudo limpiar completamente: $Path" -Level "WARNING"
        }
    }
}

try {
    Write-Log -Message "INICIANDO: Preparacion del paquete Lambda" -Level "INFO"

    # Inicializar variables de rutas
    $BuildDir = Join-Path -Path $ProjectRoot -ChildPath 'build'
    $PublicDir = Join-Path -Path $ProjectRoot -ChildPath 'Publicar'

    # Validar .NET Framework
    if (-not (Test-DotNetFramework)) {
        throw ".NET Framework System.IO.Compression.FileSystem no esta disponible"
    }
    Write-Log -Message "VALIDACION: .NET Framework disponible" -Level "INFO"

    # 1. Limpiar carpetas previas
    Write-Log -Message "LIMPIEZA: Limpiando carpetas si existen" -Level "INFO"
    
    Remove-DirectorySafe -Path $BuildDir
    
    if (-not (Test-Path $PublicDir)) {
        New-Item -ItemType Directory -Path $PublicDir -Force | Out-Null
    }

    # 2. Crear carpetas necesarias
    Write-Log -Message "SETUP: Creando carpetas de trabajo" -Level "INFO"
    New-Item -ItemType Directory -Path $BuildDir -Force | Out-Null

    # 3. Instalar dependencias con manejo corregido del ErrorActionPreference
    $requirementsFile = Join-Path -Path $ProjectRoot -ChildPath 'requirements.txt'
    if (Test-Path $requirementsFile) {
        Write-Log -Message "DEPENDENCIAS: Instalando dependencias desde requirements.txt" -Level "INFO"
        
        # Cambiar temporalmente ErrorActionPreference para pip
        $originalErrorAction = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        
        try {
            $pipCheck = pip --version 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-Log -Message "DEPENDENCIAS: Ejecutando pip install" -Level "INFO"
                
                # Primera estrategia: instalación normal ignorando warnings
                pip install -r $requirementsFile -t $BuildDir --upgrade --force-reinstall --no-cache-dir --disable-pip-version-check 2>$null
                
                # Verificar si realmente se instalaron las dependencias
                $installedPackages = @()
                $buildDirs = Get-ChildItem -Path $BuildDir -Directory -ErrorAction SilentlyContinue
                if ($buildDirs) {
                    foreach ($dir in $buildDirs) {
                        if ($dir.Name -match '^(pandas|boto3|requests|pydantic|openpyxl)') {
                            $installedPackages += $dir
                        }
                    }
                }
                
                if ($installedPackages.Count -gt 0) {
                    Write-Log -Message "DEPENDENCIAS: Instalacion exitosa - Se detectaron $($installedPackages.Count) paquetes principales" -Level "INFO"
                    foreach ($pkg in $installedPackages) {
                        Write-Log -Message "  - $($pkg.Name) instalado" -Level "INFO"
                    }
                } else {
                    Write-Log -Message "DEPENDENCIAS: No se detectaron paquetes, intentando con --no-deps" -Level "WARNING"
                    
                    # Segunda estrategia: sin verificación de dependencias
                    pip install -r $requirementsFile -t $BuildDir --no-deps --force-reinstall --no-cache-dir --disable-pip-version-check 2>$null
                    
                    # Verificar nuevamente
                    $installedPackages2 = @()
                    $buildDirs2 = Get-ChildItem -Path $BuildDir -Directory -ErrorAction SilentlyContinue
                    if ($buildDirs2) {
                        foreach ($dir2 in $buildDirs2) {
                            if ($dir2.Name -match '^(pandas|boto3|requests|pydantic|openpyxl)') {
                                $installedPackages2 += $dir2
                            }
                        }
                    }
                    
                    if ($installedPackages2.Count -gt 0) {
                        Write-Log -Message "DEPENDENCIAS: Instalacion con --no-deps exitosa" -Level "INFO"
                    } else {
                        Write-Log -Message "DEPENDENCIAS: Instalacion linea por linea" -Level "WARNING"
                        
                        # Tercera estrategia: línea por línea
                        $requirements = Get-Content $requirementsFile | Where-Object { $_.Trim() -ne '' -and -not $_.StartsWith('#') }
                        $successCount = 0
                        
                        foreach ($requirement in $requirements) {
                            $requirement = $requirement.Trim()
                            if ($requirement -ne '') {
                                Write-Log -Message "  Instalando: $requirement" -Level "INFO"
                                pip install $requirement -t $BuildDir --no-deps --force-reinstall --no-cache-dir --disable-pip-version-check 2>$null
                                if ($LASTEXITCODE -eq 0) {
                                    $successCount++
                                    Write-Log -Message "    Exito: $requirement" -Level "INFO"
                                } else {
                                    Write-Log -Message "    Fallo: $requirement" -Level "WARNING"
                                }
                            }
                        }
                        
                        Write-Log -Message "DEPENDENCIAS: Se instalaron $successCount de $($requirements.Count) dependencias" -Level "INFO"
                    }
                }
                
                # Verificación final de dependencias instaladas
                $finalPackages = Get-ChildItem -Path $BuildDir -Directory -ErrorAction SilentlyContinue
                $dependencyCount = 0
                if ($finalPackages) {
                    $dependencyCount = $finalPackages.Count
                }
                Write-Log -Message "VERIFICACION: Total de $dependencyCount directorios de paquetes en build" -Level "INFO"
                
            } else {
                Write-Log -Message "ADVERTENCIA: pip no esta disponible en el sistema" -Level "WARNING"
            }
        }
        finally {
            # Restaurar ErrorActionPreference original
            $ErrorActionPreference = $originalErrorAction
        }
    } else {
        Write-Log -Message "ADVERTENCIA: requirements.txt no encontrado" -Level "WARNING"
    }

    # 4. Copiar código fuente con exclusiones AGRESIVAS
    Write-Log -Message "COPIA: Copiando archivos fuente con exclusiones agresivas" -Level "INFO"

    # Patrones de exclusión más agresivos
    $excludePatterns = @(
        # Entornos virtuales (CRÍTICO)
        [regex]::Escape('venv\'),
        [regex]::Escape('.venv\'),
        [regex]::Escape('env\'),
        [regex]::Escape('.env\'),
        [regex]::Escape('virtualenv\'),
        # Carpetas de desarrollo
        [regex]::Escape('tests\'),
        [regex]::Escape('test\'),
        [regex]::Escape('.git\'),
        [regex]::Escape('__pycache__\'),
        [regex]::Escape('docs\'),
        [regex]::Escape('doc\'),
        [regex]::Escape('examples\'),
        [regex]::Escape('example\'),
        [regex]::Escape('testdata\'),
        [regex]::Escape('build\'),
        [regex]::Escape('Publicar\'),
        [regex]::Escape('.pytest_cache\'),
        [regex]::Escape('.vscode\'),
        [regex]::Escape('.idea\'),
        [regex]::Escape('node_modules\'),
        [regex]::Escape('\.dist-info\'),
        [regex]::Escape('\.egg-info\'),
        [regex]::Escape('\bin\'),
        [regex]::Escape('\Scripts\'),
        [regex]::Escape('\include\'),
        [regex]::Escape('\share\'),
        [regex]::Escape('\benchmark'),
        [regex]::Escape('\sample'),
        [regex]::Escape('\demo'),
        [regex]::Escape('\tutorial')
    )
    
    # Extensiones excluidas agresivas (INCLUYE .ps1 EXPLÍCITAMENTE)
    $excludeExtensions = @(
        '*.log', '*.md', '*.tmp', '*.pyc', '*.pyo', '*.pyd', 
        '.DS_Store', '*.txt', '*.rst', '*.yml', '*.yaml',
        '*.json', '*.xml', '*.cfg', '*.ini', '*.conf',
        '*.exe', '*.dll', '*.so', '*.dylib', '*.a', '*.lib',
        '*.jpg', '*.jpeg', '*.png', '*.gif', '*.bmp', '*.ico', '*.svg',
        '*.pdf', '*.doc', '*.docx', '*.xls', '*.xlsx', '*.ppt', '*.pptx',
        '*.zip', '*.tar', '*.gz', '*.bz2', '*.rar', '*.7z',
        '*.c', '*.cpp', '*.h', '*.hpp', '*.java', '*.class', '*.jar',
        '*.ps1', '*.bat', '*.cmd', '*.sh', '*.bash',
        'requirements*.txt', 'setup.py', 'setup.cfg', 'MANIFEST.in',
        'Makefile', 'CMakeLists.txt', 'Dockerfile*',
        'LICENSE*', 'COPYING*', 'COPYRIGHT*', 'NOTICE*', 'AUTHORS*',
        'CHANGELOG*', 'CHANGES*', 'HISTORY*', 'NEWS*', 'README*',
        '.env*', '.environment*'
    )

    # Procesar archivos
    $sourceFiles = Get-ChildItem -Path $ProjectRoot -Recurse -File -ErrorAction SilentlyContinue
    $copiedCount = 0
    $skippedCount = 0
    $totalSizeBytes = 0
    $excludedVenvFiles = 0
    
    foreach ($file in $sourceFiles) {
        $shouldInclude = $true
        $relativePath = $file.FullName.Replace($ProjectRoot, '')
        $fileName = $file.Name
        
        # Verificar extensiones excluidas
        foreach ($pattern in $excludeExtensions) {
            if ($fileName -like $pattern) {
                $shouldInclude = $false
                $skippedCount++
                break
            }
        }
        
        # Verificar patrones de rutas si no fue excluido por extensión
        if ($shouldInclude) {
            foreach ($pattern in $excludePatterns) {
                if ($relativePath -match $pattern) {
                    $shouldInclude = $false
                    $skippedCount++
                    
                    # Contar archivos de venv
                    if ($pattern -match 'venv|\.venv|env|\.env') {
                        $excludedVenvFiles++
                    }
                    break
                }
            }
        }
        
        # Excluir archivos grandes (>5MB)
        if ($shouldInclude -and $file.Length -gt 5MB) {
            $fileSizeMB = [Math]::Round($file.Length / 1MB, 2)
            Write-Log -Message "EXCLUSION: Archivo grande excluido: $fileName ($fileSizeMB MB)" -Level "INFO"
            $shouldInclude = $false
            $skippedCount++
        }
        
        # Copiar archivo si debe incluirse
        if ($shouldInclude) {
            try {
                $relativePathClean = $relativePath.TrimStart('\')
                $destPath = Join-Path -Path $BuildDir -ChildPath $relativePathClean
                $destDir = Split-Path -Path $destPath -Parent
                
                if (-not (Test-Path $destDir)) {
                    New-Item -ItemType Directory -Path $destDir -Force | Out-Null
                }
                
                Copy-Item -Path $file.FullName -Destination $destPath -Force
                $copiedCount++
                $totalSizeBytes += $file.Length
            }
            catch {
                Write-Log -Message "ADVERTENCIA: No se pudo copiar: $fileName" -Level "WARNING"
            }
        }
    }

    $totalSizeMB = [Math]::Round($totalSizeBytes / 1MB, 2)
    Write-Log -Message "COPIA: Se copiaron $copiedCount archivos ($totalSizeMB MB), se excluyeron $skippedCount" -Level "INFO"
    
    if ($excludedVenvFiles -gt 0) {
        Write-Log -Message "EXCLUSION: Se excluyeron $excludedVenvFiles archivos de entornos virtuales" -Level "INFO"
    }

    # 5. Optimizar dependencias pesadas instaladas (con validaciones de Path null)
    Write-Log -Message "OPTIMIZACION: Optimizando dependencias pesadas para AWS Lambda" -Level "INFO"
    
    # Verificar que BuildDir existe antes de optimizar
    if (-not (Test-Path $BuildDir)) {
        Write-Log -Message "ADVERTENCIA: BuildDir no existe, saltando optimizacion" -Level "WARNING"
    } else {
        # Optimizar pandas
        $pandasDirs = Get-ChildItem -Path $BuildDir -Directory -Name "pandas*" -ErrorAction SilentlyContinue
        if ($pandasDirs) {
            foreach ($pandasDirName in $pandasDirs) {
                if (-not [string]::IsNullOrEmpty($pandasDirName)) {
                    $pandasPath = Join-Path -Path $BuildDir -ChildPath $pandasDirName
                    
                    if (Test-Path $pandasPath) {
                        # Remover directorios de testing de pandas
                        $testDirs = @('tests', 'test', '_testing', 'conftest')
                        foreach ($testDir in $testDirs) {
                            if (-not [string]::IsNullOrEmpty($testDir)) {
                                $testPath = Join-Path -Path $pandasPath -ChildPath $testDir
                                if (Test-Path $testPath) {
                                    Remove-Item -Recurse -Force $testPath -ErrorAction SilentlyContinue
                                    Write-Log -Message "OPTIMIZACION: Removido $testDir de pandas" -Level "INFO"
                                }
                            }
                        }
                        
                        # Remover archivos .pyx y .pxd
                        $pyxFiles = Get-ChildItem -Path $pandasPath -Recurse -Filter "*.pyx" -ErrorAction SilentlyContinue
                        if ($pyxFiles) {
                            foreach ($pyxFile in $pyxFiles) {
                                if ($pyxFile -and $pyxFile.FullName) {
                                    Remove-Item -Force $pyxFile.FullName -ErrorAction SilentlyContinue
                                }
                            }
                        }
                        
                        $pxdFiles = Get-ChildItem -Path $pandasPath -Recurse -Filter "*.pxd" -ErrorAction SilentlyContinue
                        if ($pxdFiles) {
                            foreach ($pxdFile in $pxdFiles) {
                                if ($pxdFile -and $pxdFile.FullName) {
                                    Remove-Item -Force $pxdFile.FullName -ErrorAction SilentlyContinue
                                }
                            }
                        }
                    }
                }
            }
        }
        
        # Optimizar numpy
        $numpyDirs = Get-ChildItem -Path $BuildDir -Directory -Name "numpy*" -ErrorAction SilentlyContinue
        if ($numpyDirs) {
            foreach ($numpyDirName in $numpyDirs) {
                if (-not [string]::IsNullOrEmpty($numpyDirName)) {
                    $numpyPath = Join-Path -Path $BuildDir -ChildPath $numpyDirName
                    
                    if (Test-Path $numpyPath) {
                        $testsPath = Join-Path -Path $numpyPath -ChildPath "tests"
                        if (Test-Path $testsPath) {
                            Remove-Item -Recurse -Force $testsPath -ErrorAction SilentlyContinue
                            Write-Log -Message "OPTIMIZACION: Removido tests de numpy" -Level "INFO"
                        }
                    }
                }
            }
        }
        
        # Optimizar boto3 y botocore
        $botoDirs = Get-ChildItem -Path $BuildDir -Directory -Name "boto*" -ErrorAction SilentlyContinue
        if ($botoDirs) {
            foreach ($botoDirName in $botoDirs) {
                if (-not [string]::IsNullOrEmpty($botoDirName)) {
                    $botoPath = Join-Path -Path $BuildDir -ChildPath $botoDirName
                    
                    if (Test-Path $botoPath) {
                        $dataPath = Join-Path -Path $botoPath -ChildPath "data"
                        
                        if (Test-Path $dataPath) {
                            $essentialServices = @('lambda', 's3', 'dynamodb', 'ec2', 'iam', 'cloudformation')
                            $allServices = Get-ChildItem -Path $dataPath -Directory -ErrorAction SilentlyContinue
                            
                            if ($allServices) {
                                foreach ($service in $allServices) {
                                    if ($service -and $service.Name -and $service.FullName) {
                                        $isEssential = $false
                                        foreach ($essential in $essentialServices) {
                                            if ($service.Name -eq $essential) {
                                                $isEssential = $true
                                                break
                                            }
                                        }
                                        
                                        if (-not $isEssential) {
                                            Remove-Item -Recurse -Force $service.FullName -ErrorAction SilentlyContinue
                                        }
                                    }
                                }
                            }
                            Write-Log -Message "OPTIMIZACION: Optimizado servicios de $botoDirName" -Level "INFO"
                        }
                    }
                }
            }
        }
        
        # Remover metadatos de paquetes
        $distInfoDirs = Get-ChildItem -Path $BuildDir -Directory -Name "*.dist-info" -ErrorAction SilentlyContinue
        if ($distInfoDirs) {
            foreach ($distInfo in $distInfoDirs) {
                if ($distInfo -and $distInfo.FullName) {
                    Remove-Item -Recurse -Force $distInfo.FullName -ErrorAction SilentlyContinue
                }
            }
        }
        
        # Remover cache residual
        $pycacheDirs = Get-ChildItem -Path $BuildDir -Directory -Name "__pycache__" -Recurse -ErrorAction SilentlyContinue
        if ($pycacheDirs) {
            foreach ($pycache in $pycacheDirs) {
                if ($pycache -and $pycache.FullName) {
                    Remove-Item -Recurse -Force $pycache.FullName -ErrorAction SilentlyContinue
                }
            }
        }
    }
    
    Write-Log -Message "OPTIMIZACION: Optimizacion de dependencias completada" -Level "INFO"

    # 6. Verificar archivos finales en build antes de crear ZIP
    $buildFiles = Get-ChildItem -Path $BuildDir -Recurse -File -ErrorAction SilentlyContinue
    $totalFileCount = 0
    if ($buildFiles) {
        $totalFileCount = $buildFiles.Count
    }
    
    Write-Log -Message "CONTEO: Se empaquetaran $totalFileCount archivos en total (post-optimizacion)" -Level "INFO"
    
    if ($totalFileCount -eq 0) {
        Write-Log -Message "ERROR: No se encontraron archivos para empaquetar" -Level "ERROR"
        Write-Log -Message "POSIBLES CAUSAS:" -Level "ERROR"
        Write-Log -Message "1. No se instalaron dependencias por conflictos de pip" -Level "ERROR"
        Write-Log -Message "2. Todos los archivos del proyecto fueron excluidos" -Level "ERROR"
        Write-Log -Message "3. Error en la copia de archivos fuente" -Level "ERROR"
        throw "No hay contenido valido para crear el paquete Lambda"
    }
    
    # Verificar que al menos tenemos algunos archivos .py
    $pythonFiles = Get-ChildItem -Path $BuildDir -Recurse -Filter "*.py" -ErrorAction SilentlyContinue
    if (-not $pythonFiles -or $pythonFiles.Count -eq 0) {
        Write-Log -Message "ADVERTENCIA: No se encontraron archivos Python (.py) en el paquete" -Level "WARNING"
        Write-Log -Message "Verifique que su codigo fuente este siendo copiado correctamente" -Level "WARNING"
    } else {
        Write-Log -Message "VERIFICACION: Se encontraron $($pythonFiles.Count) archivos Python" -Level "INFO"
    }

    # 7. Crear ZIP con validaciones adicionales
    Write-Log -Message "COMPRESION: Empaquetando ZIP con compresion Optimal" -Level "INFO"
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $folderName = Split-Path -Path $ProjectRoot -Leaf
    $zipFileName = "${folderName}_${timestamp}.zip"
    $zipPath = Join-Path -Path $PublicDir -ChildPath $zipFileName

    # Verificar que el directorio PublicDir existe
    if (-not (Test-Path $PublicDir)) {
        New-Item -ItemType Directory -Path $PublicDir -Force | Out-Null
    }

    # Verificar que BuildDir tiene contenido válido antes de crear ZIP
    if (-not (Test-Path $BuildDir)) {
        throw "El directorio de build no existe: $BuildDir"
    }
    
    $buildContent = Get-ChildItem -Path $BuildDir -ErrorAction SilentlyContinue
    if (-not $buildContent -or $buildContent.Count -eq 0) {
        throw "El directorio de build esta vacio: $BuildDir"
    }

    try {
        [System.IO.Compression.ZipFile]::CreateFromDirectory(
            $BuildDir,
            $zipPath,
            [System.IO.Compression.CompressionLevel]::Optimal,
            $false
        )
        
        Write-Log -Message "EXITO: ZIP creado en: $zipPath" -Level "SUCCESS"
    }
    catch {
        Write-Log -Message "ERROR: No se pudo crear el ZIP: $($_.Exception.Message)" -Level "ERROR"
        throw "Fallo en la creacion del archivo ZIP"
    }

    # 8. Validar ZIP
    Write-Log -Message "VALIDACION: Validando integridad del ZIP" -Level "INFO"
    
    if (-not (Test-Path $zipPath)) {
        throw "El archivo ZIP no fue creado correctamente: $zipPath"
    }
    
    try {
        $zipArchive = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
        $entryCount = $zipArchive.Entries.Count
        $zipArchive.Dispose()
        
        if ($entryCount -gt 0) {
            Write-Log -Message "EXITO: ZIP contiene $entryCount entradas" -Level "SUCCESS"
        } else {
            throw "El ZIP esta vacio"
        }
    }
    catch {
        Write-Log -Message "ERROR: Error en validacion del ZIP: $($_.Exception.Message)" -Level "ERROR"
        throw "ZIP no valido: $($_.Exception.Message)"
    }

    # 9. Verificar tamaño y dar recomendaciones específicas
    if (-not (Test-Path $zipPath)) {
        throw "No se puede verificar el tamaño: el archivo ZIP no existe"
    }
    
    $zipInfo = Get-Item -Path $zipPath
    $zipSizeMB = [Math]::Round($zipInfo.Length / 1MB, 2)
    
    Write-Log -Message "TAMANO: ZIP final de $zipSizeMB MB" -Level "INFO"
    
    if ($zipSizeMB -gt 50) {
        Write-Log -Message "PROBLEMA: ZIP supera 50MB ($zipSizeMB MB) - Limite de AWS Lambda Console" -Level "WARNING"
        Write-Log -Message "========================================" -Level "WARNING"
        Write-Log -Message "SOLUCIONES RECOMENDADAS:" -Level "WARNING"
        Write-Log -Message "" -Level "INFO"
        Write-Log -Message "OPCION 1 - AWS CLI (MAS FACIL):" -Level "WARNING"
        Write-Log -Message "aws lambda update-function-code --function-name TU_FUNCION --zip-file fileb://$zipPath" -Level "WARNING"
        Write-Log -Message "" -Level "INFO"
        Write-Log -Message "OPCION 2 - AWS LAMBDA LAYERS:" -Level "WARNING"
        Write-Log -Message "Crear un layer separado con pandas y boto3:" -Level "WARNING"
        Write-Log -Message "1. Crear requirements-layer.txt con: pandas>=2.2.2 y boto3>=1.34.0" -Level "WARNING"
        Write-Log -Message "2. Crear requirements-function.txt con: requests, pydantic, openpyxl" -Level "WARNING"
        Write-Log -Message "3. El layer manejara las dependencias pesadas" -Level "WARNING"
        Write-Log -Message "" -Level "INFO"
        Write-Log -Message "OPCION 3 - CONTENEDOR DOCKER:" -Level "WARNING"
        Write-Log -Message "Para proyectos grandes, usar Amazon ECR + contenedores" -Level "WARNING"
        Write-Log -Message "Limite: 10GB (imagen de contenedor)" -Level "WARNING"
        Write-Log -Message "========================================" -Level "WARNING"
    } elseif ($zipSizeMB -gt 45) {
        Write-Log -Message "ATENCION: ZIP cerca del limite (50MB) - $zipSizeMB MB" -Level "WARNING"
        Write-Log -Message "Considere usar AWS CLI o Lambda Layers para futuras expansiones" -Level "WARNING"
    } else {
        Write-Log -Message "EXITO: ZIP de $zipSizeMB MB - OK para carga directa en consola AWS" -Level "SUCCESS"
    }

    # 10. Limpieza
    Remove-DirectorySafe -Path $BuildDir
    Write-Log -Message "LIMPIEZA: Carpeta build eliminada" -Level "INFO"

    Write-Log -Message "COMPLETADO: Paquete listo para AWS Lambda" -Level "INFO"
    Write-Log -Message "UBICACION: $zipPath" -Level "INFO"

    # 11. Guardar log
    if ([string]::IsNullOrEmpty($zipFileName)) {
        $logFileName = "lambda_package_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    } else {
        $logFileName = $zipFileName -replace '\.zip$', '.log'
    }
    
    $logPath = Join-Path -Path $PublicDir -ChildPath $logFileName
    $LogMessages | Out-File -FilePath $logPath -Encoding UTF8
    Write-Log -Message "LOG: Log guardado en: $logPath" -Level "INFO"

}
catch {
    $errorMessage = $_.Exception.Message
    Write-Log -Message "ERROR: Error durante la ejecucion: $errorMessage" -Level "ERROR"
    
    # Limpiar en caso de error
    Remove-DirectorySafe -Path $BuildDir
    
    # Guardar log de error
    try {
        if (-not (Test-Path $PublicDir)) {
            New-Item -ItemType Directory -Path $PublicDir -Force | Out-Null
        }
        
        $errorTimestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $errorLogPath = Join-Path -Path $PublicDir -ChildPath "error_${errorTimestamp}.log"
        
        if ($LogMessages -and $LogMessages.Count -gt 0) {
            $LogMessages | Out-File -FilePath $errorLogPath -Encoding UTF8
            Write-Host "LOG ERROR: Log de error guardado en: $errorLogPath"
        } else {
            "Error durante la ejecucion: $errorMessage" | Out-File -FilePath $errorLogPath -Encoding UTF8
            Write-Host "LOG ERROR: Log basico de error guardado en: $errorLogPath"
        }
    }
    catch {
        Write-Host "ERROR CRITICO: No se pudo guardar log de error: $($_.Exception.Message)"
    }
    
    exit 1
}