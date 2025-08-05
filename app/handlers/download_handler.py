"""
Manejador especializado para operaciones DOWNLOAD_FILE.

Este módulo contiene toda la lógica de negocio para descargar archivos
desde repositorios remotos. Optimizado para seguridad, performance
y manejo robusto de archivos binarios.

Features:
- Descarga segura con límites de tamaño
- Manejo optimizado de archivos binarios
- Detección automática de tipos MIME
- Streaming para archivos grandes
- Métricas de descarga automáticas

Author: [Your Name]
Created: 2025
Version: 2.0.0
"""

import math
import time
import hashlib
import base64
from typing import Dict, Any, Optional, Tuple
from pathlib import Path
import os

from app.core.constants import MAX_FILE_SIZE_BYTES, MetricNames
from app.core.exceptions import (
    SourceCodeError,
    FileTooLargeError,
    SecurityError,
    ValidationError,
    handle_provider_exception
)
from app.core.logger import (
    get_logger,
    log_performance,
    log_api_call,
    log_business_metric,
    log_security_event
)
from app.core.validators import validate_file_path, validate_file_size, is_safe_filename, create_validation_error
from app.utils.http_responses import create_file_response, create_exception_response, create_reference_response
import boto3

# Logger para el módulo
logger = get_logger(__name__)

# ========================================
# MANEJADOR PRINCIPAL
# ========================================

@log_performance(operation_name="download_file")
def handle_download_file(manager: Any, path: str, provider: str, ismarkdown: bool) -> Dict[str, Any]:
    """
    Maneja la operación DOWNLOAD_FILE con seguridad y optimizaciones completas.
    
    Esta es la función principal que orquesta toda la lógica para descargar
    un archivo desde un repositorio. Incluye validaciones de seguridad,
    límites de tamaño y manejo robusto de archivos binarios.
    
    Args:
        manager: Instancia del manager específico del proveedor
        path: Ruta del archivo a descargar (ya validada por request_parser)
        provider: Nombre del proveedor para logging y métricas
        
    Returns:
        Dict[str, Any]: Respuesta HTTP completa con archivo en Base64
        
    Raises:
        FileTooLargeError: Si el archivo excede límites de tamaño
        SecurityError: Si se detecta un patrón sospechoso
        SourceCodeError: Si hay problemas con el proveedor
        
    Features:
        - Validación de path adicional por seguridad
        - Límites automáticos de tamaño
        - Detección de tipos MIME
        - Base64 encoding para archivos binarios
        - Métricas detalladas de descarga
        - Logging de accesos para auditoría
        
    Example:
        >>> response = handle_download_file(github_manager, "src/main.py", "github")
        >>> # Retorna respuesta HTTP con archivo en Base64
    """
    logger.info(f"Starting file download", extra={
        "provider": provider,
        "path": path,
        "operation": "DOWNLOAD_FILE",
        "ismarkdown":ismarkdown
    })
    
    try:
        # Validación adicional de seguridad
        safe_path = _validate_download_path(path, provider)
        
        # Pre-validaciones de descarga
        _pre_download_validations(safe_path, provider)
        
        # Descargar archivo del proveedor
        file_data = _download_file_from_provider(manager, safe_path, provider, ismarkdown)
        
        # Post-procesar archivo descargado
        processed_file = _process_downloaded_file(file_data, safe_path, provider)

        if os.environ.get('EXECUTION_ENVIROMENT', 'lambda') == 'local':
            logger.info("El entorno de ejcución es local")
            s3_client = boto3.client('s3',
                                 aws_access_key_id=os.environ.get('AWS_SECRET_ID'),
                                 aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS'),
                                 verify=False,
                                 use_ssl=False)
        else:
            logger.info("El entorno de ejecución debe ser lambda")
            s3_client = boto3.client('s3')

        BUCKET_NAME = os.environ.get('BUCKET_NAME')
        FOLDER_BUCKET = os.environ.get('FOLDER_BUCKET')
        key_file = f'{FOLDER_BUCKET}/{processed_file["filename"]}'

        logger.info(f'filename -> {type(processed_file["filename"])}')

        logger.info(f"Primeros 100 caracteres del contenido {processed_file['content'][:100]}")

        response_s3 = s3_client.put_object(Bucket=BUCKET_NAME, Key=key_file, Body=processed_file['content'])

        logger.info(f'Operación de s3 ejecutada con status code -> {response_s3['ResponseMetadata']['HTTPStatusCode']}')
        
        # Crear respuesta optimizada
        response = create_reference_response(bucket_name=BUCKET_NAME, 
                                             s3_path=key_file, filename=processed_file["filename"])
        
        # Métricas finales
        _log_download_metrics(processed_file, provider)

        logger.debug("processed_file details", extra={
            "filename": processed_file["filename"],
            "content_type": processed_file["content_type"],
            "file_size": processed_file["file_size"]
        })
        
        logger.info("File download completed successfully", extra={
            "provider": provider,
            "path": safe_path,
            "file_size": len(processed_file["content"]),
            "download_content_type": processed_file["content_type"],
            "downloaded_filename": processed_file["filename"]
        })
        
        return response
        
    except Exception as e:
        # Manejo especializado de errores
        logger.error(f"Error in file download", extra={
            "provider": provider,
            "path": path,
            "error": str(e),
            "error_type": type(e).__name__
        })
        
        # Convertir a ProviderError si es necesario
        if not isinstance(e, (SourceCodeError, FileTooLargeError, SecurityError, ValidationError)):
            provider_error = handle_provider_exception(
                e, provider, "download_file", {"path": path, "operation": "DOWNLOAD_FILE"}
            )
            return create_exception_response(provider_error)
        if isinstance(e, (SourceCodeError, FileTooLargeError, SecurityError, ValidationError)):
            return create_exception_response(e)
        
        return create_exception_response(e)


# ========================================
# FUNCIONES DE VALIDACIÓN
# ========================================

def _validate_download_path(path: str, provider: str) -> str:
    """
    Validación adicional de seguridad para paths de descarga.
    
    Args:
        path: Ruta del archivo
        provider: Proveedor para contexto
        
    Returns:
        str: Ruta validada y sanitizada
        
    Raises:
        SecurityError: Si se detecta un patrón sospechoso
        ValidationError: Si la ruta es inválida
    """
    # Re-validar path (defense in depth)
    safe_path = validate_file_path(path)
    
    # Validaciones adicionales específicas para descarga
    filename = safe_path.split('/')[-1]
    
    # Verificar que el filename sea seguro
    if not is_safe_filename(filename):
        log_security_event(
            "unsafe_filename_download",
            f"Unsafe filename requested: {filename}",
            "WARNING",
            provider=provider,
            path=safe_path
        )
        raise SecurityError(
            f"Nombre de archivo no seguro: {filename}",
            attack_type="unsafe_filename",
            detected_pattern=filename
        )
    
    # Detectar patrones de archivos sensibles
    sensitive_patterns = [
        '.env', '.key', '.pem', '.p12', '.pfx',  # Archivos de credenciales
        'password', 'secret', 'token', 'api_key',  # Palabras sensibles
        '.ssh/', 'id_rsa', 'id_dsa',  # Claves SSH
        'web.config', '.htaccess', '.htpasswd'  # Archivos de configuración
    ]
    
    path_lower = safe_path.lower()
    for pattern in sensitive_patterns:
        if pattern in path_lower:
            log_security_event(
                "sensitive_file_access",
                f"Access to potentially sensitive file: {safe_path}",
                "WARNING",
                provider=provider,
                pattern=pattern
            )
            # No bloqueamos, pero loggeamos para auditoría
            break
    
    # Validar longitud de componentes individuales
    components = safe_path.split('/')
    for component in components:
        if len(component) > 255:  # Límite del sistema de archivos
            raise ValidationError(
                f"Componente de ruta demasiado largo: {component[:50]}...",
                field_name="path_component"
            )
    
    logger.debug("Download path validated", extra={
        "provider": provider,
        "original": path,
        "safe_path": safe_path,
        "filename": filename
    })
    
    return safe_path


def _pre_download_validations(path: str, provider: str) -> None:
    """
    Validaciones pre-descarga para optimizar performance.
    
    Args:
        path: Ruta validada del archivo
        provider: Nombre del proveedor
        
    Raises:
        ValidationError: Si hay problemas de validación
    """
    # Log de auditoría de acceso
    log_security_event(
        "file_access_attempt",
        f"Downloading file: {path}",
        "INFO",
        provider=provider,
        path=path
    )
    
    # Verificar extensiones potencialmente problemáticas
    filename = path.split('/')[-1]
    if '.' in filename:
        extension = filename.split('.')[-1].lower()
        
        # Extensiones que podrían ser muy grandes
        large_file_extensions = {
            'zip', 'tar', 'gz', 'rar', '7z',  # Archives
            'iso', 'dmg', 'img',  # Disk images
            'mp4', 'avi', 'mkv', 'mov',  # Videos
            'wav', 'mp3', 'flac',  # Audio
            'psd', 'ai', 'sketch'  # Design files
        }
        
        if extension in large_file_extensions:
            logger.warning("Downloading potentially large file", extra={
                "provider": provider,
                "path": path,
                "extension": extension,
                "warning": "May exceed size limits"
            })
    
    logger.debug("Pre-download validations passed", extra={
        "provider": provider,
        "path": path
    })


# ========================================
# FUNCIONES DE DESCARGA
# ========================================

def _download_file_from_provider(manager: Any, path: str, provider: str, ismarkdown: bool) -> Dict[str, Any]:
    """
    Descarga el archivo del proveedor con manejo robusto de errores.
    
    Args:
        manager: Manager del proveedor
        path: Ruta del archivo
        provider: Nombre del proveedor
        ismarkdown: Si True, usa read_wiki_file para archivos markdown; si False, usa download_file
        
    Returns:
        Dict[str, Any]: Datos del archivo descargado
        
    Raises:
        SourceCodeError: Si hay problemas con la descarga
        FileTooLargeError: Si el archivo es demasiado grande
    """
    logger.debug("Starting provider download", extra={
        "provider": provider,
        "path": path,
        "ismarkdown": ismarkdown
    })
    
    # Registrar llamada a API externa
    operation = "READ_WIKI_FILE" if ismarkdown else "DOWNLOAD_FILE"
    log_api_call(provider=provider, operation=operation, path=path)
    
    try:
        start_time = time.time()
        
        # Descargar contenido según el tipo
        raw_content = _fetch_content_from_manager(manager, path, provider, ismarkdown)
        
        # Procesar y validar contenido
        processed_content = _process_and_validate_content(raw_content, path, provider, ismarkdown)
        
        download_duration = time.time() - start_time
        
        # Validar tamaño y estado final
        file_size = len(processed_content)
        _validate_download_result(processed_content, file_size, path, provider)
        
        # Registrar métricas y logging
        _log_download_success(provider, path, file_size, download_duration, ismarkdown)
        
        return {
            "content": processed_content,
            "size": file_size,
            "download_duration": download_duration,
            "path": path
        }
        
    except FileTooLargeError:
        # Re-raise FileTooLargeError sin modificar
        raise
        
    except Exception as e:
        _handle_download_error(e, path, provider)


def _fetch_content_from_manager(manager: Any, path: str, provider: str, ismarkdown: bool) -> Any:
    """
    Obtiene el contenido del manager según el tipo de archivo.
    
    Args:
        manager: Manager del proveedor
        path: Ruta del archivo
        provider: Nombre del proveedor  
        ismarkdown: Si True, usa método de wiki; si False, usa download normal
        
    Returns:
        Any: Contenido crudo del manager
    """
    try:
        if ismarkdown:
            # Para archivos markdown, usar el método de wiki que retorna string
            content = manager.read_wiki_file(path)
            logger.debug("Wiki content fetched", extra={
                "provider": provider,
                "path": path,
                "content_type": "string",
                "content_length": len(content) if content else None
            })
        else:
            # Para archivos normales, usar download que retorna bytes
            content = manager.download_file(path)
            logger.debug("File content fetched", extra={
                "provider": provider,
                "path": path,
                "content_type": type(content).__name__,
                "content_length": len(content) if content else None
            })
        
        return content
        
    except Exception as e:
        logger.error("Failed to fetch content from manager", extra={
            "provider": provider,
            "path": path,
            "ismarkdown": ismarkdown,
            "error": str(e)
        })
        raise


def _process_and_validate_content(raw_content: Any, path: str, provider: str, ismarkdown: bool) -> bytes:
    """
    Procesa y valida el contenido descargado, convirtiéndolo a bytes.
    
    Args:
        raw_content: Contenido crudo del manager
        path: Ruta del archivo
        provider: Nombre del proveedor
        ismarkdown: Tipo de contenido esperado
        
    Returns:
        bytes: Contenido procesado como bytes
    """
    # Validar que el contenido no sea None
    if raw_content is None:
        raise create_validation_error(
            message="Archivo no encontrado",
            field_name="path",
            received_value=path
        )
    
    # Procesar según el tipo de contenido esperado
    if ismarkdown:
        return _process_markdown_content(raw_content, path, provider)
    else:
        return _process_binary_content(raw_content, path, provider)


def _process_markdown_content(content: Any, path: str, provider: str) -> bytes:
    """
    Procesa contenido markdown (debería ser string) y lo convierte a bytes.
    
    Args:
        content: Contenido markdown del manager
        path: Ruta del archivo
        provider: Nombre del proveedor
        
    Returns:
        bytes: Contenido markdown como bytes UTF-8
    """
    if isinstance(content, str):
        try:
            processed_content = content.encode('utf-8')
            logger.debug("Markdown content encoded to UTF-8 bytes", extra={
                "provider": provider,
                "path": path,
                "original_length": len(content),
                "encoded_size": len(processed_content)
            })
            return processed_content
        except UnicodeEncodeError as e:
            raise ValidationError(f"Error codificando contenido markdown como UTF-8: {str(e)}")
    
    elif isinstance(content, bytes):
        logger.debug("Markdown content already in bytes", extra={
            "provider": provider,
            "path": path,
            "size": len(content)
        })
        return content
    
    else:
        # Intentar convertir otros tipos a string primero
        try:
            str_content = str(content)
            return str_content.encode('utf-8')
        except Exception as e:
            raise ValidationError(f"No se pudo procesar contenido markdown de tipo {type(content).__name__}: {str(e)}")


def _process_binary_content(content: Any, path: str, provider: str) -> bytes:
    """
    Procesa contenido binario y maneja diferentes tipos de entrada.
    
    Args:
        content: Contenido del manager
        path: Ruta del archivo
        provider: Nombre del proveedor
        
    Returns:
        bytes: Contenido procesado como bytes
    """
    if isinstance(content, bytes):
        logger.debug("Content already in bytes format", extra={
            "provider": provider,
            "path": path,
            "size": len(content)
        })
        return content
    
    elif isinstance(content, str):
        return _convert_string_to_bytes(content, path, provider)
    
    else:
        return _convert_other_type_to_bytes(content, path, provider)


def _convert_string_to_bytes(content: str, path: str, provider: str) -> bytes:
    """
    Convierte contenido string a bytes, intentando diferentes estrategias.
    
    Args:
        content: Contenido como string
        path: Ruta del archivo
        provider: Nombre del proveedor
        
    Returns:
        bytes: Contenido convertido a bytes
    """
    logger.warning("Content is string, converting to bytes", extra={
        "provider": provider,
        "path": path,
        "content_length": len(content)
    })
    
    filename = path.split('/')[-1].lower()
    
    # Estrategia 1: Intentar decodificar como base64 primero
    try:
        decoded_content = base64.b64decode(content)
        logger.info("Successfully decoded base64 content", extra={
            "provider": provider,
            "path": path,
            "original_size": len(content),
            "decoded_size": len(decoded_content)
        })
        return decoded_content
    except Exception as base64_error:
        logger.debug("Base64 decode failed, trying text encoding", extra={
            "provider": provider,
            "path": path,
            "base64_error": str(base64_error)
        })
    
    # Estrategia 2: Para archivos de texto, codificar como UTF-8
    text_extensions = {'.txt', '.py', '.js', '.json', '.md', '.yml', '.yaml', '.xml', '.csv', '.log', '.html', '.css'}
    
    if any(filename.endswith(ext) for ext in text_extensions):
        try:
            encoded_content = content.encode('utf-8')
            logger.info("Encoded as UTF-8 text file", extra={
                "provider": provider,
                "path": path,
                "original_length": len(content),
                "encoded_size": len(encoded_content)
            })
            return encoded_content
        except UnicodeEncodeError as utf_error:
            raise ValidationError(f"No se pudo procesar el archivo de texto {filename}: {str(utf_error)}")
    
    # Para archivos binarios que llegaron como string, es un error
    raise ValidationError(
        f"Archivo binario '{filename}' recibido como string y no se pudo decodificar. "
        f"Puede ser un problema en el proveedor {provider}."
    )


def _convert_other_type_to_bytes(content: Any, path: str, provider: str) -> bytes:
    """
    Convierte tipos no estándar a bytes.
    
    Args:
        content: Contenido de tipo desconocido
        path: Ruta del archivo  
        provider: Nombre del proveedor
        
    Returns:
        bytes: Contenido convertido a bytes
    """
    try:
        str_content = str(content)
        encoded_content = str_content.encode('utf-8')
        logger.info("Converted unknown type to bytes", extra={
            "provider": provider,
            "path": path,
            "original_type": type(content).__name__,
            "encoded_size": len(encoded_content)
        })
        return encoded_content
    except Exception as convert_error:
        raise ValidationError(f"No se pudo convertir contenido de tipo {type(content).__name__} a bytes: {str(convert_error)}")


def _validate_download_result(content: bytes, file_size: int, path: str, provider: str) -> None:
    """
    Valida el resultado final de la descarga.
    
    Args:
        content: Contenido descargado
        file_size: Tamaño del archivo
        path: Ruta del archivo
        provider: Nombre del proveedor
    """
    # Validar tamaño
    validate_file_size(file_size, path.split('/')[-1])
    
    # Advertir sobre archivos vacíos
    if file_size == 0:
        logger.warning("Downloaded empty file", extra={
            "provider": provider,
            "path": path
        })


def _log_download_success(provider: str, path: str, file_size: int, duration: float, ismarkdown: bool) -> None:
    """
    Registra el éxito de la descarga con métricas y logs.
    
    Args:
        provider: Nombre del proveedor
        path: Ruta del archivo
        file_size: Tamaño del archivo
        duration: Duración de la descarga
        ismarkdown: Tipo de descarga realizada
    """
    operation_type = "wiki" if ismarkdown else "file"
    
    logger.debug("Provider download completed", extra={
        "provider": provider,
        "path": path,
        "file_size": file_size,
        "download_duration": round(duration, 3),
        "operation_type": operation_type
    })
    
    # Métricas de descarga
    log_business_metric("download_duration", duration, "seconds")
    log_business_metric(f"downloads_{provider}", 1, "count")
    log_business_metric(f"downloads_{provider}_{operation_type}", 1, "count")


def _handle_download_error(error: Exception, path: str, provider: str) -> None:
    """
    Maneja y categoriza errores de descarga.
    
    Args:
        error: Excepción ocurrida
        path: Ruta del archivo
        provider: Nombre del proveedor
    """
    logger.error("Provider download failed", extra={
        "provider": provider,
        "path": path,
        "error": str(error),
        "error_type": type(error).__name__
    })
    
    # Categorizar error específico
    error_message = str(error).lower()
    
    if "not found" in error_message or "404" in error_message:
        raise SourceCodeError(f"Archivo no encontrado: {path}", provider=provider)
    elif "permission" in error_message or "403" in error_message:
        raise SourceCodeError(f"Sin permisos para acceder al archivo: {path}", provider=provider)
    elif "timeout" in error_message:
        raise SourceCodeError(f"Timeout descargando archivo: {path}", provider=provider)
    else:
        raise ValidationError(str(error))


def _process_downloaded_file(file_data: Dict[str, Any], path: str, provider: str) -> Dict[str, Any]:
    """
    Post-procesa el archivo descargado con optimizaciones y metadatos.
    
    Args:
        file_data: Datos del archivo descargado
        path: Ruta del archivo
        provider: Nombre del proveedor
        
    Returns:
        Dict[str, Any]: Archivo procesado con metadatos
    """
    content = file_data["content"]
    filename = path.split('/')[-1]
    
    logger.debug("Processing downloaded file", extra={
        "provider": provider,
        "path": path,
        "file_size": len(content)
    })
    
    # Detectar tipo de contenido
    content_type = _detect_advanced_content_type(content, filename)
    
    # Análisis de contenido para métricas
    file_analysis = _analyze_file_content(content, filename)
    
    # Generar hash para integridad (opcional, para archivos pequeños)
    file_hash = None
    if len(content) < 1024 * 1024:  # Solo para archivos < 1MB
        file_hash = hashlib.md5(content).hexdigest()
    
    # Metadatos del archivo procesado
    processed_data = {
        "content": content,
        "filename": filename,
        "content_type": content_type,
        "file_size": len(content),
        "file_hash": file_hash,
        "analysis": file_analysis,
        "provider": provider,
        "download_path": path,
        "processing_timestamp": time.time()
    }
    
    logger.debug("File processing completed", extra={
        "provider": provider,
        "path": path,
        "content_type": content_type,
        "is_binary": file_analysis["is_binary"],
        "has_hash": bool(file_hash)
    })
    
    return processed_data


# ========================================
# FUNCIONES DE ANÁLISIS
# ========================================

def _detect_advanced_content_type(content: bytes, filename: str) -> str:
    """
    Detecta el tipo de contenido basado en contenido y nombre de archivo.
    
    Args:
        content: Contenido del archivo
        filename: Nombre del archivo
        
    Returns:
        str: Tipo MIME detectado
    """
    # Primero intentar detección por contenido (magic bytes)
    magic_signatures = {
        b'\x89PNG\r\n\x1a\n': 'image/png',
        b'\xff\xd8\xff': 'image/jpeg',
        b'GIF87a': 'image/gif',
        b'GIF89a': 'image/gif',
        b'%PDF': 'application/pdf',
        b'PK\x03\x04': 'application/zip',
        b'\x1f\x8b': 'application/gzip',
        b'Rar!': 'application/x-rar-compressed',
        b'\x00\x00\x01\x00': 'image/x-icon'
    }
    
    for signature, mime_type in magic_signatures.items():
        if content.startswith(signature):
            return mime_type
    
    # Si no se detecta por contenido, usar extensión
    if not filename:
        return 'application/octet-stream'
    
    extension = filename.lower().split('.')[-1] if '.' in filename else ''
    
    extension_map = {
        # Texto y código
        'txt': 'text/plain',
        'md': 'text/markdown',
        'json': 'application/json',
        'xml': 'application/xml',
        'yaml': 'application/x-yaml',
        'yml': 'application/x-yaml',
        'csv': 'text/csv',
        'log': 'text/plain',
        
        # Código fuente
        'py': 'text/x-python',
        'js': 'application/javascript',
        'ts': 'application/typescript',
        'html': 'text/html',
        'htm': 'text/html',
        'css': 'text/css',
        'scss': 'text/x-scss',
        'sass': 'text/x-sass',
        'java': 'text/x-java-source',
        'cpp': 'text/x-c++src',
        'c': 'text/x-csrc',
        'h': 'text/x-chdr',
        'go': 'text/x-go',
        'rs': 'text/x-rust',
        'php': 'text/x-php',
        'rb': 'text/x-ruby',
        'swift': 'text/x-swift',
        'kt': 'text/x-kotlin',
        'scala': 'text/x-scala',
        'sh': 'application/x-sh',
        'bat': 'application/x-msdos-program',
        'ps1': 'application/x-powershell',
        
        # Configuración
        'conf': 'text/plain',
        'ini': 'text/plain',
        'cfg': 'text/plain',
        'toml': 'application/toml',
        'dockerfile': 'text/plain',
        
        # Documentos
        'pdf': 'application/pdf',
        'doc': 'application/msword',
        'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'xls': 'application/vnd.ms-excel',
        'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'ppt': 'application/vnd.ms-powerpoint',
        'pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        
        # Archives
        'zip': 'application/zip',
        'tar': 'application/x-tar',
        'gz': 'application/gzip',
        'bz2': 'application/x-bzip2',
        'rar': 'application/x-rar-compressed',
        '7z': 'application/x-7z-compressed'
    }
    
    detected_type = extension_map.get(extension, 'application/octet-stream')
    
    # Verificación adicional para archivos de texto
    if detected_type.startswith('text/') or detected_type in ['application/json', 'application/xml']:
        if not _is_likely_text(content):
            return 'application/octet-stream'
    
    return detected_type


def _is_likely_text(content: bytes) -> bool:
    """
    Determina si el contenido es probablemente texto.
    
    Args:
        content: Contenido a analizar
        
    Returns:
        bool: True si parece ser texto
    """
    if not content:
        return True
    
    # Verificar los primeros bytes
    sample_size = min(1024, len(content))
    sample = content[:sample_size]
    
    # Contar bytes de control (excluyendo whitespace común)
    control_chars = 0
    for byte in sample:
        if byte < 32 and byte not in (9, 10, 13):  # Tab, LF, CR
            control_chars += 1
    
    # Si más del 5% son caracteres de control, probablemente es binario
    if control_chars / len(sample) > 0.05:
        return False
    
    # Intentar decodificar como UTF-8
    try:
        sample.decode('utf-8')
        return True
    except UnicodeDecodeError:
        pass
    
    # Intentar decodificar como latin-1 (más permisivo)
    try:
        sample.decode('latin-1')
        # Si se decodifica pero tiene muchos caracteres extraños, probablemente es binario
        decoded = sample.decode('latin-1')
        printable_chars = sum(1 for c in decoded if c.isprintable() or c.isspace())
        return printable_chars / len(decoded) > 0.7
    except UnicodeDecodeError:
        return False


def _analyze_file_content(content: bytes, filename: str) -> Dict[str, Any]:
    """
    Analiza el contenido del archivo para generar métricas útiles.
    
    Args:
        content: Contenido del archivo
        filename: Nombre del archivo
        
    Returns:
        Dict[str, Any]: Análisis del contenido
    """
    analysis = {
        "is_binary": not _is_likely_text(content),
        "file_size": len(content),
        "is_empty": len(content) == 0
    }
    
    if analysis["is_binary"]:
        # Análisis básico para archivos binarios
        analysis.update({
            "type": "binary",
            "entropy": _calculate_entropy(content[:1024]) if content else 0.0
        })
    else:
        # Análisis para archivos de texto
        try:
            text_content = content.decode('utf-8', errors='replace')
            lines = text_content.split('\n')
            
            analysis.update({
                "type": "text",
                "lines": len(lines),
                "characters": len(text_content),
                "avg_line_length": sum(len(line) for line in lines) / len(lines) if lines else 0,
                "max_line_length": max(len(line) for line in lines) if lines else 0,
                "empty_lines": sum(1 for line in lines if not line.strip()),
                "encoding": "utf-8"
            })
            
        except Exception:
            analysis["type"] = "binary"  # Fallback si falla el análisis de texto
    
    return analysis


def _calculate_entropy(data: bytes) -> float:
    """
    Calcula la entropía de Shannon para detectar archivos comprimidos/encriptados.
    
    Args:
        data: Datos a analizar
        
    Returns:
        float: Entropía (0.0 - 8.0, donde 8.0 es máxima entropía)
    """
    if not data:
        return 0.0
    
    # Contar frecuencia de cada byte
    frequencies = {}
    for byte in data:
        frequencies[byte] = frequencies.get(byte, 0) + 1
    
    # Calcular entropía
    entropy = 0.0
    data_len = len(data)
    
    for count in frequencies.values():
        probability = count / data_len
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    return entropy


# ========================================
# FUNCIONES DE MÉTRICAS
# ========================================

def _log_download_metrics(processed_file: Dict[str, Any], provider: str) -> None:
    """
    Registra métricas de negocio para la descarga completada.
    
    Args:
        processed_file: Datos del archivo procesado
        provider: Nombre del proveedor
    """
    file_size = processed_file["file_size"]
    content_type = processed_file["content_type"]
    is_binary = processed_file["analysis"]["is_binary"]
    
    # Métricas básicas
    log_business_metric(MetricNames.FILES_DOWNLOADED, 1, "count")
    log_business_metric(MetricNames.DOWNLOAD_SIZE, file_size, "bytes")
    
    # Métricas por proveedor
    log_business_metric(f"files_{provider}", 1, "count")
    log_business_metric(f"bytes_{provider}", file_size, "bytes")
    
    # Métricas por tipo
    if is_binary:
        log_business_metric("binary_files_downloaded", 1, "count")
    else:
        log_business_metric("text_files_downloaded", 1, "count")
    
    # Métricas por categoría de tamaño
    if file_size < 1024:  # < 1KB
        log_business_metric("small_files_downloaded", 1, "count")
    elif file_size < 1024 * 1024:  # < 1MB
        log_business_metric("medium_files_downloaded", 1, "count")
    else:  # >= 1MB
        log_business_metric("large_files_downloaded", 1, "count")
    
    # Métricas por tipo de contenido
    if content_type.startswith('text/'):
        log_business_metric("text_content_downloaded", 1, "count")
    elif content_type.startswith('image/'):
        log_business_metric("image_content_downloaded", 1, "count")
    elif content_type.startswith('application/'):
        log_business_metric("application_content_downloaded", 1, "count")


# ========================================
# FUNCIONES DE CONVENIENCIA PARA TESTING LOCAL
# ========================================

def handle_download_file_local(manager: Any, path: str, provider: str) -> None:
    """
    Maneja DOWNLOAD_FILE para testing local con output formateado y debug completo.
    
    Args:
        manager: Manager del proveedor
        path: Ruta del archivo
        provider: Nombre del proveedor
        
    Esta función es específica para main.py y proporciona output
    legible para debugging y desarrollo local.
    """
    try:
        logger.info("=== INICIANDO DOWNLOAD_FILE (LOCAL) ===")
        
        # Usar el manejador principal
        response = handle_download_file(manager, path, provider)
        
        # 🔍 DEBUG: Mostrar estructura completa de la respuesta
        print("\n🔍 RESPONSE STRUCTURE:")
        print(f"Keys: {list(response.keys())}")
        print(f"StatusCode: {response.get('statusCode', 'N/A')}")
        print(f"isBase64Encoded: {response.get('isBase64Encoded', 'N/A')}")
        
        # Obtener información de la respuesta
        response_body = response.get("body", "")
        headers = response.get("headers", {})
        filename = path.split('/')[-1]
        is_base64 = response.get("isBase64Encoded", False)
        
        # Output formateado para consola
        print("\n" + "="*60)
        print("📥 DESCARGA DE ARCHIVO")
        print("="*60)
        print(f"🔧 Proveedor: {provider}")
        print(f"📂 Ruta: {path}")
        print(f"📄 Archivo: {filename}")
        print(f"🏷️ Tipo: {headers.get('Content-Type', 'unknown')}")
        print(f"📦 Codificación: {'Base64' if is_base64 else 'Plain'}")
        
        # 🔍 DEBUG DEL BASE64
        print(f"\n🔍 DEBUG DE CONTENIDO:")
        print(f"📝 Response tiene 'body': {bool(response_body)}")
        print(f"📏 Longitud del body: {len(response_body) if response_body else 0}")
        
        if response_body:
            print(f"📊 Tamaño del body: {len(response_body):,} bytes ({len(response_body) / 1024:.1f} KB)")
            print(f"🔍 Primeros 100 caracteres del body:")
            print(repr(response_body[:100]))
            
            if is_base64:
                try:
                    decoded = base64.b64decode(response_body)
                    print(f"✅ Base64 válido, archivo decodificado: {len(decoded)} bytes")
                    print(f"🔍 Primeros 20 bytes del archivo: {decoded[:20]}")
                    
                    # Verificar que es realmente un archivo .docx (debe empezar con PK)
                    if decoded.startswith(b'PK'):
                        print("✅ Archivo .docx válido (ZIP signature detectada)")
                    else:
                        print("⚠️ El archivo no tiene la signature esperada de .docx")
                        
                except Exception as e:
                    print(f"❌ Error decodificando base64: {e}")
            else:
                print("⚠️ El contenido NO está marcado como base64")
        else:
            print("❌ No hay contenido en el body de la respuesta")
        
        # Mostrar preview del contenido si es texto pequeño
        if headers.get('Content-Type', '').startswith('text/') and response_body and len(response_body) < 10000:
            try:
                if is_base64:
                    decoded_content = base64.b64decode(response_body)
                    text_content = decoded_content.decode('utf-8', errors='replace')
                else:
                    text_content = response_body
                
                print("\n" + "="*60)
                print("👀 PREVIEW DEL CONTENIDO (primeros 500 caracteres)")
                print("="*60)
                print(text_content[:500])
                if len(text_content) > 500:
                    print("... (contenido truncado)")
                    
            except Exception as e:
                print(f"\n⚠️ No se pudo mostrar preview: {e}")
        
        print("\n✅ DOWNLOAD_FILE completado exitosamente")
        
    except Exception as e:
        logger.exception("Error in local download handling")
        print(f"\n❌ Error: {str(e)}")
        print(f"🔧 Tipo: {type(e).__name__}")


# Inicialización del módulo
logger.info("Download handler initialized", extra={
    "features": ["binary_support", "security_validation", "content_analysis", "size_limits"],
    "max_file_size_mb": MAX_FILE_SIZE_BYTES // 1024 // 1024
})