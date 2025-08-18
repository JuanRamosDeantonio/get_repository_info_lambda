"""
Sistema de respuestas HTTP estandarizadas para AWS Lambda.

Este módulo proporciona funciones para crear respuestas HTTP consistentes:
- Respuestas de éxito con datos JSON
- Respuestas de error categorizadas
- Respuestas de archivos con Base64
- Headers de seguridad automáticos
- Compresión y optimización

Features:
- Headers de seguridad por defecto
- Content-Type apropiado por tipo de respuesta
- CORS configurado automáticamente
- Base64 encoding para archivos binarios
- Compresión JSON optimizada
- Logging automático de métricas

Author: [Your Name]
Created: 2025
Version: 2.0.0
"""

import json
import time
import base64
from typing import Dict, Any, Optional, Union, List
from datetime import datetime, timezone
from app.utils.serializers import serialize_structure

from app.core.constants import (
    COMMON_HEADERS,
    JSON_HEADERS,
    FILE_HEADERS,
    MAX_FILE_SIZE_BYTES,
    ErrorCodes
)
from app.core.exceptions import SourceCodeError
from app.core.logger import get_logger, log_business_metric

# Logger para el módulo
logger = get_logger(__name__)

# ========================================
# RESPUESTAS DE ÉXITO
# ========================================

def create_success_response(
    data: Dict[str, Any],
    status_code: int = 200,
    extra_headers: Optional[Dict[str, str]] = None,
    compress: bool = True
) -> Dict[str, Any]:
    """
    Crea una respuesta de éxito estandarizada con datos JSON.
    
    Args:
        data: Datos a incluir en la respuesta
        status_code: Código de estado HTTP (default: 200)
        extra_headers: Headers adicionales (opcional)
        compress: Si comprimir la respuesta JSON (default: True)
        
    Returns:
        Dict[str, Any]: Respuesta HTTP completa
        
    Features:
        - Headers de seguridad automáticos
        - CORS habilitado
        - JSON optimizado (sin espacios si compress=True)
        - Timestamp automático
        - Métricas de tamaño automáticas
        
    Example:
        >>> response = create_success_response({
        ...     "mensaje": "Operación exitosa",
        ...     "datos": [1, 2, 3]
        ... })
    """
    # Preparar headers
    headers = JSON_HEADERS.copy()
    if extra_headers:
        headers.update(extra_headers)
    
    # Agregar timestamp y metadata
    response_data = {
        **data,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "success": True
    }
    
    # Serializar JSON con optimización
    if compress:
        # JSON compacto para producción
        json_body = json.dumps(response_data, ensure_ascii=False, separators=(',', ':'))
    else:
        # JSON legible para desarrollo
        json_body = json.dumps(response_data, ensure_ascii=False, indent=2)
    
    # Métricas de respuesta
    response_size = len(json_body.encode('utf-8'))
    log_business_metric("response_size", response_size, "bytes")
    log_business_metric("success_responses", 1, "count")
    
    logger.debug("Success response created", extra={
        "status_code": status_code,
        "response_size": response_size,
        "data_keys": list(data.keys()),
        "compressed": compress
    })
    
    return {
        "statusCode": status_code,
        "headers": headers,
        "body": json_body
    }


def create_structure_response(
    nodes: List[Any],
    provider: str,
    markdown: str,
    metadata: Optional[Dict[str, Any]],
    files = None
) -> Dict[str, Any]:
    """
    Crea respuesta especializada para operación GET_STRUCTURE.
    
    Args:
        nodes: Lista de nodos del árbol de archivos
        provider: Proveedor del repositorio
        markdown: Representación en Markdown
        metadata: Metadatos adicionales (opcional)
        
    Returns:
        Dict[str, Any]: Respuesta HTTP optimizada para estructuras
        
    Features:
        - Estructura optimizada para consumo por IA
        - Metadatos enriquecidos automáticamente
        - Conteo de archivos/carpetas
        - Información de profundidad
        
    Example:
        >>> response = create_structure_response(
        ...     nodes, "github", markdown_str, {"custom": "data"}
        ... )
    """
    # Calcular métricas de la estructura
    total_nodes = _count_total_nodes(nodes)
    file_metrics = _calculate_file_metrics(nodes)
    
    # Preparar datos de respuesta
    response_data = {
        "mensaje": "Estructura obtenida exitosamente",
        "proveedor": provider,
        "markdown": markdown,
        "estructura": serialize_structure(nodes),
        "total_nodos": total_nodes,
        "archivos": files or [],
        "metadatos": {
            "archivos": file_metrics["files"],
            "carpetas": file_metrics["folders"],
            "profundidad_maxima": file_metrics["max_depth"],
            "tamaño_estructura": len(markdown),
            **(metadata or {})
        }
    }
    
    # Métricas de negocio
    log_business_metric("structure_nodes_returned", total_nodes, "count")
    log_business_metric("structure_files_returned", file_metrics["files"], "count")
    log_business_metric("structure_folders_returned", file_metrics["folders"], "count")
    
    return create_success_response(response_data)


def create_file_response(
    content: bytes,
    filename: Optional[str] = None,
    content_type: Optional[str] = None,
    cache_control: Optional[str] = None
) -> Dict[str, Any]:
    """
    Crea respuesta optimizada para descarga de archivos.
    
    Args:
        content: Contenido del archivo en bytes
        filename: Nombre sugerido del archivo (opcional)
        content_type: Tipo MIME del archivo (opcional)
        cache_control: Configuración de cache (opcional)
        
    Returns:
        Dict[str, Any]: Respuesta HTTP para descarga de archivo
        
    Raises:
        ValueError: Si el archivo es demasiado grande
        
    Features:
        - Base64 encoding automático para binarios
        - Headers de descarga apropiados
        - Detección automática de tipo MIME
        - Límites de tamaño automáticos
        - Content-Disposition para nombres de archivo
        
    Example:
        >>> response = create_file_response(
        ...     file_bytes, "script.py", "text/python"
        ... )
    """
    file_size = len(content)
    
    # Verificar límite de tamaño
    if file_size > MAX_FILE_SIZE_BYTES:
        raise ValueError(
            f"Archivo de {file_size // 1024 // 1024}MB excede límite de "
            f"{MAX_FILE_SIZE_BYTES // 1024 // 1024}MB"
        )
    
    # Preparar headers
    headers = FILE_HEADERS.copy()
    
    # Content-Type
    if content_type:
        headers["Content-Type"] = content_type
    elif filename:
        headers["Content-Type"] = _detect_content_type(filename)
    
    # Cache control
    if cache_control:
        headers["Cache-Control"] = cache_control
    elif _is_cacheable_file(filename):
        headers["Cache-Control"] = "public, max-age=3600"  # 1 hora
    
    # Content-Disposition para descarga
    if filename:
        safe_filename = _sanitize_filename_for_header(filename)
        headers["Content-Disposition"] = f'attachment; filename="{safe_filename}"'
    
    # Codificar contenido en Base64
    encoded_content = base64.b64encode(content).decode('utf-8')
    
    # Métricas de archivo
    log_business_metric("file_downloads", 1, "count")
    log_business_metric("file_download_size", file_size, "bytes")
    
    logger.info("File response created", extra={
        "filename_retrieved": filename,
        "file_size": file_size,
        "content_type": content_type,
        "encoded_size": len(encoded_content)
    })
    
    return {
        "statusCode": 200,
        "headers": headers,
        "body": encoded_content,
        "isBase64Encoded": True
    }

def create_reference_response(
    bucket_name: str,
    s3_path: str,
    filename: Optional[str] = None,
    content_type: Optional[str] = None,
    cache_control: Optional[str] = None
) -> Dict[str, Any]:
    """
    Crea respuesta optimizada para referencia a archivos en S3.
    
    Args:
        bucket_name: Nombre del bucket de S3
        s3_path: Clave/ruta del archivo en el bucket
        filename: Nombre sugerido del archivo (opcional)
        content_type: Tipo MIME del archivo (opcional)
        cache_control: Configuración de cache (opcional)
        
    Returns:
        Dict[str, Any]: Respuesta HTTP con referencia al archivo en S3
        
    Raises:
        ValueError: Si el bucket_name o s3_path están vacíos
        
    Features:
        - Referencias a archivos en S3 sin transferir contenido
        - Headers de descarga apropiados
        - Detección automática de tipo MIME
        - Content-Disposition para nombres de archivo
        - Métricas de referencias generadas
        
    Example:
        >>> response = create_reference_response(
        ...     "my-bucket", "documents/script.py", "script.py", "text/python"
        ... )
    """
    # Validar parámetros requeridos
    if not bucket_name or not bucket_name.strip():
        raise ValueError("bucket_name no puede estar vacío")
        
    if not s3_path or not s3_path.strip():
        raise ValueError("s3_path no puede estar vacío")
    
    # Limpiar parámetros
    bucket_name = bucket_name.strip()
    s3_path = s3_path.strip().lstrip('/')  # Remover slash inicial si existe
    
    # Preparar headers
    headers = FILE_HEADERS.copy()
    
    # Content-Type
    if content_type:
        headers["Content-Type"] = content_type
    elif filename:
        headers["Content-Type"] = _detect_content_type(filename)
    elif s3_path:
        # Intentar detectar desde la extensión del s3_path
        headers["Content-Type"] = _detect_content_type(s3_path)
    
    # Cache control
    if cache_control:
        headers["Cache-Control"] = cache_control
    elif _is_cacheable_file(filename or s3_path):
        headers["Cache-Control"] = "public, max-age=3600"  # 1 hora
    
    # Content-Disposition para descarga
    display_filename = filename or s3_path.split('/')[-1]  # Usar último segmento del path si no hay filename
    if display_filename:
        safe_filename = _sanitize_filename_for_header(display_filename)
        headers["Content-Disposition"] = f'attachment; filename="{safe_filename}"'
    
    # Crear cuerpo de respuesta con referencia a S3
    response_body = {
        "bucket_name": bucket_name,
        "s3_path": s3_path
    }
    
    # Métricas de referencia
    log_business_metric("file_references", 1, "count")
    log_business_metric("s3_references", 1, "count")
    
    logger.info("S3 reference response created", extra={
        "bucket_name": bucket_name,
        "s3_path": s3_path,
        "filename_retrieved": filename,
        "content_type": content_type,
        "display_filename": display_filename
    })
    
    return {
        "statusCode": 200,
        "headers": headers,
        "body": json.dumps(response_body),
        "isBase64Encoded": False
    }


# ========================================
# RESPUESTAS DE ERROR
# ========================================

def create_error_response(
    status_code: int,
    error_message: str,
    error_type: str = "error",
    error_code: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    provider: Optional[str] = None
) -> Dict[str, Any]:
    """
    Crea una respuesta de error estandarizada.
    
    Args:
        status_code: Código de estado HTTP
        error_message: Mensaje de error para el usuario
        error_type: Tipo de error para categorización
        error_code: Código de error específico (opcional)
        details: Detalles adicionales del error (opcional)
        provider: Proveedor relacionado (opcional)
        
    Returns:
        Dict[str, Any]: Respuesta HTTP de error
        
    Features:
        - Categorización automática de errores
        - Headers de seguridad
        - Logging automático de métricas
        - Información estructurada para debugging
        - Sanitización de mensajes sensibles
        
    Example:
        >>> response = create_error_response(
        ...     400, "Campo requerido faltante", "validation_error",
        ...     error_code="MISSING_FIELD", details={"field": "operation"}
        ... )
    """
    # Preparar headers de error
    headers = JSON_HEADERS.copy()
    
    # Sanitizar detalles sensibles en producción
    safe_details = _sanitize_error_details(details) if details else None
    
    # Estructura de error estandarizada
    error_data = {
        "error": error_message,
        "error_type": error_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "success": False
    }
    
    # Campos opcionales
    if error_code:
        error_data["error_code"] = error_code
    if safe_details:
        error_data["details"] = safe_details
    if provider:
        error_data["provider"] = provider
    
    # Serializar respuesta
    json_body = json.dumps(error_data, ensure_ascii=False, separators=(',', ':'))
    
    # Métricas de error
    log_business_metric("error_responses", 1, "count")
    log_business_metric(f"errors_{error_type}", 1, "count")
    if provider:
        log_business_metric(f"errors_{provider}", 1, "count")
    
    logger.warning("Error response created", extra={
        "status_code": status_code,
        "error_type": error_type,
        "error_code": error_code,
        "provider": provider,
        "has_details": bool(details)
    })
    
    return {
        "statusCode": status_code,
        "headers": headers,
        "body": json_body
    }


def create_validation_error_response(
    error_message: str,
    field_name: Optional[str] = None,
    received_value: Any = None
) -> Dict[str, Any]:
    """
    Crea respuesta especializada para errores de validación.
    
    Args:
        error_message: Mensaje del error
        field_name: Campo que causó el error (opcional)
        received_value: Valor recibido que causó el error (opcional)
        
    Returns:
        Dict[str, Any]: Respuesta HTTP 400 para error de validación
    """
    details = {}
    if field_name:
        details["field"] = field_name
    if received_value is not None:
        details["received_value"] = str(received_value)[:100]  # Limitar longitud
        details["received_type"] = type(received_value).__name__
    
    return create_error_response(
        status_code=400,
        error_message=error_message,
        error_type="validation_error",
        error_code=ErrorCodes.INVALID_PATH if "path" in error_message.lower() else None,
        details=details if details else None
    )


def create_configuration_error_response(
    error_message: str,
    provider: str,
    missing_keys: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Crea respuesta especializada para errores de configuración.
    
    Args:
        error_message: Mensaje del error
        provider: Proveedor que causó el error
        missing_keys: Claves faltantes (opcional)
        
    Returns:
        Dict[str, Any]: Respuesta HTTP 400 para error de configuración
    """
    details = {"provider": provider}
    if missing_keys:
        details["missing_keys"] = missing_keys
    
    return create_error_response(
        status_code=400,
        error_message=error_message,
        error_type="configuration_error",
        error_code=ErrorCodes.MISSING_REQUIRED_KEYS,
        details=details,
        provider=provider
    )


def create_exception_response(exception: Exception) -> Dict[str, Any]:
    """
    Crea respuesta desde una excepción del sistema.
    
    Args:
        exception: Excepción a convertir en respuesta
        
    Returns:
        Dict[str, Any]: Respuesta HTTP apropiada para la excepción
        
    Features:
        - Mapeo automático de excepciones a códigos HTTP
        - Extracción de contexto de excepciones personalizadas
        - Sanitización automática de mensajes
        - Preservación de códigos de error
    """
    # Si es una de nuestras excepciones personalizadas
    if isinstance(exception, SourceCodeError):
        return create_error_response(
            status_code=getattr(exception, 'http_status', 500),
            error_message=str(exception),
            error_type=type(exception).__name__.lower().replace('error', '_error'),
            error_code=getattr(exception, 'error_code', None),
            details=getattr(exception, 'details', None),
            provider=getattr(exception, 'provider', None)
        )
    
    # Excepciones estándar de Python
    elif isinstance(exception, ValueError):
        return create_error_response(
            status_code=400,
            error_message=str(exception),
            error_type="validation_error"
        )
    
    elif isinstance(exception, FileNotFoundError):
        return create_error_response(
            status_code=404,
            error_message="Archivo o recurso no encontrado",
            error_type="not_found_error"
        )
    
    elif isinstance(exception, PermissionError):
        return create_error_response(
            status_code=403,
            error_message="Sin permisos para acceder al recurso",
            error_type="permission_error"
        )
    
    elif isinstance(exception, TimeoutError):
        return create_error_response(
            status_code=504,
            error_message="Operación expiró por timeout",
            error_type="timeout_error"
        )
    
    # Excepción no reconocida
    else:
        logger.exception("Unhandled exception converted to response")
        return create_error_response(
            status_code=500,
            error_message="Error interno del servidor",
            error_type="internal_error"
        )


# ========================================
# RESPUESTAS ESPECIALIZADAS
# ========================================

def create_cors_preflight_response() -> Dict[str, Any]:
    """
    Crea respuesta para requests CORS preflight (OPTIONS).
    
    Returns:
        Dict[str, Any]: Respuesta HTTP 200 con headers CORS
    """
    headers = COMMON_HEADERS.copy()
    headers.update({
        "Access-Control-Max-Age": "86400",  # 24 horas
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With"
    })
    
    return {
        "statusCode": 200,
        "headers": headers,
        "body": ""
    }


def create_health_check_response() -> Dict[str, Any]:
    """
    Crea respuesta para health checks.
    
    Returns:
        Dict[str, Any]: Respuesta HTTP 200 con información de salud
    """
    health_data = {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "2.0.0",
        "service": "source-code-lambda"
    }
    
    return create_success_response(health_data)


def create_method_not_allowed_response(allowed_methods: List[str]) -> Dict[str, Any]:
    """
    Crea respuesta para métodos HTTP no permitidos.
    
    Args:
        allowed_methods: Lista de métodos permitidos
        
    Returns:
        Dict[str, Any]: Respuesta HTTP 405
    """
    headers = JSON_HEADERS.copy()
    headers["Allow"] = ", ".join(allowed_methods)
    
    return create_error_response(
        status_code=405,
        error_message=f"Método no permitido. Métodos válidos: {', '.join(allowed_methods)}",
        error_type="method_not_allowed",
        details={"allowed_methods": allowed_methods}
    )


# ========================================
# FUNCIONES AUXILIARES
# ========================================

def _count_total_nodes(nodes: List[Any]) -> int:
    """Cuenta recursivamente el total de nodos en la estructura"""
    count = len(nodes)
    for node in nodes:
        if hasattr(node, 'children') and node.children:
            count += _count_total_nodes(node.children)
    return count


def _calculate_file_metrics(nodes: List[Any]) -> Dict[str, int]:
    """Calcula métricas de archivos y carpetas"""
    metrics = {"files": 0, "folders": 0, "max_depth": 0}
    
    def traverse(node_list: List[Any], depth: int = 0) -> None:
        metrics["max_depth"] = max(metrics["max_depth"], depth)
        
        for node in node_list:
            if hasattr(node, 'type'):
                if node.type == 'file':
                    metrics["files"] += 1
                elif node.type == 'folder':
                    metrics["folders"] += 1
            
            if hasattr(node, 'children') and node.children:
                traverse(node.children, depth + 1)
    
    traverse(nodes)
    return metrics


def _detect_content_type(filename: str) -> str:
    """Detecta el tipo MIME basado en la extensión del archivo"""
    if not filename:
        return "application/octet-stream"
    
    extension = filename.lower().split('.')[-1] if '.' in filename else ''
    
    content_types = {
        # Texto
        'txt': 'text/plain',
        'md': 'text/markdown',
        'json': 'application/json',
        'xml': 'application/xml',
        'csv': 'text/csv',
        
        # Código
        'py': 'text/x-python',
        'js': 'application/javascript',
        'html': 'text/html',
        'css': 'text/css',
        'java': 'text/x-java-source',
        'cpp': 'text/x-c++src',
        'c': 'text/x-csrc',
        'go': 'text/x-go',
        'rs': 'text/x-rust',
        'php': 'text/x-php',
        'rb': 'text/x-ruby',
        
        # Imágenes
        'png': 'image/png',
        'jpg': 'image/jpeg',
        'jpeg': 'image/jpeg',
        'gif': 'image/gif',
        'svg': 'image/svg+xml',
        
        # Documentos
        'pdf': 'application/pdf',
        'doc': 'application/msword',
        'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        
        # Archivos
        'zip': 'application/zip',
        'tar': 'application/x-tar',
        'gz': 'application/gzip'
    }
    
    return content_types.get(extension, 'application/octet-stream')


def _is_cacheable_file(filename: Optional[str]) -> bool:
    """Determina si un archivo debe ser cacheable"""
    if not filename:
        return False
    
    # Extensiones que típicamente no cambian frecuentemente
    cacheable_extensions = {
        'png', 'jpg', 'jpeg', 'gif', 'svg',  # Imágenes
        'css', 'js',  # Assets estáticos
        'pdf', 'doc', 'docx',  # Documentos
        'zip', 'tar', 'gz'  # Archives
    }
    
    extension = filename.lower().split('.')[-1] if '.' in filename else ''
    return extension in cacheable_extensions


def _sanitize_filename_for_header(filename: str) -> str:
    """Sanitiza nombre de archivo para header HTTP"""
    # Remover caracteres problemáticos para headers HTTP
    safe_chars = []
    for char in filename:
        if char.isalnum() or char in '.-_ ':
            safe_chars.append(char)
        else:
            safe_chars.append('_')
    
    sanitized = ''.join(safe_chars).strip()
    
    # Asegurar longitud razonable
    if len(sanitized) > 100:
        name_part = sanitized[:95]
        ext_part = sanitized[-5:] if '.' in sanitized[-10:] else ""
        sanitized = name_part + ext_part
    
    return sanitized or "download"


def _sanitize_error_details(details: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitiza detalles de error para producción"""
    sanitized = {}
    
    # Campos que son seguros de exponer
    safe_fields = {
        'field_name', 'received_type', 'missing_keys', 'provider',
        'operation', 'error_code', 'file_size', 'max_size'
    }
    
    for key, value in details.items():
        if key in safe_fields:
            sanitized[key] = value
        elif key == 'received_value':
            # Truncar valores largos
            sanitized[key] = str(value)[:50] + "..." if len(str(value)) > 50 else str(value)
    
    return sanitized


# Inicialización del módulo
logger.info("HTTP response system initialized", extra={
    "features": ["security_headers", "cors_support", "base64_encoding", "error_categorization"],
    "default_headers": list(COMMON_HEADERS.keys())
})