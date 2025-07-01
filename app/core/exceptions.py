"""
Excepciones personalizadas para el servicio de gestión de repositorios.

Este módulo define una jerarquía de excepciones tipadas que facilitan
el manejo de errores específicos del dominio y mejoran la observabilidad.

Features:
- Excepciones con códigos de error estandarizados
- Context adicional para debugging
- Integración con sistema de logging
- Mapeo directo a códigos HTTP

Author: [Your Name]
Created: 2025
Version: 2.0.0
"""

from typing import Optional, Dict, Any, Union
from app.core.constants import ErrorCodes


class SourceCodeError(Exception):
    """
    Excepción base para todos los errores del servicio de código fuente.
    
    Proporciona un punto central para el manejo de errores específicos del dominio,
    facilitando la captura y el manejo diferenciado de errores con contexto rico.
    
    Attributes:
        message: Mensaje descriptivo del error para el usuario
        error_code: Código de error estandarizado (ver ErrorCodes)
        details: Información adicional del error para debugging
        http_status: Código HTTP sugerido para la respuesta
        provider: Proveedor relacionado con el error (opcional)
    
    Example:
        raise SourceCodeError(
            "Error procesando repositorio",
            error_code=ErrorCodes.STRUCTURE_FETCH_FAILED,
            details={"repo": "my-repo", "provider": "github"},
            http_status=500
        )
    """
    
    def __init__(
        self, 
        message: str, 
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        http_status: int = 500,
        provider: Optional[str] = None
    ):
        self.message = message
        self.error_code = error_code
        self.details = details or {}
        self.http_status = http_status
        self.provider = provider
        
        # Agregar provider a details si está disponible
        if provider and 'provider' not in self.details:
            self.details['provider'] = provider
            
        super().__init__(self.message)
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convierte la excepción a diccionario para serialización.
        
        Returns:
            Dict con información estructurada del error
        """
        return {
            "error": self.message,
            "error_code": self.error_code,
            "details": self.details,
            "http_status": self.http_status,
            "provider": self.provider
        }
    
    def __str__(self) -> str:
        """Representación string con contexto adicional"""
        parts = [self.message]
        if self.error_code:
            parts.append(f"Code: {self.error_code}")
        if self.provider:
            parts.append(f"Provider: {self.provider}")
        return " | ".join(parts)


class ValidationError(SourceCodeError):
    """
    Error de validación de entrada del usuario.
    
    Se lanza cuando los datos de entrada no cumplen con los requisitos
    del sistema (formato, tipo, valores permitidos, etc.).
    
    HTTP Status: 400 Bad Request
    
    Common Scenarios:
        - Parámetros requeridos faltantes
        - Formato de datos inválido
        - Valores fuera de rango permitido
        - Path traversal attempts
        - JSON malformado
    
    Example:
        raise ValidationError(
            "El campo 'operation' es requerido",
            error_code=ErrorCodes.MISSING_OPERATION,
            details={"received_fields": ["provider", "config"]}
        )
    """
    
    def __init__(
        self, 
        message: str, 
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        field_name: Optional[str] = None,
        received_value: Any = None
    ):
        # Agregar información de campo si está disponible
        enhanced_details = details or {}
        if field_name:
            enhanced_details['field_name'] = field_name
        if received_value is not None:
            enhanced_details['received_value'] = str(received_value)
            enhanced_details['received_type'] = type(received_value).__name__
        
        super().__init__(
            message=message,
            error_code=error_code,
            details=enhanced_details,
            http_status=400
        )
        
        self.field_name = field_name
        self.received_value = received_value


class ConfigurationError(SourceCodeError):
    """
    Error en la configuración del proveedor de repositorio.
    
    Se lanza cuando la configuración del proveedor es inválida,
    está incompleta o contiene valores incorrectos.
    
    HTTP Status: 400 Bad Request
    
    Common Scenarios:
        - Claves requeridas faltantes en config
        - Proveedor no soportado
        - Tokens inválidos o expirados
        - URLs mal formateadas
        - Valores de configuración inválidos
    
    Example:
        raise ConfigurationError(
            "Falta token de GitHub",
            error_code=ErrorCodes.MISSING_REQUIRED_KEYS,
            details={
                "provider": "github",
                "missing_keys": ["token"],
                "received_keys": ["owner", "repo"]
            },
            provider="github"
        )
    """
    
    def __init__(
        self, 
        message: str, 
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        provider: Optional[str] = None,
        missing_keys: Optional[list] = None,
        invalid_keys: Optional[list] = None
    ):
        # Agregar información específica de configuración
        enhanced_details = details or {}
        if missing_keys:
            enhanced_details['missing_keys'] = missing_keys
        if invalid_keys:
            enhanced_details['invalid_keys'] = invalid_keys
        
        super().__init__(
            message=message,
            error_code=error_code,
            details=enhanced_details,
            http_status=400,
            provider=provider
        )
        
        self.missing_keys = missing_keys or []
        self.invalid_keys = invalid_keys or []


class SecurityError(ValidationError):
    """
    Error de seguridad detectado en la entrada.
    
    Se lanza cuando se detectan intentos de exploits o patrones
    peligrosos en los datos de entrada.
    
    HTTP Status: 400 Bad Request (no revelar detalles de seguridad)
    
    Common Scenarios:
        - Path traversal attempts (../, ..\)
        - Injection attempts (script tags, commands)
        - Caracteres de control maliciosos
        - Rutas absolutas no permitidas
        - Patrones de exploit conocidos
    
    Example:
        raise SecurityError(
            "Ruta de archivo inválida",
            error_code=ErrorCodes.PATH_TRAVERSAL,
            details={"detected_pattern": "../", "sanitized_input": True},
            attack_type="path_traversal"
        )
    """
    
    def __init__(
        self, 
        message: str, 
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        attack_type: Optional[str] = None,
        detected_pattern: Optional[str] = None
    ):
        # Agregar información específica de seguridad
        enhanced_details = details or {}
        if attack_type:
            enhanced_details['attack_type'] = attack_type
        if detected_pattern:
            enhanced_details['detected_pattern'] = detected_pattern
        enhanced_details['security_event'] = True
        
        super().__init__(
            message=message,
            error_code=error_code,
            details=enhanced_details
        )
        
        self.attack_type = attack_type
        self.detected_pattern = detected_pattern


class FileTooLargeError(SourceCodeError):
    """
    Error cuando un archivo excede el límite de tamaño permitido.
    
    Se implementa para prevenir memory overrun en AWS Lambda y
    controlar costos de transferencia.
    
    HTTP Status: 413 Payload Too Large
    
    Common Scenarios:
        - Archivos que exceden MAX_FILE_SIZE_BYTES
        - Estructuras con demasiados nodos
        - Respuestas que consumirían demasiada memoria
    
    Example:
        raise FileTooLargeError(
            f"Archivo de {file_size}MB excede límite de {max_size}MB",
            error_code=ErrorCodes.FILE_TOO_LARGE,
            details={
                "file_size_bytes": file_size_bytes,
                "max_size_bytes": max_size_bytes,
                "filename": "large_file.zip"
            },
            file_size=file_size_bytes,
            max_size=max_size_bytes
        )
    """
    
    def __init__(
        self, 
        message: str, 
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        file_size: Optional[int] = None,
        max_size: Optional[int] = None,
        filename: Optional[str] = None
    ):
        # Agregar información específica de tamaño
        enhanced_details = details or {}
        if file_size is not None:
            enhanced_details['file_size_bytes'] = file_size
            enhanced_details['file_size_mb'] = round(file_size / 1024 / 1024, 2)
        if max_size is not None:
            enhanced_details['max_size_bytes'] = max_size
            enhanced_details['max_size_mb'] = round(max_size / 1024 / 1024, 2)
        if filename:
            enhanced_details['filename'] = filename
        
        super().__init__(
            message=message,
            error_code=error_code,
            details=enhanced_details,
            http_status=413
        )
        
        self.file_size = file_size
        self.max_size = max_size
        self.filename = filename


class ProviderError(SourceCodeError):
    """
    Error específico del proveedor de repositorio externo.
    
    Se lanza cuando hay problemas con las APIs de los proveedores
    externos (GitHub, GitLab, Azure DevOps, SVN).
    
    HTTP Status: 502 Bad Gateway (problema con servicio externo)
    
    Common Scenarios:
        - API del proveedor retorna error
        - Problemas de autenticación/autorización
        - Rate limiting del proveedor
        - Timeouts de red
        - Servicios temporalmente no disponibles
    
    Example:
        raise ProviderError(
            "GitHub API rate limit exceeded",
            error_code=ErrorCodes.PROVIDER_RATE_LIMIT,
            details={
                "rate_limit_remaining": 0,
                "rate_limit_reset": 1640995200,
                "retry_after": 3600
            },
            provider="github",
            api_response_code=403
        )
    """
    
    def __init__(
        self, 
        message: str, 
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        provider: Optional[str] = None,
        api_response_code: Optional[int] = None,
        retry_after: Optional[int] = None,
        original_error: Optional[Exception] = None
    ):
        # Agregar información específica del proveedor
        enhanced_details = details or {}
        if api_response_code:
            enhanced_details['api_response_code'] = api_response_code
        if retry_after:
            enhanced_details['retry_after_seconds'] = retry_after
        if original_error:
            enhanced_details['original_error'] = str(original_error)
            enhanced_details['original_error_type'] = type(original_error).__name__
        
        super().__init__(
            message=message,
            error_code=error_code,
            details=enhanced_details,
            http_status=502,
            provider=provider
        )
        
        self.api_response_code = api_response_code
        self.retry_after = retry_after
        self.original_error = original_error


class TimeoutError(ProviderError):
    """
    Error específico de timeout en operaciones con proveedores.
    
    Se lanza cuando las operaciones exceden los límites de tiempo
    configurados para prevenir Lambda timeouts.
    
    HTTP Status: 504 Gateway Timeout
    
    Example:
        raise TimeoutError(
            "Timeout descargando archivo desde GitHub",
            error_code=ErrorCodes.DOWNLOAD_TIMEOUT,
            details={"timeout_seconds": 30, "operation": "download_file"},
            provider="github",
            timeout_seconds=30
        )
    """
    
    def __init__(
        self, 
        message: str, 
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        provider: Optional[str] = None,
        timeout_seconds: Optional[int] = None,
        operation: Optional[str] = None
    ):
        # Agregar información específica de timeout
        enhanced_details = details or {}
        if timeout_seconds:
            enhanced_details['timeout_seconds'] = timeout_seconds
        if operation:
            enhanced_details['operation'] = operation
        
        super().__init__(
            message=message,
            error_code=error_code,
            details=enhanced_details,
            provider=provider
        )
        
        # Override HTTP status para timeout
        self.http_status = 504
        self.timeout_seconds = timeout_seconds
        self.operation = operation


# ========================================
# FUNCIONES DE UTILIDAD PARA EXCEPCIONES
# ========================================

def create_validation_error(
    message: str,
    field_name: Optional[str] = None,
    received_value: Any = None,
    error_code: Optional[str] = None
) -> ValidationError:
    """
    Factory function para crear errores de validación consistentes.
    
    Args:
        message: Mensaje del error
        field_name: Nombre del campo que causó el error
        received_value: Valor recibido que causó el error
        error_code: Código de error específico
        
    Returns:
        ValidationError configurado
    """
    return ValidationError(
        message=message,
        field_name=field_name,
        received_value=received_value,
        error_code=error_code
    )

def create_config_error(
    message: str,
    provider: str,
    missing_keys: Optional[list] = None,
    invalid_keys: Optional[list] = None,
    error_code: Optional[str] = None
) -> ConfigurationError:
    """
    Factory function para crear errores de configuración consistentes.
    
    Args:
        message: Mensaje del error
        provider: Proveedor que causó el error
        missing_keys: Claves faltantes en la configuración
        invalid_keys: Claves inválidas en la configuración
        error_code: Código de error específico
        
    Returns:
        ConfigurationError configurado
    """
    return ConfigurationError(
        message=message,
        provider=provider,
        missing_keys=missing_keys,
        invalid_keys=invalid_keys,
        error_code=error_code
    )

def create_security_error(
    message: str,
    attack_type: str,
    detected_pattern: Optional[str] = None,
    error_code: Optional[str] = None
) -> SecurityError:
    """
    Factory function para crear errores de seguridad consistentes.
    
    Args:
        message: Mensaje del error
        attack_type: Tipo de ataque detectado
        detected_pattern: Patrón específico detectado
        error_code: Código de error específico
        
    Returns:
        SecurityError configurado
    """
    return SecurityError(
        message=message,
        attack_type=attack_type,
        detected_pattern=detected_pattern,
        error_code=error_code
    )

def create_provider_error(
    message: str,
    provider: str,
    api_response_code: Optional[int] = None,
    original_error: Optional[Exception] = None,
    error_code: Optional[str] = None
) -> ProviderError:
    """
    Factory function para crear errores de proveedor consistentes.
    
    Args:
        message: Mensaje del error
        provider: Proveedor que causó el error
        api_response_code: Código de respuesta de la API
        original_error: Excepción original que causó el error
        error_code: Código de error específico
        
    Returns:
        ProviderError configurado
    """
    return ProviderError(
        message=message,
        provider=provider,
        api_response_code=api_response_code,
        original_error=original_error,
        error_code=error_code
    )

def handle_provider_exception(
    e: Exception,
    provider: str,
    operation: str,
    context: Optional[Dict[str, Any]] = None
) -> ProviderError:
    """
    Convierte excepciones genéricas en ProviderError específicos.
    
    Analiza la excepción original y crea un ProviderError apropiado
    con el código de error y contexto correcto.
    
    Args:
        e: Excepción original
        provider: Proveedor donde ocurrió el error
        operation: Operación que se estaba realizando
        context: Contexto adicional (path, repo, etc.)
        
    Returns:
        ProviderError apropiado para la excepción
    """
    error_message = str(e).lower()
    context = context or {}
    
    # Analizar tipo de error basado en el mensaje
    if "timeout" in error_message:
        return TimeoutError(
            f"Timeout en {operation} con {provider}",
            error_code=ErrorCodes.PROVIDER_TIMEOUT,
            details=context,
            provider=provider,
            operation=operation,
            original_error=e
        )
    elif "not found" in error_message or "404" in error_message:
        return ProviderError(
            f"Recurso no encontrado en {provider}",
            error_code=ErrorCodes.FILE_NOT_FOUND,
            details=context,
            provider=provider,
            api_response_code=404,
            original_error=e
        )
    elif "permission" in error_message or "403" in error_message:
        return ProviderError(
            f"Sin permisos para acceder a {provider}",
            error_code=ErrorCodes.ACCESS_DENIED,
            details=context,
            provider=provider,
            api_response_code=403,
            original_error=e
        )
    elif "rate limit" in error_message or "429" in error_message:
        return ProviderError(
            f"Rate limit excedido en {provider}",
            error_code=ErrorCodes.PROVIDER_RATE_LIMIT,
            details=context,
            provider=provider,
            api_response_code=429,
            original_error=e
        )
    else:
        return ProviderError(
            f"Error de {provider} en {operation}",
            error_code=ErrorCodes.PROVIDER_API_ERROR,
            details=context,
            provider=provider,
            original_error=e
        )