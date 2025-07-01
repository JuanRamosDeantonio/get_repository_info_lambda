"""
Sistema de validación robusto para entrada de usuarios y configuraciones.

Este módulo proporciona validadores reutilizables y componibles para:
- Validación de configuraciones de proveedores
- Sanitización de rutas de archivos
- Validación de parámetros de entrada
- Detección de ataques de seguridad

Features:
- Validadores específicos por proveedor
- Detección avanzada de path traversal
- Caching de validaciones para performance
- Integración con sistema de excepciones
- Logging automático de eventos de seguridad

Author: [Your Name]
Created: 2025
Version: 2.0.0
"""

import re
import unicodedata
import urllib.parse
from typing import Dict, Any, List, Optional, Union, Tuple
from functools import lru_cache

from app.core.constants import (
    SUPPORTED_PROVIDERS,
    PROVIDER_NAMES,
    MAX_PATH_LENGTH,
    MAX_FILE_SIZE_BYTES,
    MAX_NODES_STRUCTURE,
    DANGEROUS_PATH_PATTERNS,
    ALLOWED_FILENAME_CHARS,
    Operations,
    ErrorCodes
)
from app.core.exceptions import (
    ValidationError,
    ConfigurationError,
    SecurityError,
    create_validation_error,
    create_config_error,
    create_security_error
)
from app.core.logger import get_logger, log_security_event

# Logger para el módulo
logger = get_logger(__name__)

# ========================================
# VALIDADORES DE ENTRADA PRINCIPAL
# ========================================

def validate_operation(operation: str) -> str:
    """
    Valida que la operación solicitada sea soportada.
    
    Args:
        operation: Operación a validar
        
    Returns:
        str: Operación validada
        
    Raises:
        ValidationError: Si la operación es inválida
        
    Example:
        >>> validate_operation("GET_STRUCTURE")
        'GET_STRUCTURE'
        
        >>> validate_operation("INVALID_OP")
        ValidationError: Operación 'INVALID_OP' no soportada
    """
    if not operation or not isinstance(operation, str):
        raise create_validation_error(
            "El campo 'operation' es requerido y debe ser una cadena",
            field_name="operation",
            received_value=operation,
            error_code=ErrorCodes.MISSING_OPERATION
        )
    
    operation = operation.strip().upper()
    
    if operation not in Operations.ALL:
        available_ops = ", ".join(Operations.ALL)
        raise create_validation_error(
            f"Operación '{operation}' no soportada. Disponibles: {available_ops}",
            field_name="operation",
            received_value=operation,
            error_code=ErrorCodes.INVALID_OPERATION
        )
    
    logger.debug(f"Operation validated: {operation}")
    return operation


def validate_provider(provider: str) -> str:
    """
    Valida que el proveedor sea soportado.
    
    Args:
        provider: Proveedor a validar
        
    Returns:
        str: Proveedor validado (normalizado a lowercase)
        
    Raises:
        ValidationError: Si el proveedor es inválido
        
    Example:
        >>> validate_provider("GitHub")
        'github'
        
        >>> validate_provider("unsupported")
        ValidationError: Proveedor 'unsupported' no soportado
    """
    if not provider or not isinstance(provider, str):
        raise create_validation_error(
            "El campo 'provider' es requerido y debe ser una cadena",
            field_name="provider",
            received_value=provider,
            error_code=ErrorCodes.MISSING_PROVIDER
        )
    
    provider_lower = provider.strip().lower()
    
    if provider_lower not in PROVIDER_NAMES:
        available_providers = ", ".join(PROVIDER_NAMES)
        raise create_validation_error(
            f"Proveedor '{provider}' no soportado. Disponibles: {available_providers}",
            field_name="provider",
            received_value=provider,
            error_code=ErrorCodes.INVALID_PROVIDER
        )
    
    logger.debug(f"Provider validated: {provider_lower}")
    return provider_lower


# ========================================
# VALIDADORES DE CONFIGURACIÓN
# ========================================

def validate_config(provider: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Valida la configuración completa de un proveedor.
    
    Orquesta todas las validaciones necesarias para un proveedor específico:
    - Validación de tipo y estructura básica
    - Claves requeridas y opcionales
    - Validaciones específicas del proveedor
    - Sanitización de valores
    
    Args:
        provider: Proveedor ya validado
        config: Configuración a validar
        
    Returns:
        Dict[str, Any]: Configuración validada y sanitizada
        
    Raises:
        ConfigurationError: Si la configuración es inválida
        
    Example:
        >>> config = {"token": "ghp_xxx", "owner": "user", "repo": "repo"}
        >>> validate_config("github", config)
        {'token': 'ghp_xxx', 'owner': 'user', 'repo': 'repo', 'branch': 'main'}
    """
    # Validación básica de tipo
    if not isinstance(config, dict):
        raise create_config_error(
            "La configuración debe ser un diccionario",
            provider=provider,
            error_code=ErrorCodes.INVALID_CONFIG_TYPE
        )
    
    if not config:
        raise create_config_error(
            "La configuración no puede estar vacía",
            provider=provider,
            error_code=ErrorCodes.MISSING_CONFIG
        )
    
    # Obtener configuración del proveedor
    provider_config = SUPPORTED_PROVIDERS[provider]
    required_keys = provider_config["required_keys"]
    optional_keys = provider_config.get("optional_keys", [])
    
    # Validar claves requeridas
    missing_keys = [key for key in required_keys if key not in config or not config[key]]
    if missing_keys:
        logger.warning(f"Missing required keys for {provider}: {missing_keys}")
        raise create_config_error(
            f"Faltan claves requeridas para {provider}: {', '.join(missing_keys)}",
            provider=provider,
            missing_keys=missing_keys,
            error_code=ErrorCodes.MISSING_REQUIRED_KEYS
        )
    
    # Identificar claves inválidas (ni requeridas ni opcionales)
    valid_keys = set(required_keys + optional_keys)
    invalid_keys = [key for key in config.keys() if key not in valid_keys]
    if invalid_keys:
        logger.warning(f"Invalid keys for {provider}: {invalid_keys}")
        # No es error crítico, pero loggeamos para awareness
    
    # Crear configuración validada con defaults
    validated_config = config.copy()
    
    # Agregar valores por defecto para claves opcionales
    if provider == "github" and "branch" not in validated_config:
        validated_config["branch"] = provider_config["default_branch"]
    elif provider == "gitlab":
        if "branch" not in validated_config:
            validated_config["branch"] = provider_config["default_branch"]
        if "base_url" not in validated_config:
            validated_config["base_url"] = provider_config["default_base_url"]
    elif provider == "azure" and "branch" not in validated_config:
        validated_config["branch"] = provider_config["default_branch"]
    
    # Validaciones específicas por proveedor
    if provider == "github":
        validated_config = _validate_github_config(validated_config)
    elif provider == "gitlab":
        validated_config = _validate_gitlab_config(validated_config)
    elif provider == "azure":
        validated_config = _validate_azure_config(validated_config)
    elif provider == "svn":
        validated_config = _validate_svn_config(validated_config)
    
    logger.debug(f"Config validated for {provider}", extra={
        "provider": provider,
        "config_keys": list(validated_config.keys()),
        "has_defaults": bool(invalid_keys)
    })
    
    return validated_config


def _validate_github_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """Validaciones específicas para configuración de GitHub"""
    validated = config.copy()
    
    # Validar formato de token
    token = validated["token"]
    if not token.startswith(("ghp_", "github_pat_", "gho_", "ghu_", "ghs_")):
        logger.warning("GitHub token format may be incorrect", extra={
            "token_prefix": token[:4] if len(token) > 4 else token
        })
    
    # Validar owner (no debe contener caracteres especiales)
    owner = validated["owner"]
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-])*[a-zA-Z0-9]$', owner):
        raise create_config_error(
            f"GitHub owner '{owner}' contiene caracteres inválidos",
            provider="github",
            error_code=ErrorCodes.INVALID_CONFIG_TYPE
        )
    
    # Validar repo name
    repo = validated["repo"]
    if not re.match(r'^[a-zA-Z0-9._-]+$', repo):
        raise create_config_error(
            f"GitHub repo '{repo}' contiene caracteres inválidos",
            provider="github",
            error_code=ErrorCodes.INVALID_CONFIG_TYPE
        )
    
    # Validar branch si está presente
    if "branch" in validated:
        branch = validated["branch"]
        if not re.match(r'^[a-zA-Z0-9._/-]+$', branch):
            raise create_config_error(
                f"GitHub branch '{branch}' contiene caracteres inválidos",
                provider="github",
                error_code=ErrorCodes.INVALID_CONFIG_TYPE
            )
    
    return validated


def _validate_gitlab_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """Validaciones específicas para configuración de GitLab"""
    validated = config.copy()
    
    # Validar base_url si está presente
    if "base_url" in validated:
        base_url = validated["base_url"]
        if not base_url.startswith(("http://", "https://")):
            raise create_config_error(
                "GitLab base_url debe incluir protocolo (http:// o https://)",
                provider="gitlab",
                error_code=ErrorCodes.INVALID_CONFIG_TYPE
            )
        
        # Remover trailing slash para consistencia
        validated["base_url"] = base_url.rstrip("/")
    
    # Validar project_path
    project_path = validated["project_path"]
    if not re.match(r'^[a-zA-Z0-9._/-]+$', project_path):
        raise create_config_error(
            f"GitLab project_path '{project_path}' contiene caracteres inválidos",
            provider="gitlab",
            error_code=ErrorCodes.INVALID_CONFIG_TYPE
        )
    
    # Validar token (debe ser string no vacío)
    token = validated["token"]
    if len(token) < 8:
        logger.warning("GitLab token seems too short", extra={
            "token_length": len(token)
        })
    
    return validated


def _validate_azure_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """Validaciones específicas para configuración de Azure DevOps"""
    validated = config.copy()
    
    # Validar organization
    org = validated["organization"]
    if not re.match(r'^[a-zA-Z0-9-_]+$', org):
        raise create_config_error(
            f"Azure organization '{org}' contiene caracteres inválidos",
            provider="azure",
            error_code=ErrorCodes.INVALID_CONFIG_TYPE
        )
    
    # Validar project
    project = validated["project"]
    if not re.match(r'^[a-zA-Z0-9._\s-]+$', project):
        raise create_config_error(
            f"Azure project '{project}' contiene caracteres inválidos",
            provider="azure",
            error_code=ErrorCodes.INVALID_CONFIG_TYPE
        )
    
    # Validar repository
    repo = validated["repository"]
    if not re.match(r'^[a-zA-Z0-9._-]+$', repo):
        raise create_config_error(
            f"Azure repository '{repo}' contiene caracteres inválidos",
            provider="azure",
            error_code=ErrorCodes.INVALID_CONFIG_TYPE
        )
    
    # Validar branch format si está presente
    if "branch" in validated:
        branch = validated["branch"]
        if not branch.startswith("refs/heads/") and not branch.startswith("refs/tags/"):
            # Auto-corregir branch común
            if not branch.startswith("refs/"):
                validated["branch"] = f"refs/heads/{branch}"
                logger.debug(f"Auto-corrected Azure branch format: {branch} -> {validated['branch']}")
    
    return validated


def _validate_svn_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """Validaciones específicas para configuración de SVN"""
    validated = config.copy()
    
    # Validar repo_url
    repo_url = validated["repo_url"]
    if not repo_url.startswith(("http://", "https://", "svn://", "file://")):
        raise create_config_error(
            "SVN repo_url debe incluir protocolo válido (http://, https://, svn://, file://)",
            provider="svn",
            error_code=ErrorCodes.INVALID_CONFIG_TYPE
        )
    
    # Normalizar URL (remover trailing slash)
    validated["repo_url"] = repo_url.rstrip("/")
    
    # Validar credenciales si están presentes
    if "username" in validated and not validated["username"]:
        # Remover username vacío
        del validated["username"]
    
    if "password" in validated and not validated["password"]:
        # Remover password vacío
        del validated["password"]
    
    # Advertir sobre credenciales en texto plano
    if "password" in validated:
        logger.warning("SVN password provided in plain text", extra={
            "security_risk": True,
            "recommendation": "Use environment variables or secrets manager"
        })
    
    return validated


# ========================================
# VALIDADORES DE ARCHIVOS Y RUTAS
# ========================================

@lru_cache(maxsize=1000)
def validate_file_path(path: str) -> str:
    """
    Valida y sanitiza ruta de archivo con protección avanzada contra path traversal.
    
    Implementa múltiples capas de seguridad y usa caching para performance.
    
    Args:
        path: Ruta del archivo a validar
        
    Returns:
        str: Ruta sanitizada y validada
        
    Raises:
        SecurityError: Si se detecta un ataque
        ValidationError: Si la ruta es inválida
        
    Example:
        >>> validate_file_path("src/main.py")
        'src/main.py'
        
        >>> validate_file_path("../../../etc/passwd")
        SecurityError: Path traversal detected
    """

    print(f"******************************************")
    print(f"******************************************{path}")
    print(f"******************************************")
    

    # Validación básica de tipo y presencia
    if not path or not isinstance(path, str):
        raise create_validation_error(
            "La ruta del archivo es requerida y debe ser una cadena",
            field_name="path",
            received_value=path,
            error_code=ErrorCodes.INVALID_PATH
        )
    
    # Verificar longitud para prevenir DoS
    if len(path) > MAX_PATH_LENGTH:
        log_security_event("path_too_long", f"Path length: {len(path)}", "WARNING")
        raise create_validation_error(
            f"Ruta demasiado larga. Máximo: {MAX_PATH_LENGTH} caracteres",
            field_name="path",
            received_value=f"{path[:50]}..." if len(path) > 50 else path,
            error_code=ErrorCodes.PATH_TOO_LONG
        )
    print(f"******************************************")
    print(f"******************************************{path}")
    print(f"******************************************")
    
    # Sanitización básica
    clean_path = path.strip().strip('/')
    clean_path = unicodedata.normalize('NFC', clean_path)
    if not clean_path:
        raise create_validation_error(
            "La ruta del archivo no puede estar vacía después de sanitización",
            field_name="path",
            received_value=path,
            error_code=ErrorCodes.EMPTY_PATH
        )
    
    # Detección avanzada de path traversal
    _detect_path_traversal(clean_path, path)
    
    # Validar caracteres de control
    _validate_control_characters(clean_path)
    
    # Verificar que no sea ruta absoluta
    if clean_path.startswith(('/', '\\')):
        log_security_event("absolute_path_attempt", f"Path: {clean_path}", "WARNING")
        raise create_security_error(
            "No se permiten rutas absolutas",
            attack_type="absolute_path",
            detected_pattern=clean_path[0],
            error_code=ErrorCodes.INVALID_PATH
        )
    
    # Normalizar separadores
    normalized_path = clean_path.replace('\\', '/')
    
    # Validación final de componentes de ruta
    _validate_path_components(normalized_path)
    
    logger.debug(f"Path validated", extra={
        "original": path,
        "normalized": normalized_path,
        "components": len(normalized_path.split('/'))
    })
    
    return normalized_path


def _detect_path_traversal(clean_path: str, original_path: str) -> None:
    """Detecta patrones de path traversal"""
    for pattern in DANGEROUS_PATH_PATTERNS:
        if pattern in clean_path:
            log_security_event(
                "path_traversal_attempt",
                f"Dangerous pattern '{pattern}' in path: {clean_path}",
                "ERROR"
            )
            raise create_security_error(
                f"Ruta contiene patrón peligroso",
                attack_type="path_traversal",
                detected_pattern=pattern,
                error_code=ErrorCodes.PATH_TRAVERSAL
            )
    
    # Detección adicional de encodings
    decoded_variants = [
        urllib.parse.unquote(clean_path),  # URL decoding
        clean_path.encode().decode('unicode_escape', errors='ignore'),  # Unicode escape
    ]
    
    for variant in decoded_variants:
        if variant != clean_path:
            for pattern in DANGEROUS_PATH_PATTERNS:
                if pattern in variant:
                    log_security_event(
                        "encoded_path_traversal",
                        f"Encoded path traversal detected: {variant}",
                        "ERROR"
                    )
                    raise create_security_error(
                        "Intento de path traversal codificado detectado",
                        attack_type="encoded_path_traversal",
                        detected_pattern=pattern,
                        error_code=ErrorCodes.PATH_TRAVERSAL
                    )


def _validate_control_characters(path: str) -> None:
    """Valida que no haya caracteres de control peligrosos"""
    for i, char in enumerate(path):
        if ord(char) < 32 and char not in ('\t',):  # Permitir tab
            log_security_event(
                "control_chars_in_path",
                f"Control character at position {i}: {repr(char)}",
                "WARNING"
            )
            raise create_security_error(
                "Ruta contiene caracteres de control inválidos",
                attack_type="control_character_injection",
                detected_pattern=repr(char),
                error_code=ErrorCodes.INVALID_PATH
            )


def _validate_path_components(path: str) -> None:
    """Valida cada componente de la ruta"""
    components = path.split('/')

    for component in components:
        if not component:
            continue

        if len(component) > 255:
            raise create_validation_error(
                f"Componente de ruta demasiado largo: {component[:50]}...",
                field_name="path_component",
                received_value=component,
                error_code=ErrorCodes.INVALID_PATH
            )

        for char in component:
            category = unicodedata.category(char)

            # Bloquear caracteres de control (categoría C)
            if category.startswith("C"):
                log_security_event(
                    "invalid_unicode_control",
                    f"Caracter de control en componente: {component} (char={repr(char)})",
                    level="WARNING"
                )
                raise create_security_error(
                    f"Componente contiene caracteres de control inválidos: {component}",
                    attack_type="invalid_unicode_control",
                    detected_pattern=repr(char),
                    error_code=ErrorCodes.INVALID_PATH
                )

            # Bloquear separadores invisibles distintos de espacio normal (U+0020)
            if category == "Zs" and char != " ":
                log_security_event(
                    "invalid_unicode_separator",
                    f"Separador unicode sospechoso en componente: {component} (char={repr(char)})",
                    level="WARNING"
                )
                raise create_security_error(
                    f"Componente contiene separadores invisibles inválidos: {component}",
                    attack_type="invalid_unicode_separator",
                    detected_pattern=repr(char),
                    error_code=ErrorCodes.INVALID_PATH
                )


# ========================================
# VALIDADORES DE LÍMITES
# ========================================

def validate_file_size(size_bytes: int, filename: Optional[str] = None) -> None:
    """
    Valida que el tamaño del archivo esté dentro de límites.
    
    Args:
        size_bytes: Tamaño en bytes
        filename: Nombre del archivo (opcional, para contexto)
        
    Raises:
        FileTooLargeError: Si excede el límite
    """
    if size_bytes > MAX_FILE_SIZE_BYTES:
        from app.core.exceptions import FileTooLargeError
        size_mb = size_bytes / 1024 / 1024
        max_mb = MAX_FILE_SIZE_BYTES / 1024 / 1024
        
        raise FileTooLargeError(
            f"Archivo de {size_mb:.1f}MB excede límite de {max_mb}MB",
            error_code=ErrorCodes.FILE_TOO_LARGE,
            file_size=size_bytes,
            max_size=MAX_FILE_SIZE_BYTES,
            filename=filename
        )


def validate_structure_size(node_count: int) -> None:
    """
    Valida que la estructura no sea demasiado grande.
    
    Args:
        node_count: Número total de nodos
        
    Raises:
        ValidationError: Si excede el límite
    """
    if node_count > MAX_NODES_STRUCTURE:
        raise create_validation_error(
            f"Estructura demasiado grande: {node_count} nodos (máximo: {MAX_NODES_STRUCTURE})",
            field_name="structure_size",
            received_value=node_count,
            error_code=ErrorCodes.STRUCTURE_TOO_LARGE
        )


# ========================================
# VALIDADORES COMPUESTOS
# ========================================

def validate_request_data(data: Dict[str, Any]) -> Tuple[str, str, Dict[str, Any], Optional[str]]:
    """
    Valida todos los datos de un request de manera integral.
    
    Args:
        data: Datos del request a validar
        
    Returns:
        Tuple[str, str, Dict, Optional[str]]: (operation, provider, config, path)
        
    Raises:
        ValidationError: Si algún dato es inválido
        ConfigurationError: Si la configuración es inválida
        SecurityError: Si se detecta un ataque
        
    Example:
        >>> data = {
        ...     "operation": "DOWNLOAD_FILE",
        ...     "provider": "github",
        ...     "config": {"token": "xxx", "owner": "user", "repo": "repo"},
        ...     "path": "src/main.py"
        ... }
        >>> operation, provider, config, path = validate_request_data(data)
    """
    logger.debug("Starting comprehensive request validation", extra={
        "data_keys": list(data.keys()) if isinstance(data, dict) else "not_dict"
    })

    print("DATA***********************************************************************")
    print(data)
    print("DATA***********************************************************************")

    # Validar estructura básica
    if not isinstance(data, dict):
        raise create_validation_error(
            "Los datos del request deben ser un diccionario",
            field_name="request_data",
            received_value=type(data).__name__,
            error_code=ErrorCodes.INVALID_JSON
        )
    
    # Extraer y validar campos principales
    operation = validate_operation(data.get("operation"))
    provider = validate_provider(data.get("provider"))
    
    # Validar configuración
    config_data = data.get("config")
    if not config_data:
        raise create_validation_error(
            "El campo 'config' es requerido",
            field_name="config",
            received_value=config_data,
            error_code=ErrorCodes.MISSING_CONFIG
        )
    
    config = validate_config(provider, config_data)
    
    # Validar path si la operación lo requiere
    path = None
    if operation == Operations.DOWNLOAD_FILE:
        path_data = data.get("path")
        if not path_data:
            raise create_validation_error(
                "El campo 'path' es requerido para DOWNLOAD_FILE",
                field_name="path",
                received_value=path_data,
                error_code=ErrorCodes.MISSING_PATH
            )
        path_data =  fix_encoding(path_data)
        path = validate_file_path(path_data)
    
    logger.info("Request validation completed successfully", extra={
        "operation": operation,
        "provider": provider,
        "has_path": bool(path),
        "config_keys": list(config.keys())
    })
    
    return operation, provider, config, path

def fix_encoding(text):
    return text.encode('latin1').decode('utf-8')

# ========================================
# UTILIDADES DE VALIDACIÓN
# ========================================

def is_safe_filename(filename: str) -> bool:
    """
    Verifica si un nombre de archivo es seguro.
    
    Args:
        filename: Nombre del archivo
        
    Returns:
        bool: True si es seguro
    """
    if not filename or len(filename) > 255:
        return False
    
    # Verificar caracteres peligrosos
    dangerous_chars = set(DANGEROUS_PATH_PATTERNS) - {'.'}  # Punto está permitido
    if any(char in filename for char in dangerous_chars):
        return False
    
    # Verificar nombres reservados (Windows)
    reserved_names = {
        'CON', 'PRN', 'AUX', 'NUL',
        'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
        'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'
    }
    
    base_name = filename.split('.')[0].upper()
    if base_name in reserved_names:
        return False
    
    return True


def sanitize_filename(filename: str) -> str:
    """
    Sanitiza un nombre de archivo removiendo caracteres peligrosos.
    
    Args:
        filename: Nombre original
        
    Returns:
        str: Nombre sanitizado
    """
    if not filename:
        return "unnamed_file"
    
    # Remover caracteres peligrosos
    safe_chars = []
    for char in filename:
        if char in ALLOWED_FILENAME_CHARS:
            safe_chars.append(char)
        elif char == ' ':
            safe_chars.append('_')  # Reemplazar espacios
    
    sanitized = ''.join(safe_chars)
    
    # Asegurar que no esté vacío
    if not sanitized:
        sanitized = "sanitized_file"
    
    # Truncar si es muy largo
    if len(sanitized) > 100:
        name_part = sanitized[:95]
        ext_part = sanitized[-5:] if '.' in sanitized[-10:] else ""
        sanitized = name_part + ext_part
    
    return sanitized


# ========================================
# CACHE Y PERFORMANCE
# ========================================

def clear_validation_cache() -> None:
    """Limpia el cache de validaciones para testing"""
    validate_file_path.cache_clear()


def get_validation_cache_info() -> Dict[str, Any]:
    """Obtiene información del cache de validaciones"""
    return {
        "file_path_cache": validate_file_path.cache_info()._asdict()
    }