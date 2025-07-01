"""
Constantes globales para el servicio de gestión de repositorios.

Este módulo centraliza todas las constantes del sistema para facilitar
la configuración y mantenimiento. Separadas por categorías lógicas.

Author: [Your Name]
Created: 2025
Version: 2.0.0
"""

import os
from typing import Dict, List

# ========================================
# LÍMITES DE PERFORMANCE Y MEMORIA
# ========================================

# Límites de archivo para prevenir memory overrun en AWS Lambda
MAX_FILE_SIZE_BYTES = int(os.getenv('MAX_FILE_SIZE_MB', '10')) * 1024 * 1024  # Default: 10MB
MAX_FILE_SIZE_MB = MAX_FILE_SIZE_BYTES // 1024 // 1024

# Límites de estructura para prevenir performance issues
MAX_NODES_STRUCTURE = int(os.getenv('MAX_NODES_STRUCTURE', '10000'))  # Default: 10K nodos
MAX_PATH_LENGTH = int(os.getenv('MAX_PATH_LENGTH', '1000'))  # Default: 1000 chars
MAX_DEPTH_LEVELS = int(os.getenv('MAX_DEPTH_LEVELS', '20'))  # Default: 20 niveles

# ========================================
# TIMEOUTS Y PERFORMANCE
# ========================================

# Timeouts para requests HTTP (prevenir Lambda timeout)
REQUEST_TIMEOUT = int(os.getenv('REQUEST_TIMEOUT', '30'))  # Default: 30 segundos
CONNECTION_TIMEOUT = int(os.getenv('CONNECTION_TIMEOUT', '10'))  # Default: 10 segundos
READ_TIMEOUT = int(os.getenv('READ_TIMEOUT', '30'))  # Default: 30 segundos

# Configuración de reintentos
MAX_RETRIES = int(os.getenv('MAX_RETRIES', '3'))  # Default: 3 reintentos
RETRY_BACKOFF_FACTOR = float(os.getenv('RETRY_BACKOFF_FACTOR', '0.3'))  # Default: 0.3s

# Pool de conexiones para mejor performance
CONNECTION_POOL_SIZE = int(os.getenv('CONNECTION_POOL_SIZE', '10'))
CONNECTION_POOL_MAXSIZE = int(os.getenv('CONNECTION_POOL_MAXSIZE', '20'))

# ========================================
# CONFIGURACIÓN DE LOGGING
# ========================================

# Niveles de logging
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()
LOG_FORMAT = os.getenv('LOG_FORMAT', 'structured')  # 'structured' o 'simple'

# Configuración específica de logging
LOG_STRUCTURED_FORMAT = (
    '[%(levelname)s] %(asctime)s | '
    'function=%(funcName)s | '
    'line=%(lineno)d | '
    'module=%(name)s | '
    'message=%(message)s'
)

LOG_SIMPLE_FORMAT = '[%(levelname)s] %(asctime)s - %(message)s'

# ========================================
# PROVEEDORES SOPORTADOS
# ========================================

# Configuración de proveedores y sus requerimientos
SUPPORTED_PROVIDERS = {
    "github": {
        "name": "GitHub",
        "required_keys": ["token", "owner", "repo"],
        "optional_keys": ["branch"],
        "default_branch": "main",
        "api_base": "https://api.github.com",
        "raw_base": "https://raw.githubusercontent.com",
        "description": "GitHub repository access via REST API"
    },
    "gitlab": {
        "name": "GitLab",
        "required_keys": ["token", "project_path"],
        "optional_keys": ["branch", "base_url"],
        "default_branch": "main",
        "default_base_url": "https://gitlab.com",
        "api_version": "v4",
        "description": "GitLab repository access via REST API"
    },
    "azure": {
        "name": "Azure DevOps",
        "required_keys": ["token", "organization", "project", "repository"],
        "optional_keys": ["branch"],
        "default_branch": "refs/heads/main",
        "api_version": "7.1-preview.1",
        "api_base": "https://dev.azure.com",
        "description": "Azure DevOps Git repository access"
    },
    "svn": {
        "name": "Subversion",
        "required_keys": ["repo_url"],
        "optional_keys": ["username", "password"],
        "supported_protocols": ["http://", "https://", "svn://"],
        "description": "Subversion repository access via command line"
    }
}

# Lista simple de proveedores para validación rápida
PROVIDER_NAMES = list(SUPPORTED_PROVIDERS.keys())

# ========================================
# OPERACIONES SOPORTADAS
# ========================================

class Operations:
    """Constantes para operaciones soportadas"""
    GET_STRUCTURE = "GET_STRUCTURE"
    DOWNLOAD_FILE = "DOWNLOAD_FILE"
    
    # Lista de todas las operaciones para validación
    ALL = [GET_STRUCTURE, DOWNLOAD_FILE]
    
    # Descripciones para documentación
    DESCRIPTIONS = {
        GET_STRUCTURE: "Obtiene la estructura jerárquica del repositorio",
        DOWNLOAD_FILE: "Descarga un archivo específico del repositorio"
    }

# ========================================
# CÓDIGOS DE ERROR ESTANDARIZADOS
# ========================================

class ErrorCodes:
    """Códigos de error estandarizados para mejor categorización"""
    
    # Errores de validación (4xx)
    MISSING_OPERATION = "MISSING_OPERATION"
    MISSING_PROVIDER = "MISSING_PROVIDER"
    MISSING_CONFIG = "MISSING_CONFIG"
    MISSING_PATH = "MISSING_PATH_FOR_DOWNLOAD"
    INVALID_OPERATION = "UNSUPPORTED_OPERATION"
    INVALID_PROVIDER = "UNSUPPORTED_PROVIDER"
    INVALID_JSON = "INVALID_JSON"
    INVALID_PATH = "INVALID_PATH"
    PATH_TRAVERSAL = "PATH_TRAVERSAL_DETECTED"
    PATH_TOO_LONG = "PATH_TOO_LONG"
    EMPTY_PATH = "EMPTY_CLEAN_PATH"
    
    # Errores de configuración (4xx)
    MISSING_REQUIRED_KEYS = "MISSING_REQUIRED_KEYS"
    INVALID_CONFIG_TYPE = "INVALID_CONFIG_TYPE"
    INVALID_PROVIDER_TYPE = "INVALID_PROVIDER_TYPE"
    
    # Errores de límites (413)
    FILE_TOO_LARGE = "FILE_SIZE_EXCEEDED"
    STRUCTURE_TOO_LARGE = "STRUCTURE_TOO_LARGE"
    
    # Errores de proveedor (5xx)
    PROVIDER_API_ERROR = "PROVIDER_API_ERROR"
    PROVIDER_AUTH_ERROR = "PROVIDER_AUTH_ERROR"
    PROVIDER_RATE_LIMIT = "PROVIDER_RATE_LIMIT"
    PROVIDER_TIMEOUT = "PROVIDER_TIMEOUT"
    
    # Errores de servicio (5xx)
    STRUCTURE_FETCH_FAILED = "STRUCTURE_FETCH_FAILED"
    DOWNLOAD_FAILED = "DOWNLOAD_FAILED"
    FILE_NOT_FOUND = "FILE_NOT_FOUND"
    ACCESS_DENIED = "ACCESS_DENIED"
    DOWNLOAD_TIMEOUT = "DOWNLOAD_TIMEOUT"
    EMPTY_FILE = "EMPTY_FILE"

# ========================================
# HEADERS HTTP ESTANDARIZADOS
# ========================================

# Headers comunes para todas las respuestas
COMMON_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block"
}

# Headers específicos para respuestas JSON
JSON_HEADERS = {
    **COMMON_HEADERS,
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-cache, no-store, must-revalidate"
}

# Headers específicos para descarga de archivos
FILE_HEADERS = {
    **COMMON_HEADERS,
    "Content-Type": "application/octet-stream",
    "Access-Control-Expose-Headers": "Content-Disposition",
    "Cache-Control": "private, max-age=3600"  # Cache por 1 hora
}

# ========================================
# PATRONES DE SEGURIDAD
# ========================================

# Patrones peligrosos para detección de path traversal
DANGEROUS_PATH_PATTERNS = [
    '..',           # Unix path traversal
    '.\\',          # Windows path traversal  
    '/./',          # Current directory reference
    '\\.\\',        # Windows current directory
    '\\\\',         # UNC paths
    ':',            # Drive letters / URL schemes
    '|',            # Command injection
    '<',            # Redirection
    '>',            # Redirection
    '*',            # Wildcards
    '?',            # Wildcards
    '"',            # Quote injection
    '\x00',         # Null byte
]

# Caracteres permitidos en nombres de archivo
ALLOWED_FILENAME_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_"

# ========================================
# CONFIGURACIÓN DE ENTORNO
# ========================================

# Detectar entorno de ejecución
IS_LAMBDA = bool(os.getenv('AWS_LAMBDA_FUNCTION_NAME'))
IS_LOCAL = not IS_LAMBDA

# Configuración específica por entorno
if IS_LAMBDA:
    # Configuración optimizada para Lambda
    DEFAULT_LOG_LEVEL = 'INFO'
    ENABLE_DEBUG_METRICS = False
    ENABLE_DETAILED_LOGGING = False
else:
    # Configuración para desarrollo local
    DEFAULT_LOG_LEVEL = 'DEBUG'
    ENABLE_DEBUG_METRICS = True
    ENABLE_DETAILED_LOGGING = True

# ========================================
# MÉTRICAS Y MONITORING
# ========================================

# Nombres de métricas para CloudWatch/monitoring
class MetricNames:
    """Nombres estandarizados de métricas para observabilidad"""
    
    # Métricas de negocio
    STRUCTURES_RETRIEVED = "structures_retrieved"
    FILES_DOWNLOADED = "files_downloaded"
    REQUESTS_TOTAL = "requests_total"
    
    # Métricas de performance
    REQUEST_DURATION = "request_duration"
    RESPONSE_SIZE = "response_size"
    STRUCTURE_NODES = "structure_nodes"
    STRUCTURE_FILES = "structure_files"
    STRUCTURE_FOLDERS = "structure_folders"
    DOWNLOAD_SIZE = "download_size"
    
    # Métricas de error
    ERRORS_TOTAL = "errors_total"
    ERRORS_VALIDATION = "errors_validation"
    ERRORS_CONFIGURATION = "errors_configuration"
    ERRORS_PROVIDER = "errors_provider"
    LARGE_FILES_REJECTED = "large_files_rejected"
    OVERSIZED_FILES = "oversized_files"
    
    # Métricas por proveedor
    DOWNLOADS_GITHUB = "downloads_github"
    DOWNLOADS_GITLAB = "downloads_gitlab"
    DOWNLOADS_AZURE = "downloads_azure"
    DOWNLOADS_SVN = "downloads_svn"

# ========================================
# FUNCIONES DE UTILIDAD
# ========================================

def get_provider_config(provider: str) -> Dict:
    """
    Obtiene la configuración de un proveedor específico.
    
    Args:
        provider: Nombre del proveedor
        
    Returns:
        Dict: Configuración del proveedor
        
    Raises:
        KeyError: Si el proveedor no está soportado
    """
    return SUPPORTED_PROVIDERS[provider.lower()]

def is_supported_provider(provider: str) -> bool:
    """
    Verifica si un proveedor está soportado.
    
    Args:
        provider: Nombre del proveedor
        
    Returns:
        bool: True si está soportado
    """
    return provider.lower() in PROVIDER_NAMES

def get_required_keys(provider: str) -> List[str]:
    """
    Obtiene las claves requeridas para un proveedor.
    
    Args:
        provider: Nombre del proveedor
        
    Returns:
        List[str]: Lista de claves requeridas
    """
    return get_provider_config(provider)["required_keys"]

def get_optional_keys(provider: str) -> List[str]:
    """
    Obtiene las claves opcionales para un proveedor.
    
    Args:
        provider: Nombre del proveedor
        
    Returns:
        List[str]: Lista de claves opcionales
    """
    return get_provider_config(provider)["optional_keys"]