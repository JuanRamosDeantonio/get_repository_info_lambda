"""
Sistema de logging optimizado para AWS Lambda y desarrollo local.

Este módulo proporciona un sistema de logging centralizado con:
- Configuración única por cold start (performance optimized)
- Logging estructurado para CloudWatch y análisis
- Decoradores para métricas automáticas
- Integración con sistema de excepciones
- Contexto de request automático

Features:
- Formato JSON-like para mejor parseabilidad
- Niveles configurables vía variables de entorno
- Performance monitoring automático
- Security event logging
- Business metrics integration

Author: [Your Name]
Created: 2025
Version: 2.0.0
"""

import logging
import time
import os
import json
import functools
from typing import Dict, Any, Optional, Union, Callable
from datetime import datetime
from app.core.constants import (
    LOG_LEVEL, 
    LOG_FORMAT, 
    LOG_STRUCTURED_FORMAT, 
    LOG_SIMPLE_FORMAT,
    IS_LAMBDA,
    IS_LOCAL,
    ENABLE_DEBUG_METRICS,
    ENABLE_DETAILED_LOGGING,
    MetricNames
)

# ========================================
# CONFIGURACIÓN GLOBAL DE LOGGING
# ========================================

# Cache de loggers configurados para evitar reconfiguración
_configured_loggers: Dict[str, logging.Logger] = {}

# Contexto global de request (se actualiza por request)
_request_context: Dict[str, Any] = {}


def get_logger(name: str = __name__) -> logging.Logger:
    """
    Obtiene o crea un logger optimizado con configuración única.
    
    Este es el punto de entrada principal para obtener loggers en todo el sistema.
    Implementa caching para evitar reconfiguración en cada request (performance critical).
    
    Args:
        name: Nombre del logger (típicamente __name__ del módulo)
        
    Returns:
        logging.Logger: Logger configurado y listo para uso
        
    Performance Notes:
        - Primera llamada: configura el logger
        - Llamadas subsecuentes: retorna desde cache
        - Evita overhead de configuración en requests calientes
        
    Example:
        >>> logger = get_logger(__name__)
        >>> logger.info("Message", extra={"key": "value"})
    """
    # Retornar desde cache si ya está configurado
    if name in _configured_loggers:
        return _configured_loggers[name]
    
    # Crear y configurar nuevo logger
    logger = logging.getLogger(name)
    
    # Evitar reconfiguración si ya tiene handlers
    if logger.handlers:
        _configured_loggers[name] = logger
        return logger
    
    # Configurar nivel desde constantes
    log_level = getattr(logging, LOG_LEVEL, logging.INFO)
    logger.setLevel(log_level)
    
    # Crear handler apropiado para el entorno
    if IS_LAMBDA:
        handler = _create_lambda_handler()
    else:
        handler = _create_local_handler()
    
    # Configurar formatter
    formatter = _create_formatter()
    handler.setFormatter(formatter)
    
    # Agregar handler y configurar
    logger.addHandler(handler)
    logger.propagate = False  # Evitar logs duplicados
    
    # Cachear para futuras llamadas
    _configured_loggers[name] = logger
    
    return logger


def _create_lambda_handler() -> logging.Handler:
    """Crea handler optimizado para AWS Lambda"""
    handler = logging.StreamHandler()
    
    # CloudWatch maneja timestamps automáticamente en Lambda
    # No necesitamos timestamps redundantes
    return handler


def _create_local_handler() -> logging.Handler:
    """Crea handler optimizado para desarrollo local"""
    handler = logging.StreamHandler()
    
    # Configuraciones adicionales para desarrollo local
    if ENABLE_DETAILED_LOGGING:
        handler.setLevel(logging.DEBUG)
    
    return handler


def _create_formatter() -> logging.Formatter:
    """
    Crea formatter apropiado según configuración.
    
    Returns:
        logging.Formatter: Formatter configurado para el entorno
    """
    if LOG_FORMAT == 'structured':
        return StructuredFormatter()
    else:
        return logging.Formatter(LOG_SIMPLE_FORMAT)


class StructuredFormatter(logging.Formatter):
    """
    Formatter personalizado para logging estructurado.
    
    Genera logs en formato semi-JSON que es fácil de parsear
    tanto por humanos como por sistemas de análisis.
    
    Features:
        - Campos separados por pipes para fácil parsing
        - Contexto automático de request
        - Handling especial para excepciones
        - Timestamps optimizados para CloudWatch
    """
    
    def format(self, record: logging.LogRecord) -> str:
        """
        Formatea un log record en formato estructurado.
        
        Args:
            record: Log record a formatear
            
        Returns:
            str: Log formateado
        """
        # Extraer información básica
        timestamp = self._format_timestamp(record.created)
        level = record.levelname
        function = record.funcName
        line = record.lineno
        module = record.name
        message = record.getMessage()
        
        # Construir partes del log
        parts = [
            f"[{level}]",
            timestamp,
            f"function={function}",
            f"line={line}",
            f"module={module}"
        ]
        
        # Agregar contexto de request si está disponible
        if _request_context:
            for key, value in _request_context.items():
                parts.append(f"{key}={value}")
        
        # Agregar campos extra del record
        extra_fields = self._extract_extra_fields(record)
        for key, value in extra_fields.items():
            parts.append(f"{key}={value}")
        
        # Agregar mensaje principal
        parts.append(f"message={message}")
        
        # Handling especial para excepciones
        if record.exc_info:
            exc_text = self.formatException(record.exc_info)
            parts.append(f"exception={exc_text}")
        
        return " | ".join(parts)
    
    def _format_timestamp(self, created: float) -> str:
        """Formatea timestamp optimizado para el entorno"""
        if IS_LAMBDA:
            # CloudWatch agrega timestamps automáticamente
            # Usar formato más compacto
            dt = datetime.fromtimestamp(created)
            return dt.strftime("%H:%M:%S.%f")[:-3]  # HH:MM:SS.mmm
        else:
            # Desarrollo local: timestamp completo
            dt = datetime.fromtimestamp(created)
            return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    
    def _extract_extra_fields(self, record: logging.LogRecord) -> Dict[str, Any]:
        """Extrae campos extra del log record"""
        # Campos estándar que no queremos duplicar
        standard_fields = {
            'name', 'msg', 'args', 'levelname', 'levelno', 'pathname', 
            'filename', 'module', 'lineno', 'funcName', 'created', 
            'msecs', 'relativeCreated', 'thread', 'threadName', 
            'processName', 'process', 'stack_info', 'exc_info', 'exc_text'
        }
        
        extra = {}
        for key, value in record.__dict__.items():
            if key not in standard_fields:
                # Sanitizar valores para logging seguro
                if isinstance(value, (dict, list)):
                    extra[key] = json.dumps(value, default=str)
                else:
                    extra[key] = str(value)
        
        return extra


# ========================================
# CONTEXTO DE REQUEST
# ========================================

def set_request_context(**kwargs) -> None:
    """
    Establece contexto global para el request actual.
    
    Este contexto se incluirá automáticamente en todos los logs
    del request actual, facilitando el tracing distribuido.
    
    Args:
        **kwargs: Campos de contexto (request_id, operation, provider, etc.)
        
    Example:
        >>> set_request_context(request_id="123-456", operation="GET_STRUCTURE")
        >>> logger.info("Processing")  # Incluirá request_id y operation automáticamente
    """
    global _request_context
    _request_context.update(kwargs)


def clear_request_context() -> None:
    """Limpia el contexto del request actual"""
    global _request_context
    _request_context.clear()


def get_request_context() -> Dict[str, Any]:
    """Obtiene el contexto actual del request"""
    return _request_context.copy()


# ========================================
# DECORADORES DE PERFORMANCE
# ========================================

def log_performance(func: Optional[Callable] = None, *, 
                   operation_name: Optional[str] = None,
                   include_args: bool = False,
                   log_level: int = logging.INFO) -> Callable:
    """
    Decorator para logging automático de performance.
    
    Mide tiempo de ejecución y logea métricas automáticamente.
    Incluye manejo de excepciones y contexto enriquecido.
    
    Args:
        func: Función a decorar (automático en uso como @log_performance)
        operation_name: Nombre personalizado para la operación
        include_args: Si incluir argumentos en el log
        log_level: Nivel de log para métricas de performance
        
    Returns:
        Callable: Función decorada con logging de performance
        
    Example:
        >>> @log_performance
        >>> def expensive_operation():
        >>>     time.sleep(1)
        
        >>> @log_performance(operation_name="custom_op", include_args=True)
        >>> def process_file(filename):
        >>>     # processing logic
        >>>     pass
    """
    def decorator(f: Callable) -> Callable:
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            logger = get_logger(f.__module__)
            op_name = operation_name or f.__name__
            start_time = time.time()
            
            # Contexto de función
            context = {
                "operation": op_name,
                "function": f.__name__,
                "caller_module": f.__module__
            }
            
            # Incluir argumentos si se solicita
            if include_args and (args or kwargs):
                context["args_count"] = len(args)
                context["kwargs_count"] = len(kwargs)
                if ENABLE_DEBUG_METRICS:
                    context["args"] = str(args)[:100]  # Limitar tamaño
                    context["kwargs"] = str(kwargs)[:100]
            
            # Log inicio de operación
            logger.log(log_level, f"PERF_START", extra=context)
            
            try:
                # Ejecutar función
                result = f(*args, **kwargs)
                
                # Calcular métricas de éxito
                duration = time.time() - start_time
                success_context = {
                    **context,
                    "duration_seconds": round(duration, 3),
                    "status": "success"
                }
                
                # Log éxito con métricas
                logger.log(log_level, f"PERF_SUCCESS", extra=success_context)
                
                # Métrica de negocio
                log_business_metric(MetricNames.REQUEST_DURATION, duration, "seconds")
                
                return result
                
            except Exception as e:
                # Calcular métricas de error
                duration = time.time() - start_time
                error_context = {
                    **context,
                    "duration_seconds": round(duration, 3),
                    "status": "error",
                    "error_type": type(e).__name__,
                    "error_message": str(e)
                }
                
                # Log error con métricas
                logger.error(f"PERF_ERROR", extra=error_context)
                
                # Re-raise la excepción
                raise
        
        return wrapper
    
    # Permitir uso con y sin parámetros
    if func is None:
        return decorator
    else:
        return decorator(func)


# ========================================
# LOGGING ESPECIALIZADO
# ========================================

def log_api_call(provider: str, operation: str, **kwargs) -> None:
    """
    Logea llamadas a APIs externas con contexto estructurado.
    
    Args:
        provider: Proveedor del repositorio (github, gitlab, etc.)
        operation: Operación realizada (list_files, download_file)
        **kwargs: Contexto adicional (path, file_size, etc.)
        
    Example:
        >>> log_api_call("github", "download_file", path="src/main.py", file_size=1024)
    """
    logger = get_logger("api_calls")
    
    context = {
        "event_type": "API_CALL",
        "provider": provider,
        "operation": operation,
        **kwargs
    }
    
    logger.info("External API call", extra=context)


def log_security_event(event_type: str, details: str, severity: str = "WARNING",
                      **kwargs) -> None:
    """
    Logea eventos de seguridad para auditoría y monitoreo.
    
    Args:
        event_type: Tipo de evento (path_traversal, invalid_input, etc.)
        details: Detalles del evento
        severity: Severidad (INFO, WARNING, ERROR, CRITICAL)
        **kwargs: Contexto adicional
        
    Example:
        >>> log_security_event("path_traversal", "Attempted access to ../../../etc/passwd", 
        ...                   "ERROR", client_ip="192.168.1.1")
    """
    logger = get_logger("security")
    
    context = {
        "event_type": "SECURITY_EVENT",
        "security_event_type": event_type,
        "details": details,
        "severity": severity,
        **kwargs
    }
    
    level = getattr(logging, severity.upper(), logging.WARNING)
    logger.log(level, f"Security event: {event_type}", extra=context)


def log_business_metric(metric_name: str, value: Union[int, float], 
                       unit: str = "count", **kwargs) -> None:
    """
    Logea métricas de negocio para dashboard y alertas.
    
    Args:
        metric_name: Nombre de la métrica
        value: Valor numérico
        unit: Unidad de medida
        **kwargs: Contexto adicional
        
    Example:
        >>> log_business_metric("files_downloaded", 1, "count")
        >>> log_business_metric("response_size", 1024, "bytes")
    """
    logger = get_logger("metrics")
    
    context = {
        "event_type": "BUSINESS_METRIC",
        "metric_name": metric_name,
        "metric_value": value,
        "metric_unit": unit,
        **kwargs
    }
    
    logger.info(f"Metric: {metric_name}={value}{unit}", extra=context)


def log_request_lifecycle(phase: str, request_id: str, **kwargs) -> None:
    """
    Logea fases del ciclo de vida del request.

    Args:
        phase: Fase del request (START, END, ERROR)
        request_id: ID único del request
        **kwargs: Contexto específico de la fase

    Example:
        >>> log_request_lifecycle("START", "123-456", operation="GET_STRUCTURE")
        >>> log_request_lifecycle("END", "123-456", status_code=200, duration=1.5)
    """
    logger = get_logger("request_lifecycle")

    # Lista de claves reservadas por el sistema de logging
    reserved_keys = {
        'args', 'msg', 'levelname', 'levelno', 'pathname', 'filename',
        'module', 'exc_info', 'exc_text', 'stack_info', 'lineno',
        'funcName', 'created', 'msecs', 'relativeCreated',
        'thread', 'threadName', 'processName', 'process'
    }

    # Sanitizar contexto
    safe_context = {
        (f"context_{k}" if k in reserved_keys else k): v
        for k, v in kwargs.items()
    }

    context = {
        "event_type": "REQUEST_LIFECYCLE",
        "lifecycle_phase": phase,
        "request_id": request_id,
        **safe_context
    }

    # Log según tipo
    if phase == "ERROR":
        logger.error(f"Request {phase}: {request_id}", extra=context)
    else:
        logger.info(f"Request {phase}: {request_id}", extra=context)



# ========================================
# UTILIDADES DE DEBUG
# ========================================

def log_exception_with_context(e: Exception, context: Dict[str, Any] = None,
                              logger_name: str = "exceptions") -> None:
    """
    Logea excepciones con contexto enriquecido.
    
    Args:
        e: Excepción a loggear
        context: Contexto adicional
        logger_name: Nombre del logger a usar
        
    Example:
        >>> try:
        >>>     risky_operation()
        >>> except Exception as e:
        >>>     log_exception_with_context(e, {"operation": "download", "file": "test.py"})
    """
    logger = get_logger(logger_name)
    
    exc_context = {
        "event_type": "EXCEPTION",
        "exception_type": type(e).__name__,
        "exception_message": str(e),
        **(context or {})
    }
    
    # Si es una de nuestras excepciones personalizadas, incluir detalles extra
    if hasattr(e, 'to_dict'):
        exc_context.update(e.to_dict())
    
    logger.exception("Exception occurred", extra=exc_context)


def debug_log_if_enabled(message: str, **kwargs) -> None:
    """
    Logea mensaje de debug solo si está habilitado.
    
    Útil para logs costosos que solo queremos en desarrollo.
    
    Args:
        message: Mensaje de debug
        **kwargs: Contexto adicional
    """
    if ENABLE_DEBUG_METRICS:
        logger = get_logger("debug")
        logger.debug(message, extra=kwargs)


# ========================================
# CONFIGURACIÓN INICIAL
# ========================================

def configure_root_logger() -> None:
    """
    Configura el logger raíz para capturar logs de librerías externas.
    
    Se ejecuta automáticamente al importar el módulo.
    """
    root_logger = logging.getLogger()
    
    # Solo configurar si no tiene handlers
    if not root_logger.handlers:
        # Nivel más alto para evitar spam de librerías
        root_logger.setLevel(logging.WARNING)
        
        # Handler simple para librerías externas
        handler = logging.StreamHandler()
        formatter = logging.Formatter(LOG_SIMPLE_FORMAT)
        handler.setFormatter(formatter)
        root_logger.addHandler(handler)


# Configuración automática al importar
configure_root_logger()

# Logger por defecto para el módulo
logger = get_logger(__name__)
logger.info("Logging system initialized", extra={
    "log_level": LOG_LEVEL,
    "log_format": LOG_FORMAT,
    "environment": "lambda" if IS_LAMBDA else "local",
    "debug_metrics": ENABLE_DEBUG_METRICS
})