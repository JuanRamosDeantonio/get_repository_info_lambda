"""
AWS Lambda Handler para gestión de código fuente
================================================

Este módulo actúa como router principal para AWS Lambda.
Toda la lógica de negocio ha sido extraída y organizada en módulos
especializados siguiendo una arquitectura desacoplada.

Componentes:
- Parsing y validación:       app.utils.request_parser
- Lógica de negocio:          app.handlers.*
- Respuestas HTTP:            app.utils.http_responses
- Logging y métricas:         app.core.logger
- Manejo de errores:          app.core.exceptions

Ejemplo de evento (GET_STRUCTURE):
{
  "operation": "GET_STRUCTURE",
  "provider": "github",
  "config": {
    "token": "ghp_abc123...",
    "owner": "org",
    "repo": "repo-name",
    "branch": "main"
  }
}

Autor: Equipo de Ingeniería
Versión: 2.0.0
"""

import unicodedata
from typing import Dict, Any
import os, subprocess

from app.core.logger import get_logger, set_request_context, clear_request_context
from app.utils.request_parser import parse_lambda_event
from app.utils.http_responses import create_exception_response
from app.handlers.structure_handler import handle_get_structure
from app.handlers.download_handler import handle_download_file

logger = get_logger(__name__)

def _normalize_event_encoding(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normaliza el encoding de strings en el evento para evitar errores UTF-8.
    
    Args:
        event: Evento Lambda original
        
    Returns:
        Dict[str, Any]: Evento con strings normalizados
    """
    if not isinstance(event, dict):
        return event
    
    # Crear copia del evento para no modificar el original
    normalized_event = {}
    
    for key, value in event.items():
        if isinstance(value, str):
            try:
                # Normalizar Unicode para caracteres especiales como ñ
                normalized_value = unicodedata.normalize('NFC', value)
                normalized_event[key] = normalized_value
                
                # Log si hubo cambios
                if normalized_value != value:
                    logger.debug(f"Normalized {key}: {repr(value)} -> {repr(normalized_value)}")
                    
            except Exception as e:
                logger.warning(f"Could not normalize {key}: {e}")
                normalized_event[key] = value
        elif isinstance(value, dict):
            # Recursivamente normalizar diccionarios anidados
            normalized_event[key] = _normalize_event_encoding(value)
        else:
            normalized_event[key] = value
    
    return normalized_event

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Punto de entrada principal para AWS Lambda.

    Recibe un evento, valida los parámetros, crea el manager
    correspondiente, y delega la ejecución a un handler especializado.

    Args:
        event (Dict[str, Any]): Evento Lambda con la operación y config
        context (Any): Objeto de contexto Lambda (contiene request_id)

    Returns:
        Dict[str, Any]: Respuesta HTTP estándar (statusCode, body, headers)
    """
    request_id = getattr(context, 'aws_request_id', 'unknown')


 
# Añadir /opt/bin al PATH para que git esté disponible
    os.environ["PATH"] = "/opt/bin:" + os.environ.get("PATH", "")
    
    # Ahora esto funciona porque buscará en /opt/bin/git
   
    try:

        version = subprocess.check_output(["git", "--version"]).decode().strip()
        print("Versión de git:", version)

        # Contexto de ejecución para logging y trazabilidad
        set_request_context(request_id=request_id, environment="lambda")
        logger.info("🚀 Lambda execution started", extra={"request_id": request_id})

        # 🔧 CORRECCIÓN: Normalizar encoding del evento antes del parsing
        try:
            normalized_event = _normalize_event_encoding(event)
            
            # Debug logging para troubleshooting
            if 'path' in event:
                original_path = event.get('path', '')
                normalized_path = normalized_event.get('path', '')
                
                logger.debug("Path encoding normalization", extra={
                    "request_id": request_id,
                    "original_path": repr(original_path),
                    "normalized_path": repr(normalized_path),
                    "changed": original_path != normalized_path
                })
                
        except Exception as normalize_error:
            logger.error("Failed to normalize event encoding", extra={
                "request_id": request_id,
                "error": str(normalize_error),
                "error_type": type(normalize_error).__name__
            })
            # Si falla la normalización, usar el evento original pero con logging
            normalized_event = event

        # Extraer operación y contexto usando el evento normalizado
        operation, manager, provider, path, iswiki = parse_lambda_event(normalized_event, context)

        logger.info("🔁 Routing operation", extra={
            "request_id": request_id,
            "operation": operation,
            "provider": provider,
            "path": path if operation == "DOWNLOAD_FILE" else None
        })

        # Enrutamiento
        if operation == "GET_STRUCTURE":
            return handle_get_structure(manager, provider)

        elif operation == "DOWNLOAD_FILE":
            return handle_download_file(manager, path, provider, iswiki)

        else:
            raise ValueError(f"Operación no reconocida: {operation}")

    except UnicodeDecodeError as unicode_error:
        logger.error("Unicode decoding error in lambda handler", extra={
            "request_id": request_id,
            "error": str(unicode_error),
            "error_position": getattr(unicode_error, 'start', 'unknown'),
            "problematic_byte": f"0x{unicode_error.object[unicode_error.start]:02x}" if hasattr(unicode_error, 'object') else 'unknown'
        })
        
        return create_exception_response(Exception(
            f"Error de codificación Unicode: {str(unicode_error)}. "
            "Verifique que el path no contenga caracteres especiales mal codificados."
        ))
        
    except Exception as e:
        logger.error("💥 Lambda execution failed", extra={
            "request_id": request_id,
            "error": str(e),
            "error_type": type(e).__name__
        })
        return create_exception_response(e)

    finally:
        clear_request_context()
        logger.info("✅ Lambda execution completed", extra={"request_id": request_id})