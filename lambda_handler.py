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

from typing import Dict, Any

from app.core.logger import get_logger, set_request_context, clear_request_context
from app.utils.request_parser import parse_lambda_event
from app.utils.http_responses import create_exception_response
from app.handlers.structure_handler import handle_get_structure
from app.handlers.download_handler import handle_download_file

logger = get_logger(__name__)

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

    try:
        # Contexto de ejecución para logging y trazabilidad
        set_request_context(request_id=request_id, environment="lambda")
        logger.info("🚀 Lambda execution started", extra={"request_id": request_id})

        # Extraer operación y contexto
        operation, manager, provider, path = parse_lambda_event(event, context)

        logger.info("🔁 Routing operation", extra={
            "request_id": request_id,
            "operation": operation,
            "provider": provider
        })

        # Enrutamiento
        if operation == "GET_STRUCTURE":
            return handle_get_structure(manager, provider)

        elif operation == "DOWNLOAD_FILE":
            return handle_download_file(manager, path, provider)

        else:
            raise ValueError(f"Operación no reconocida: {operation}")

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
