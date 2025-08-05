"""
Sistema de parseo de requests para AWS Lambda y testing local.

Este módulo maneja el parseo y validación de eventos desde múltiples fuentes:
- AWS Lambda (API Gateway, direct invocation)
- Testing local (archivos JSON, objetos directos)
- Desarrollo (diferentes formatos de entrada)

Features:
- Auto-detección del formato de entrada
- Validación integral usando el sistema de validators
- Creación automática de managers via factory
- Contexto de request para logging
- Manejo robusto de errores

Author: [Your Name]
Created: 2025
Version: 2.0.0
"""

import json
import sys
from typing import Dict, Any, Tuple, Optional, Union
from pathlib import Path

from app.core.constants import IS_LAMBDA, IS_LOCAL
from app.core.exceptions import ValidationError, create_validation_error
from app.core.logger import get_logger, set_request_context, log_request_lifecycle
from app.core.validators import validate_request_data
from app.factory.source_code_factory import SourceCodeManagerFactory

# Logger para el módulo
logger = get_logger(__name__)

# ========================================
# PARSERS PARA AWS LAMBDA
# ========================================

def parse_lambda_event(event: Dict[str, Any], context: Any) -> Tuple[str, Any, str, Optional[str]]:
    """
    Parsea y valida un evento completo de AWS Lambda.
    
    Esta es la función principal que orquesta todo el proceso de parseo
    para requests de AWS Lambda. Maneja diferentes formatos de entrada
    y retorna todo lo necesario para procesar el request.
    
    Args:
        event: Evento de AWS Lambda
        context: Contexto de AWS Lambda
        
    Returns:
        Tuple[str, Any, str, Optional[str]]: (operation, manager, provider, path)
        
    Raises:
        ValidationError: Si el evento es inválido
        ConfigurationError: Si la configuración del proveedor es inválida
        
    Example:
        >>> operation, manager, provider, path = parse_lambda_event(event, context)
        >>> if operation == "GET_STRUCTURE":
        >>>     result = manager.list_files()
    """
    # Extraer request ID para tracing
    request_id = getattr(context, 'aws_request_id', 'unknown')
    
    # Configurar contexto de logging
    set_request_context(
        request_id=request_id,
        environment="lambda",
        source="api_gateway"
    )
    
    # Log inicio del parseo
    log_request_lifecycle("PARSE_START", request_id, event_keys=list(event.keys()))
    
    try:
        # Parsear body del evento
        body = _extract_event_body(event)
        
        # Validar datos completos del request
        operation, provider, config, path, ismarkdown = validate_request_data(body)
        
        # Actualizar contexto con información del request
        set_request_context(
            operation=operation,
            provider=provider,
            has_path=bool(path)
        )
        
        # Crear manager para el proveedor
        logger.info(f"Creating manager for provider: {provider}")
        manager = SourceCodeManagerFactory.create(provider, config)
        
        # Log éxito del parseo
        log_request_lifecycle("PARSE_SUCCESS", request_id, 
                            operation=operation, provider=provider)
        
        return operation, manager, provider, path, ismarkdown
        
    except Exception as e:
        # Log error del parseo
        log_request_lifecycle("PARSE_ERROR", request_id, 
                            error=str(e), error_type=type(e).__name__)
        raise


def _extract_event_body(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extrae el body del evento Lambda con manejo robusto de formatos.
    
    Maneja múltiples formatos de entrada:
    - API Gateway: {"body": "json_string"}
    - Direct invocation: {"body": {...}}
    - Testing: {...} (sin wrapper body)
    
    Args:
        event: Evento completo de Lambda
        
    Returns:
        Dict[str, Any]: Body parseado
        
    Raises:
        ValidationError: Si el formato es inválido
    """
    if not isinstance(event, dict):
        raise create_validation_error(
            "El evento debe ser un diccionario",
            field_name="event",
            received_value=type(event).__name__
        )
    
    # Intentar extraer body
    body = event.get("body")
    
    # Si no hay body, usar event directamente (testing/direct invocation)
    if body is None:
        if "operation" in event:
            logger.debug("Using event as body directly (direct invocation)")
            return event
        else:
            raise create_validation_error(
                "El evento debe contener un 'body' o campos de operación directos",
                field_name="body"
            )
        
    print("BODY************************************************************************")    
    print(body)    
    print("BODY************************************************************************")    
    
    # Si body es string, parsearlo como JSON (API Gateway)
    if isinstance(body, str):
        try:
            parsed_body = json.loads(body)
            logger.debug("Parsed string body as JSON (API Gateway)")
            return parsed_body
        except json.JSONDecodeError as e:
            raise create_validation_error(
                f"Body JSON inválido: {str(e)}",
                field_name="body",
                received_value=body[:100] + "..." if len(body) > 100 else body
            )
    
    # Si body ya es dict, usarlo directamente (direct invocation)
    if isinstance(body, dict):
        logger.debug("Using dict body directly (direct invocation)")
        return body
    
    # Formato no reconocido
    raise create_validation_error(
        "Formato de body no reconocido",
        field_name="body",
        received_value=type(body).__name__
    )


# ========================================
# PARSERS PARA TESTING LOCAL
# ========================================

def parse_local_event(event_file: Optional[str] = None) -> Tuple[str, Any, str, Optional[str]]:
    """
    Parsea eventos para testing local desde archivos o argumentos.
    
    Esta función maneja el parseo para desarrollo local, incluyendo:
    - Lectura desde archivos JSON
    - Parseo de argumentos de línea de comandos
    - Configuración de contexto local
    
    Args:
        event_file: Ruta al archivo de evento (opcional)
        
    Returns:
        Tuple[str, Any, str, Optional[str]]: (operation, manager, provider, path)
        
    Raises:
        ValidationError: Si el evento es inválido
        FileNotFoundError: Si el archivo no existe
        
    Example:
        >>> # Desde archivo
        >>> operation, manager, provider, path = parse_local_event("event.json")
        
        >>> # Desde argumentos de línea de comandos
        >>> operation, manager, provider, path = parse_local_event()
    """
    # Configurar contexto local
    request_id = f"local-{hash(str(sys.argv)) % 10000}"
    set_request_context(
        request_id=request_id,
        environment="local",
        source="file" if event_file else "args"
    )
    
    log_request_lifecycle("PARSE_START", request_id, 
                        event_file=event_file, args=sys.argv)
    
    try:
        # Determinar fuente del evento
        if event_file:
            event_data = _load_event_from_file(event_file)
        else:
            event_data = _parse_command_line_args()
        
        # Validar datos del request
        operation, provider, config, path, ismarkdown = validate_request_data(event_data)
        
        # Actualizar contexto
        set_request_context(
            operation=operation,
            provider=provider,
            has_path=bool(path)
        )
        
        # Crear manager
        logger.info(f"Creating local manager for provider: {provider}")
        manager = SourceCodeManagerFactory.create(provider, config)
        
        log_request_lifecycle("PARSE_SUCCESS", request_id,
                            operation=operation, provider=provider)
        
        return operation, manager, provider, path, ismarkdown
        
    except Exception as e:
        log_request_lifecycle("PARSE_ERROR", request_id,
                            error=str(e), error_type=type(e).__name__)
        raise


def _load_event_from_file(file_path: str) -> Dict[str, Any]:
    """
    Carga evento desde archivo JSON con validación.
    
    Args:
        file_path: Ruta al archivo JSON
        
    Returns:
        Dict[str, Any]: Datos del evento
        
    Raises:
        ValidationError: Si el archivo es inválido
        FileNotFoundError: Si el archivo no existe
    """
    try:
        path = Path(file_path)

        print("LOADEVENTFROMFILE****************************************************")
        print(file_path)
        print(path)
        print("LOADEVENTFROMFILE****************************************************")
        
        # Verificar que el archivo existe
        if not path.exists():
            raise FileNotFoundError(f"Archivo de evento no encontrado: {file_path}")
        
        # Verificar que es un archivo
        if not path.is_file():
            raise ValidationError(f"La ruta no es un archivo: {file_path}")
        
        # Leer y parsear JSON
        with path.open('r', encoding='latin-1') as f:
            data = json.load(f)
        
        logger.debug(f"Loaded event from file: {file_path}")

        print("LOADEVENTFROMFILE****************************************************V1")
        print(data)
        print("LOADEVENTFROMFILE****************************************************V1")
        return data
        
    except json.JSONDecodeError as e:
        raise create_validation_error(
            f"Error parseando JSON en {file_path}: {str(e)}",
            field_name="event_file",
            received_value=file_path
        )
    except Exception as e:
        raise create_validation_error(
            f"Error leyendo archivo {file_path}: {str(e)}",
            field_name="event_file",
            received_value=file_path
        )


def _parse_command_line_args() -> Dict[str, Any]:
    """
    Parsea argumentos de línea de comandos como evento.

    Formato esperado:
        python main.py --operation GET_STRUCTURE --provider github --config '{"token":"xxx",...}'

    Returns:
        Dict[str, Any]: Datos del evento construidos desde args

    Raises:
        ValidationError: Si los argumentos son inválidos
    """
    if len(sys.argv) < 2:
        raise create_validation_error(
            "❌ No se pasaron argumentos suficientes.\n\n"
            "✅ Formato esperado:\n"
            "    python main.py --operation GET_STRUCTURE --provider github --config '{\"token\":\"xxx\", \"owner\":\"org\", \"repo\":\"repo\"}'",
            field_name="command_args"
        )

    # Si el primer argumento no es una flag, asumir que es archivo
    if not sys.argv[1].startswith('--'):
        return _load_event_from_file(sys.argv[1])

    args = {}
    i = 1
    while i < len(sys.argv):
        if sys.argv[i].startswith('--'):
            key = sys.argv[i][2:]
            if i + 1 < len(sys.argv) and not sys.argv[i + 1].startswith('--'):
                value = sys.argv[i + 1]

                if key == 'config':
                    try:
                        value = json.loads(value)
                    except json.JSONDecodeError:
                        raise create_validation_error(
                            f"❌ El valor de '--config' no es un JSON válido:\n    {value}",
                            field_name="config_arg"
                        )

                args[key] = value
                i += 2
            else:
                raise create_validation_error(
                    f"❌ Falta el valor para la opción '--{key}'\n\n"
                    "✅ Uso correcto:\n"
                    "    --operation GET_STRUCTURE --provider github --config '{...}'",
                    field_name="command_args"
                )
        else:
            i += 1

    required_keys = {"operation", "provider", "config"}
    missing_keys = required_keys - args.keys()

    if missing_keys:
        raise create_validation_error(
            f"❌ Argumentos obligatorios faltantes: {', '.join(missing_keys)}\n\n"
            "✅ Ejemplo válido:\n"
            "    python main.py --operation GET_STRUCTURE --provider github --config '{\"token\":\"xxx\", \"owner\":\"org\", \"repo\":\"repo\"}'",
            field_name="command_args"
        )

    logger.debug(f"Parsed command line args: {list(args.keys())}")
    return args


# ========================================
# PARSERS GENÉRICOS
# ========================================

def parse_event_auto(event: Union[Dict, str], context: Optional[Any] = None) -> Tuple[str, Any, str, Optional[str]]:
    """
    Auto-detecta el formato del evento y parsea apropiadamente.
    
    Esta función inteligente detecta automáticamente si está ejecutándose
    en Lambda o localmente y usa el parser apropiado.
    
    Args:
        event: Evento a parsear (dict o string)
        context: Contexto de Lambda (opcional)
        
    Returns:
        Tuple[str, Any, str, Optional[str]]: (operation, manager, provider, path)
        
    Example:
        >>> # En Lambda
        >>> operation, manager, provider, path = parse_event_auto(lambda_event, lambda_context)
        
        >>> # En local (testing)
        >>> operation, manager, provider, path = parse_event_auto(local_event)
    """
    # Auto-detectar entorno
    if IS_LAMBDA and context is not None:
        # Ejecutándose en AWS Lambda
        logger.debug("Auto-detected Lambda environment")
        return parse_lambda_event(event, context)
    
    elif IS_LOCAL or context is None:
        # Ejecutándose localmente o sin contexto
        logger.debug("Auto-detected local environment")
        
        # Si event es string, asumir que es archivo
        if isinstance(event, str):
            return parse_local_event(event)
        
        # Si event es dict, parsearlo directamente
        elif isinstance(event, dict):
            operation, provider, config, path = validate_request_data(event)
            manager = SourceCodeManagerFactory.create(provider, config)
            return operation, manager, provider, path
        
        else:
            raise create_validation_error(
                "Formato de evento no reconocido para entorno local",
                field_name="event",
                received_value=type(event).__name__
            )
    
    else:
        raise create_validation_error(
            "No se pudo determinar el entorno de ejecución",
            field_name="environment"
        )


# ========================================
# UTILIDADES DE PARSEO
# ========================================

def validate_event_structure(event: Dict[str, Any]) -> None:
    """
    Valida la estructura básica del evento sin procesar el contenido.
    
    Útil para validación temprana antes del procesamiento completo.
    
    Args:
        event: Evento a validar
        
    Raises:
        ValidationError: Si la estructura es inválida
    """
    if not isinstance(event, dict):
        raise create_validation_error(
            "El evento debe ser un diccionario",
            field_name="event_structure",
            received_value=type(event).__name__
        )
    
    # Lista de campos que esperamos encontrar
    expected_fields = ["operation", "provider", "config"]
    present_fields = []
    
    # Verificar en el evento directo o en el body
    check_locations = [event]
    if "body" in event:
        if isinstance(event["body"], dict):
            check_locations.append(event["body"])
        elif isinstance(event["body"], str):
            try:
                body = json.loads(event["body"])
                if isinstance(body, dict):
                    check_locations.append(body)
            except json.JSONDecodeError:
                pass
    
    # Buscar campos esperados
    for location in check_locations:
        for field in expected_fields:
            if field in location:
                present_fields.append(field)
    
    # Verificar que al menos tengamos operation y provider
    required_fields = ["operation", "provider"]
    missing_required = [field for field in required_fields if field not in present_fields]
    
    if missing_required:
        raise create_validation_error(
            f"Faltan campos requeridos en el evento: {', '.join(missing_required)}",
            field_name="event_structure"
        )
    
    logger.debug("Event structure validation passed", extra={
        "present_fields": present_fields,
        "locations_checked": len(check_locations)
    })


def extract_metadata_from_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extrae metadatos útiles del evento para logging y debugging.
    
    Args:
        event: Evento completo
        
    Returns:
        Dict[str, Any]: Metadatos extraídos
    """
    metadata = {}
    
    # Metadatos de API Gateway
    if "requestContext" in event:
        request_ctx = event["requestContext"]
        metadata.update({
            "request_id": request_ctx.get("requestId"),
            "stage": request_ctx.get("stage"),
            "http_method": request_ctx.get("httpMethod"),
            "source_ip": request_ctx.get("identity", {}).get("sourceIp"),
            "user_agent": request_ctx.get("identity", {}).get("userAgent")
        })
    
    # Headers HTTP
    if "headers" in event:
        headers = event["headers"]
        metadata.update({
            "content_type": headers.get("Content-Type"),
            "content_length": headers.get("Content-Length"),
            "host": headers.get("Host"),
            "referer": headers.get("Referer")
        })
    
    # Información del body
    if "body" in event:
        body = event["body"]
        metadata.update({
            "body_type": type(body).__name__,
            "body_size": len(str(body)) if body else 0,
            "is_base64": event.get("isBase64Encoded", False)
        })
    
    # Filtrar valores None
    return {k: v for k, v in metadata.items() if v is not None}


# ========================================
# FUNCIONES DE CONVENIENCIA
# ========================================

def create_test_event(operation: str, provider: str, config: Dict[str, Any], 
                     path: Optional[str] = None) -> Dict[str, Any]:
    """
    Crea un evento de prueba para testing.
    
    Args:
        operation: Operación a realizar
        provider: Proveedor a usar
        config: Configuración del proveedor
        path: Ruta del archivo (opcional)
        
    Returns:
        Dict[str, Any]: Evento de prueba válido
        
    Example:
        >>> event = create_test_event(
        ...     "GET_STRUCTURE",
        ...     "github", 
        ...     {"token": "xxx", "owner": "user", "repo": "repo"}
        ... )
    """
    event_data = {
        "operation": operation,
        "provider": provider,
        "config": config
    }
    
    if path:
        event_data["path"] = path
    
    return event_data


def save_test_event(event: Dict[str, Any], filename: str) -> None:
    """
    Guarda un evento como archivo JSON para testing.
    
    Args:
        event: Evento a guardar
        filename: Nombre del archivo
        
    Example:
        >>> event = create_test_event("GET_STRUCTURE", "github", config)
        >>> save_test_event(event, "test_event.json")
    """
    path = Path(filename)
    
    with path.open('w', encoding='utf-8') as f:
        json.dump(event, f, indent=2, ensure_ascii=False)
    
    logger.info(f"Test event saved to: {filename}")


# Inicialización del módulo
logger.info("Request parser initialized", extra={
    "environment": "lambda" if IS_LAMBDA else "local",
    "features": ["auto_detection", "multi_format", "validation", "context_tracking"]
})