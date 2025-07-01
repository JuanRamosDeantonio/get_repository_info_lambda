"""
Manejador especializado para operaciones GET_STRUCTURE.

Este módulo contiene toda la lógica de negocio para obtener y formatear
la estructura jerárquica de repositorios. Optimizado para performance
y consumo por sistemas de IA.

Responsabilidades:
- Obtener estructura de archivos desde proveedores externos.
- Validar y calcular métricas relevantes de dicha estructura.
- Generar una respuesta enriquecida en Markdown y JSON.
- Registrar métricas para monitoreo, performance y seguridad.

Autor: Equipo de Ingeniería
Versión: 2.0.0
Fecha: 2025
"""

import time
import json
from typing import Any, Dict, List, Union
from dataclasses import asdict

from app.interfaces.source_code_interface import ISourceCodeManager
from app.models.file_node import FileNode
from app.utils.serializers import serialize_structure

from app.core.constants import MAX_NODES_STRUCTURE, MetricNames
from app.core.exceptions import (
    SourceCodeError,
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
from app.core.validators import validate_structure_size
from app.services.structure_formatter import format_markdown
from app.utils.http_responses import create_structure_response, create_exception_response

from app.utils.tree_utils import flatten_file_paths

# Inicialización del logger del módulo
logger = get_logger(__name__)


@log_performance(operation_name="get_structure")
def handle_get_structure(manager: ISourceCodeManager, provider: str) -> Dict[str, any]:
    """
    Función principal que orquesta el flujo completo para obtener la estructura
    de un repositorio, procesarla y retornarla en un formato enriquecido.

    Argumentos:
        manager (ISourceCodeManager): Instancia concreta del proveedor de código fuente.
        provider (str): Nombre del proveedor (github, gitlab, etc.).

    Retorna:
        Dict[str, any]: Estructura en JSON compatible con cliente HTTP.

    Manejo de errores:
        - Valida estructura vacía o inválida.
        - Captura excepciones específicas y las convierte en errores formateados.
        - Registra errores para observabilidad.
    """
    logger.info("Iniciando proceso de obtención de estructura", extra={"provider": provider, "operation": "GET_STRUCTURE"})

    try:
        log_api_call(provider=provider, operation="GET_STRUCTURE", action="list_files")

        nodes = _fetch_repository_structure(manager, provider)
        processed_structure = _process_structure(nodes, provider)
        output_data = _generate_structure_output(processed_structure, provider)

        file_paths = flatten_file_paths(processed_structure["nodes"])

        response = create_structure_response(
            nodes=serialize_structure(processed_structure["nodes"]),
            provider=provider,
            markdown=output_data["markdown"],
            metadata=output_data["metadata"],
            files=file_paths
        )

        _log_structure_metrics(processed_structure["metrics"], provider)

        logger.info("Estructura generada correctamente", extra={
            "provider": provider,
            "total_nodes": processed_structure["metrics"]["total_nodes"],
            "files": processed_structure["metrics"]["files"],
            "folders": processed_structure["metrics"]["folders"]
        })

        return response

    except Exception as e:
        logger.error("Error crítico durante la obtención de estructura", extra={
            "provider": provider,
            "error": str(e),
            "error_type": type(e).__name__
        })

        if not isinstance(e, (SourceCodeError, ValidationError)):
            provider_error = handle_provider_exception(e, provider, "get_structure", {"operation": "GET_STRUCTURE"})
            return create_exception_response(provider_error)

        return create_exception_response(e)


def _fetch_repository_structure(manager: ISourceCodeManager, provider: str) -> List[FileNode]:
    """
    Obtiene la estructura cruda del repositorio utilizando el manager correspondiente.

    Argumentos:
        manager (ISourceCodeManager): Implementación del proveedor.
        provider (str): Nombre del proveedor para fines de logging.

    Retorna:
        List[FileNode]: Lista de nodos raíz representando la estructura del repositorio.

    Lanza:
        SourceCodeError: En caso de errores en la obtención desde la fuente externa.
    """
    try:
        start_time = time.time()
        nodes = manager.list_files()
        fetch_duration = time.time() - start_time

        if not nodes:
            logger.warning("La estructura del repositorio está vacía", extra={"provider": provider, "fetch_duration": fetch_duration})
            return []

        if not isinstance(nodes, list):
            raise SourceCodeError(f"Manager retornó estructura inválida: se esperaba una lista, se recibió {type(nodes)}", provider=provider)

        logger.debug("Estructura recibida correctamente desde el manager", extra={
            "provider": provider,
            "root_nodes": len(nodes),
            "fetch_duration": round(fetch_duration, 3)
        })

        log_business_metric("structure_fetch_duration", fetch_duration, "seconds")
        return nodes

    except Exception as e:
        logger.error("Error al obtener estructura del repositorio", extra={
            "provider": provider,
            "error": str(e),
            "error_type": type(e).__name__
        })
        raise SourceCodeError(str(e), provider=provider) from e


def _process_structure(nodes: List[FileNode], provider: str) -> Dict[str, Union[List[FileNode], Dict[str, Any], bool]]:
    """
    Procesa y valida la estructura recibida para aplicar límites de seguridad
    y calcular métricas relevantes.

    Argumentos:
        nodes (List[FileNode]): Lista de nodos raíz.
        provider (str): Nombre del proveedor para fines de trazabilidad.

    Retorna:
        Dict[str, any]: Diccionario que incluye la estructura optimizada y sus métricas.
    """
    logger.debug("Procesando estructura del repositorio", extra={"provider": provider, "root_nodes": len(nodes)})
    metrics = _calculate_detailed_structure_metrics(nodes)
    total_nodes = metrics["total_nodes"]
    validate_structure_size(total_nodes)

    if metrics["max_depth"] > 50:
        logger.warning("Estructura con demasiada profundidad", extra={"provider": provider, "max_depth": metrics["max_depth"], "total_nodes": total_nodes})

    if total_nodes > MAX_NODES_STRUCTURE * 0.8:
        log_security_event("large_structure_request", f"Repositorio con {total_nodes} nodos", "WARNING", provider=provider, total_nodes=total_nodes)

    optimized_nodes = _optimize_structure_if_needed(nodes, metrics)
    return {"nodes": optimized_nodes, "metrics": metrics, "optimized": optimized_nodes is not nodes}


def _calculate_detailed_structure_metrics(nodes: List[FileNode]) -> Dict[str, any]:
    """
    Recorre de forma recursiva la estructura del repositorio para calcular
    métricas clave: cantidad de archivos y carpetas, profundidad, extensiones, etc.

    Argumentos:
        nodes (List[FileNode]): Lista de nodos raíz.

    Retorna:
        Dict[str, any]: Diccionario con las métricas detalladas calculadas.
    """
    metrics = {
        "total_nodes": 0,
        "files": 0,
        "folders": 0,
        "max_depth": 0,
        "avg_depth": 0,
        "largest_folder_size": 0,
        "file_extensions": {},
        "folder_distribution": {}
    }
    depths = []
    folder_sizes = {}

    def traverse_node(node: FileNode, current_depth: int = 0, parent_path: str = "") -> None:
        metrics["total_nodes"] += 1
        depths.append(current_depth)
        metrics["max_depth"] = max(metrics["max_depth"], current_depth)

        if node.type == 'file':
            metrics["files"] += 1
            if '.' in node.name:
                ext = node.name.split('.')[-1].lower()
                metrics["file_extensions"][ext] = metrics["file_extensions"].get(ext, 0) + 1

        elif node.type == 'folder':
            metrics["folders"] += 1
            folder_sizes[node.path] = 0

        if node.children:
            folder_sizes[node.path] = len(node.children)
            metrics["largest_folder_size"] = max(metrics["largest_folder_size"], len(node.children))
            for child in node.children:
                traverse_node(child, current_depth + 1, node.path)

    for root_node in nodes:
        traverse_node(root_node)

    if depths:
        metrics["avg_depth"] = sum(depths) / len(depths)

    if folder_sizes:
        dist = {"small": 0, "medium": 0, "large": 0, "xlarge": 0}
        for size in folder_sizes.values():
            if size < 10: dist["small"] += 1
            elif size < 50: dist["medium"] += 1
            elif size < 200: dist["large"] += 1
            else: dist["xlarge"] += 1
        metrics["folder_distribution"] = dist

    return metrics


def _generate_structure_output(processed_structure: Dict[str, any], provider: str) -> Dict[str, any]:
    nodes = processed_structure["nodes"]
    metrics = processed_structure["metrics"]

    logger.debug("Generando salida en formato Markdown", extra={"provider": provider, "total_nodes": metrics["total_nodes"]})
    start_time = time.time()

    # Solo usar objetos FileNode aquí
    markdown_structure = format_markdown(nodes)

    markdown_duration = time.time() - start_time
    markdown_size = len(markdown_structure.encode("utf-8"))

    metadata = {
        **metrics,
        "markdown_size_bytes": markdown_size,
        "markdown_generation_time": round(markdown_duration, 3),
        "structure_optimized": processed_structure["optimized"],
        "provider": provider,
        "generation_timestamp": time.time()
    }

    log_business_metric("markdown_generation_duration", markdown_duration, "seconds")
    log_business_metric("markdown_size", markdown_size, "bytes")

    logger.debug("Markdown generado exitosamente", extra={
        "provider": provider,
        "markdown_size": markdown_size,
        "generation_time": markdown_duration
    })

    return {"markdown": markdown_structure, "metadata": metadata}


def _log_structure_metrics(metrics: Dict[str, any], provider: str) -> None:
    """
    Registra métricas de negocio y operación relacionadas con la estructura analizada.

    Argumentos:
        metrics (Dict[str, any]): Métricas previamente calculadas.
        provider (str): Nombre del proveedor.
    """
    log_business_metric(MetricNames.STRUCTURE_NODES, metrics["total_nodes"], "count")
    log_business_metric(MetricNames.STRUCTURE_FILES, metrics["files"], "count")
    log_business_metric(MetricNames.STRUCTURE_FOLDERS, metrics["folders"], "count")
    log_business_metric(f"structures_{provider}", 1, "count")
    log_business_metric(f"nodes_{provider}", metrics["total_nodes"], "count")

    if metrics["max_depth"] > 0:
        log_business_metric("structure_max_depth", metrics["max_depth"], "levels")
    if metrics["avg_depth"] > 0:
        log_business_metric("structure_avg_depth", metrics["avg_depth"], "levels")

    for ext, count in metrics.get("file_extensions", {}).items():
        if count > 5:
            log_business_metric(f"files_{ext}", count, "count")


def _optimize_structure_if_needed(nodes: List[FileNode], metrics: Dict[str, any]) -> List[FileNode]:
    """
    Aplica reglas de optimización si la estructura excede ciertos umbrales
    definidos de tamaño o complejidad.

    Argumentos:
        nodes (List[FileNode]): Lista de nodos originales.
        metrics (Dict[str, any]): Métricas asociadas a los nodos.

    Retorna:
        List[FileNode]: Nodos optimizados o los originales si no aplica.
    """
    total_nodes = metrics["total_nodes"]

    if total_nodes < 1000:
        return nodes  # Sin optimización si es pequeña

    if total_nodes > 5000:
        logger.info("Estructura grande detectada, aplicando estrategia de optimización", extra={
            "total_nodes": total_nodes,
            "files": metrics["files"],
            "folders": metrics["folders"]
        })
        # Aquí podrían agregarse estrategias como paginación o lazy-loading

    return nodes


def handle_get_structure_local(manager: ISourceCodeManager, provider: str) -> None:
    """
    Permite ejecutar la obtención de estructura de forma local (CLI)
    con impresión de resultados formateados para debugging.

    Argumentos:
        manager (ISourceCodeManager): Implementación concreta.
        provider (str): Nombre del proveedor.

    Salida:
        Imprime en consola los resultados en formato Markdown y JSON.
    """
    try:
        logger.info("=== INICIANDO GET_STRUCTURE (LOCAL) ===")
        response = handle_get_structure(manager, provider)
        response_body = response.get("body", "{}")
        data = json.loads(response_body)

        print("\n" + "="*60)
        print("📦 ESTRUCTURA DEL REPOSITORIO")
        print("="*60)
        print(f"🔧 Proveedor: {provider}")
        print(f"📊 Total de nodos: {data.get('total_nodos', 0)}")

        metadata = data.get('metadatos', {})
        print(f"📄 Archivos: {metadata.get('archivos', 0)}")
        print(f"📁 Carpetas: {metadata.get('carpetas', 0)}")
        print(f"🏗️ Profundidad máxima: {metadata.get('profundidad_maxima', 0)}")

        print("\n" + "="*60)
        print("📋 ESTRUCTURA EN FORMATO MARKDOWN")
        print("="*60)
        print(data.get('markdown', 'No disponible'))

        print("\n" + "="*60)
        print("🔍 METADATOS DETALLADOS")
        print("="*60)
        print(json.dumps(metadata, indent=2, ensure_ascii=False))

        archivos = data.get("archivos", [])
        if archivos:
            print("\n" + "="*60)
            print("🧾 LISTADO DE ARCHIVOS (rutas relativas)")
            print("="*60)
            for archivo in archivos:
                print(f"- {archivo}")

        print("\n✅ GET_STRUCTURE completado exitosamente")

    except Exception as e:
        logger.exception("Error en modo local")
        print(f"\n❌ Error: {str(e)}")
        print(f"🔧 Tipo: {type(e).__name__}")
