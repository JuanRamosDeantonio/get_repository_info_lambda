"""
Utilidades para recorrer estructuras de FileNode y aplanar rutas de archivos.
Pensado para ejecutarse en AWS Lambda sin emitir warnings innecesarios.
"""

from typing import Iterable, List, Tuple
import os
import posixpath
import warnings

from app.models.file_node import FileNode

__all__ = ["flatten_file_paths"]

# Detecta entorno Lambda para silenciar warnings de compatibilidad
_LAMBDA_ENV = bool(os.getenv("AWS_LAMBDA_FUNCTION_NAME")) or os.getenv("AWS_EXECUTION_ENV", "").startswith("AWS_Lambda_")


def flatten_file_paths(nodes: Iterable[FileNode], base_path: str = "") -> List[Tuple[str, bool]]:
    """
    Recorre recursivamente la estructura de FileNode y devuelve una lista de
    tuplas (ruta_relativa_POSIX, iswiki) SOLO para nodos de tipo archivo.

    Args:
        nodes: Iterable de FileNode raíz o hijos.
        base_path: Ruta base relativa (se unirá con separador POSIX '/').
    Returns:
        List[Tuple[str, bool]]: Lista de (path, iswiki).
    """
    files: List[Tuple[str, bool]] = []

    for node in nodes:
        name = getattr(node, "name", None)
        if not name:
            # defensivo: ignora nodos sin nombre
            continue

        current_path = posixpath.join(base_path, name) if base_path else name
        ntype = getattr(node, "type", None)

        if ntype == "file":
            iswiki = bool(getattr(node, "iswiki", False))
            files.append((current_path, iswiki))

        elif ntype == "folder":
            children = getattr(node, "children", None)
            if children:
                files.extend(flatten_file_paths(children, current_path))

        # Otros tipos se ignoran silenciosamente

    return files

