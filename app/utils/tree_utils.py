from typing import List
from app.models.file_node import FileNode

def flatten_file_paths(nodes: List[FileNode], base_path: str = "") -> List[str]:
    """
    Recorre recursivamente la estructura de FileNode y extrae todas
    las rutas relativas de archivos (no carpetas).
    """
    files = []

    for node in nodes:
        current_path = f"{base_path}/{node.name}" if base_path else node.name

        if node.type == "file":
            files.append(current_path)

        elif node.type == "folder" and node.children:
            files.extend(flatten_file_paths(node.children, current_path))

    return files
