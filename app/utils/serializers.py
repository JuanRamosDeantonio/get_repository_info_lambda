from typing import List, Union
from app.models.file_node import FileNode

def serialize_node(node: FileNode) -> dict:
    return {
        "name": node.name,
        "path": node.path,
        "type": node.type,
        "download_url": node.download_url,
        "children": [serialize_node(child) for child in node.children] if node.children else []
    }

def serialize_structure(nodes: List[Union[FileNode, dict]]) -> List[dict]:
    """
    Convierte recursivamente una lista de FileNode (o dict) a una lista de dict serializable en JSON.

    Soporta nodos que ya hayan sido previamente serializados para evitar doble transformación.
    """
    serialized = []

    for node in nodes:
        if isinstance(node, dict):
            # Ya está serializado
            serialized.append(node)
        else:
            serialized_node = {
                "name": node.name,
                "path": node.path,
                "type": node.type,
                "download_url": node.download_url,
                "children": serialize_structure(node.children or [])
            }
            serialized.append(serialized_node)

    return serialized

