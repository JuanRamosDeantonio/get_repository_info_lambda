# app/models/file_node.py

from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class FileNode:
    """
    Modelo de datos que representa un nodo dentro de la estructura
    jerárquica de un repositorio. Puede ser un archivo o una carpeta.

    Atributos:
    ----------
    name : str
        Nombre del archivo o carpeta (ej: "main.py", "src").
    
    path : str
        Ruta completa del nodo dentro del repositorio (ej: "src/utils/main.py").
    
    type : str
        Tipo de nodo: "file" o "folder".
    
    children : Optional[List[FileNode]]
        Lista de subnodos hijos (sólo aplicable si el tipo es "folder").
        Por defecto, es una lista vacía.
    
    download_url : Optional[str]
        Enlace directo de descarga si es un archivo (opcional).
    """
    name: str
    path: str
    type: str  # "file" o "folder"
    title: Optional[str] = None
    children: Optional[List["FileNode"]] = field(default_factory=list)
    download_url: Optional[str] = None
    iswiki: Optional[bool] = False
