"""
Servicio de Formateo Markdown de Estructura de Repositorio
===========================================================

Este módulo convierte una lista jerárquica de nodos (carpetas y archivos)
en una representación textual en formato Markdown optimizada para lectura
humana y modelos de lenguaje (IA).

Cada carpeta se muestra con un ícono 📁 y cada archivo con 📄, junto con
su nombre, respetando los niveles de indentación según la profundidad
de la estructura.

Autor: Equipo de Ingeniería
Versión: 1.0.0
"""

from typing import List
from app.models.file_node import FileNode

def format_markdown(nodes: List[FileNode], indent: int = 0) -> str:
    """
    Convierte una lista de nodos de archivos/directorios a formato Markdown jerárquico.

    Este formato es compatible con visualización humana y con modelos de IA
    que procesan estructuras de texto ordenadas.

    Argumentos:
        nodes (List[FileNode]): Lista de nodos de primer nivel (raíz).
        indent (int): Nivel de indentación inicial (para recursividad).

    Retorna:
        str: Representación en Markdown de la estructura de archivos.
    
    Ejemplo de salida:
        - 📁 `src`
          - 📄 `main.py`
          - 📁 `utils`
            - 📄 `helpers.py`
    """
    lines = []
    prefix = "  " * indent  # Espacios por nivel de profundidad

    for node in nodes:
        icon = "📁" if node.type == "folder" else "📄"
        line = f"{prefix}- {icon} `{node.name}`"
        lines.append(line)

        # Procesar hijos recursivamente (si existen)
        if node.children:
            lines.append(format_markdown(node.children, indent + 1))

    return "\n".join(lines)
