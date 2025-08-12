from abc import ABC, abstractmethod
from typing import List
from app.models.file_node import FileNode

class ISourceCodeManager(ABC):
    """
    Interfaz base para gestores de código fuente (repositorios).

    Define el contrato que deben cumplir todas las implementaciones específicas
    para acceder y manipular estructuras de repositorios en distintas plataformas
    (por ejemplo: GitHub, GitLab, Bitbucket, Azure Repos).

    Esta interfaz permite desacoplar la lógica de negocio de la fuente real de los datos,
    incluyendo acceso tanto al código fuente como a la documentación wiki asociada.
    """

    @abstractmethod
    def list_files(self) -> List[FileNode]:
        """
        Lista los archivos y carpetas del repositorio de forma jerárquica.

        Returns:
            List[FileNode]: Estructura completa del repositorio como lista de nodos raíz.
        
        Raises:
            SourceCodeError: Si hay problemas accediendo al repositorio.
        """
        pass

    @abstractmethod
    def download_file(self, path: str) -> bytes:
        """
        Descarga el contenido bruto (binario) de un archivo específico.

        Args:
            path (str): Ruta completa del archivo dentro del repositorio.
        
        Returns:
            bytes: Contenido del archivo.
        
        Raises:
            SourceCodeError: Si el archivo no existe o hay error en la descarga.
        """
        pass

    @abstractmethod
    def read_wiki_file(self, file_path: str) -> str:
        """
        Lee el contenido de un archivo markdown de la wiki del repositorio.

        La wiki es un espacio de documentación separado del código fuente principal
        donde se almacenan archivos markdown con información del proyecto.

        Args:
            file_path (str): Nombre o ruta del archivo en la wiki (ej: "Home.md", "Installation.md").
                           Se puede omitir la extensión .md, se añadirá automáticamente si es necesario.
        
        Returns:
            str: Contenido del archivo markdown como string UTF-8.
        
        Raises:
            SourceCodeError: Si la wiki no existe, el archivo no se encuentra, 
                           hay problemas de permisos, o errores de decodificación.
        """
        pass