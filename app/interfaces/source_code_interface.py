
from abc import ABC, abstractmethod
from typing import List
from app.models.file_node import FileNode

class ISourceCodeManager(ABC):
    """
    Interfaz base para gestores de código fuente (repositorios).

    Define el contrato que deben cumplir todas las implementaciones específicas
    para acceder y manipular estructuras de repositorios en distintas plataformas
    (por ejemplo: GitHub, GitLab, Bitbucket, Azure Repos).

    Esta interfaz permite desacoplar la lógica de negocio de la fuente real de los datos.
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
