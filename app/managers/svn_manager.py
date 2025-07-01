"""
Manejador de Subversion con detección de entorno AWS Lambda.

IMPORTANTE: SVN requiere binarios del sistema que no están disponibles
en el entorno AWS Lambda. Este manager detecta automáticamente el entorno
y proporciona errores informativos cuando se ejecuta en Lambda.

Para uso en AWS Lambda, use GitHub, GitLab o Azure DevOps en su lugar.

Author: [Your Name]
Created: 2025
Version: 2.0.0 - Lambda Compatible
"""

import subprocess
from typing import List

from app.core.constants import IS_LAMBDA
from app.core.exceptions import SourceCodeError, ConfigurationError
from app.core.logger import get_logger
from app.interfaces.source_code_interface import ISourceCodeManager
from app.models.file_node import FileNode

# Logger para el módulo
logger = get_logger(__name__)

class SubversionManager(ISourceCodeManager):
    """
    Manager para repositorios Subversion (SVN).
    
    LIMITACIÓN AWS LAMBDA:
    Este manager NO funciona en AWS Lambda porque requiere:
    - Binarios SVN del sistema operativo
    - Capacidad de ejecutar subprocess
    - Acceso al filesystem local
    
    Para AWS Lambda, use en su lugar:
    - GitHub (recomendado)
    - GitLab (recomendado)  
    - Azure DevOps (recomendado)
    
    Este manager funciona perfectamente en:
    - Desarrollo local
    - Servidores tradicionales
    - Contenedores Docker con SVN instalado
    - EC2 instances con SVN
    """
    
    def __init__(self, config: dict):
        """
        Inicializa el manager SVN con validación de entorno.
        
        Args:
            config: Configuración del repositorio SVN
            
        Raises:
            ConfigurationError: Si se ejecuta en AWS Lambda
            SourceCodeError: Si la configuración es inválida
        """
        # DETECCIÓN DE ENTORNO LAMBDA
        if IS_LAMBDA:
            logger.error("SVN attempted in Lambda environment", extra={
                "environment": "lambda",
                "provider": "svn",
                "limitation": "subprocess_not_available"
            })
            raise ConfigurationError(
                "Subversion (SVN) no está soportado en AWS Lambda. "
                "AWS Lambda no incluye binarios SVN y no permite subprocess externos. "
                "Use GitHub, GitLab o Azure DevOps en su lugar.",
                provider="svn",
                error_code="SVN_NOT_SUPPORTED_IN_LAMBDA",
                details={
                    "environment": "aws_lambda",
                    "reason": "svn_binaries_not_available",
                    "alternatives": ["github", "gitlab", "azure"],
                    "recommendation": "Use GitHub para mejor performance en Lambda"
                }
            )
        
        # Validación de configuración básica
        self.repo_url = config["repo_url"].rstrip("/")
        self.username = config.get("username")
        self.password = config.get("password")
        
        # Validar que SVN esté disponible en el sistema
        self._validate_svn_availability()
        
        logger.info("SVN manager initialized", extra={
            "repo_url": self.repo_url,
            "has_credentials": bool(self.username and self.password),
            "environment": "local"
        })
    
    def _validate_svn_availability(self) -> None:
        """
        Valida que SVN esté disponible en el sistema local.
        
        Raises:
            SourceCodeError: Si SVN no está instalado o disponible
        """
        try:
            # Verificar que SVN está instalado
            result = subprocess.run(
                ["svn", "--version"], 
                capture_output=True, 
                text=True, 
                timeout=5
            )
            
            if result.returncode != 0:
                raise SourceCodeError(
                    "SVN no está instalado o no funciona correctamente en este sistema",
                    provider="svn",
                    error_code="SVN_NOT_AVAILABLE",
                    details={
                        "return_code": result.returncode,
                        "stderr": result.stderr,
                        "suggestion": "Instale SVN: apt-get install subversion (Ubuntu) o brew install svn (macOS)"
                    }
                )
            
            logger.debug("SVN availability validated", extra={
                "svn_version": result.stdout.split('\n')[0] if result.stdout else "unknown"
            })
            
        except subprocess.TimeoutExpired:
            raise SourceCodeError(
                "Timeout verificando disponibilidad de SVN",
                provider="svn",
                error_code="SVN_VALIDATION_TIMEOUT"
            )
        except FileNotFoundError:
            raise SourceCodeError(
                "SVN no está instalado en este sistema",
                provider="svn", 
                error_code="SVN_NOT_INSTALLED",
                details={
                    "suggestion": "Instale SVN usando su package manager",
                    "ubuntu": "apt-get install subversion",
                    "centos": "yum install subversion",
                    "macos": "brew install svn",
                    "windows": "Descargue desde https://tortoisesvn.net/"
                }
            )
        except Exception as e:
            raise SourceCodeError(
                f"Error validando SVN: {str(e)}",
                provider="svn",
                error_code="SVN_VALIDATION_ERROR"
            )

    def list_files(self) -> List[FileNode]:
        """
        Lista todos los archivos y carpetas del repositorio SVN.
        
        Returns:
            List[FileNode]: Lista jerárquica de archivos y carpetas
            
        Raises:
            SourceCodeError: Si hay problemas accediendo al repositorio
            
        Note:
            Esta función NO funciona en AWS Lambda debido a limitaciones
            de subprocess y disponibilidad de binarios SVN.
        """
        logger.info("Listing SVN repository files", extra={
            "repo_url": self.repo_url,
            "operation": "list_files"
        })
        
        # Construir comando SVN
        cmd = ["svn", "list", self.repo_url, "--recursive"]
        
        # Agregar credenciales si están disponibles
        if self.username:
            cmd.extend(["--username", self.username])
        if self.password:
            cmd.extend(["--password", self.password])
        
        # Agregar flags adicionales
        cmd.extend([
            "--non-interactive",    # No pedir input interactivo
            "--trust-server-cert",  # Confiar en certificados del servidor
            "--no-auth-cache"       # No cachear credenciales
        ])
        
        try:
            logger.debug("Executing SVN command", extra={
                "command": " ".join(cmd[:3] + ["[REPO_URL]"] + cmd[4:]),  # Ocultar URL completa
                "timeout": 30
            })
            
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                check=True,
                timeout=30  # Timeout de 30 segundos
            )
            
            lines = result.stdout.strip().split("\n")
            if not lines or (len(lines) == 1 and not lines[0]):
                logger.warning("Empty SVN repository", extra={
                    "repo_url": self.repo_url
                })
                return []
            
            # Procesar salida SVN en estructura jerárquica
            nodes = self._parse_svn_output(lines)
            
            logger.info("SVN files listed successfully", extra={
                "repo_url": self.repo_url,
                "total_items": len(lines),
                "root_nodes": len(nodes)
            })
            
            return nodes
            
        except subprocess.TimeoutExpired:
            raise SourceCodeError(
                f"Timeout listando archivos del repositorio SVN (30s)",
                provider="svn",
                error_code="SVN_LIST_TIMEOUT",
                details={"repo_url": self.repo_url}
            )
        except subprocess.CalledProcessError as e:
            error_details = {
                "return_code": e.returncode,
                "stderr": e.stderr,
                "repo_url": self.repo_url
            }
            
            # Categorizar errores comunes
            if "authentication failed" in e.stderr.lower():
                raise SourceCodeError(
                    "Falló la autenticación SVN. Verifique usuario y contraseña",
                    provider="svn",
                    error_code="SVN_AUTH_FAILED",
                    details=error_details
                )
            elif "repository not found" in e.stderr.lower():
                raise SourceCodeError(
                    f"Repositorio SVN no encontrado: {self.repo_url}",
                    provider="svn", 
                    error_code="SVN_REPO_NOT_FOUND",
                    details=error_details
                )
            else:
                raise SourceCodeError(
                    f"Error ejecutando comando SVN: {e.stderr}",
                    provider="svn",
                    error_code="SVN_COMMAND_FAILED",
                    details=error_details
                )
        except Exception as e:
            raise SourceCodeError(
                f"Error inesperado listando archivos SVN: {str(e)}",
                provider="svn",
                error_code="SVN_UNEXPECTED_ERROR",
                details={"repo_url": self.repo_url}
            )

    def download_file(self, path: str) -> bytes:
        """
        Descarga un archivo específico del repositorio SVN.
        
        Args:
            path: Ruta del archivo en el repositorio
            
        Returns:
            bytes: Contenido del archivo
            
        Raises:
            SourceCodeError: Si hay problemas descargando el archivo
            
        Note:
            Esta función NO funciona en AWS Lambda debido a limitaciones
            de subprocess y disponibilidad de binarios SVN.
        """
        logger.info("Downloading SVN file", extra={
            "repo_url": self.repo_url,
            "path": path,
            "operation": "download_file"
        })
        
        # Construir comando SVN cat
        cmd = ["svn", "cat", f"{self.repo_url}/{path}"]
        
        # Agregar credenciales si están disponibles
        if self.username:
            cmd.extend(["--username", self.username])
        if self.password:
            cmd.extend(["--password", self.password])
        
        # Agregar flags adicionales
        cmd.extend([
            "--non-interactive",
            "--trust-server-cert",
            "--no-auth-cache"
        ])
        
        try:
            logger.debug("Executing SVN cat command", extra={
                "path": path,
                "timeout": 30
            })
            
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                check=True,
                timeout=30
            )
            
            content = result.stdout
            file_size = len(content)
            
            logger.info("SVN file downloaded successfully", extra={
                "path": path,
                "file_size": file_size
            })
            
            return content
            
        except subprocess.TimeoutExpired:
            raise SourceCodeError(
                f"Timeout descargando archivo SVN: {path} (30s)",
                provider="svn",
                error_code="SVN_DOWNLOAD_TIMEOUT",
                details={"path": path, "repo_url": self.repo_url}
            )
        except subprocess.CalledProcessError as e:
            error_details = {
                "return_code": e.returncode,
                "stderr": e.stderr.decode('utf-8', errors='replace'),
                "path": path,
                "repo_url": self.repo_url
            }
            
            # Categorizar errores comunes
            if "file not found" in e.stderr.decode('utf-8', errors='replace').lower():
                raise SourceCodeError(
                    f"Archivo no encontrado en SVN: {path}",
                    provider="svn",
                    error_code="SVN_FILE_NOT_FOUND", 
                    details=error_details
                )
            elif "authentication failed" in e.stderr.decode('utf-8', errors='replace').lower():
                raise SourceCodeError(
                    "Falló la autenticación SVN al descargar archivo",
                    provider="svn",
                    error_code="SVN_AUTH_FAILED",
                    details=error_details
                )
            else:
                raise SourceCodeError(
                    f"Error descargando archivo SVN: {e.stderr.decode('utf-8', errors='replace')}",
                    provider="svn",
                    error_code="SVN_DOWNLOAD_FAILED",
                    details=error_details
                )
        except Exception as e:
            raise SourceCodeError(
                f"Error inesperado descargando archivo SVN: {str(e)}",
                provider="svn",
                error_code="SVN_UNEXPECTED_ERROR",
                details={"path": path, "repo_url": self.repo_url}
            )

    def _parse_svn_output(self, lines: List[str]) -> List[FileNode]:
        """
        Convierte la salida de 'svn list' en estructura jerárquica de FileNode.
        
        Args:
            lines: Líneas de salida del comando 'svn list --recursive'
            
        Returns:
            List[FileNode]: Estructura jerárquica de archivos y carpetas
        """
        path_map = {}
        root = FileNode("root", "", "folder")
        path_map[""] = root

        for line in lines:
            if not line.strip():
                continue
                
            # SVN list termina carpetas con '/'
            is_folder = line.endswith("/")
            clean_path = line.rstrip("/")
            
            if not clean_path:
                continue
                
            parts = clean_path.split("/")
            
            # Crear directorios padre si no existen
            for i in range(1, len(parts)):
                parent_path = "/".join(parts[:i])
                if parent_path not in path_map:
                    path_map[parent_path] = FileNode(
                        name=parts[i - 1],
                        path=parent_path,
                        type_="folder"
                    )

            # Crear nodo para el item actual
            full_path = "/".join(parts)
            node = FileNode(
                name=parts[-1],
                path=full_path,
                type_="folder" if is_folder else "file",
                download_url=f"{self.repo_url}/{full_path}" if not is_folder else None
            )
            path_map[full_path] = node

            # Conectar con padre
            parent_path = "/".join(parts[:-1])
            if parent_path in path_map:
                path_map[parent_path].children.append(node)

        return [root]


# Función de utilidad para verificar compatibilidad
def is_svn_supported() -> bool:
    """
    Verifica si SVN está soportado en el entorno actual.
    
    Returns:
        bool: True si SVN está soportado, False si estamos en Lambda
        
    Usage:
        >>> if is_svn_supported():
        >>>     manager = SubversionManager(config)
        >>> else:
        >>>     raise ConfigurationError("Use GitHub, GitLab o Azure DevOps en Lambda")
    """
    return not IS_LAMBDA


def get_alternative_providers() -> List[str]:
    """
    Retorna lista de proveedores alternativos recomendados para Lambda.
    
    Returns:
        List[str]: Lista de proveedores compatibles con Lambda
    """
    return ["github", "gitlab", "azure"]


# Log de inicialización del módulo
if IS_LAMBDA:
    logger.warning("SVN manager loaded in Lambda environment", extra={
        "limitation": "SVN will not work in Lambda",
        "alternatives": get_alternative_providers(),
        "recommendation": "Use GitHub for best Lambda performance"
    })
else:
    logger.info("SVN manager initialized", extra={
        "environment": "local",
        "svn_support": "available"
    })