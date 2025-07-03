import requests
from typing import List
from datetime import datetime

import urllib
from app.interfaces.source_code_interface import ISourceCodeManager
from app.models.file_node import FileNode
from app.core.exceptions import SourceCodeError
from app.core.logger import get_logger, log_api_call

logger = get_logger(__name__)

class GitHubManager(ISourceCodeManager):
    """
    Gestor de repositorios GitHub que permite obtener la estructura y contenido de archivos.
    """

    def __init__(self, config: dict):
        self.token = config["token"]
        self.owner = config["owner"]
        self.repo = config["repo"]
        self.branch = config.get("branch", "main")

        self.api_base = f"https://api.github.com/repos/{self.owner}/{self.repo}"
        self.raw_base = f"https://raw.githubusercontent.com/{self.owner}/{self.repo}/{self.branch}"

        self.headers = {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github.v3+json"
        }



    def list_files(self) -> List[FileNode]:
        """
        Obtiene la estructura del repositorio GitHub desde el árbol de la rama configurada.
        Manejo detallado de errores comunes: token inválido, permisos, rate limits, rama inexistente.
        """
        try:
            log_api_call("github", "list_files", branch=self.branch)

            # Paso 1: Obtener SHA de la rama
            ref_url = f"{self.api_base}/git/refs/heads/{self.branch}"
            ref_response = requests.get(ref_url, headers=self.headers)

            # Validaciones comunes
            if ref_response.status_code == 401:
                raise SourceCodeError("🔐 Token inválido o expirado. Verifica tu token de acceso.", provider="github")

            if ref_response.status_code == 403:
                if ref_response.headers.get("X-RateLimit-Remaining") == "0":
                    reset_ts = ref_response.headers.get("X-RateLimit-Reset")
                    reset_human = datetime.utcfromtimestamp(int(reset_ts)).isoformat() if reset_ts else "desconocido"
                    raise SourceCodeError(
                        f"⏳ Has alcanzado el límite de peticiones de GitHub. Puedes reintentar después de: {reset_human} UTC.",
                        provider="github"
                    )
                raise SourceCodeError("🚫 Permiso denegado. El token no tiene permisos suficientes.", provider="github")

            if ref_response.status_code == 404:
                raise SourceCodeError(f"📦 La rama '{self.branch}' no fue encontrada en el repositorio.", provider="github")

            ref_response.raise_for_status()
            sha = ref_response.json()["object"]["sha"]

            # Paso 2: Obtener árbol de archivos
            tree_url = f"{self.api_base}/git/trees/{sha}?recursive=1"
            tree_response = requests.get(tree_url, headers=self.headers)

            if tree_response.status_code == 403:
                if tree_response.headers.get("X-RateLimit-Remaining") == "0":
                    reset_ts = tree_response.headers.get("X-RateLimit-Reset")
                    reset_human = datetime.utcfromtimestamp(int(reset_ts)).isoformat() if reset_ts else "desconocido"
                    raise SourceCodeError(
                        f"⏳ Límite de peticiones excedido. Intenta nuevamente después de: {reset_human} UTC.",
                        provider="github"
                    )
                raise SourceCodeError("🚫 Acceso denegado al árbol de archivos.", provider="github")

            tree_response.raise_for_status()
            tree = tree_response.json().get("tree", [])

            return self._build_file_tree(tree)

        except requests.HTTPError as http_err:
            raise SourceCodeError(f"❗ Error HTTP inesperado: {http_err}", provider="github") from http_err

        except Exception as e:
            raise SourceCodeError(f"❗ Error inesperado: {e}", provider="github") from e

    def _build_file_tree(self, tree: List[dict]) -> List[FileNode]:
        """
        Construye la jerarquía de FileNodes a partir de la lista plana del árbol GitHub.
        """
        path_map = {}
        root = FileNode(name=self.repo, path="", type="folder")
        path_map[""] = root

        for item in tree:
            item_path = item["path"]
            parts = item_path.split("/")

            for i in range(1, len(parts)):
                parent_path = "/".join(parts[:i])
                if parent_path not in path_map:
                    path_map[parent_path] = FileNode(
                        name=parts[i - 1],
                        path=parent_path,
                        type="folder"
                    )

            node_type = "file" if item["type"] == "blob" else "folder"
            node = FileNode(
                name=parts[-1],
                path=item_path,
                type=node_type,
                download_url=f"{self.raw_base}/{item_path}" if node_type == "file" else None
            )

            path_map[item_path] = node

            parent_path = "/".join(parts[:-1])
            if parent_path in path_map:
                path_map[parent_path].children.append(node)

        return [root]

    def download_file(self, path: str) -> bytes:
        """
        Descarga el contenido binario de un archivo específico en la rama activa.
        Implementa fallback: raw URL -> API contents -> error detallado.
        """
        try:
            # Método 1: Intentar raw URL (más eficiente)
            encoded_path = urllib.parse.quote(path, safe='/')  # No codificar las barras
            raw_url = f"{self.raw_base}/{encoded_path}"
            
            print(f"🔄 Intentando raw URL: {raw_url}")
            
            response = requests.get(raw_url, headers=self.headers)
            
            # Verificar si es realmente el archivo binario
            if response.status_code == 200:
                content_type = response.headers.get('content-type', '').lower()
                
                # Si GitHub devuelve HTML (error), usar API
                if 'text/html' in content_type:
                    print(f"⚠️ Raw URL devolvió HTML, usando GitHub API")
                    return self._download_via_api(path)
                
                print(f"✅ Raw URL exitosa. Content-Type: {content_type}, Size: {len(response.content)} bytes")
                return response.content
            
            # Si raw URL falla, usar API
            elif response.status_code == 404:
                print(f"⚠️ Raw URL no encontrada (404), intentando GitHub API")
                return self._download_via_api(path)
            
            else:
                response.raise_for_status()
                
        except Exception as e:
            print(f"❌ Error con raw URL: {str(e)}")
            # Fallback a API
            return self._download_via_api(path)

    def _download_via_api(self, path: str) -> bytes:
        """
        Descarga archivo usando GitHub Contents API (devuelve base64).
        """
        try:
            # GitHub Contents API
            api_url = f"{self.api_base}/contents/{path}"
            params = {'ref': self.branch}
            
            print(f"🔄 Usando GitHub API: {api_url}")
            
            log_api_call("github", "download_file_api", path=path)
            
            response = requests.get(api_url, headers=self.headers, params=params)
            
            if response.status_code == 404:
                raise SourceCodeError(f"📁 Archivo no encontrado: {path}", provider="github")
            
            response.raise_for_status()
            
            file_data = response.json()
            
            # Verificar que es un archivo (no directorio)
            if file_data.get('type') != 'file':
                raise SourceCodeError(f"📂 La ruta especificada es un directorio, no un archivo: {path}", provider="github")
            
            # El contenido viene en base64
            import base64
            content_b64 = file_data.get('content', '')
            
            if not content_b64:
                raise SourceCodeError(f"📄 El archivo está vacío: {path}", provider="github")
            
            # Decodificar de base64
            binary_content = base64.b64decode(content_b64)
            
            print(f"✅ API exitosa. Size: {len(binary_content)} bytes")
            return binary_content
            
        except requests.HTTPError as http_err:
            if http_err.response.status_code == 403:
                raise SourceCodeError("🚫 Sin permisos para acceder al archivo o límite de API excedido", provider="github")
            raise SourceCodeError(f"❌ Error HTTP descargando archivo: {str(http_err)}", provider="github")
        
        except Exception as e:
            raise SourceCodeError(f"❌ Error inesperado descargando archivo: {str(e)}", provider="github")