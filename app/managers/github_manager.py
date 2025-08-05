import requests
from typing import List
from datetime import datetime
import base64

import urllib
from app.interfaces.source_code_interface import ISourceCodeManager
from app.models.file_node import FileNode
from app.core.exceptions import SourceCodeError
from app.core.logger import get_logger, log_api_call

logger = get_logger(__name__)

class GitHubManager(ISourceCodeManager):
    """
    Gestor de repositorios GitHub que permite obtener la estructura y contenido de archivos,
    así como acceso a la documentación wiki asociada.
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

    def read_wiki_file(self, file_path: str) -> str:
        """
        Lee el contenido de un archivo markdown de la wiki del repositorio.
        
        Args:
            file_path (str): Ruta del archivo en la wiki (ej: "Home.md", "Installation.md")
                           Se añade automáticamente .md si no está presente.
        
        Returns:
            str: Contenido del archivo markdown como string UTF-8
            
        Raises:
            SourceCodeError: Si hay errores de acceso, permisos, o archivo no encontrado
        """
        try:
            # Asegurar extensión .md
            if not file_path.endswith('.md'):
                file_path += '.md'
            
            log_api_call("github", "read_wiki_file", file_path=file_path)
            
            # Las wikis están en un repositorio separado con .wiki
            wiki_repo = f"{self.repo}.wiki"
            wiki_api_base = f"https://api.github.com/repos/{self.owner}/{wiki_repo}"
            
            # Método 1: Intentar raw URL primero (más eficiente)
            encoded_path = urllib.parse.quote(file_path, safe='/')
            raw_url = f"https://raw.githubusercontent.com/{self.owner}/{wiki_repo}/master/{encoded_path}"
            
            print(f"🔄 Intentando wiki raw URL: {raw_url}")
            
            response = requests.get(raw_url, headers=self.headers)
            
            if response.status_code == 200:
                content_type = response.headers.get('content-type', '').lower()
                
                # Verificar que no sea una página de error HTML
                if 'text/html' in content_type and '<html' in response.text.lower():
                    print(f"⚠️ Raw URL devolvió HTML de error, usando GitHub API")
                    return self._read_wiki_via_api(wiki_api_base, file_path)
                
                # Decodificar como UTF-8
                try:
                    content = response.content.decode('utf-8')
                    print(f"✅ Wiki raw URL exitosa. Size: {len(content)} caracteres")
                    return content
                except UnicodeDecodeError:
                    print(f"⚠️ Error decodificando UTF-8, usando GitHub API")
                    return self._read_wiki_via_api(wiki_api_base, file_path)
            
            elif response.status_code == 404:
                print(f"⚠️ Wiki raw URL no encontrada (404), intentando GitHub API")
                return self._read_wiki_via_api(wiki_api_base, file_path)
            
            else:
                # Para otros errores, intentar API
                print(f"⚠️ Wiki raw URL falló ({response.status_code}), usando GitHub API")
                return self._read_wiki_via_api(wiki_api_base, file_path)
                
        except Exception as e:
            print(f"❌ Error con wiki raw URL: {str(e)}")
            # Fallback a API
            return self._read_wiki_via_api(wiki_api_base, file_path)

    def _read_wiki_via_api(self, wiki_api_base: str, file_path: str) -> str:
        """
        Lee archivo de wiki usando GitHub Contents API.
        
        Args:
            wiki_api_base (str): Base URL de la API para el repositorio wiki
            file_path (str): Ruta del archivo en la wiki
            
        Returns:
            str: Contenido del archivo como string UTF-8
        """
        try:
            api_url = f"{wiki_api_base}/contents/{file_path}"
            
            print(f"🔄 Usando GitHub API para wiki: {api_url}")
            
            log_api_call("github", "read_wiki_file_api", file_path=file_path)
            
            response = requests.get(api_url, headers=self.headers)
            
            # Manejo detallado de errores comunes
            if response.status_code == 401:
                raise SourceCodeError("🔐 Token inválido o expirado para acceder a la wiki.", provider="github")
            
            if response.status_code == 403:
                if response.headers.get("X-RateLimit-Remaining") == "0":
                    reset_ts = response.headers.get("X-RateLimit-Reset")
                    reset_human = datetime.utcfromtimestamp(int(reset_ts)).isoformat() if reset_ts else "desconocido"
                    raise SourceCodeError(
                        f"⏳ Límite de peticiones de GitHub excedido. Intenta después de: {reset_human} UTC.",
                        provider="github"
                    )
                raise SourceCodeError("🚫 Sin permisos para acceder a la wiki o la wiki no existe.", provider="github")
            
            if response.status_code == 404:
                # Verificar si es el archivo o la wiki completa
                # Intentar acceder a la wiki root para distinguir errores
                wiki_root_response = requests.get(f"{wiki_api_base}/contents", headers=self.headers)
                if wiki_root_response.status_code == 404:
                    raise SourceCodeError(f"📚 La wiki no existe para el repositorio {self.owner}/{self.repo}.", provider="github")
                else:
                    raise SourceCodeError(f"📄 Archivo '{file_path}' no encontrado en la wiki.", provider="github")
            
            response.raise_for_status()
            
            file_data = response.json()
            
            # Verificar que es un archivo (no directorio)
            if file_data.get('type') != 'file':
                raise SourceCodeError(f"📂 La ruta especificada es un directorio, no un archivo: {file_path}", provider="github")
            
            # El contenido viene en base64
            content_b64 = file_data.get('content', '')
            
            if not content_b64:
                raise SourceCodeError(f"📄 El archivo de wiki está vacío: {file_path}", provider="github")
            
            # Decodificar de base64 a bytes, luego a UTF-8
            try:
                binary_content = base64.b64decode(content_b64)
                content = binary_content.decode('utf-8')
                
                print(f"✅ Wiki API exitosa. Size: {len(content)} caracteres")
                return content
                
            except UnicodeDecodeError as decode_err:
                raise SourceCodeError(
                    f"📝 Error decodificando archivo de wiki como UTF-8: {file_path}. Puede no ser un archivo de texto válido.", 
                    provider="github"
                ) from decode_err
            
        except requests.HTTPError as http_err:
            raise SourceCodeError(f"❌ Error HTTP leyendo wiki: {str(http_err)}", provider="github") from http_err
        
        except Exception as e:
            raise SourceCodeError(f"❌ Error inesperado leyendo archivo de wiki: {str(e)}", provider="github") from e

    def list_wiki_files(self) -> List[str]:
        """
        Lista todos los archivos markdown disponibles en la wiki.
        
        Returns:
            List[str]: Lista de nombres de archivos .md en la wiki
            
        Raises:
            SourceCodeError: Si hay errores de acceso o la wiki no existe
        """
        try:
            wiki_repo = f"{self.repo}.wiki"
            wiki_api_base = f"https://api.github.com/repos/{self.owner}/{wiki_repo}"
            
            log_api_call("github", "list_wiki_files")
            
            response = requests.get(f"{wiki_api_base}/contents", headers=self.headers)
            
            # Manejo de errores similar al método anterior
            if response.status_code == 401:
                raise SourceCodeError("🔐 Token inválido para acceder a la wiki.", provider="github")
            
            if response.status_code == 403:
                if response.headers.get("X-RateLimit-Remaining") == "0":
                    reset_ts = response.headers.get("X-RateLimit-Reset")
                    reset_human = datetime.utcfromtimestamp(int(reset_ts)).isoformat() if reset_ts else "desconocido"
                    raise SourceCodeError(
                        f"⏳ Límite de peticiones excedido. Intenta después de: {reset_human} UTC.",
                        provider="github"
                    )
                raise SourceCodeError("🚫 Sin permisos para acceder a la wiki.", provider="github")
            
            if response.status_code == 404:
                raise SourceCodeError(f"📚 La wiki no existe para el repositorio {self.owner}/{self.repo}.", provider="github")
            
            response.raise_for_status()
            
            files_data = response.json()
            
            # Filtrar solo archivos .md
            markdown_files = [
                file_info['name'] 
                for file_info in files_data 
                if file_info['type'] == 'file' and file_info['name'].endswith('.md')
            ]
            
            print(f"✅ Encontrados {len(markdown_files)} archivos markdown en la wiki")
            return sorted(markdown_files)  # Ordenar alfabéticamente
            
        except requests.HTTPError as http_err:
            raise SourceCodeError(f"❌ Error HTTP listando wiki: {str(http_err)}", provider="github") from http_err
        
        except Exception as e:
            raise SourceCodeError(f"❌ Error inesperado listando archivos de wiki: {str(e)}", provider="github") from e