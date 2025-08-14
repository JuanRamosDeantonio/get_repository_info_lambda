import requests
from typing import List, Optional
from datetime import datetime
import base64
import time
from urllib.parse import unquote
import platform
import concurrent.futures
import threading

import urllib
from app.interfaces.source_code_interface import ISourceCodeManager
from app.models.file_node import FileNode
from app.core.exceptions import SourceCodeError
from app.core.logger import get_logger, log_api_call
from app.managers.wiki_reader import (
    MemoryOnlyWikiReader,
    quick_get_wiki_structure_memory,
    quick_get_file_content_memory,
    test_memory_usage
)
from app.core.constants import is_image_file

logger = get_logger(__name__)

class GitHubManager(ISourceCodeManager):
    """
    Gestor de repositorios GitHub que permite obtener la estructura y contenido de archivos,
    así como acceso a la documentación wiki asociada.
    VERSIÓN SÍNCRONA corregida para compatibilidad con handlers síncronos.
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
        self.platform = platform.system()
        # Inicializar reader si está disponible
        try:
            self.reader = MemoryOnlyWikiReader()
        except:
            self.reader = None
    
    def _get_pages_content(self, owner, repo, md_files, preview_length):
        """Obtiene contenido de páginas usando el reader único"""
        pages_details = []
        
        print(f"🔗 Usando WikiReader Híbrido en {self.platform}...")
        
        for file_info in md_files:
            page_detail = {
                'name': self.format_page_name(file_info['name']),
                'filename': file_info['name'],
                'path': file_info['path'],
                'size_bytes': file_info['size_estimated'],
                'size_human': self.format_file_size(file_info['size_estimated']),
                'download_url': file_info['raw_url']
            }
            
            # Obtener contenido usando nuestro reader único si está disponible
            if self.reader:
                try:
                    content_result = self.reader.get_file_content(owner, repo, file_info['path'])
                    
                    if content_result.success:
                        content = content_result.data.content
                        page_detail.update({
                            'content_preview': content[:preview_length] + '...' if len(content) > preview_length else content,
                            'content_length': len(content),
                            'has_content': True,
                            'content_lines': content.count('\n') + 1,
                            'fetch_time': content_result.execution_time,
                            'method': content_result.method_used
                        })
                    else:
                        page_detail.update({
                            'content_preview': None,
                            'has_content': False,
                            'error': content_result.error
                        })
                except Exception as e:
                    page_detail.update({
                        'content_preview': None,
                        'has_content': False,
                        'error': str(e)
                    })
            else:
                # Sin reader, solo metadatos
                page_detail.update({
                    'content_preview': None,
                    'has_content': False,
                    'error': 'WikiReader no disponible'
                })
            
            pages_details.append(page_detail)
        
        # Reporte final si el reader está disponible
        if self.reader:
            try:
                resource_report = self.reader.get_resource_usage_report()
                if 'disk_note' in resource_report:
                    print(f"💾 Recursos usados: {resource_report['memory_peak_mb']:.1f}MB RAM")
                    print(f"📁 Disco: {resource_report['disk_used_mb']:.1f}MB ({resource_report['disk_note']})")
                else:
                    print(f"💾 Recursos usados: {resource_report['memory_peak_mb']:.1f}MB RAM, {resource_report['disk_used_mb']}MB disco")
            except:
                print("💾 Recursos: información no disponible")
        
        return sorted(pages_details, key=lambda x: x.get('name', ''))

    def format_file_size(self, size_bytes):
        """Convierte bytes a formato legible"""
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        else:
            return f"{size_bytes / (1024 * 1024):.1f} MB"

    def format_page_name(self, filename):
        """Convierte filename a nombre legible de página"""
        if filename.endswith('.md'):
            name = filename[:-3]
        else:
            name = filename

        name = unquote(name)
        name = name.replace('-', ' ').replace('_', ' ')
        return name

    def _convert_to_legacy_format(self, wiki_structure, owner, repo, include_content, preview_length):
        """Convierte a formato legacy"""
        md_files = [f for f in wiki_structure.files if f['file_type'] == 'markdown']
        other_files = [f for f in wiki_structure.files if f['file_type'] != 'markdown']
        
        result = {
            'repository': wiki_structure.repository,
            'wiki_exists': True,
            'scan_timestamp': int(time.time()),
            'total_files': wiki_structure.total_files,
            'markdown_pages': wiki_structure.markdown_files,
            'other_files_count': wiki_structure.other_files,
            'structure': {
                'pages': [self.format_page_name(f['name']) for f in md_files],
                'other_files': [f['name'] for f in other_files]
            },
            'pages_details': [],
            'memory_usage_mb': wiki_structure.memory_usage_mb,
            'disk_usage_mb': 0.0,
            'files': wiki_structure.files
        }
        
        # Obtener contenido si es solicitado
        if include_content and md_files:
            print(f"📖 Obteniendo contenido de {len(md_files)} páginas (100% memoria)...")
            result['pages_details'] = self._get_pages_content(
                owner, repo, md_files, preview_length
            )
        else:
            # Solo metadatos
            result['pages_details'] = [{
                'name': self.format_page_name(f['name']),
                'filename': f['name'],
                'path': f['path'],
                'size_bytes': f['size_estimated'],
                'size_human': self.format_file_size(f['size_estimated']),
                'download_url': f['raw_url']
            } for f in md_files]
        
        return result

    def _limit_pages_if_needed(self, wiki_structure, max_pages):
        """Limita páginas si es necesario"""
        if not max_pages or not wiki_structure.files:
            return wiki_structure
        
        md_files = [f for f in wiki_structure.files if f['file_type'] == 'markdown']
        if len(md_files) <= max_pages:
            return wiki_structure
        
        # Crear estructura limitada
        try:
            from wiki_reader import WikiStructure
            limited_files = []
            limited_md_count = 0
            
            for f in wiki_structure.files:
                if f['file_type'] == 'markdown' and limited_md_count < max_pages:
                    limited_files.append(f)
                    limited_md_count += 1
                elif f['file_type'] != 'markdown':
                    limited_files.append(f)
            
            return WikiStructure(
                repository=wiki_structure.repository,
                exists=True,
                method_used=wiki_structure.method_used,
                total_files=len(limited_files),
                total_directories=wiki_structure.total_directories,
                markdown_files=limited_md_count,
                image_files=wiki_structure.image_files,
                other_files=len(limited_files) - limited_md_count - wiki_structure.image_files,
                files=limited_files,
                directory_tree=wiki_structure.directory_tree,
                scan_time=wiki_structure.scan_time,
                memory_usage_mb=wiki_structure.memory_usage_mb
            )
        except ImportError:
            # Si WikiStructure no está disponible, retornar estructura original
            return wiki_structure

    def _get_wiki_structure_simple(self, owner, repo, 
                                  include_content=False, max_pages=50, preview_length=300):
        """Versión simplificada para compatibilidad legacy"""
        print(f"🧠 Usando WikiReader Memory-Only para {owner}/{repo} en {self.platform}...")
        
        try:
            # Obtener estructura usando nuestro reader si está disponible
            if quick_get_wiki_structure_memory:
                wiki_structure = quick_get_wiki_structure_memory(owner, repo, self.token)
                
                if not wiki_structure:
                    return {
                        'repository': f"{owner}/{repo}",
                        'wiki_exists': False,
                        'message': 'Wiki no encontrada o no accesible',
                        'memory_usage_mb': 5.0,
                        'disk_usage_mb': 0.0
                    }
                
                # Limitar páginas si es necesario
                wiki_structure = self._limit_pages_if_needed(wiki_structure, max_pages)
                
                # Convertir al formato legacy
                return self._convert_to_legacy_format(
                    wiki_structure, owner, repo, include_content, preview_length
                )
            else:
                # Fallback si el wiki reader no está disponible
                return self._get_wiki_structure_fallback(owner, repo)
            
        except Exception as e:
            logger.warning(f"Error en wiki structure: {e}")
            return {
                'repository': f"{owner}/{repo}",
                'wiki_exists': False,
                'message': f'Error: {str(e)}',
                'memory_usage_mb': 5.0,
                'disk_usage_mb': 0.0
            }

    def _get_wiki_structure_fallback(self, owner, repo):
        """Fallback para obtener estructura wiki sin el reader completo"""
        try:
            wiki_files = self.list_wiki_files()
            if not wiki_files:
                return {
                    'repository': f"{owner}/{repo}",
                    'wiki_exists': False,
                    'message': 'No se encontraron archivos wiki',
                    'memory_usage_mb': 2.0,
                    'disk_usage_mb': 0.0
                }
            
            files = []
            for wiki_file in wiki_files:
                files.append({
                    'name': wiki_file,
                    'path': f"wiki/{wiki_file}",
                    'file_type': 'markdown',
                    'size_estimated': 1024,
                    'raw_url': f"https://raw.githubusercontent.com/wiki/{owner}/{repo}/{wiki_file}"
                })
            
            return {
                'repository': f"{owner}/{repo}",
                'wiki_exists': True,
                'scan_timestamp': int(time.time()),
                'total_files': len(files),
                'markdown_pages': len(files),
                'other_files_count': 0,
                'structure': {
                    'pages': [self.format_page_name(f['name']) for f in files],
                    'other_files': []
                },
                'pages_details': [{
                    'name': self.format_page_name(f['name']),
                    'filename': f['name'],
                    'path': f['path'],
                    'size_bytes': f['size_estimated'],
                    'size_human': self.format_file_size(f['size_estimated']),
                    'download_url': f['raw_url']
                } for f in files],
                'memory_usage_mb': 2.0,
                'disk_usage_mb': 0.0,
                'files': files
            }
            
        except Exception as e:
            return {
                'repository': f"{owner}/{repo}",
                'wiki_exists': False,
                'message': f'Error en fallback: {str(e)}',
                'memory_usage_mb': 2.0,
                'disk_usage_mb': 0.0
            }

    def list_files(self) -> List[FileNode]:
        """
        Obtiene la estructura del repositorio GitHub desde el árbol de la rama configurada.
        VERSIÓN SÍNCRONA - Manejo detallado de errores comunes: token inválido, permisos, rate limits, rama inexistente.
        """
        try:
            finished_list = self.process_parallel_sync()
            return finished_list
        except Exception as e:
            logger.error(f'Error durante la obtención de directorios {e}')
            raise SourceCodeError(f"Error obteniendo estructura: {str(e)}", provider="github") from e

    def process_parallel_sync(self) -> List[FileNode]:
        """
        Ejecuta ambos métodos en paralelo usando ThreadPoolExecutor.
        Versión síncrona que reemplaza process_parallel async.
        """
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                # Enviar ambas tareas al pool de threads
                future_main = executor.submit(self._structure_main_repo_sync)
                future_wiki = executor.submit(self._structure_wiki_repo_sync)
                
                # Esperar a que ambas terminen con timeout
                try:
                    result1 = future_main.result(timeout=60)  # 60 segundos timeout
                    result2 = future_wiki.result(timeout=30)  # 30 segundos para wiki
                    
                    # Combinar resultados
                    combined = self.merge_results(result1, result2)
                    print("✅ Procesamiento completado exitosamente")
                    return combined
                    
                except concurrent.futures.TimeoutError:
                    print("❌ Timeout en operaciones paralelas")
                    # Cancelar tareas pendientes
                    future_main.cancel()
                    future_wiki.cancel()
                    return []
                    
                except Exception as e:
                    print(f"❌ Error durante el procesamiento: {e}")
                    # Si el main repo falla, intentar solo ese
                    try:
                        if future_main.done() and not future_main.cancelled():
                            result1 = future_main.result()
                            print("⚠️ Usando solo estructura principal")
                            return result1
                    except:
                        pass
                    return []

        except Exception as e:
            print(f"❌ Error durante el procesamiento paralelo: {e}")
            # Fallback: intentar solo estructura principal
            try:
                return self._structure_main_repo_sync()
            except Exception as fallback_error:
                logger.error(f"Fallback también falló: {fallback_error}")
                return []

    def _structure_main_repo_sync(self) -> List[FileNode]:
        """
        Versión síncrona de structure_main_repo.
        Procesa el repositorio principal.
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
            simplified_tree = list(map(lambda t: {'path': t['path'], 'type': t['type'], 'iswiki': False},
                                       tree))

            return self._build_file_tree(simplified_tree)

        except requests.HTTPError as http_err:
            raise SourceCodeError(f"❗ Error HTTP inesperado: {http_err}", provider="github") from http_err
        except Exception as e:
            raise SourceCodeError(f"❗ Error inesperado: {e}", provider="github") from e
    
    def _structure_wiki_repo_sync(self) -> List[FileNode]:
        """
        Versión síncrona de structure_wiki_repo.
        Procesa el repositorio wiki.
        """
        try:
            # Obtener estructura wiki
            wiki_structure = self._get_wiki_structure_simple(repo=self.repo, owner=self.owner)
            
            if not wiki_structure or not wiki_structure.get('wiki_exists'):
                return []
            
            files = wiki_structure.get('files', [])
            if not files:
                return []
            
            simplified_wiki_structure = []
            for w_s in files:
                if isinstance(w_s, dict) and 'path' in w_s:
                    simplified_wiki_structure.append({
                        'path': w_s['path'], 
                        'type': 'blob',
                        'iswiki': True  # GitHub tree format
                    })

            return self._build_file_tree(simplified_wiki_structure)
            
        except Exception as e:
            logger.warning(f"Error obteniendo wiki: {e}")
            return []  # Si falla wiki, continuamos sin ella

    def merge_results(self, result1: List[FileNode], result2: List[FileNode]) -> List[FileNode]:
        """
        Une dos listas de FileNode en un resultado combinado.
        """
        if not result1:
            return result2 if result2 else []
        if not result2:
            return result1
        return result1 + result2

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

            # Crear todas las carpetas padre necesarias (excluyendo el archivo final)
            for i in range(len(parts) - 1):
                current_path = "/".join(parts[:i+1])
                if current_path not in path_map:
                    path_map[current_path] = FileNode(
                        name=parts[i],
                        path=current_path,
                        type="folder"
                    )

            # Crear el nodo del archivo/carpeta actual
            node_type = "file" if item.get("type") == "blob" else "folder"
            node = FileNode(
                name=parts[-1],
                path=item_path,
                type=node_type,
                download_url=f"{self.raw_base}/{item_path}" if node_type == "file" else None,
                iswiki=item['iswiki']
            )
            path_map[item_path] = node

        # Establecer todas las relaciones padre-hijo después de crear todos los nodos
        for path, node in path_map.items():
            if path == "":  # Skip root
                continue
            
            # Encontrar el path del padre
            path_parts = path.split("/")
            parent_path = "/".join(path_parts[:-1])

            # Agregar el nodo a su padre
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
            #if not file_path.endswith('.md'):
            #    file_path += '.md'
            
            log_api_call("github", "read_wiki_file", file_path=file_path)
            
            # Las wikis están en un repositorio separado con .wiki
            wiki_repo = f"{self.repo}"
            wiki_api_base = f"https://api.github.com/repos/{self.owner}/{wiki_repo}"
            
            # Método 1: Intentar raw URL primero (más eficiente)
            encoded_path = urllib.parse.quote(file_path, safe='/')
            raw_url = f"https://raw.githubusercontent.com/wiki/{self.owner}/{wiki_repo}/{encoded_path}"
            
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
                    name_file = file_path.split('/', -1)
                    if not is_image_file(file_path):
                        content = response.content.decode('utf-8')
                    else:
                        content = response.content
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
            wiki_api_base = f"https://api.github.com/repos/{self.owner}/{self.repo}"
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