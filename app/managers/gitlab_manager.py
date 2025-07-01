import requests
import urllib.parse
from typing import List

from app.interfaces.source_code_interface import ISourceCodeManager
from app.models.file_node import FileNode

class GitLabManager(ISourceCodeManager):
    def __init__(self, config: dict):
        self.token = config["token"]
        self.project_path = config["project_path"]
        self.branch = config.get("branch", "main")
        self.base_url = config.get("base_url", "https://gitlab.com")
        self.api_base = f"{self.base_url}/api/v4"
        self.headers = {"PRIVATE-TOKEN": self.token}
        self.project_id = self._get_project_id()

    def _get_project_id(self) -> int:
        url = f"{self.api_base}/projects/{urllib.parse.quote_plus(self.project_path)}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()["id"]

    def list_files(self) -> List[FileNode]:
        url = f"{self.api_base}/projects/{self.project_id}/repository/tree"
        params = {"ref": self.branch, "recursive": True, "per_page": 100}
        response = requests.get(url, headers=self.headers, params=params)
        response.raise_for_status()
        items = response.json()

        path_map = {}
        root = FileNode(name=self.project_path.split("/")[-1], path="", type_="folder")
        path_map[""] = root

        for item in items:
            item_path = item["path"]
            parts = item_path.split("/")
            for i in range(1, len(parts)):
                parent_path = "/".join(parts[:i])
                if parent_path not in path_map:
                    path_map[parent_path] = FileNode(parts[i - 1], parent_path, "folder")

            node_type = item["type"]
            node = FileNode(
                name=parts[-1],
                path=item_path,
                type_="file" if node_type == "blob" else "folder",
                download_url=f"{self.base_url}/{self.project_path}/-/raw/{self.branch}/{item_path}" if node_type == "blob" else None
            )
            path_map[item_path] = node

            parent_path = "/".join(parts[:-1])
            if parent_path in path_map:
                path_map[parent_path].children.append(node)

        return [root]

    def download_file(self, path: str) -> bytes:
        encoded_path = urllib.parse.quote(path, safe="")
        url = f"{self.api_base}/projects/{self.project_id}/repository/files/{encoded_path}/raw?ref={self.branch}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.content