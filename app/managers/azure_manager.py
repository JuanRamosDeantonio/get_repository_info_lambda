import requests
from requests.auth import HTTPBasicAuth
from typing import List

from app.interfaces.source_code_interface import ISourceCodeManager
from app.models.file_node import FileNode

class AzureDevOpsManager(ISourceCodeManager):
    def __init__(self, config: dict):
        self.organization = config["organization"]
        self.project = config["project"]
        self.repository = config["repository"]
        self.branch = config.get("branch", "refs/heads/main")
        self.token = config["token"]
        self.api_base = f"https://dev.azure.com/{self.organization}/{self.project}/_apis/git/repositories/{self.repository}"
        self.auth = HTTPBasicAuth("", self.token)
        self.api_version = "7.1-preview.1"

    def list_files(self) -> List[FileNode]:
        url = f"{self.api_base}/items"
        params = {
            "recursionLevel": "Full",
            "scopePath": "/",
            "includeContentMetadata": "true",
            "api-version": self.api_version
        }
        response = requests.get(url, auth=self.auth, params=params)
        response.raise_for_status()
        items = response.json().get("value", [])

        path_map = {}
        root = FileNode(name=self.repository, path="", type_="folder")
        path_map[""] = root

        for item in items:
            item_path = item["path"].lstrip("/")
            parts = item_path.split("/")
            for i in range(1, len(parts)):
                parent_path = "/".join(parts[:i])
                if parent_path not in path_map:
                    path_map[parent_path] = FileNode(parts[i - 1], parent_path, "folder")

            node = FileNode(
                name=parts[-1],
                path=item_path,
                type_="file" if item["gitObjectType"] == "blob" else "folder",
                download_url=item.get("url")
            )
            path_map[item_path] = node

            parent_path = "/".join(parts[:-1])
            if parent_path in path_map:
                path_map[parent_path].children.append(node)

        return [root]

    def download_file(self, path: str) -> bytes:
        url = f"{self.api_base}/items"
        params = {
            "path": f"/{path}",
            "api-version": self.api_version,
            "includeContent": "true"
        }
        headers = {"Accept": "application/octet-stream"}
        response = requests.get(url, auth=self.auth, headers=headers, params=params)
        response.raise_for_status()
        return response.content