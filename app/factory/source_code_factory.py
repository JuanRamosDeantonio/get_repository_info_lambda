from app.interfaces.source_code_interface import ISourceCodeManager
from app.managers.github_manager import GitHubManager
from app.managers.gitlab_manager import GitLabManager
from app.managers.azure_manager import AzureDevOpsManager
from app.managers.svn_manager import SubversionManager

class SourceCodeManagerFactory:
    @staticmethod
    def create(provider: str, config: dict) -> ISourceCodeManager:
        provider = provider.lower()
        if provider == "github":
            return GitHubManager(config)
        elif provider == "gitlab":
            return GitLabManager(config)
        elif provider == "azure":
            return AzureDevOpsManager(config)
        elif provider == "svn":
            return SubversionManager(config)
        else:
            raise ValueError(f"Proveedor no soportado: {provider}")