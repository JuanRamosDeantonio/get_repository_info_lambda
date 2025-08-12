"""
Ejecución local del servicio de gestión de repositorios
=======================================================

Este script permite probar de forma local las operaciones principales del servicio:
- Obtener la estructura de un repositorio (GET_STRUCTURE)
- Descargar archivos individuales (DOWNLOAD_FILE)

Simula la ejecución de AWS Lambda, pero usando output en consola
para facilitar el desarrollo, debugging y validación.

Uso:
-----
Desde archivo de evento:
    python main.py tests/events/github_event.json

Desde argumentos CLI:
    python main.py --operation GET_STRUCTURE --provider github --config '{"token": "...", "owner": "...", "repo": "..."}'

Autor: Equipo de Ingeniería
Versión: 2.0.0
"""

import sys
from typing import Any
import os, subprocess

from app.core.logger import (
    get_logger,
    set_request_context,
    clear_request_context
)
from app.utils.request_parser import parse_local_event
from app.handlers.structure_handler import handle_get_structure_local
from app.handlers.download_handler import handle_download_file_local

# Logger central
logger = get_logger(__name__)

def main() -> None:
    """
    Función principal de ejecución local.

    Carga un evento desde archivo o argumentos CLI, configura el entorno local
    e invoca el handler correspondiente según la operación deseada.
    """
    try:
 
        # Añadir /opt/bin al PATH para que git esté disponible
        os.environ["PATH"] = "/opt/bin:" + os.environ.get("PATH", "")

        # Ahora esto funciona porque buscará en /opt/bin/git
        version = subprocess.check_output(["git", "--version"]).decode().strip()
        print("Versión de git:", version)

        # Contexto artificial para simular entorno Lambda
        set_request_context(environment="local", source="main")
        logger.info("🧪 Inicio de prueba local")

        # Obtener archivo de evento si existe
        event_file = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('--') else None
        
        print("EVENTFILE********************************")
        print(event_file)
        print("EVENTFILE********************************")
        
        # Parsear evento (desde archivo o línea de comandos)
        operation, manager, provider, path, iswiki = parse_local_event(event_file)

        print("E1********************************")
        print(path)
        print("E1********************************")

        # Enrutamiento local según operación
        if operation == "GET_STRUCTURE":
            handle_get_structure_local(manager, provider)

        elif operation == "DOWNLOAD_FILE":
            handle_download_file_local(manager, path, provider,iswiki)

        else:
            print(f"❌ Operación no reconocida: {operation}")
            sys.exit(1)

    except KeyboardInterrupt:
        print("\n⏹️ Ejecución interrumpida por el usuario")
        sys.exit(0)

    except Exception as e:
        logger.exception("🛑 Fallo durante ejecución local")
        print(f"\n❌ Error inesperado: {str(e)}")
        print(f"🔧 Tipo: {type(e).__name__}")
        sys.exit(1)

    finally:
        clear_request_context()
        logger.info("✅ Prueba local finalizada correctamente")

# Entry point
if __name__ == "__main__":
    main()
