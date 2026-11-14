from abc import ABC, abstractmethod
import os
import shutil
import platform
import subprocess
import re
import shlex
from typing import AsyncGenerator, Dict, Any, List, Optional

class BaseProvider(ABC):
    """
    Abstract Base Class for ReconForge discovery plugins.
    Each plugin must implement this class to be loaded by the platform.
    """
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Return the unique name of the provider plugin."""
        pass
        
    @property
    @abstractmethod
    def description(self) -> str:
        """Return a user-friendly description of the provider's discovery technique."""
        pass

    @abstractmethod
    async def discover(self, seed_domains: List[str]) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Discover assets associated with seed domains.
        Yields dictionaries representing discovered assets or logs.
        Format of yielded dicts:
        {
            "type": "log" | "asset",
            "message": str (if type is log),
            "data": dict (if type is asset, representing the Asset schema)
        }
        """
        pass

    @staticmethod
    def wsl_path_convert(path: str) -> str:
        if platform.system().lower() != "windows":
            return path
        drive, rest = os.path.splitdrive(os.path.abspath(path))
        drive_letter = drive.rstrip(":").lower()
        rest = rest.replace("\\", "/")
        return f"/mnt/{drive_letter}{rest}"

    @classmethod
    def detect_tool(cls, tool_name: str, force_refresh: bool = False) -> Optional[str]:
        """
        Dynamically resolves the absolute path to an executable in WSL or host.
        Validates tool_name against the tool registry and ^[a-z0-9_-]+$ before execution.
        Caches resolved absolute paths and NEVER returns bare names with wsl -e.
        Returns the absolute path (e.g. '/usr/bin/ffuf') if available, or None if missing.
        """
        if not isinstance(tool_name, str) or not re.match(r"^[a-z0-9_-]+$", tool_name):
            raise ValueError(f"Invalid tool name: '{tool_name}'. Must match ^[a-z0-9_-]+$")

        from app.core.tools import RECON_TOOLS, resolve_tool_absolute_path
        if tool_name not in RECON_TOOLS:
            raise ValueError(f"Tool '{tool_name}' is not registered in the tool registry")

        return resolve_tool_absolute_path(tool_name, force_refresh=force_refresh)

    @staticmethod
    def format_cmd_log(cmd: List[str]) -> str:
        """Formats and redacts a command list for safe execution logging."""
        from app.core.redaction import redact_cmd_args
        redacted = redact_cmd_args(cmd)
        return f"[*] Executing command: {' '.join(redacted)}"

