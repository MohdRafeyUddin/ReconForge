from abc import ABC, abstractmethod
import os
import shutil
import platform
import subprocess
from typing import AsyncGenerator, Dict, Any, List

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

    @staticmethod
    def detect_tool(tool_name: str) -> str:
        is_windows = platform.system().lower() == "windows"
        wsl_user = os.getenv("WSL_USER", "kali")
        home_dir = f"/home/{wsl_user}" if is_windows else os.path.expanduser("~")
        
        candidates = [
            tool_name,
            f"{home_dir}/go/bin/{tool_name}",
            f"{home_dir}/.local/bin/{tool_name}",
            f"/usr/bin/{tool_name}",
            f"/usr/local/bin/{tool_name}",
        ]
        
        if not is_windows:
            path_which = shutil.which(tool_name)
            if path_which:
                return path_which
                
        if is_windows:
            for cand in candidates:
                try:
                    cmd = ["wsl", "which" if cand == tool_name else "test", "-f" if cand != tool_name else cand]
                    if cand != tool_name:
                        cmd.append(cand)
                    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
                    if proc.returncode == 0:
                        return cand
                except Exception:
                    pass
        else:
            for cand in candidates:
                if cand == tool_name:
                    if shutil.which(cand):
                        return cand
                else:
                    if os.path.exists(cand):
                        return cand
                        
        # Final fallback
        if tool_name == "linkfinder":
            return f"{home_dir}/tools/LinkFinder/linkfinder.py"
        elif tool_name == "openredirex":
            return f"{home_dir}/tools/OpenRedirex/openredirex.py"
        return f"{home_dir}/go/bin/{tool_name}"

