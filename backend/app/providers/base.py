from abc import ABC, abstractmethod
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
