from abc import ABC, abstractmethod
from typing import List
from core.models import OSINTResult, TargetType

class OSINTProvider(ABC):
    """
    The strict contract for all detectives.
    Each provider must declare what targets it can investigate.
    """
    
    @property
    @abstractmethod
    def supported_types(self) -> List[TargetType]:
        """Returns a list of TargetTypes this provider can handle."""
        pass

    @abstractmethod
    async def analyze(self, target_value: str, target_type: TargetType) -> OSINTResult:
        """Executes the investigation based on target type."""
        pass