from abc import ABC, abstractmethod
from core.models import OSINTResult

class OSINTProvider(ABC):
    """
    Abstract Base Class for all OSINT modules.
    This acts as a strict contract: any new detective we hire (Shodan, DNS, etc.)
    MUST implement the 'analyze' method and return an OSINTResult.
    """
    
    @abstractmethod
    async def analyze(self, target_domain: str) -> OSINTResult:
        """
        Executes the specific OSINT investigation.
        """
        pass