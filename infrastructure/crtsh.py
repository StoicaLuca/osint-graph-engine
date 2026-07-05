import httpx
from typing import List
from infrastructure.base import OSINTProvider
from core.models import OSINTResult, ProviderStatus, TargetType

class CrtShProvider(OSINTProvider):
    """Queries crt.sh exclusively for domain targets."""
    
    @property
    def supported_types(self) -> List[TargetType]:
        # This provider ONLY accepts domains. The router will enforce this.
        return [TargetType.DOMAIN]
    
    async def analyze(self, target_value: str, target_type: TargetType) -> OSINTResult:
        url = f"https://crt.sh/?q=%.{target_value}&output=json"
        
        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                response = await client.get(url)
                response.raise_for_status()
                data = response.json()
                
                return OSINTResult(
                    source_module="crt.sh",
                    target=target_value,
                    status=ProviderStatus.OK,
                    raw_data={"certificates": data[:50]},
                    risk_score=10
                )
            except httpx.ReadTimeout:
                return OSINTResult(
                    source_module="crt.sh", target=target_value,
                    status=ProviderStatus.TIMEOUT, error_message="crt.sh timed out"
                )
            except Exception as e:
                return OSINTResult(
                    source_module="crt.sh", target=target_value,
                    status=ProviderStatus.ERROR, error_message=str(e)
                )