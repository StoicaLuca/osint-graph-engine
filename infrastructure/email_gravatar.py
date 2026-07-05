import httpx
import hashlib
from typing import List
from infrastructure.base import OSINTProvider
from core.models import OSINTResult, ProviderStatus, TargetType

class GravatarProvider(OSINTProvider):
    """Hashes an email and checks Gravatar for linked profiles and images."""
    
    @property
    def supported_types(self) -> List[TargetType]:
        return [TargetType.EMAIL]
    
    async def analyze(self, target_value: str, target_type: TargetType) -> OSINTResult:
        # Gravatar requires an MD5 hash of the lowercase email
        email_hash = hashlib.md5(target_value.encode('utf-8')).hexdigest()
        url = f"https://en.gravatar.com/{email_hash}.json"
        
        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                # We need to simulate a browser user-agent, otherwise Gravatar might block us
                headers = {"User-Agent": "Mozilla/5.0 OSINT-Graph-Engine"}
                response = await client.get(url, headers=headers)
                
                if response.status_code == 404:
                    return OSINTResult(
                        source_module="Gravatar", target=target_value,
                        status=ProviderStatus.NOT_FOUND, error_message="No Gravatar profile found"
                    )
                    
                response.raise_for_status()
                data = response.json()
                
                return OSINTResult(
                    source_module="Gravatar", target=target_value,
                    status=ProviderStatus.OK, raw_data=data.get("entry", [])[0]
                )
            except Exception as e:
                return OSINTResult(
                    source_module="Gravatar", target=target_value,
                    status=ProviderStatus.ERROR, error_message=str(e)
                )