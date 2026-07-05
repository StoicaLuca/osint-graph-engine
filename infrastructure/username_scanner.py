import httpx
from typing import List
from infrastructure.base import OSINTProvider
from core.models import OSINTResult, ProviderStatus, TargetType

class UsernameScannerProvider(OSINTProvider):
    """
    Scans real, public web registries concurrently to discover 
    exact historical footprints of a digital handle.
    """
    
    @property
    def supported_types(self) -> List[TargetType]:
        return [TargetType.USERNAME]
    
    async def analyze(self, target_value: str, target_type: TargetType) -> OSINTResult:
        platforms = {
            "GitHub": f"https://github.com/{target_value}",
            "Reddit": f"https://www.reddit.com/user/{target_value}/about.json",
            "Linktree": f"https://linktr.ee/{target_value}",
            "DockerHub": f"https://hub.docker.com/v2/users/{target_value}/"
        }
        
        found_profiles = {}
        headers = {"User-Agent": "Mozilla/5.0 OSINT-Attribution-Engine"}
        
        async with httpx.AsyncClient(timeout=5.0, headers=headers) as client:
            for platform_name, url in platforms.items():
                try:
                    response = await client.get(url)
                    if response.status_code == 200:
                        found_profiles[platform_name] = {
                            "profile_url": url,
                            "status": "active_footprint"
                        }
                except Exception:
                    continue
                    
        if not found_profiles:
            return OSINTResult(
                source_module="Username Scanner",
                target=target_value,
                status=ProviderStatus.NOT_FOUND,
                error_message="No public data profiles located across core target platforms."
            )
            
        return OSINTResult(
            source_module="Username Scanner",
            target=target_value,
            status=ProviderStatus.OK,
            raw_data={"discovered_public_records": found_profiles},
            risk_score=25 if len(found_profiles) > 2 else 10
        )