import httpx
from typing import List
from infrastructure.base import OSINTProvider
from core.models import OSINTResult, ProviderStatus, TargetType

class GitHubProvider(OSINTProvider):
    """Checks if a username exists on GitHub and extracts public intel."""
    
    @property
    def supported_types(self) -> List[TargetType]:
        return [TargetType.USERNAME]
    
    async def analyze(self, target_value: str, target_type: TargetType) -> OSINTResult:
        url = f"https://api.github.com/users/{target_value}"
        
        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                response = await client.get(url)
                
                if response.status_code == 404:
                    return OSINTResult(
                        source_module="GitHub", target=target_value,
                        status=ProviderStatus.NOT_FOUND, error_message="User not found on GitHub"
                    )
                
                # GitHub rate limits anonymous requests to 60/hour. We handle this cleanly.
                if response.status_code in [403, 429]:
                    return OSINTResult(
                        source_module="GitHub", target=target_value,
                        status=ProviderStatus.RATE_LIMITED, error_message="GitHub API rate limit exceeded"
                    )
                    
                response.raise_for_status()
                data = response.json()
                
                # Filter out useless data to keep our graph clean
                clean_data = {
                    "name": data.get("name"),
                    "company": data.get("company"),
                    "location": data.get("location"),
                    "email": data.get("email"),
                    "bio": data.get("bio"),
                    "twitter_username": data.get("twitter_username")
                }
                
                return OSINTResult(
                    source_module="GitHub", target=target_value,
                    status=ProviderStatus.OK, raw_data=clean_data
                )
            except Exception as e:
                return OSINTResult(
                    source_module="GitHub", target=target_value,
                    status=ProviderStatus.ERROR, error_message=str(e)
                )