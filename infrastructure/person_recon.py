import httpx
from typing import List
from infrastructure.base import OSINTProvider
from core.models import OSINTResult, ProviderStatus, TargetType

class PersonReconProvider(OSINTProvider):
    """
    Queries open metadata indices to locate verifiable, factual 
    public records, citations, or cross-referenced document footprints.
    """
    
    @property
    def supported_types(self) -> List[TargetType]:
        return [TargetType.PERSON]
    
    async def analyze(self, target_value: str, target_type: TargetType) -> OSINTResult:
        sanitized_name = target_value.replace(" ", "+")
        url = f"https://api.crossref.org/works?query={sanitized_name}&rows=3"
        
        async with httpx.AsyncClient(timeout=8.0) as client:
            try:
                response = await client.get(url)
                response.raise_for_status()
                data = response.json()
                
                items = data.get("message", {}).get("items", [])
                public_records = []
                
                for item in items:
                    public_records.append({
                        "title": item.get("title", ["Unknown Title"])[0],
                        "publisher": item.get("publisher", "Public Record Source"),
                        "recorded_date": item.get("created", {}).get("date-time", "Unknown Date"),
                        "resource_link": item.get("URL", "No link available")
                    })
                    
                if not public_records:
                    return OSINTResult(
                        source_module="Person Recon",
                        target=target_value,
                        status=ProviderStatus.NOT_FOUND,
                        error_message="No explicit public references found in primary data indices."
                    )
                    
                return OSINTResult(
                    source_module="Person Recon",
                    target=target_value,
                    status=ProviderStatus.OK,
                    raw_data={"verifiable_public_mentions": public_records},
                    risk_score=15
                )
                
            except Exception as e:
                return OSINTResult(
                    source_module="Person Recon",
                    target=target_value,
                    status=ProviderStatus.ERROR,
                    error_message=f"Public intelligence registry query failed: {str(e)}"
                )