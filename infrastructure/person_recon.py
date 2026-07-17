import httpx
from typing import List
from core.providers.base import OSINTProvider
from core.models import OSINTResult, ProviderStatus, TargetType


class PersonReconProvider(OSINTProvider):
    """
    A person name is a SEED, not a lookup. Returns candidate public entities from a
    structured open source (Wikidata) that MATCH the name and REQUIRE human verification.
    It never claims the matches ARE the target person. Honest labeling is the point.
    """

    @property
    def supported_types(self) -> List[TargetType]:
        return [TargetType.PERSON]

    async def analyze(self, target_value: str, target_type: TargetType) -> OSINTResult:
        params = {
            "action": "wbsearchentities",
            "search": target_value,
            "language": "en",
            "format": "json",
            "limit": 7,
        }
        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                r = await client.get("https://www.wikidata.org/w/api.php", params=params)
                r.raise_for_status()
                hits = r.json().get("search", [])
            except httpx.HTTPError as e:
                return OSINTResult(
                    source_module="Person Recon (Wikidata)", target=target_value,
                    status=ProviderStatus.ERROR, error_message=str(e),
                )

        # Extract only the useful fields from each raw Wikidata hit.
        candidates = [
            {
                "label": h.get("label"),
                "description": h.get("description"),
                "wikidata_id": h.get("id"),
                "url": h.get("concepturi"),
            }
            for h in hits
        ]

        if not candidates:
            return OSINTResult(
                source_module="Person Recon (Wikidata)", target=target_value,
                status=ProviderStatus.NOT_FOUND,
                error_message="No matching public entities (name may not be notable/registered).",
            )

        return OSINTResult(
            source_module="Person Recon (Wikidata)", target=target_value,
            status=ProviderStatus.OK,
            raw_data={"candidate_entities_unverified": candidates},
        )