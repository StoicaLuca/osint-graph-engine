import re
import httpx
from typing import List
from core.providers.base import OSINTProvider
from core.models import OSINTResult, ProviderStatus, TargetType


# Strips HTML tags (DBpedia wraps matched terms in <B>...</B>).
_TAG_RE = re.compile(r"<[^>]+>")


def _clean(text):
    if not isinstance(text, str):
        return text
    return _TAG_RE.sub("", text).strip()


class PersonReconProvider(OSINTProvider):
    """
    A person name is a SEED, not a lookup. Returns candidate public entities from a
    structured open source (DBpedia) that MATCH the name and REQUIRE human verification.
    It never claims the matches ARE the target person. Honest labeling is the point.
    """

    @property
    def supported_types(self) -> List[TargetType]:
        return [TargetType.PERSON]

    async def analyze(self, target_value: str, target_type: TargetType) -> OSINTResult:
        url = "https://lookup.dbpedia.org/api/search"
        params = {"query": target_value, "maxResults": 7, "format": "json"}
        headers = {
            "Accept": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        }

        async with httpx.AsyncClient(timeout=10.0, headers=headers) as client:
            try:
                r = await client.get(url, params=params)
                r.raise_for_status()
                hits = r.json().get("docs", [])
            except httpx.HTTPError as e:
                return OSINTResult(
                    source_module="Person Recon (DBpedia)", target=target_value,
                    status=ProviderStatus.ERROR, error_message=str(e),
                )

        def _first(field):
            # DBpedia returns each field as a list; take the first value or None.
            if isinstance(field, list):
                return field[0] if field else None
            return field

        candidates = [
            {
                "label": _clean(_first(h.get("label"))),
                "description": _clean(_first(h.get("comment"))),
                "url": _first(h.get("resource")),
            }
            for h in hits
        ]

        if not candidates:
            return OSINTResult(
                source_module="Person Recon (DBpedia)", target=target_value,
                status=ProviderStatus.NOT_FOUND,
                error_message="No matching public entities (name may not be notable/registered).",
            )

        return OSINTResult(
            source_module="Person Recon (DBpedia)", target=target_value,
            status=ProviderStatus.OK,
            raw_data={"candidate_entities_unverified": candidates},
        )