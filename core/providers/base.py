from typing import Protocol
import httpx
from core.models import OSINTResult


class OSINTProvider(Protocol):
    name: str

    async def fetch(self, target: str, client: httpx.AsyncClient) -> OSINTResult: ...