import httpx
from fastapi import FastAPI

from core.models import TargetDomain, OSINTResult
from core.providers.crtsh import CrtShProvider

app = FastAPI(title="OSINT Graph Engine", version="0.1.0")

crtsh = CrtShProvider()


@app.get("/health", tags=["System"])
async def health() -> dict:
    return {"status": "ok"}


@app.post("/api/v1/investigate", tags=["Investigation"], response_model=OSINTResult)
async def investigate(target: TargetDomain) -> OSINTResult:
    async with httpx.AsyncClient() as client:
        return await crtsh.fetcgith(target.domain_name, client)