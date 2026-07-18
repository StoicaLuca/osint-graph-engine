import asyncio
from uuid import uuid4
from typing import Dict, Any
from contextlib import asynccontextmanager

from fastapi import FastAPI, BackgroundTasks, HTTPException

from core.models import InvestigationTarget, ProviderStatus, TargetType
from core.database import db

from infrastructure.crtsh import CrtShProvider
from infrastructure.ipwhois import IPWhoisProvider
from infrastructure.email_gravatar import GravatarProvider
from infrastructure.username_scanner import UsernameScannerProvider
from infrastructure.person_recon import PersonReconProvider
from core.ingestion import ingest_result
from infrastructure.certspotter import CertSpotterProvider
from infrastructure.hackertarget import HackerTargetProvider


# --- Application lifespan: run once at startup and once at shutdown ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Starting OSINT Engine...")
    await db.connect()
    try:
        await db.init_schema()
    except Exception as e:
        # The app still boots without the database; graph features just stay inert.
        print(f"WARNING: Neo4j unreachable, graph features disabled ({e})")
    yield
    print("Shutting down OSINT Engine...")
    await db.close()

app = FastAPI(
    title="OSINT Attribution Engine",
    version="0.4.0",
    lifespan=lifespan,
)

# The universal roster: every provider the router can dispatch to.
PROVIDERS = [
    CrtShProvider(),
    CertSpotterProvider(),
    HackerTargetProvider(),
    IPWhoisProvider(),
    GravatarProvider(),
    UsernameScannerProvider(),
    PersonReconProvider(),
]

# In-memory job store (results live here until the request cycle ends).
JOBS: Dict[str, Dict[str, Any]] = {}


async def run_investigation(job_id: str, target: InvestigationTarget):
    """Background worker: runs every matching provider concurrently."""
    JOBS[job_id]["status"] = "processing"

    pending_tasks = []
    for provider in PROVIDERS:
        if target.target_type in provider.supported_types:
            task = provider.analyze(target.value, target.target_type)
            pending_tasks.append(task)

    raw_results = await asyncio.gather(*pending_tasks, return_exceptions=True)

    clean_results = []
    for res in raw_results:
        # Safety net: a provider crash returns an Exception object, not an OSINTResult.
        if isinstance(res, Exception):
            clean_results.append({
                "source_module": "System Architecture",
                "status": ProviderStatus.ERROR,
                "error_message": f"Critical task failure: {str(res)}",
            })
        else:
            result_dict = res.model_dump()
            clean_results.append(result_dict)
            try:
                await ingest_result(target.value, result_dict)
            except Exception as e:
                # A database failure must not destroy the investigation results.
                print(f"WARNING: graph ingestion failed ({e})")

    JOBS[job_id]["status"] = "completed"
    JOBS[job_id]["results"] = clean_results


@app.post("/api/v1/investigate", tags=["Investigation"])
async def start_investigation(target: InvestigationTarget, bg_tasks: BackgroundTasks):
    # Reject anything we couldn't classify, instead of running an empty investigation.
    if target.target_type == TargetType.UNKNOWN:
        raise HTTPException(
            status_code=422,
            detail=f"Cannot classify '{target.value}' as a domain, IP, email, username or person.",
        )

    job_id = str(uuid4())
    JOBS[job_id] = {
        "status": "pending",
        "target": target.value,
        "detected_type": target.target_type,
        "results": [],
    }

    bg_tasks.add_task(run_investigation, job_id, target)

    return {
        "job_id": job_id,
        "detected_type": target.target_type,
        "status": "pending",
    }


@app.get("/api/v1/investigate/{job_id}", tags=["Investigation"])
async def get_job_status(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job