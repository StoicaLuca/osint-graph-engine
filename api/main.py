import asyncio
from uuid import uuid4
from typing import Dict, Any
from contextlib import asynccontextmanager

from fastapi import FastAPI, BackgroundTasks, HTTPException

from core.models import InvestigationTarget, ProviderStatus
# 1. Import our database manager
from core.database import db 

from infrastructure.crtsh import CrtShProvider
from infrastructure.ipwhois import IPWhoisProvider
from infrastructure.email_gravatar import GravatarProvider
from infrastructure.username_scanner import UsernameScannerProvider
from infrastructure.person_recon import PersonReconProvider

# 2. Define the Application Lifespan
@asynccontextmanager
async def lifespan(app: FastAPI):
    # --- STARTUP LOGIC ---
    print("Starting OSINT Engine...")
    await db.connect()  # Initialize the database connection pool
    
    yield  # This tells FastAPI: "The setup is done, start accepting HTTP requests now."
    
    # --- SHUTDOWN LOGIC ---
    print("Shutting down OSINT Engine...")
    await db.close()  # Cleanly close all database connections


# 3. Pass the lifespan to the FastAPI initialization
app = FastAPI(
    title="OSINT Attribution Engine", 
    version="0.4.0",
    lifespan=lifespan
)

PROVIDERS = [
    CrtShProvider(),
    IPWhoisProvider(),
    GravatarProvider(),
    UsernameScannerProvider(),
    PersonReconProvider()
]

JOBS: Dict[str, Dict[str, Any]] = {}

async def run_investigation(job_id: str, target: InvestigationTarget):
    JOBS[job_id]["status"] = "processing"
    
    pending_tasks = []

    for provider in PROVIDERS:
        if target.target_type in provider.supported_types:
            task = provider.analyze(target.value, target.target_type)
            pending_tasks.append(task)

    raw_results = await asyncio.gather(*pending_tasks, return_exceptions=True)

    clean_results = []
    for res in raw_results:
        if isinstance(res, Exception):
            clean_results.append({
                "source_module": "System Architecture",
                "status": ProviderStatus.ERROR,
                "error_message": f"Critical task failure: {str(res)}"
            })
        else:
            clean_results.append(res.model_dump())

    JOBS[job_id]["status"] = "completed"
    JOBS[job_id]["results"] = clean_results


@app.post("/api/v1/investigate", tags=["Investigation"])
async def start_investigation(target: InvestigationTarget, bg_tasks: BackgroundTasks):
    job_id = str(uuid4())
    JOBS[job_id] = {
        "status": "pending",
        "target": target.value,
        "detected_type": target.target_type, 
        "results": []
    }
    
    bg_tasks.add_task(run_investigation, job_id, target)
    
    return {
        "job_id": job_id, 
        "detected_type": target.target_type, 
        "status": "pending"
    }


@app.get("/api/v1/investigate/{job_id}", tags=["Investigation"])
async def get_job_status(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job