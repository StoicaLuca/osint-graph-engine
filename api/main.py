from fastapi import FastAPI
from core.models import TargetDomain

# 1. Initialize the FastAPI application
app = FastAPI(
    title="OSINT Graph Engine",
    description="Advanced Distributed Digital Investigation API",
    version="0.1.0",
)

# 2. Define a health check endpoint
@app.get("/health", tags=["System"])
async def health_check():
    """
    Health check endpoint to verify service status.
    """
    return {
        "status": "online",
        "message": "OSINT Engine is operational and ready to accept requests."
    }

# 3. Define the main investigation endpoint
@app.post("/api/v1/investigate", tags=["Investigation"])
async def start_investigation(target: TargetDomain):
    """
    Submit a new domain for OSINT investigation.
    The input is strictly validated by the TargetDomain Pydantic model.
    """
    # Here we will later trigger the async workers and Neo4j database
    return {
        "message": "Investigation started successfully.",
        "target_received": target.domain_name,
        "timestamp": target.submitted_at
    }