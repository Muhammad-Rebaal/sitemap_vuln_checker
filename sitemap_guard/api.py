from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import asyncio
from typing import Dict, Any
import uuid
import json

from sitemap_guard.pipeline import BugBountyPipeline

app = FastAPI(title="SiteMap Guard v4 API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Simple in-memory task store for MVP
tasks_store: Dict[str, Dict[str, Any]] = {}

class ScanRequest(BaseModel):
    url: str

@app.post("/scan")
async def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    task_id = str(uuid.uuid4())
    tasks_store[task_id] = {"status": "running", "target": req.url, "results": None}
    
    async def run_scan_task(tid: str, target: str):
        pipeline = BugBountyPipeline(target)
        try:
            results = await pipeline.run()
            # Ensure serialization of datetimes/paths
            safe_results = json.loads(json.dumps(results, default=str))
            tasks_store[tid]["status"] = "completed"
            tasks_store[tid]["results"] = safe_results
        except Exception as e:
            tasks_store[tid]["status"] = "failed"
            tasks_store[tid]["error"] = str(e)
            
    background_tasks.add_task(run_scan_task, task_id, req.url)
    return {"task_id": task_id, "status": "started"}

@app.get("/status/{task_id}")
async def get_status(task_id: str):
    if task_id not in tasks_store:
        return {"error": "Task not found"}
    return tasks_store[task_id]
