"""
SOC Platform – Human-in-the-Loop (HITL) Gateway
بوابة الموافقة البشرية — FastAPI server + Dashboard

Endpoints:
    GET  /                              → HITL Dashboard (HTML)
    GET  /api/approvals/pending         → List pending AI actions
    GET  /api/approvals/history         → List executed/rejected actions
    GET  /api/stats                     → Quick counts
    POST /api/approvals/{id}/approve    → Approve an action
    POST /api/approvals/{id}/reject     → Reject an action (with reason)
"""

import json
import logging
import os
import time
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import uvicorn
from pydantic import BaseModel
import redis

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("soc.hitl_api")

app = FastAPI(
    title="Khandaq HITL Gateway",
    description="بوابة الموافقة البشرية لقرارات وكلاء الذكاء الاصطناعي",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve static files (dashboard)
STATIC_DIR = Path(__file__).parent / "static"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Setup Redis connection
REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))
REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD", "Ch@ngeMe_Redis_AI_2024!")
try:
    redis_client = redis.Redis(
        host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD,
        db=0, decode_responses=True,
    )
    redis_client.ping()
except Exception as e:
    logger.error(f"Failed to connect to Redis: {e}")
    redis_client = None


class ReviewRequest(BaseModel):
    feedback_reason: str = ""


# ---------------------------------------------------------------------------
# Dashboard Route / مسار الواجهة
# ---------------------------------------------------------------------------

@app.get("/", include_in_schema=False)
def serve_dashboard():
    """Serve the HITL Dashboard HTML page."""
    dashboard_path = STATIC_DIR / "hitl_dashboard.html"
    if dashboard_path.exists():
        return FileResponse(str(dashboard_path), media_type="text/html")
    raise HTTPException(status_code=404, detail="Dashboard not found.")


# ---------------------------------------------------------------------------
# Pending Actions / الإجراءات المعلّقة
# ---------------------------------------------------------------------------

@app.get("/api/approvals/pending")
def list_pending_actions():
    """Returns all actions waiting for human approval."""
    try:
        if not redis_client:
            raise HTTPException(status_code=503, detail="Redis connection unavailable.")
        pending_raw = redis_client.hgetall("soc:pending_approvals")
        pending_list = []
        for action_id, action_str in pending_raw.items():
            try:
                pending_list.append(json.loads(action_str))
            except json.JSONDecodeError:
                continue
        # Sort newest first
        pending_list.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
        return {"count": len(pending_list), "actions": pending_list}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching pending actions: {e}")
        raise HTTPException(status_code=500, detail="Database connection error.")


# ---------------------------------------------------------------------------
# History / سجل القرارات السابقة
# ---------------------------------------------------------------------------

@app.get("/api/approvals/history")
def list_history():
    """Returns all executed and rejected actions."""
    try:
        if not redis_client:
            raise HTTPException(status_code=503, detail="Redis connection unavailable.")

        actions = []

        # Executed (approved) actions
        executed_raw = redis_client.hgetall("soc:executed_actions") or {}
        for action_id, action_str in executed_raw.items():
            try:
                action = json.loads(action_str)
                action["status"] = action.get("status", "APPROVED")
                actions.append(action)
            except json.JSONDecodeError:
                continue

        # Rejected actions
        rejected_raw = redis_client.hgetall("soc:rejected_actions") or {}
        for action_id, action_str in rejected_raw.items():
            try:
                action = json.loads(action_str)
                actions.append(action)
            except json.JSONDecodeError:
                continue

        # Sort newest first
        actions.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
        return {"count": len(actions), "actions": actions}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching history: {e}")
        raise HTTPException(status_code=500, detail="Internal error.")


# ---------------------------------------------------------------------------
# Stats / الإحصائيات
# ---------------------------------------------------------------------------

@app.get("/api/stats")
def get_stats():
    """Quick stats for the dashboard header."""
    try:
        if not redis_client:
            return {"pending": 0, "approved": 0, "rejected": 0, "total": 0}

        pending = redis_client.hlen("soc:pending_approvals") or 0
        approved = redis_client.hlen("soc:executed_actions") or 0
        rejected = redis_client.hlen("soc:rejected_actions") or 0
        total = pending + approved + rejected

        return {
            "pending": pending,
            "approved": approved,
            "rejected": rejected,
            "total": total,
        }
    except Exception as e:
        logger.error(f"Error fetching stats: {e}")
        return {"pending": 0, "approved": 0, "rejected": 0, "total": 0}


# ---------------------------------------------------------------------------
# Approve / الموافقة
# ---------------------------------------------------------------------------

@app.post("/api/approvals/{action_id}/approve")
def approve_action(action_id: str, request: ReviewRequest = None):
    """Approves an action, triggering execution."""
    try:
        if not redis_client:
            raise HTTPException(status_code=503, detail="Redis connection unavailable.")
        action_str = redis_client.hget("soc:pending_approvals", action_id)
        if not action_str:
            raise HTTPException(status_code=404, detail="Action not found or already processed.")

        action = json.loads(action_str)
        action["status"] = "APPROVED"
        action["reviewed_at"] = time.time()
        if request and request.feedback_reason:
            action["human_feedback"] = request.feedback_reason

        # Publish to execution trigger channel
        redis_client.publish("soc:execute-action", json.dumps({"payload": action}))

        # Move from pending to executed
        redis_client.hdel("soc:pending_approvals", action_id)
        redis_client.hset("soc:executed_actions", action_id, json.dumps(action))

        logger.info(f"[HITL] Action {action_id} APPROVED by human analyst.")
        return {"message": "تمت الموافقة وإرسال الأمر للتنفيذ.", "action_id": action_id}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error approving action: {e}")
        raise HTTPException(status_code=500, detail="Internal error.")


# ---------------------------------------------------------------------------
# Reject / الرفض
# ---------------------------------------------------------------------------

@app.post("/api/approvals/{action_id}/reject")
def reject_action(action_id: str, request: ReviewRequest):
    """Rejects an action, discarding it and logging feedback for AI tuning."""
    try:
        if not redis_client:
            raise HTTPException(status_code=503, detail="Redis connection unavailable.")
        action_str = redis_client.hget("soc:pending_approvals", action_id)
        if not action_str:
            raise HTTPException(status_code=404, detail="Action not found or already processed.")

        action = json.loads(action_str)
        action["status"] = "REJECTED_BY_HUMAN"
        action["human_feedback"] = request.feedback_reason
        action["reviewed_at"] = time.time()

        # Remove from pending, move to rejected
        redis_client.hdel("soc:pending_approvals", action_id)
        redis_client.hset("soc:rejected_actions", action_id, json.dumps(action))

        # Publish feedback for the reinforcement learning agent (W28)
        redis_client.publish("soc:ai-feedback", json.dumps({
            "action_id": action_id,
            "type": "negative_feedback",
            "source_role": action.get("source", "commander"),
            "status": "rejected",
            "reason": request.feedback_reason,
            "original_action": action,
        }))

        logger.info(f"[HITL] Action {action_id} REJECTED. Reason: {request.feedback_reason}")
        return {"message": "تم رفض الإجراء وإرسال التغذية الراجعة للتعلم.", "action_id": action_id}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error rejecting action: {e}")
        raise HTTPException(status_code=500, detail="Internal error.")


if __name__ == "__main__":
    uvicorn.run("hitl_api:app", host="0.0.0.0", port=8000, reload=True)
