"""Server-Sent Events route — live progress for a scan."""
import asyncio
import json

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse

from webapp import db
from webapp.routers.auth import require_viewer_sse
from webapp.services import events as bus

router = APIRouter(prefix="/api/scans", tags=["events"])


@router.get("/{scan_id}/events")
async def scan_events(scan_id: int, user: dict = Depends(require_viewer_sse)):
    scan = db.get_scan(scan_id, user["organization_id"])
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    async def gen():
        # send initial snapshot
        for ev in bus.snapshot(scan_id):
            yield f"data: {json.dumps(ev)}\n\n"
        # stream new events until scan finishes/errors
        while True:
            item = bus.drain(scan_id)
            for ev in item:
                yield f"data: {json.dumps(ev)}\n\n"
                if ev.get("type") in ("done", "error"):
                    yield f"event: end\ndata: {{}}\n\n"
                    bus.drop(scan_id)
                    return
            current = db.get_scan(scan_id, user["organization_id"])
            if current and current["status"] not in ("running", "queued"):
                if not item:
                    yield f"event: end\ndata: {{}}\n\n"
                    bus.drop(scan_id)
                    return
            await asyncio.sleep(1.0)

    return StreamingResponse(
        gen(), media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})