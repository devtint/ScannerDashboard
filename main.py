"""FastAPI Application - Security Scanner Platform"""
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, BackgroundTasks, Form
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func
from typing import List, Optional
from datetime import datetime, timedelta
import asyncio
import json

from config import settings
from app.database import init_db, get_db
from app.models import ScanRecord, ScanHistory, AuditLog
from scanners import scanner_registry
from utils.helpers import validate_url, sanitize_url, format_duration, calculate_security_score

# Initialize FastAPI app
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    debug=settings.debug
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files and templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# WebSocket connections manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
    
    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
    
    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                pass

manager = ConnectionManager()


@app.on_event("startup")
async def startup_event():
    """Initialize database on startup"""
    await init_db()


@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve main dashboard"""
    with open("templates/index.html", "r", encoding="utf-8") as f:
        return f.read()


@app.get("/api/scanners")
async def list_scanners():
    """List all available scanners"""
    scanner_ids = scanner_registry.list_scanners()
    scanners = []
    for scanner_id in scanner_ids:
        scanner_info = scanner_registry.get_scanner(scanner_id).get_scanner_info()
        scanner_info["id"] = scanner_id  # Add the registry ID
        scanners.append(scanner_info)
    return JSONResponse(content={"scanners": scanners, "count": len(scanners)})


@app.post("/api/scan")
async def start_scan(
    background_tasks: BackgroundTasks,
    url: str = Form(...),
    scanner_names: Optional[str] = Form(None),
    db: AsyncSession = Depends(get_db)
):
    """
    Start security scan(s) for a URL
    
    Parameters:
    - url: Target URL to scan
    - scanner_names: Comma-separated scanner names (if None, run all scanners)
    """
    # Parse scanner names if provided
    if scanner_names:
        scanner_names = [s.strip() for s in scanner_names.split(',') if s.strip()]
    else:
        scanner_names = None
    
    # Validate URL
    url = sanitize_url(url)
    if not validate_url(url):
        raise HTTPException(status_code=400, detail="Invalid URL format")
    
    # Get scanners to run
    if not scanner_names:
        scanner_names = scanner_registry.list_scanners()
    
    # Validate scanner names
    available_scanners = scanner_registry.list_scanners()
    invalid_scanners = [s for s in scanner_names if s not in available_scanners]
    if invalid_scanners:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid scanner names: {', '.join(invalid_scanners)}"
        )
    
    # Create scan tasks
    scan_id = datetime.utcnow().isoformat()
    
    # Run scans in background
    background_tasks.add_task(
        execute_scans,
        scan_id=scan_id,
        url=url,
        scanner_names=scanner_names,
        db=db
    )
    
    # Log audit
    audit = AuditLog(
        action="scan_started",
        target_url=url,
        scanner_name=",".join(scanner_names),
        details={"scan_id": scan_id}
    )
    db.add(audit)
    await db.commit()
    
    return JSONResponse(content={
        "scan_id": scan_id,
        "status": "started",
        "url": url,
        "scanners": scanner_names,
        "message": "Scans initiated successfully"
    })


async def execute_scans(scan_id: str, url: str, scanner_names: List[str], db: AsyncSession):
    """Execute multiple scans and store results"""
    
    for scanner_name in scanner_names:
        try:
            # Broadcast scan start
            await manager.broadcast({
                "type": "scan_started",
                "scan_id": scan_id,
                "scanner": scanner_name,
                "url": url
            })
            
            # Get scanner instance
            scanner = scanner_registry.get_scanner(
                scanner_name,
                timeout=settings.scan_timeout,
                user_agent=settings.user_agent
            )
            
            # Execute scan
            report = await scanner.scan(url)
            
            # Store results
            scan_record = ScanRecord(
                target_url=url,
                scanner_name=scanner_name,
                scan_date=report.scan_date,
                duration=report.duration,
                status="completed",
                results=[
                    {
                        "check_name": r.check_name,
                        "status": r.status,
                        "severity": r.severity.value,
                        "message": r.message,
                        "details": r.details,
                        "recommendation": r.recommendation,
                        "reference": r.reference,
                        "value": r.value
                    }
                    for r in report.results
                ],
                summary=report.summary,
                metadata=report.metadata
            )
            db.add(scan_record)
            await db.flush()
            
            # Create history entry
            history = ScanHistory(
                scan_record_id=scan_record.id,
                target_url=url,
                scanner_name=scanner_name,
                scan_date=report.scan_date,
                critical_count=report.summary.get("critical", 0),
                high_count=report.summary.get("high", 0),
                medium_count=report.summary.get("medium", 0),
                low_count=report.summary.get("low", 0),
                info_count=report.summary.get("info", 0),
                total_checks=len(report.results),
                passed_checks=len([r for r in report.results if r.status == "pass"]),
                failed_checks=len([r for r in report.results if r.status == "fail"])
            )
            db.add(history)
            await db.commit()
            
            # Broadcast scan completion
            await manager.broadcast({
                "type": "scan_completed",
                "scan_id": scan_id,
                "scanner": scanner_name,
                "url": url,
                "record_id": scan_record.id,
                "summary": report.summary,
                "duration": report.duration
            })
            
        except Exception as e:
            # Log failure
            audit = AuditLog(
                action="scan_failed",
                target_url=url,
                scanner_name=scanner_name,
                details={"error": str(e), "scan_id": scan_id}
            )
            db.add(audit)
            await db.commit()
            
            # Broadcast error
            await manager.broadcast({
                "type": "scan_failed",
                "scan_id": scan_id,
                "scanner": scanner_name,
                "url": url,
                "error": str(e)
            })


@app.get("/api/scans/recent")
async def get_recent_scans(
    limit: int = 20,
    db: AsyncSession = Depends(get_db)
):
    """Get recent scan records"""
    query = select(ScanRecord).order_by(desc(ScanRecord.scan_date)).limit(limit)
    result = await db.execute(query)
    records = result.scalars().all()
    
    return JSONResponse(content={
        "scans": [
            {
                "id": r.id,
                "target_url": r.target_url,
                "scanner_name": r.scanner_name,
                "scan_date": r.scan_date.isoformat(),
                "duration": r.duration,
                "status": r.status,
                "summary": r.summary,
                "security_score": calculate_security_score(r.summary)
            }
            for r in records
        ]
    })


@app.get("/api/scans/{scan_id}")
async def get_scan_details(
    scan_id: int,
    db: AsyncSession = Depends(get_db)
):
    """Get detailed scan results"""
    query = select(ScanRecord).where(ScanRecord.id == scan_id)
    result = await db.execute(query)
    record = result.scalar_one_or_none()
    
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return JSONResponse(content={
        "id": record.id,
        "target_url": record.target_url,
        "scanner_name": record.scanner_name,
        "scan_date": record.scan_date.isoformat(),
        "duration": record.duration,
        "status": record.status,
        "results": record.results,
        "summary": record.summary,
        "metadata": record.scan_metadata,
        "security_score": calculate_security_score(record.summary)
    })


@app.get("/api/statistics")
async def get_statistics(db: AsyncSession = Depends(get_db)):
    """Get platform statistics"""
    
    # Total scans
    total_query = select(func.count(ScanRecord.id))
    total_result = await db.execute(total_query)
    total_scans = total_result.scalar()
    
    # Scans today
    today = datetime.utcnow().date()
    today_query = select(func.count(ScanRecord.id)).where(
        func.date(ScanRecord.scan_date) == today
    )
    today_result = await db.execute(today_query)
    scans_today = today_result.scalar()
    
    # Unique URLs scanned
    unique_query = select(func.count(func.distinct(ScanRecord.target_url)))
    unique_result = await db.execute(unique_query)
    unique_urls = unique_result.scalar()
    
    # Average security score
    recent_query = select(ScanRecord).order_by(desc(ScanRecord.scan_date)).limit(100)
    recent_result = await db.execute(recent_query)
    recent_scans = recent_result.scalars().all()
    
    if recent_scans:
        avg_score = sum(calculate_security_score(r.summary) for r in recent_scans) / len(recent_scans)
    else:
        avg_score = 0
    
    return JSONResponse(content={
        "total_scans": total_scans,
        "scans_today": scans_today,
        "unique_urls": unique_urls,
        "average_security_score": round(avg_score, 1),
        "available_scanners": len(scanner_registry.list_scanners())
    })


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates"""
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive
            data = await websocket.receive_text()
            # Echo back for heartbeat
            await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        manager.disconnect(websocket)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug
    )
