from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse
import uvicorn
from typing import List, Optional
import json

from core.models import ScanRequest, ScanResult, Framework
from core.scanner import ComplianceScanner
from core.reporter import ReportGenerator

app = FastAPI(
    title="AI-Powered Compliance & Security Checker",
    description="Scan code, documents, and config files for ISO 27001, SOC 2, and GDPR compliance violations",
    version="1.0.0"
)

scanner = ComplianceScanner()
reporter = ReportGenerator()

# Store scan results (in production, use proper database)
scan_cache = {}

@app.post("/scan", response_model=ScanResult)
async def scan_paths(request: ScanRequest):
    """Scan the provided paths for compliance violations."""
    try:
        result = scanner.scan_paths(request.paths, request.frameworks)
        scan_cache[result.scan_id] = result
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

@app.get("/report/{scan_id}")
async def get_report(
    scan_id: str, 
    format: str = Query(default="json", regex="^(json|html)$")
):
    """Retrieve a scan report in JSON or HTML format."""
    if scan_id not in scan_cache:
        raise HTTPException(status_code=404, detail="Scan result not found")
    
    result = scan_cache[scan_id]
    
    if format == "html":
        html_content = reporter._render_html_template(result)
        return HTMLResponse(content=html_content)
    else:
        return result

@app.get("/")
async def root():
    """API status and information."""
    return {
        "service": "AI-Powered Compliance & Security Checker",
        "status": "running",
        "supported_frameworks": ["iso27001", "soc2", "gdpr"],
        "endpoints": {
            "scan": "/scan",
            "report": "/report/{scan_id}?format=json|html"
        }
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
