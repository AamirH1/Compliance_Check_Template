from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any, Literal
from datetime import datetime
from enum import Enum

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high" 
    MEDIUM = "medium"
    LOW = "low"

class Framework(str, Enum):
    ISO27001 = "iso27001"
    SOC2 = "soc2"
    GDPR = "gdpr"

class Finding(BaseModel):
    id: str
    rule_id: str
    framework: Framework
    control_id: str
    severity: Severity
    file_path: str
    line_range: str
    evidence_snippet: str
    why_it_matters: str
    remediation_steps: str
    mapping_confidence: Literal["high", "medium", "low"] = "high"
    needs_review: bool = False

class ScanSummary(BaseModel):
    total_files_scanned: int
    total_findings: int
    findings_by_severity: Dict[str, int]
    findings_by_framework: Dict[str, int]
    scan_duration_seconds: float

class ScanResult(BaseModel):
    scan_id: str
    timestamp: datetime
    paths_scanned: List[str]
    summary: ScanSummary
    findings: List[Finding]
    top_risks: List[Finding] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)

class ScanRequest(BaseModel):
    paths: List[str]
    frameworks: Optional[List[Framework]] = None
