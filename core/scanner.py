import os
import time
from pathlib import Path
from typing import List, Dict
from datetime import datetime
import uuid

from .models import ScanResult, ScanSummary, Finding, Framework
from .rule_engine import RuleEngine
from .detectors import DocumentGapDetector, ConfigMisconfigDetector

class ComplianceScanner:
    def __init__(self, rules_dir: str = "rules"):
        self.rule_engine = RuleEngine(rules_dir)
        self.doc_detector = DocumentGapDetector()
        self.config_detector = ConfigMisconfigDetector()
    
    def scan_paths(self, paths: List[str], frameworks: List[Framework] = None) -> ScanResult:
        """Scan the given paths for compliance issues."""
        start_time = time.time()
        scan_id = str(uuid.uuid4())
        
        all_findings = []
        files_scanned = 0
        
        for path_str in paths:
            path = Path(path_str)
            if path.is_file():
                findings = self._scan_single_file(path)
                all_findings.extend(findings)
                files_scanned += 1
            elif path.is_dir():
                for file_path in path.rglob('*'):
                    if file_path.is_file() and not self._should_skip_file(file_path):
                        findings = self._scan_single_file(file_path)
                        all_findings.extend(findings)
                        files_scanned += 1
        
        # Filter by frameworks if specified
        if frameworks:
            all_findings = [f for f in all_findings if f.framework in frameworks]
        
        # Deduplicate findings
        all_findings = self._deduplicate_findings(all_findings)
        
        # Sort by severity (critical -> low)
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        all_findings.sort(key=lambda x: severity_order.get(x.severity, 4))
        
        # Generate summary
        scan_duration = time.time() - start_time
        summary = self._generate_summary(files_scanned, all_findings, scan_duration)
        
        # Get top risks (critical and high severity)
        top_risks = [f for f in all_findings if f.severity in ["critical", "high"]][:10]
        
        # Generate recommendations
        recommendations = self._generate_recommendations(all_findings)
        
        return ScanResult(
            scan_id=scan_id,
            timestamp=datetime.now(),
            paths_scanned=paths,
            summary=summary,
            findings=all_findings,
            top_risks=top_risks,
            recommendations=recommendations
        )
    
    def _scan_single_file(self, file_path: Path) -> List[Finding]:
        """Scan a single file with all applicable detectors."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception:
            return []
        
        findings = []
        
        # Rule engine scanning
        findings.extend(self.rule_engine.scan_file(file_path, content))
        
        # Document gap detection for policy files
        if file_path.suffix in ['.md', '.txt', '.doc', '.docx']:
            findings.extend(self.doc_detector.scan_document(file_path, content))
        
        # Configuration file analysis
        if file_path.suffix in ['.yml', '.yaml', '.json', '.conf', '.ini', '.toml']:
            findings.extend(self.config_detector.scan_config(file_path, content))
        
        return findings
    
    def _should_skip_file(self, file_path: Path) -> bool:
        """Determine if a file should be skipped during scanning."""
        skip_extensions = {'.pyc', '.pyo', '.exe', '.bin', '.so', '.dylib', '.dll'}
        skip_dirs = {'.git', '.svn', '__pycache__', 'node_modules', '.venv', 'venv'}
        
        if file_path.suffix in skip_extensions:
            return True
        
        if any(part in skip_dirs for part in file_path.parts):
            return True
        
        # Skip binary files (basic check)
        if file_path.stat().st_size > 10 * 1024 * 1024:  # Skip files > 10MB
            return True
        
        return False
    
    def _deduplicate_findings(self, findings: List[Finding]) -> List[Finding]:
        """Remove duplicate findings based on file path and rule."""
        seen = set()
        deduplicated = []
        
        for finding in findings:
            key = (finding.file_path, finding.rule_id, finding.line_range)
            if key not in seen:
                seen.add(key)
                deduplicated.append(finding)
        
        return deduplicated
    
    def _generate_summary(self, files_scanned: int, findings: List[Finding], duration: float) -> ScanSummary:
        """Generate scan summary statistics."""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        framework_counts = {"iso27001": 0, "soc2": 0, "gdpr": 0}
        
        for finding in findings:
            severity_counts[finding.severity] += 1
            framework_counts[finding.framework] += 1
        
        return ScanSummary(
            total_files_scanned=files_scanned,
            total_findings=len(findings),
            findings_by_severity=severity_counts,
            findings_by_framework=framework_counts,
            scan_duration_seconds=round(duration, 2)
        )
    
    def _generate_recommendations(self, findings: List[Finding]) -> List[str]:
        """Generate prioritized recommendations based on findings."""
        recommendations = []
        
        critical_count = sum(1 for f in findings if f.severity == "critical")
        high_count = sum(1 for f in findings if f.severity == "high")
        
        if critical_count > 0:
            recommendations.append(f"🚨 Address {critical_count} critical security issues immediately")
        
        if high_count > 0:
            recommendations.append(f"⚠️  Review and remediate {high_count} high-severity findings")
        
        # Common issue patterns
        pii_findings = [f for f in findings if "pii" in f.rule_id.lower() or "personal" in f.why_it_matters.lower()]
        if len(pii_findings) > 3:
            recommendations.append("🔒 Implement comprehensive PII handling and masking procedures")
        
        secret_findings = [f for f in findings if "secret" in f.rule_id.lower() or "api" in f.rule_id.lower()]
        if len(secret_findings) > 2:
            recommendations.append("🔑 Audit and rotate exposed credentials, implement secret management")
        
        config_findings = [f for f in findings if f.framework == Framework.SOC2 and f.severity in ["critical", "high"]]
        if len(config_findings) > 2:
            recommendations.append("⚙️  Review system configurations against security baselines")
        
        return recommendations[:5]  # Top 5 recommendations
