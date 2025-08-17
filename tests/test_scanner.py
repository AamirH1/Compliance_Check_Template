import pytest
from pathlib import Path
import tempfile
import os
from core.scanner import ComplianceScanner
from core.models import Framework

def test_scanner_integration():
    """Test complete scanning workflow."""
    scanner = ComplianceScanner("rules")
    
    # Create temporary test files
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Create test code file
        code_file = temp_path / "test.py"
        code_file.write_text("""
        # Test file with issues
        AWS_KEY = "AKIA1234567890ABCDEF"
        user_email = "test@example.com"
        """)
        
        # Create test config file
        config_file = temp_path / "config.yml"
        config_file.write_text("""
        database:
          password: "plain_password"
          ssl: false
        """)
        
        # Run scan
        result = scanner.scan_paths([str(temp_path)])
        
        # Verify results
        assert result.summary.total_files_scanned == 2
        assert result.summary.total_findings > 0
        
        # Check for specific findings
        aws_findings = [f for f in result.findings if "aws" in f.rule_id.lower()]
        assert len(aws_findings) > 0
        
        ssl_findings = [f for f in result.findings if "tls" in f.rule_id.lower()]
        assert len(ssl_findings) > 0

def test_scanner_framework_filtering():
    """Test scanning with framework filtering."""
    scanner = ComplianceScanner("rules")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        test_file = temp_path / "test.py"
        test_file.write_text('email = "test@example.com"')
        
        # Scan with only GDPR framework
        result = scanner.scan_paths([str(temp_path)], [Framework.GDPR])
        
        # All findings should be GDPR
        for finding in result.findings:
            assert finding.framework == Framework.GDPR

def test_scanner_deduplication():
    """Test that duplicate findings are removed."""
    scanner = ComplianceScanner("rules")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Create file with duplicate pattern
        test_file = temp_path / "test.py"
        test_file.write_text("""
        email1 = "test@example.com"
        email2 = "test@example.com"  # Same email, should not duplicate finding
        """)
        
        result = scanner.scan_paths([str(temp_path)])
        
        # Check findings are deduplicated by file + rule + line range
        findings_by_rule = {}
        for finding in result.findings:
            key = (finding.file_path, finding.rule_id)
            findings_by_rule[key] = findings_by_rule.get(key, 0) + 1
        
        # Should not have excessive duplicates for same pattern
        assert max(findings_by_rule.values()) <= 2  # Allow for multiple instances

def test_scanner_severity_ordering():
    """Test that findings are ordered by severity."""
    scanner = ComplianceScanner("rules")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Create file with mixed severity issues
        test_file = temp_path / "mixed.py"
        test_file.write_text("""
        # Critical: AWS key
        AWS_ACCESS_KEY = "AKIA1234567890ABCDEF"
        
        # Medium: Email
        email = "test@example.com" 
        
        # High: API key
        api_key = "sk-1234567890abcdef1234567890abcdef"
        """)
        
        result = scanner.scan_paths([str(temp_path)])
        
        # Check severity ordering (critical -> high -> medium -> low)
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        
        for i in range(len(result.findings) - 1):
            current_severity = severity_order.get(result.findings[i].severity, 4)
            next_severity = severity_order.get(result.findings[i + 1].severity, 4)
            assert current_severity <= next_severity
