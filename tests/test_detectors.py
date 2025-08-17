import pytest
from pathlib import Path
from core.detectors import DocumentGapDetector, ConfigMisconfigDetector, luhn_check

def test_luhn_check():
    """Test credit card validation using Luhn algorithm."""
    # Valid credit card numbers
    assert luhn_check("4532015112830366") == True  # Visa
    assert luhn_check("5555555555554444") == True  # Mastercard
    
    # Invalid credit card numbers
    assert luhn_check("4532015112830367") == False  # Wrong check digit
    assert luhn_check("1234567890123456") == False  # Invalid sequence

def test_document_gap_detector():
    """Test document gap detection for missing policy sections."""
    detector = DocumentGapDetector()
    
    # Policy document missing retention section
    content = """
    Privacy Policy
    
    We collect personal data to provide services.
    We protect data with security measures.
    Contact us for questions.
    """
    
    findings = detector.scan_document(Path("privacy-policy.md"), content)
    
    # Should find missing sections
    assert len(findings) > 0
    
    # Check for GDPR data retention finding
    retention_findings = [f for f in findings if "retention" in f.evidence_snippet.lower()]
    assert len(retention_findings) > 0

def test_config_detector_disabled_tls():
    """Test detection of disabled TLS in configuration."""
    detector = ConfigMisconfigDetector()
    
    config_content = """
    database:
      ssl: false
      verify: false
    """
    
    findings = detector.scan_config(Path("config.yml"), config_content)
    
    # Should detect disabled TLS
    tls_findings = [f for f in findings if f.rule_id == "disabled_tls"]
    assert len(tls_findings) > 0
    assert tls_findings[0].severity == "high"

def test_config_detector_broad_iam():
    """Test detection of overly broad IAM permissions."""
    detector = ConfigMisconfigDetector()
    
    config_content = """
    {
      "Statement": [
        {
          "Effect": "Allow",
          "Action": "*",
          "Resource": "*"
        }
      ]
    }
    """
    
    findings = detector.scan_config(Path("policy.json"), config_content)
    
    # Should detect broad IAM permissions
    iam_findings = [f for f in findings if f.rule_id == "broad_iam"]
    assert len(iam_findings) > 0
    assert iam_findings[0].severity == "critical"

def test_config_detector_public_storage():
    """Test detection of public storage configuration."""
    detector = ConfigMisconfigDetector()
    
    config_content = """
    storage:
      public: true
      access: open
    """
    
    findings = detector.scan_config(Path("storage.yml"), config_content)
    
    # Should detect public storage
    public_findings = [f for f in findings if f.rule_id == "public_storage"]
    assert len(public_findings) > 0
