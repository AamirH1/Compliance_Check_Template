import pytest
from pathlib import Path
from core.rule_engine import RuleEngine, Rule

def test_rule_engine_aws_key_detection():
    """Test AWS access key detection."""
    engine = RuleEngine("rules")
    
    content = """
    # Configuration file
    AWS_ACCESS_KEY_ID = "AKIA1234567890ABCDEF"
    AWS_SECRET_ACCESS_KEY = "secret123"
    """
    
    findings = engine.scan_file(Path("config.py"), content)
    
    # Should detect AWS access key
    aws_findings = [f for f in findings if "aws" in f.rule_id.lower()]
    assert len(aws_findings) > 0
    assert aws_findings[0].severity == "critical"

def test_rule_engine_email_detection():
    """Test email address detection."""
    engine = RuleEngine("rules")
    
    content = """
    user_email = "test.user@example.com"
    contact = "admin@company.org"
    """
    
    findings = engine.scan_file(Path("app.py"), content)
    
    # Should detect email addresses
    email_findings = [f for f in findings if "email" in f.rule_id.lower()]
    assert len(email_findings) >= 2

def test_rule_engine_password_detection():
    """Test plaintext password detection in config files."""
    engine = RuleEngine("rules")
    
    content = """
    database:
      password: "secret123"
      user: admin
    """
    
    findings = engine.scan_file(Path("database.yml"), content)
    
    # Should detect plaintext password
    password_findings = [f for f in findings if "password" in f.rule_id.lower()]
    assert len(password_findings) > 0

def test_rule_engine_credit_card_detection():
    """Test credit card number detection."""
    engine = RuleEngine("rules")
    
    content = """
    # Test payment data
    card_number = "4532015112830366"  # Valid Visa
    another_card = "5555555555554444" # Valid Mastercard
    """
    
    findings = engine.scan_file(Path("payment.py"), content)
    
    # Should detect credit card numbers
    cc_findings = [f for f in findings if "credit" in f.rule_id.lower()]
    assert len(cc_findings) >= 2

def test_rule_engine_evidence_redaction():
    """Test that sensitive data is redacted in evidence snippets."""
    engine = RuleEngine("rules")
    
    content = """
    user_data = {
        "email": "sensitive@example.com",
        "card": "4532015112830366"
    }
    """
    
    findings = engine.scan_file(Path("data.py"), content)
    
    # Check that evidence is redacted
    for finding in findings:
        assert "sensitive@example.com" not in finding.evidence_snippet
        assert "4532015112830366" not in finding.evidence_snippet
