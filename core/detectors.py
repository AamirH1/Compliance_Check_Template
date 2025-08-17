import re
from typing import List, Dict, Any
from pathlib import Path
from .models import Finding, Framework, Severity
import uuid

class DocumentGapDetector:
    """Detect missing sections in policy documents."""
    
    REQUIRED_SECTIONS = {
        Framework.GDPR: [
            {'keywords': ['data retention', 'retention period'], 'control_id': 'Article 5'},
            {'keywords': ['data subject rights', 'individual rights'], 'control_id': 'Article 12'},
            {'keywords': ['data protection impact', 'DPIA'], 'control_id': 'Article 35'},
            {'keywords': ['data breach', 'incident response'], 'control_id': 'Article 33'},
        ],
        Framework.ISO27001: [
            {'keywords': ['access control', 'access management'], 'control_id': 'A.9'},
            {'keywords': ['incident response', 'incident management'], 'control_id': 'A.16'},
            {'keywords': ['encryption', 'cryptographic'], 'control_id': 'A.10'},
        ],
        Framework.SOC2: [
            {'keywords': ['access control', 'logical access'], 'control_id': 'CC 6.1'},
            {'keywords': ['encryption', 'data protection'], 'control_id': 'CC 6.7'},
            {'keywords': ['monitoring', 'system monitoring'], 'control_id': 'CC 7.1'},
        ]
    }
    
    def scan_document(self, file_path: Path, content: str) -> List[Finding]:
        """Scan policy documents for missing sections."""
        findings = []
        
        # Only scan documents that appear to be policies
        if not self._is_policy_document(content):
            return findings
        
        content_lower = content.lower()
        
        for framework, sections in self.REQUIRED_SECTIONS.items():
            for section in sections:
                if not any(keyword in content_lower for keyword in section['keywords']):
                    finding = Finding(
                        id=str(uuid.uuid4()),
                        rule_id=f"doc_gap_{framework.value}_{section['control_id'].replace('.', '_').replace(' ', '_')}",
                        framework=framework,
                        control_id=section['control_id'],
                        severity=Severity.MEDIUM,
                        file_path=str(file_path),
                        line_range="1-end",
                        evidence_snippet=f"Missing section: {', '.join(section['keywords'])}",
                        why_it_matters=f"Policy documents should address {section['keywords'][0]} requirements for {framework.value} compliance",
                        remediation_steps=f"Add a section covering {', '.join(section['keywords'])} in the policy document",
                        mapping_confidence="medium",
                        needs_review=True
                    )
                    findings.append(finding)
        
        return findings
    
    def _is_policy_document(self, content: str) -> bool:
        """Heuristic to identify policy documents."""
        policy_indicators = ['policy', 'procedure', 'guideline', 'standard', 'privacy', 'security']
        content_lower = content.lower()
        return any(indicator in content_lower for indicator in policy_indicators)

class ConfigMisconfigDetector:
    """Detect security misconfigurations in config files."""
    
    def scan_config(self, file_path: Path, content: str) -> List[Finding]:
        """Scan configuration files for security issues."""
        findings = []
        
        # Disabled TLS/SSL
        if re.search(r'ssl\s*[:=]\s*false|verify\s*[:=]\s*false|tls\s*[:=]\s*false', content, re.IGNORECASE):
            findings.append(self._create_config_finding(
                file_path, "disabled_tls", Framework.ISO27001, "A.13",
                Severity.HIGH, "TLS/SSL disabled in configuration",
                "Disabled encryption exposes data in transit to interception",
                "Enable TLS/SSL and certificate verification"
            ))
        
        # Overly broad IAM permissions
        if re.search(r'"Action"\s*:\s*"\*".*"Resource"\s*:\s*"\*"', content) or \
           re.search(r'"Resource"\s*:\s*"\*".*"Action"\s*:\s*"\*"', content):
            findings.append(self._create_config_finding(
                file_path, "broad_iam", Framework.SOC2, "CC 6.2",
                Severity.CRITICAL, "Overly broad IAM permissions",
                "Wildcard permissions violate principle of least privilege",
                "Restrict actions and resources to specific required permissions"
            ))
        
        # Public bucket/storage
        if re.search(r'"public"[\s\n]*:[\s\n]*true|public[\s]*=[\s]*true', content, re.IGNORECASE):
            findings.append(self._create_config_finding(
                file_path, "public_storage", Framework.GDPR, "Article 32",
                Severity.HIGH, "Public storage configuration",
                "Public access may expose personal data",
                "Review and restrict public access to necessary resources only"
            ))
        
        # Weak cipher suites
        if re.search(r'cipher.*RC4|cipher.*DES|cipher.*MD5', content, re.IGNORECASE):
            findings.append(self._create_config_finding(
                file_path, "weak_cipher", Framework.ISO27001, "A.10",
                Severity.HIGH, "Weak cipher suites configured",
                "Weak cryptographic algorithms are vulnerable to attacks",
                "Use strong cipher suites (AES-256, SHA-256 or higher)"
            ))
        
        return findings
    
    def _create_config_finding(self, file_path: Path, rule_id: str, framework: Framework, 
                             control_id: str, severity: Severity, evidence: str,
                             why: str, remediation: str) -> Finding:
        return Finding(
            id=str(uuid.uuid4()),
            rule_id=rule_id,
            framework=framework,
            control_id=control_id,
            severity=severity,
            file_path=str(file_path),
            line_range="1-end",
            evidence_snippet=evidence,
            why_it_matters=why,
            remediation_steps=remediation,
            mapping_confidence="high"
        )

def luhn_check(card_number: str) -> bool:
    """Validate credit card number using Luhn algorithm."""
    def digits_of(n):
        return [int(d) for d in str(n)]
    
    digits = digits_of(card_number.replace(' ', '').replace('-', ''))
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    checksum = sum(odd_digits)
    for d in even_digits:
        checksum += sum(digits_of(d*2))
    return checksum % 10 == 0
