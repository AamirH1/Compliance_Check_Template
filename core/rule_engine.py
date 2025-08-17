import yaml
import re
import os
from typing import Dict, List, Any
from pathlib import Path
from .models import Framework, Severity, Finding
import uuid

class Rule:
    def __init__(self, rule_data: Dict[str, Any]):
        self.id = rule_data['id']
        self.framework = Framework(rule_data['framework'])
        self.control_id = rule_data['control_id']
        self.severity = Severity(rule_data['severity'])
        self.pattern = re.compile(rule_data['pattern'], re.IGNORECASE | re.MULTILINE)
        self.file_globs = rule_data.get('file_globs', ['*'])
        self.why_it_matters = rule_data['why_it_matters']
        self.remediation_steps = rule_data['remediation_steps']
        self.mapping_confidence = rule_data.get('mapping_confidence', 'high')
        self.needs_review = rule_data.get('needs_review', False)

class RuleEngine:
    def __init__(self, rules_dir: str = "rules"):
        self.rules: List[Rule] = []
        self.rules_dir = Path(rules_dir)
        self.load_rules()
    
    def load_rules(self):
        """Load all YAML rule files from rules directory."""
        for rule_file in self.rules_dir.glob("*.yaml"):
            with open(rule_file, 'r') as f:
                rule_data = yaml.safe_load(f)
                for rule_dict in rule_data.get('rules', []):
                    self.rules.append(Rule(rule_dict))
    
    def scan_file(self, file_path: Path, content: str) -> List[Finding]:
        """Scan a single file against all applicable rules."""
        findings = []
        
        for rule in self.rules:
            # Check if file matches glob patterns
            if not any(file_path.match(glob) for glob in rule.file_globs):
                continue
            
            # Find all matches
            for match in rule.pattern.finditer(content):
                line_num = content[:match.start()].count('\n') + 1
                line_end = content[:match.end()].count('\n') + 1
                
                # Extract evidence snippet and redact sensitive data
                evidence = self._extract_evidence(content, match.start(), match.end())
                evidence_redacted = self._redact_sensitive_data(evidence)
                
                finding = Finding(
                    id=str(uuid.uuid4()),
                    rule_id=rule.id,
                    framework=rule.framework,
                    control_id=rule.control_id,
                    severity=rule.severity,
                    file_path=str(file_path),
                    line_range=f"{line_num}-{line_end}",
                    evidence_snippet=evidence_redacted,
                    why_it_matters=rule.why_it_matters,
                    remediation_steps=rule.remediation_steps,
                    mapping_confidence=rule.mapping_confidence,
                    needs_review=rule.needs_review
                )
                findings.append(finding)
        
        return findings
    
    def _extract_evidence(self, content: str, start: int, end: int) -> str:
        """Extract a snippet around the match for evidence."""
        lines = content.split('\n')
        start_line = content[:start].count('\n')
        end_line = content[:end].count('\n')
        
        # Include some context (2 lines before/after)
        context_start = max(0, start_line - 2)
        context_end = min(len(lines), end_line + 3)
        
        evidence_lines = lines[context_start:context_end]
        return '\n'.join(evidence_lines)
    
    def _redact_sensitive_data(self, text: str) -> str:
        """Redact sensitive patterns in evidence snippets."""
        # Email addresses
        text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '****@****.***', text)
        
        # Credit card numbers (basic pattern)
        text = re.sub(r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b', '****-****-****-****', text)
        
        # Phone numbers
        text = re.sub(r'\b\d{3}[- ]?\d{3}[- ]?\d{4}\b', '***-***-****', text)
        
        # API keys and secrets (long alphanumeric strings)
        text = re.sub(r'\b[A-Za-z0-9+/]{20,}\b', '****[REDACTED]****', text)
        
        return text
