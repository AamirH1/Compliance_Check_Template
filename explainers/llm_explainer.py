import os
from typing import List, Optional
from core.models import Finding

class LLMExplainer:
    """Optional LLM integration for enhanced explanations."""
    
    def __init__(self):
        self.enabled = os.getenv("USE_LLM", "false").lower() == "true"
        
    def enhance_findings(self, findings: List[Finding]) -> List[Finding]:
        """Enhance finding explanations with LLM-generated content."""
        if not self.enabled:
            return findings
        
        # Placeholder for LLM integration
        # In a real implementation, this would call an LLM API
        # to improve the why_it_matters and remediation_steps
        
        for finding in findings:
            if self._should_enhance(finding):
                finding.why_it_matters = self._enhance_explanation(finding.why_it_matters)
                finding.remediation_steps = self._enhance_remediation(finding.remediation_steps)
        
        return findings
    
    def _should_enhance(self, finding: Finding) -> bool:
        """Determine if a finding should be enhanced with LLM."""
        # Only enhance high-severity findings to save API costs
        return finding.severity in ["critical", "high"]
    
    def _enhance_explanation(self, original: str) -> str:
        """Enhance explanation text with LLM (stub implementation)."""
        # In real implementation, would call LLM API like:
        # response = openai.Completion.create(
        #     prompt=f"Improve this security explanation: {original}",
        #     max_tokens=100
        # )
        # return response.choices[0].text.strip()
        
        return f"[Enhanced] {original}"
    
    def _enhance_remediation(self, original: str) -> str:
        """Enhance remediation steps with LLM (stub implementation)."""
        # Similar to above, would call LLM for better remediation steps
        return f"[Enhanced] {original}"
