import json
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, Any
from jinja2 import Template

from .models import ScanResult

class ReportGenerator:
    def __init__(self, reports_dir: str = "reports"):
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(exist_ok=True)
    
    def generate_json_report(self, scan_result: ScanResult, output_path: str = None) -> str:
        """Generate JSON report from scan results."""
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = self.reports_dir / f"compliance_report_{timestamp}.json"
        
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Convert to dict for JSON serialization
        report_data = scan_result.model_dump(mode='json')
        
        with open(output_path, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        return str(output_path)
    
    def generate_html_report(self, scan_result: ScanResult, output_path: str = None) -> str:
        """Generate HTML report from scan results."""
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = self.reports_dir / f"compliance_report_{timestamp}.html"
        
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        html_content = self._render_html_template(scan_result)
        
        with open(output_path, 'w') as f:
            f.write(html_content)
        
        return str(output_path)
    
    def _render_html_template(self, scan_result: ScanResult) -> str:
        """Render HTML report using Jinja2 template."""
        template_str = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Compliance Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { border-bottom: 3px solid #2c3e50; padding-bottom: 20px; margin-bottom: 30px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .summary-card { background: #ecf0f1; padding: 20px; border-radius: 6px; text-align: center; }
        .summary-card h3 { margin: 0 0 10px 0; color: #2c3e50; }
        .summary-card .number { font-size: 2em; font-weight: bold; color: #3498db; }
        .severity-critical { color: #e74c3c; }
        .severity-high { color: #f39c12; }
        .severity-medium { color: #f1c40f; }
        .severity-low { color: #27ae60; }
        .findings { margin-top: 30px; }
        .finding { border: 1px solid #ddd; border-radius: 6px; margin-bottom: 20px; overflow: hidden; }
        .finding-header { padding: 15px; background: #34495e; color: white; cursor: pointer; }
        .finding-header:hover { background: #2c3e50; }
        .finding-content { padding: 20px; display: none; }
        .finding-content.active { display: block; }
        .evidence-box { background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 4px; padding: 15px; margin: 10px 0; font-family: monospace; white-space: pre-wrap; }
        .recommendations { background: #e8f5e8; border-left: 4px solid #27ae60; padding: 20px; margin: 20px 0; }
        .top-risks { background: #ffe6e6; border-left: 4px solid #e74c3c; padding: 20px; margin: 20px 0; }
    </style>
    <script>
        function toggleFinding(id) {
            const content = document.getElementById('content-' + id);
            const header = document.getElementById('header-' + id);
            if (content.classList.contains('active')) {
                content.classList.remove('active');
                header.innerHTML = header.innerHTML.replace('▼', '▶');
            } else {
                content.classList.add('active');
                header.innerHTML = header.innerHTML.replace('▶', '▼');
            }
        }
    </script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Compliance & Security Scan Report</h1>
            <p><strong>Scan ID:</strong> {{ scan_result.scan_id }}</p>
            <p><strong>Timestamp:</strong> {{ scan_result.timestamp.strftime('%Y-%m-%d %H:%M:%S') }}</p>
            <p><strong>Paths Scanned:</strong> {{ ', '.join(scan_result.paths_scanned) }}</p>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <h3>Files Scanned</h3>
                <div class="number">{{ scan_result.summary.total_files_scanned }}</div>
            </div>
            <div class="summary-card">
                <h3>Total Findings</h3>
                <div class="number">{{ scan_result.summary.total_findings }}</div>
            </div>
            <div class="summary-card">
                <h3>Critical Issues</h3>
                <div class="number severity-critical">{{ scan_result.summary.findings_by_severity.critical }}</div>
            </div>
            <div class="summary-card">
                <h3>High Priority</h3>
                <div class="number severity-high">{{ scan_result.summary.findings_by_severity.high }}</div>
            </div>
            <div class="summary-card">
                <h3>Scan Duration</h3>
                <div class="number">{{ "%.2f"|format(scan_result.summary.scan_duration_seconds) }}s</div>
            </div>
        </div>
        
        {% if scan_result.recommendations %}
        <div class="recommendations">
            <h2>🎯 Priority Recommendations</h2>
            <ul>
                {% for rec in scan_result.recommendations %}
                <li>{{ rec }}</li>
                {% endfor %}
            </ul>
        </div>
        {% endif %}
        
        {% if scan_result.top_risks %}
        <div class="top-risks">
            <h2>🚨 Top Security Risks</h2>
            <ul>
                {% for risk in scan_result.top_risks[:5] %}
                <li><strong>{{ risk.file_path }}</strong>: {{ risk.why_it_matters }}</li>
                {% endfor %}
            </ul>
        </div>
        {% endif %}
        
        <div class="findings">
            <h2>🔍 Detailed Findings ({{ scan_result.findings|length }})</h2>
            {% for finding in scan_result.findings %}
            <div class="finding">
                <div class="finding-header" id="header-{{ loop.index }}" onclick="toggleFinding({{ loop.index }})">
                    ▶ <span class="severity-{{ finding.severity }}">{{ finding.severity.upper() }}</span>
                    - {{ finding.framework.upper() }} {{ finding.control_id }}
                    - {{ finding.file_path }}
                    {% if finding.needs_review %}<span style="color: #f39c12;"> [NEEDS REVIEW]</span>{% endif %}
                </div>
                <div class="finding-content" id="content-{{ loop.index }}">
                    <p><strong>Rule:</strong> {{ finding.rule_id }}</p>
                    <p><strong>Line Range:</strong> {{ finding.line_range }}</p>
                    <p><strong>Why It Matters:</strong> {{ finding.why_it_matters }}</p>
                    <p><strong>Remediation:</strong> {{ finding.remediation_steps }}</p>
                    <p><strong>Mapping Confidence:</strong> {{ finding.mapping_confidence }}</p>
                    <div class="evidence-box">
                        <strong>Evidence:</strong><br>
                        {{ finding.evidence_snippet }}
                    </div>
                </div>
            </div>
            {% endfor %}
        </div>
        
        <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; text-align: center; color: #666;">
            Generated by AI-Powered Compliance & Security Checker by Aamir Hussain
        </div>
    </div>
</body>
</html>
        """
        
        template = Template(template_str)
        return template.render(scan_result=scan_result)
