import os

# For brevity, some content is abbreviated. See previous full code blocks for actual content.
FILE_CONTENTS = {
    "requirements.txt": """fastapi==0.104.1
uvicorn==0.24.0
pydantic==2.5.0
PyYAML==6.0.1
rich==13.7.0
jinja2==3.1.2
pytest==7.4.3
click==8.1.7
aiofiles==23.2.1
""",
    "README.md": """# AI-Powered Compliance & Security Checker
See previous response for full README content.
""",
    "app.py": """# See previous code for full app.py
[...]
""",
    "cli.py": """# See previous code for full cli.py
[...]
""",
    "core/__init__.py": "",
    "core/models.py": """# See previous code for core/models.py
[...]
""",
    "core/rule_engine.py": """# See previous code for core/rule_engine.py
[...]
""",
    "core/detectors.py": """# See previous code for core/detectors.py
[...]
""",
    "core/scanner.py": """# See previous code for core/scanner.py
[...]
""",
    "core/reporter.py": """# See previous code for core/reporter.py
[...]
""",
    "explainers/__init__.py": "",
    "explainers/llm_explainer.py": """# See previous code for explainers/llm_explainer.py
[...]
""",
    "rules/iso27001.yaml": """# See previous code for rules/iso27001.yaml
[...]
""",
    "rules/soc2.yaml": """# See previous code for rules/soc2.yaml
[...]
""",
    "rules/gdpr.yaml": """# See previous code for rules/gdpr.yaml
[...]
""",
    "samples/code/app.py": """# See previous code for samples/code/app.py
[...]
""",
    "samples/code/config.yml": """# See previous code for samples/code/config.yml
[...]
""",
    "samples/config/aws-config.json": """# See previous code for samples/config/aws-config.json
[...]
""",
    "samples/docs/privacy-policy.md": """# See previous code for samples/docs/privacy-policy.md
[...]
""",
    "samples/docs/security-policy.txt": """# See previous code for samples/docs/security-policy.txt
[...]
""",
    "tests/__init__.py": "",
    "tests/test_detectors.py": """# See previous code for tests/test_detectors.py
[...]
""",
    "tests/test_rule_engine.py": """# See previous code for tests/test_rule_engine.py
[...]
""",
    "tests/test_scanner.py": """# See previous code for tests/test_scanner.py
[...]
""",
    "templates/report.html": """<!-- See previous code for templates/report.html -->
[...]
""",
}


def write_file(path, content):
    dir_name = os.path.dirname(path)
    if dir_name:
        os.makedirs(dir_name, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content.rstrip() + "\n")


def main():
    print("Creating AI-Powered Compliance & Security Checker project structure...")
    for file_path, content in FILE_CONTENTS.items():
        write_file(file_path, content)
        print(f"Created: {file_path}")
    print("\n✅ All files created!")
    print("\nNext steps:")
    print("  python -m venv .venv")
    print("  source .venv/bin/activate")
    print("  pip install -r requirements.txt")
    print("  python -m cli scan samples/ --format html")

if __name__ == "__main__":
    main()
