"""Output package init."""
from .json_report import generate_json
from .pdf_report import generate_pdf
from .github_issues import generate_github_issues

__all__ = ["generate_json", "generate_pdf", "generate_github_issues"]
