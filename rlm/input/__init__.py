"""Input package init."""
from .local_loader import load_local
from .zip_loader import load_zip
from .github_loader import load_github

__all__ = ["load_local", "load_zip", "load_github"]
