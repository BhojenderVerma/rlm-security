"""Analyzers package — exports all static analyzer classes."""

# Original 6
from .sql_injection import SQLInjectionAnalyzer
from .xss import XSSAnalyzer
from .hardcoded_secrets import HardcodedSecretsAnalyzer
from .path_traversal import PathTraversalAnalyzer
from .insecure_deps import InsecureDepsAnalyzer
from .crypto_misuse import CryptoMisuseAnalyzer

# New 10 — deeper detection
from .command_injection import CommandInjectionAnalyzer
from .xxe import XXEAnalyzer
from .ssrf import SSRFAnalyzer
from .insecure_deserialization import InsecureDeserializationAnalyzer
from .template_injection import TemplateInjectionAnalyzer
from .nosql_injection import NoSQLInjectionAnalyzer
from .jwt_weakness import JWTWeaknessAnalyzer
from .debug_exposure import DebugExposureAnalyzer
from .open_redirect import OpenRedirectAnalyzer
from .prototype_pollution import PrototypePollutionAnalyzer

ALL_ANALYZERS = [
    # Severity: CRITICAL
    HardcodedSecretsAnalyzer,
    InsecureDeserializationAnalyzer,
    CommandInjectionAnalyzer,
    # Severity: HIGH
    SQLInjectionAnalyzer,
    XSSAnalyzer,
    PathTraversalAnalyzer,
    CryptoMisuseAnalyzer,
    SSRFAnalyzer,
    XXEAnalyzer,
    NoSQLInjectionAnalyzer,
    TemplateInjectionAnalyzer,
    JWTWeaknessAnalyzer,
    PrototypePollutionAnalyzer,
    # Severity: MEDIUM
    DebugExposureAnalyzer,
    OpenRedirectAnalyzer,
    # Manifest-based
    InsecureDepsAnalyzer,
]

__all__ = [
    "SQLInjectionAnalyzer", "XSSAnalyzer", "HardcodedSecretsAnalyzer",
    "PathTraversalAnalyzer", "InsecureDepsAnalyzer", "CryptoMisuseAnalyzer",
    "CommandInjectionAnalyzer", "XXEAnalyzer", "SSRFAnalyzer",
    "InsecureDeserializationAnalyzer", "TemplateInjectionAnalyzer",
    "NoSQLInjectionAnalyzer", "JWTWeaknessAnalyzer", "DebugExposureAnalyzer",
    "OpenRedirectAnalyzer", "PrototypePollutionAnalyzer",
    "ALL_ANALYZERS",
]
