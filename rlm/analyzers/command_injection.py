"""
Command Injection Detector.
Detects shell command execution with unsanitized user input.
"""
from __future__ import annotations
from typing import List
from .base import BaseAnalyzer
from ..models import Finding

PATTERNS = [
    {
        "regex": r'os\.system\s*\(\s*(f["\']|["\'].*\+|.*request\.|.*req\.|.*input)',
        "title": "Command Injection via os.system()",
        "description": "os.system() called with user-controlled input. Attackers can inject shell commands using metacharacters like ;, &&, |, `backticks`.",
        "recommendation": "Never pass user input to os.system(). Use subprocess.run() with a list of arguments and shell=False.",
        "cwe_id": "CWE-78", "confidence": "HIGH",
        "references": ["https://owasp.org/www-community/attacks/Command_Injection"],
    },
    {
        "regex": r'subprocess\.(call|run|Popen|check_output|check_call)\s*\(.*shell\s*=\s*True',
        "title": "Command Injection via subprocess with shell=True",
        "description": "subprocess executed with shell=True allows shell metacharacter injection. When combined with user input, this is a critical command injection vector.",
        "recommendation": "Use shell=False (default) and pass arguments as a list: subprocess.run(['cmd', arg1, arg2], shell=False).",
        "cwe_id": "CWE-78", "confidence": "HIGH",
    },
    {
        "regex": r'(exec|eval)\s*\(\s*(.*request\.|.*req\.|.*input|.*params|.*user)',
        "title": "Code/Command Injection via exec()/eval()",
        "description": "exec() or eval() called with user-controlled input can execute arbitrary Python/JavaScript code on the server.",
        "recommendation": "Never use exec()/eval() with user input. Refactor to use safe alternatives like ast.literal_eval() for data parsing.",
        "cwe_id": "CWE-78", "confidence": "HIGH",
    },
    {
        "regex": r'(commands\.getoutput|commands\.getstatusoutput|popen)\s*\(',
        "title": "Deprecated Command Execution Function",
        "description": "Deprecated command execution function detected. These are insecure and should not be used.",
        "recommendation": "Replace with subprocess.run() with shell=False and explicit argument lists.",
        "cwe_id": "CWE-78", "confidence": "MEDIUM",
    },
    {
        "regex": r'`[^`]*(request|req|input|user|param)[^`]*`',
        "title": "Command Injection via Backtick Execution (Ruby/Shell)",
        "description": "Backtick command execution with user-controlled variables.",
        "recommendation": "Use safe APIs that don't invoke a shell. Validate and whitelist inputs strictly.",
        "cwe_id": "CWE-78", "confidence": "HIGH",
    },
    {
        "regex": r'(child_process\.exec|execSync|spawnSync)\s*\(\s*(.*\+|.*`.*\$\{|.*req\.|.*request\.)',
        "title": "Command Injection via child_process.exec (Node.js)",
        "description": "Node.js exec/execSync with user input is a classic command injection vector.",
        "recommendation": "Use child_process.spawn() with an argument array and avoid shell interpolation.",
        "cwe_id": "CWE-78", "confidence": "HIGH",
    },
    {
        "regex": r'Runtime\.getRuntime\(\)\.exec\s*\(',
        "title": "Command Injection via Runtime.exec() (Java)",
        "description": "Java Runtime.exec() can be vulnerable if command strings are built from user input.",
        "recommendation": "Use ProcessBuilder with a string array. Never concatenate user input into command strings.",
        "cwe_id": "CWE-78", "confidence": "MEDIUM",
    },
]

class CommandInjectionAnalyzer(BaseAnalyzer):
    name = "CommandInjectionAnalyzer"
    category = "OTHER"

    def analyze(self, file_path: str, content: str, language: str) -> List[Finding]:
        findings = self._scan_patterns(file_path, content, PATTERNS, severity="CRITICAL")
        for f in findings:
            f.category = "OTHER"
        return findings
