"""
PDF Report Generator — produces a high-contrast, professional security report PDF.
Uses ReportLab for pure-Python PDF generation.

Design: White/light background for maximum text readability in all PDF viewers.
Each finding includes the vulnerability description, vulnerable code snippet,
AND a complete fixed code example showing how to remediate.
"""

from __future__ import annotations
import os
from datetime import datetime
from typing import List
from ..models import Report, Finding

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, PageBreak, KeepTogether,
    )
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


# ── High-contrast Color Palette (light background for readability) ────────────
CLR_PAGE_BG     = colors.white                    # page background
CLR_HEADER_BG   = colors.HexColor("#1A1F2E")      # dark header/cover
CLR_SECTION_BG  = colors.HexColor("#F6F8FA")      # section backgrounds
CLR_ROW_ALT     = colors.HexColor("#EAECEF")      # alternating table rows
CLR_BORDER      = colors.HexColor("#D0D7DE")      # table borders

# Text colors (all on light backgrounds)
CLR_TEXT_DARK   = colors.HexColor("#0D1117")      # primary text — near-black
CLR_TEXT_BODY   = colors.HexColor("#24292F")      # body text
CLR_TEXT_DIM    = colors.HexColor("#57606A")      # secondary/muted text
CLR_HEADER_TEXT = colors.white                    # text on dark headers

# Severity colors (vivid, high-contrast)
CLR_CRITICAL    = colors.HexColor("#CF222E")      # deep red
CLR_HIGH        = colors.HexColor("#BC4C00")      # burnt orange
CLR_MEDIUM      = colors.HexColor("#9A6700")      # dark gold
CLR_LOW         = colors.HexColor("#116329")      # forest green
CLR_INFO        = colors.HexColor("#0550AE")      # deep blue

# Severity badge backgrounds
CLR_CRITICAL_BG = colors.HexColor("#FFEBE9")
CLR_HIGH_BG     = colors.HexColor("#FFF1E5")
CLR_MEDIUM_BG   = colors.HexColor("#FFF8C5")
CLR_LOW_BG      = colors.HexColor("#DCFFE4")
CLR_INFO_BG     = colors.HexColor("#DDF4FF")

# Code snippet backgrounds
CLR_CODE_BG     = colors.HexColor("#F6F8FA")      # light grey code bg
CLR_FIX_BG     = colors.HexColor("#E6FFEC")      # green-tinted fix bg

# Accent
CLR_ACCENT      = colors.HexColor("#0550AE")      # blue accent


SEVERITY_COLORS = {
    "CRITICAL": CLR_CRITICAL,
    "HIGH":     CLR_HIGH,
    "MEDIUM":   CLR_MEDIUM,
    "LOW":      CLR_LOW,
    "INFO":     CLR_INFO,
}

SEVERITY_BG_COLORS = {
    "CRITICAL": CLR_CRITICAL_BG,
    "HIGH":     CLR_HIGH_BG,
    "MEDIUM":   CLR_MEDIUM_BG,
    "LOW":      CLR_LOW_BG,
    "INFO":     CLR_INFO_BG,
}

SEVERITY_LABELS = {
    "CRITICAL": "CRITICAL",
    "HIGH":     "HIGH",
    "MEDIUM":   "MEDIUM",
    "LOW":      "LOW",
    "INFO":     "INFO",
}

# ── Fix code examples keyed by category ─────────────────────────────────────
FIX_EXAMPLES = {
    "SQL_INJECTION": {
        "python": (
            "# SECURE: Use parameterized queries\n"
            "cursor.execute(\n"
            "    'SELECT * FROM users WHERE id = %s',\n"
            "    (user_id,)  # tuple prevents injection\n"
            ")\n\n"
            "# SECURE: Using SQLAlchemy ORM\n"
            "user = session.query(User).filter_by(id=user_id).first()"
        ),
        "javascript": (
            "// SECURE: Parameterized query (mysql2)\n"
            "db.query(\n"
            "    'SELECT * FROM users WHERE id = ?',\n"
            "    [userId],   // values passed separately\n"
            "    (err, results) => { ... }\n"
            ");\n\n"
            "// SECURE: Using an ORM (Prisma/Sequelize)\n"
            "const user = await prisma.user.findUnique({ where: { id: userId } });"
        ),
        "default": (
            "// SECURE: Always use parameterized queries\n"
            "// Never concatenate or interpolate user input into SQL strings.\n"
            "// Use your language's database driver's parameter binding feature.\n"
            "// Example: db.query('SELECT ... WHERE id = ?', [userId])"
        ),
    },
    "XSS": {
        "javascript": (
            "// SECURE: Use textContent instead of innerHTML\n"
            "element.textContent = userInput;  // auto-escaped, safe\n\n"
            "// SECURE: If HTML needed, sanitize with DOMPurify\n"
            "import DOMPurify from 'dompurify';\n"
            "element.innerHTML = DOMPurify.sanitize(userInput);\n\n"
            "// SECURE: React — never use dangerouslySetInnerHTML with user data\n"
            "// Instead: <div>{userInput}</div>  ← React auto-escapes"
        ),
        "python": (
            "# SECURE: In Jinja2, use auto-escaping (default) — remove |safe\n"
            "# Bad:  {{ user_bio | safe }}\n"
            "# Good: {{ user_bio }}  ← auto-escaped\n\n"
            "# SECURE: In Django, avoid mark_safe() on user input\n"
            "from django.utils.html import escape\n"
            "safe_content = escape(user_input)  # escapes <, >, &, ', \""
        ),
        "default": (
            "// SECURE: Always escape user output before rendering in HTML\n"
            "// Use your framework's built-in escaping mechanisms.\n"
            "// Never insert untrusted data directly into HTML, JS, or CSS."
        ),
    },
    "HARDCODED_SECRET": {
        "python": (
            "# SECURE: Load secrets from environment variables\n"
            "import os\n"
            "from dotenv import load_dotenv\n\n"
            "load_dotenv()  # loads .env file\n"
            "API_KEY = os.environ['API_KEY']  # raises if missing\n"
            "DB_URL  = os.getenv('DATABASE_URL', 'sqlite:///dev.db')  # with default\n\n"
            "# SECURE: For production — use a secrets manager\n"
            "# AWS: boto3 / Secrets Manager\n"
            "# GCP: google-cloud-secret-manager\n"
            "# HashiCorp Vault: hvac library"
        ),
        "javascript": (
            "// SECURE: Load from environment variables\n"
            "const apiKey = process.env.API_KEY;\n"
            "if (!apiKey) throw new Error('API_KEY environment variable not set');\n\n"
            "// SECURE: Use dotenv for local development\n"
            "require('dotenv').config();\n"
            "const secret = process.env.JWT_SECRET;"
        ),
        "default": (
            "# SECURE: Move all credentials to environment variables\n"
            "# 1. Create a .env file (add to .gitignore!)\n"
            "#    API_KEY=your_actual_key_here\n"
            "# 2. Load at runtime, never hardcode\n"
            "# 3. Use a secrets manager in production\n"
            "# 4. Rotate any key that was already committed to git"
        ),
    },
    "PATH_TRAVERSAL": {
        "python": (
            "# SECURE: Validate paths against a safe base directory\n"
            "import os\n\n"
            "SAFE_DIR = '/var/app/uploads'\n\n"
            "def serve_file(user_filename: str) -> bytes:\n"
            "    # Resolve to absolute path, then check it's inside SAFE_DIR\n"
            "    safe_path = os.path.realpath(\n"
            "        os.path.join(SAFE_DIR, user_filename)\n"
            "    )\n"
            "    if not safe_path.startswith(SAFE_DIR + os.sep):\n"
            "        raise ValueError('Access denied: path traversal detected')\n"
            "    with open(safe_path, 'rb') as f:\n"
            "        return f.read()\n\n"
            "# SECURE: In Flask, use send_from_directory (validates automatically)\n"
            "from flask import send_from_directory\n"
            "return send_from_directory(SAFE_DIR, user_filename)"
        ),
        "javascript": (
            "// SECURE: Validate resolved path stays within base dir\n"
            "const path = require('path');\n\n"
            "const SAFE_DIR = '/var/app/uploads';\n\n"
            "function serveFile(userFilename) {\n"
            "    const resolved = path.resolve(SAFE_DIR, userFilename);\n"
            "    if (!resolved.startsWith(SAFE_DIR + path.sep)) {\n"
            "        throw new Error('Path traversal attempt detected');\n"
            "    }\n"
            "    return fs.readFileSync(resolved);\n"
            "}"
        ),
        "default": (
            "# SECURE: Path traversal prevention\n"
            "# 1. Resolve the full absolute path with realpath()\n"
            "# 2. Verify it starts with your allowed base directory\n"
            "# 3. Use framework helpers (send_from_directory in Flask, etc.)\n"
            "# 4. Prefer using whitelisted filenames over user-supplied paths"
        ),
    },
    "INSECURE_DEPENDENCY": {
        "default": (
            "# SECURE: Keep dependencies up to date\n\n"
            "# Check for vulnerabilities:\n"
            "#   pip install pip-audit && pip-audit\n"
            "#   npm audit\n"
            "#   npm audit fix\n\n"
            "# Update to fixed version as indicated in the finding.\n"
            "# Pin exact versions in production to prevent unexpected upgrades.\n\n"
            "# requirements.txt:\n"
            "#   lodash>=4.17.21    # minimum safe version\n\n"
            "# Enable Dependabot or Renovate for automated PR updates."
        ),
    },
    "CRYPTO_MISUSE": {
        "python": (
            "# SECURE: Modern hashing\n"
            "import hashlib, secrets\n\n"
            "# For data integrity: use SHA-256 or SHA-3\n"
            "checksum = hashlib.sha256(data).hexdigest()\n\n"
            "# For passwords: use bcrypt or argon2 (NEVER MD5/SHA1)\n"
            "from argon2 import PasswordHasher\n"
            "ph = PasswordHasher()\n"
            "hashed = ph.hash(password)       # secure hash\n"
            "ph.verify(hashed, password)       # secure verify\n\n"
            "# For random tokens: use secrets module\n"
            "token = secrets.token_hex(32)    # cryptographically secure\n\n"
            "# For symmetric encryption: use AES-GCM (authenticated)\n"
            "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
            "key = AESGCM.generate_key(bit_length=256)\n"
            "aesgcm = AESGCM(key)\n"
            "nonce = secrets.token_bytes(12)  # fresh nonce each time!\n"
            "ct = aesgcm.encrypt(nonce, plaintext, None)"
        ),
        "javascript": (
            "// SECURE: Use Node.js crypto with strong algorithms\n"
            "const crypto = require('crypto');\n\n"
            "// For data integrity: SHA-256\n"
            "const hash = crypto.createHash('sha256').update(data).digest('hex');\n\n"
            "// For passwords: bcrypt\n"
            "const bcrypt = require('bcrypt');\n"
            "const hashed = await bcrypt.hash(password, 12);  // 12 rounds\n"
            "const ok = await bcrypt.compare(password, hashed);\n\n"
            "// For random tokens: crypto.randomBytes\n"
            "const token = crypto.randomBytes(32).toString('hex');\n\n"
            "// For encryption: AES-256-GCM (authenticated)\n"
            "const key = crypto.randomBytes(32);\n"
            "const iv  = crypto.randomBytes(12);  // fresh IV every time!\n"
            "const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);"
        ),
        "default": (
            "# SECURE: Cryptography best practices\n"
            "# Hashing:    SHA-256 or SHA-3 (not MD5, not SHA-1)\n"
            "# Passwords:  bcrypt, argon2, or scrypt  (not any raw hash)\n"
            "# Encryption: AES-256-GCM (authenticated, not ECB)\n"
            "# Random:     OS-backed CSPRNG (secrets.token_hex, crypto.randomBytes)\n"
            "# Keys:       Min 2048-bit RSA, 256-bit AES, 256-bit EC\n"
            "# IV/Nonce:   Always fresh random per encryption operation"
        ),
    },
    "OTHER": {
        "default": (
            "// Consult the CWE reference and OWASP guidance\n"
            "// for remediation steps specific to this issue type."
        ),
    },
}


def _get_fix_example(finding: Finding) -> str:
    """Return the best-matched fix code example for a finding."""
    cat_fixes = FIX_EXAMPLES.get(finding.category, FIX_EXAMPLES.get("OTHER", {}))
    # Try to match language from file extension
    lang = "default"
    fp = finding.location.file.lower()
    if fp.endswith((".py", ".pyw")):
        lang = "python"
    elif fp.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs")):
        lang = "javascript"
    return cat_fixes.get(lang, cat_fixes.get("default", "// See recommendation above."))


# ── Main PDF generator ───────────────────────────────────────────────────────

def generate_pdf(report: Report, output_path: str) -> str:
    """
    Generate a high-contrast, professional PDF security report.
    Includes vulnerable code snippets AND fixed code examples for each finding.

    Args:
        report: The Report object
        output_path: File path to write the PDF to

    Returns:
        Absolute path of the written file
    """
    if not REPORTLAB_AVAILABLE:
        raise ImportError("reportlab is required. Run: pip install reportlab")

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    output_path = os.path.abspath(output_path)

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=22 * mm,
        bottomMargin=22 * mm,
        title=f"RLM Security Report — {report.source}",
        author="RLM Security Analysis System",
    )

    styles = _build_styles()
    story = []

    story += _cover_page(report, styles)
    story.append(PageBreak())

    story += _executive_summary(report, styles)
    story.append(PageBreak())

    story += _findings_section(report, styles)

    story.append(PageBreak())
    story += _file_matrix(report, styles)

    doc.build(story, onFirstPage=_add_header_footer, onLaterPages=_add_header_footer)
    return output_path


# ── Styles ───────────────────────────────────────────────────────────────────

def _build_styles() -> dict:
    return {
        "cover_title": ParagraphStyle(
            "cover_title",
            fontName="Helvetica-Bold", fontSize=30,
            textColor=CLR_HEADER_TEXT, alignment=TA_LEFT, spaceAfter=6,
            leading=34,
        ),
        "cover_sub": ParagraphStyle(
            "cover_sub",
            fontName="Helvetica", fontSize=13,
            textColor=colors.HexColor("#8B949E"), alignment=TA_LEFT, spaceAfter=4,
        ),
        "cover_dim": ParagraphStyle(
            "cover_dim",
            fontName="Helvetica", fontSize=9,
            textColor=colors.HexColor("#8B949E"), alignment=TA_LEFT, spaceAfter=2,
        ),
        "h1": ParagraphStyle(
            "h1",
            fontName="Helvetica-Bold", fontSize=17,
            textColor=CLR_ACCENT, spaceBefore=14, spaceAfter=6,
        ),
        "h2": ParagraphStyle(
            "h2",
            fontName="Helvetica-Bold", fontSize=12,
            textColor=CLR_TEXT_DARK, spaceBefore=10, spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "body",
            fontName="Helvetica", fontSize=10,
            textColor=CLR_TEXT_BODY, spaceAfter=5, leading=15,
        ),
        # Monospaced code — dark text on very light grey
        "code": ParagraphStyle(
            "code",
            fontName="Courier", fontSize=8,
            textColor=CLR_TEXT_DARK,  # BLACK text on light grey bg
            spaceAfter=4, leading=13,
            backColor=CLR_CODE_BG,
            leftIndent=6, rightIndent=6,
            borderPadding=4,
        ),
        # Fixed code — dark text on green-tinted bg
        "code_fix": ParagraphStyle(
            "code_fix",
            fontName="Courier", fontSize=8,
            textColor=colors.HexColor("#116329"),  # dark green text
            spaceAfter=4, leading=13,
            backColor=CLR_FIX_BG,
            leftIndent=6, rightIndent=6,
            borderPadding=4,
        ),
        "dim": ParagraphStyle(
            "dim",
            fontName="Helvetica", fontSize=8,
            textColor=CLR_TEXT_DIM, spaceAfter=3,
        ),
        "label": ParagraphStyle(
            "label",
            fontName="Helvetica-Bold", fontSize=8,
            textColor=CLR_ACCENT, spaceAfter=3,
            spaceBefore=4,
        ),
        "label_fix": ParagraphStyle(
            "label_fix",
            fontName="Helvetica-Bold", fontSize=8,
            textColor=CLR_LOW, spaceAfter=3,  # green label for fix sections
            spaceBefore=4,
        ),
        "table_header": ParagraphStyle(
            "table_header",
            fontName="Helvetica-Bold", fontSize=9,
            textColor=CLR_HEADER_TEXT,
        ),
        "table_cell": ParagraphStyle(
            "table_cell",
            fontName="Helvetica", fontSize=9,
            textColor=CLR_TEXT_BODY, leading=13,
        ),
    }


# ── Cover page ───────────────────────────────────────────────────────────────

def _cover_page(report: Report, styles: dict) -> list:
    s = report.summary
    elements = []

    # Dark header banner
    risk_color = CLR_CRITICAL if s.risk_score >= 70 else CLR_HIGH if s.risk_score >= 40 else CLR_MEDIUM if s.risk_score >= 15 else CLR_LOW

    header_data = [[
        Paragraph("RLM Security Report", styles["cover_title"]),
        Paragraph(
            f"<b>{s.risk_score}/100</b>",
            ParagraphStyle("rs", fontName="Helvetica-Bold", fontSize=28,
                           textColor=risk_color, alignment=TA_RIGHT, leading=32),
        ),
    ]]
    header_tbl = Table(header_data, colWidths=[115 * mm, 50 * mm])
    header_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), CLR_HEADER_BG),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (0, -1), 14),
        ("RIGHTPADDING", (-1, 0), (-1, -1), 14),
        ("TOPPADDING", (0, 0), (-1, -1), 18),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 18),
    ]))
    elements.append(header_tbl)

    # Metadata strip
    ts = report.timestamp.strftime("%Y-%m-%d %H:%M UTC")
    meta_data = [[
        Paragraph(f"<b>Source:</b> {_safe_text(report.source)}", styles["dim"]),
        Paragraph(f"<b>Scan ID:</b> {report.scan_id}", styles["dim"]),
        Paragraph(f"<b>Date:</b> {ts}", styles["dim"]),
    ]]
    meta_tbl = Table(meta_data, colWidths=[80 * mm, 60 * mm, 35 * mm])
    meta_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), CLR_SECTION_BG),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("BOX", (0, 0), (-1, -1), 0.5, CLR_BORDER),
    ]))
    elements.append(meta_tbl)
    elements.append(Spacer(1, 10 * mm))

    # Risk rating bar
    elements.append(Paragraph("Overall Risk Assessment", styles["h2"]))
    elements.append(HRFlowable(width="100%", color=CLR_BORDER, thickness=0.5))
    elements.append(Spacer(1, 4 * mm))

    risk_label = ("CRITICAL RISK" if s.risk_score >= 70 else
                  "HIGH RISK"     if s.risk_score >= 40 else
                  "MODERATE RISK" if s.risk_score >= 15 else "LOW RISK")

    rating_data = [[
        Paragraph("Risk Score", styles["dim"]),
        Paragraph(f"<b>{s.risk_score} / 100</b>", ParagraphStyle(
            "rm", fontName="Helvetica-Bold", fontSize=20,
            textColor=risk_color, alignment=TA_CENTER,
        )),
        Paragraph(f"<b>{risk_label}</b>", ParagraphStyle(
            "rl", fontName="Helvetica-Bold", fontSize=11,
            textColor=risk_color, alignment=TA_CENTER,
        )),
    ]]
    rating_tbl = Table(rating_data, colWidths=[30 * mm, 40 * mm, 50 * mm])
    rating_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), CLR_SECTION_BG),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("BOX", (0, 0), (-1, -1), 1, risk_color),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, CLR_BORDER),
    ]))
    elements.append(rating_tbl)
    elements.append(Spacer(1, 8 * mm))

    # Stats grid
    sev = s.by_severity
    grid_data = [
        [
            Paragraph("Files Scanned", styles["dim"]),
            Paragraph("Files w/ Issues", styles["dim"]),
            Paragraph("Total Findings", styles["dim"]),
            Paragraph("Critical", styles["dim"]),
            Paragraph("High", styles["dim"]),
            Paragraph("Medium", styles["dim"]),
        ],
        [
            Paragraph(f"<b>{s.total_files}</b>", ParagraphStyle("gn", fontName="Helvetica-Bold", fontSize=20, textColor=CLR_TEXT_DARK, alignment=TA_CENTER)),
            Paragraph(f"<b>{s.files_with_issues}</b>", ParagraphStyle("gn2", fontName="Helvetica-Bold", fontSize=20, textColor=CLR_HIGH, alignment=TA_CENTER)),
            Paragraph(f"<b>{s.total_findings}</b>", ParagraphStyle("gn3", fontName="Helvetica-Bold", fontSize=20, textColor=CLR_ACCENT, alignment=TA_CENTER)),
            Paragraph(f"<b>{sev.get('CRITICAL', 0)}</b>", ParagraphStyle("gn4", fontName="Helvetica-Bold", fontSize=20, textColor=CLR_CRITICAL, alignment=TA_CENTER)),
            Paragraph(f"<b>{sev.get('HIGH', 0)}</b>", ParagraphStyle("gn5", fontName="Helvetica-Bold", fontSize=20, textColor=CLR_HIGH, alignment=TA_CENTER)),
            Paragraph(f"<b>{sev.get('MEDIUM', 0)}</b>", ParagraphStyle("gn6", fontName="Helvetica-Bold", fontSize=20, textColor=CLR_MEDIUM, alignment=TA_CENTER)),
        ],
    ]
    cw = [165 / 6 * mm] * 6
    grid_tbl = Table(grid_data, colWidths=cw)
    grid_tbl.setStyle(TableStyle([
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BACKGROUND", (0, 0), (-1, -1), CLR_SECTION_BG),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("BOX", (0, 0), (-1, -1), 0.5, CLR_BORDER),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, CLR_BORDER),
        ("LINEABOVE", (0, 1), (-1, 1), 0.5, CLR_BORDER),
    ]))
    elements.append(grid_tbl)
    return elements


# ── Executive Summary ─────────────────────────────────────────────────────────

def _executive_summary(report: Report, styles: dict) -> list:
    s = report.summary
    elements = [Paragraph("Executive Summary", styles["h1"])]
    elements.append(HRFlowable(width="100%", color=CLR_ACCENT, thickness=1))
    elements.append(Spacer(1, 4 * mm))

    risk_text = ("critical risk" if s.risk_score >= 70 else
                 "high risk"     if s.risk_score >= 40 else
                 "moderate risk" if s.risk_score >= 15 else "low risk")

    summary_text = (
        f"The RLM Security Analysis System scanned <b>{s.total_files}</b> files from "
        f"<i>{_safe_text(report.source)}</i> and identified <b>{s.total_findings} security findings</b> "
        f"with a calculated risk score of <b>{s.risk_score}/100</b> ({risk_text}). "
        f"Of the {s.total_files} files analyzed, <b>{s.files_with_issues}</b> contained at least "
        f"one vulnerability. Immediate remediation is required for the "
        f"<b>{s.by_severity.get('CRITICAL', 0)} critical</b> and "
        f"<b>{s.by_severity.get('HIGH', 0)} high</b> severity findings."
    )
    elements.append(Paragraph(summary_text, styles["body"]))
    elements.append(Spacer(1, 6 * mm))

    # Category breakdown table
    elements.append(Paragraph("Findings by Category", styles["h2"]))
    cat_risk_map = {
        "SQL_INJECTION": ("HIGH", CLR_HIGH),
        "XSS": ("HIGH", CLR_HIGH),
        "HARDCODED_SECRET": ("CRITICAL", CLR_CRITICAL),
        "PATH_TRAVERSAL": ("HIGH", CLR_HIGH),
        "INSECURE_DEPENDENCY": ("MEDIUM", CLR_MEDIUM),
        "CRYPTO_MISUSE": ("MEDIUM", CLR_MEDIUM),
    }

    header = [
        Paragraph("Category", styles["table_header"]),
        Paragraph("Findings", styles["table_header"]),
        Paragraph("Risk Level", styles["table_header"]),
    ]
    cat_data = [header]
    for cat, count in sorted(s.by_category.items(), key=lambda x: -x[1]):
        risk_label, risk_clr = cat_risk_map.get(cat, ("MEDIUM", CLR_MEDIUM))
        cat_data.append([
            Paragraph(cat.replace("_", " ").title(), styles["table_cell"]),
            Paragraph(f"<b>{count}</b>", ParagraphStyle("cc", fontName="Helvetica-Bold", fontSize=9, textColor=CLR_TEXT_DARK, alignment=TA_CENTER)),
            Paragraph(f"<b>{risk_label}</b>", ParagraphStyle("rc", fontName="Helvetica-Bold", fontSize=9, textColor=risk_clr, alignment=TA_CENTER)),
        ])

    if len(cat_data) > 1:
        cat_tbl = Table(cat_data, colWidths=[95 * mm, 30 * mm, 50 * mm])
        row_bgs = []
        for i in range(1, len(cat_data)):
            bg = CLR_SECTION_BG if i % 2 == 1 else CLR_PAGE_BG
            row_bgs.extend([
                ("BACKGROUND", (0, i), (-1, i), bg),
            ])
        cat_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), CLR_HEADER_BG),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("ALIGN", (1, 0), (-1, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("BOX", (0, 0), (-1, -1), 0.5, CLR_BORDER),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, CLR_BORDER),
        ] + row_bgs))
        elements.append(cat_tbl)

    return elements


# ── Detailed Findings ─────────────────────────────────────────────────────────

def _findings_section(report: Report, styles: dict) -> list:
    elements = [Paragraph("Detailed Findings", styles["h1"])]
    elements.append(HRFlowable(width="100%", color=CLR_ACCENT, thickness=1))
    elements.append(Spacer(1, 4 * mm))

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_findings = sorted(
        report.all_findings,
        key=lambda f: severity_order.get(f.severity, 9),
    )

    if not sorted_findings:
        elements.append(Paragraph("No security findings detected.", styles["body"]))
        return elements

    for i, finding in enumerate(sorted_findings, 1):
        clr = SEVERITY_COLORS.get(finding.severity, CLR_INFO)
        bg_clr = SEVERITY_BG_COLORS.get(finding.severity, CLR_INFO_BG)
        sev_label = SEVERITY_LABELS.get(finding.severity, finding.severity)

        card = []

        # ── Finding header banner ──────────────────────────────────────────
        header_data = [[
            Paragraph(
                f"<b>#{i}  {_safe_text(finding.title)}</b>",
                ParagraphStyle("fh", fontName="Helvetica-Bold", fontSize=11,
                               textColor=CLR_HEADER_TEXT, leading=14),
            ),
            Paragraph(
                f"<b>{sev_label}</b>",
                ParagraphStyle("badge", fontName="Helvetica-Bold", fontSize=11,
                               textColor=clr, alignment=TA_RIGHT, leading=14),
            ),
        ]]
        header_tbl = Table(header_data, colWidths=[125 * mm, 45 * mm])
        header_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), CLR_HEADER_BG),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("LEFTPADDING", (0, 0), (0, 0), 10),
            ("RIGHTPADDING", (-1, 0), (-1, 0), 10),
            ("LINEBELOW", (0, 0), (-1, -1), 2.5, clr),
        ]))
        card.append(header_tbl)

        # ── Metadata row ───────────────────────────────────────────────────
        meta_items = [
            f"<b>File:</b> {_safe_text(finding.location.file)}:{finding.location.line_start}",
            f"<b>CWE:</b> {finding.cwe_id or 'N/A'}",
            f"<b>Confidence:</b> {finding.confidence}",
        ]
        meta_tbl = Table(
            [[Paragraph(item, styles["dim"]) for item in meta_items]],
            colWidths=[80 * mm, 40 * mm, 50 * mm],
        )
        meta_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), bg_clr),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("BOX", (0, 0), (-1, -1), 0.5, CLR_BORDER),
        ]))
        card.append(meta_tbl)
        card.append(Spacer(1, 2 * mm))

        # ── Description ────────────────────────────────────────────────────
        card.append(Paragraph("Description", styles["label"]))
        card.append(Paragraph(_safe_text(finding.description), styles["body"]))

        # ── Vulnerable code snippet ────────────────────────────────────────
        card.append(Paragraph("Vulnerable Code", styles["label"]))
        snippet = _safe_text(finding.code_snippet or "(no snippet available)")
        card.append(Paragraph(snippet, styles["code"]))

        # ── Recommendation ─────────────────────────────────────────────────
        card.append(Paragraph("Recommendation", styles["label"]))
        card.append(Paragraph(_safe_text(finding.recommendation), styles["body"]))

        # ── Fixed code example (NEW!) ──────────────────────────────────────
        fix_code = _get_fix_example(finding)
        card.append(Paragraph("Fix / Secure Code Example", styles["label_fix"]))
        card.append(Paragraph(_safe_text(fix_code), styles["code_fix"]))

        # ── References ─────────────────────────────────────────────────────
        if finding.references:
            card.append(Paragraph("References", styles["label"]))
            for ref in finding.references:
                card.append(Paragraph(f"  • {_safe_text(ref)}", styles["dim"]))

        card.append(Spacer(1, 5 * mm))
        card.append(HRFlowable(width="100%", color=CLR_BORDER, thickness=0.5))
        card.append(Spacer(1, 3 * mm))

        elements.append(KeepTogether(card))

    return elements


# ── File Matrix ───────────────────────────────────────────────────────────────

def _file_matrix(report: Report, styles: dict) -> list:
    elements = [Paragraph("File Scan Matrix", styles["h1"])]
    elements.append(HRFlowable(width="100%", color=CLR_ACCENT, thickness=1))
    elements.append(Spacer(1, 4 * mm))

    header_row = [
        Paragraph("File", styles["table_header"]),
        Paragraph("Language", styles["table_header"]),
        Paragraph("Lines", styles["table_header"]),
        Paragraph("Findings", styles["table_header"]),
        Paragraph("Duration", styles["table_header"]),
    ]
    data = [header_row]

    for r in sorted(report.file_results, key=lambda x: -len(x.findings)):
        fc = len(r.findings)
        fpath = r.file_path[-55:] if len(r.file_path) > 55 else r.file_path
        count_clr = CLR_CRITICAL if fc >= 5 else CLR_HIGH if fc >= 1 else CLR_LOW
        data.append([
            Paragraph(_safe_text(fpath), ParagraphStyle("fc", fontName="Courier", fontSize=8, textColor=CLR_TEXT_BODY)),
            Paragraph(_safe_text(r.language or "—"), styles["dim"]),
            Paragraph(str(r.lines_analyzed or 0), styles["dim"]),
            Paragraph(f"<b>{fc}</b>", ParagraphStyle("fcc", fontName="Helvetica-Bold", fontSize=9, textColor=count_clr, alignment=TA_CENTER)),
            Paragraph(f"{r.scan_duration_ms:.1f}ms" if r.scan_duration_ms else "—", styles["dim"]),
        ])

    row_bgs = []
    for i in range(1, len(data)):
        bg = CLR_SECTION_BG if i % 2 == 1 else CLR_PAGE_BG
        row_bgs.append(("BACKGROUND", (0, i), (-1, i), bg))

    tbl = Table(data, colWidths=[80 * mm, 26 * mm, 15 * mm, 20 * mm, 24 * mm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), CLR_HEADER_BG),
        ("ALIGN", (2, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("BOX", (0, 0), (-1, -1), 0.5, CLR_BORDER),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, CLR_BORDER),
    ] + row_bgs))
    elements.append(tbl)
    return elements


# ── Header / Footer ───────────────────────────────────────────────────────────

def _add_header_footer(canvas, doc):
    """Draw a clean header line and page footer on every page."""
    canvas.saveState()
    w, h = A4

    # Top border
    canvas.setStrokeColor(CLR_ACCENT)
    canvas.setLineWidth(1.5)
    canvas.line(18 * mm, h - 14 * mm, w - 18 * mm, h - 14 * mm)

    # Header right label
    canvas.setFillColor(CLR_TEXT_DIM)
    canvas.setFont("Helvetica", 7)
    canvas.drawRightString(w - 18 * mm, h - 11 * mm, "RLM Security Analysis Report")

    # Footer
    canvas.setFillColor(CLR_TEXT_DIM)
    canvas.setFont("Helvetica", 7)
    canvas.drawString(18 * mm, 13 * mm, "CONFIDENTIAL — RLM Security Analysis System")
    canvas.drawRightString(w - 18 * mm, 13 * mm, f"Page {doc.page}")

    # Bottom border
    canvas.setStrokeColor(CLR_BORDER)
    canvas.setLineWidth(0.5)
    canvas.line(18 * mm, 17 * mm, w - 18 * mm, 17 * mm)

    canvas.restoreState()


# ── Utility ───────────────────────────────────────────────────────────────────

def _safe_text(s: str) -> str:
    """Escape HTML special characters for ReportLab Paragraph."""
    if not s:
        return ""
    return (str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;"))
