import os
import json
import uuid
from datetime import datetime
import gradio as gr
from rlm.core import RootAgent
from rlm.input import load_zip

# ── Styles ──────────────────────────────────────────────────────────────
theme = gr.themes.Soft(
    primary_hue="indigo",
    secondary_hue="blue",
    neutral_hue="slate",
    text_size="lg",
    spacing_size="lg",
    radius_size="lg",
)

css = """
h1 {text-align: center; color: #4F46E5; margin-bottom: 0;}
h3 {text-align: center; color: #6B7280; font-weight: 300; margin-top: 0;}
.finding-box { border-left: 4px solid #ef4444; padding: 10px; margin-bottom: 10px; background: #fef2f2; border-radius: 4px; }
.finding-box.HIGH { border-left-color: #f97316; background: #fff7ed; }
.finding-box.MEDIUM { border-left-color: #eab308; background: #fefce8; }
.finding-box.LOW { border-left-color: #22c55e; background: #f0fdf4; }
.finding-box.INFO { border-left-color: #3b82f6; background: #eff6ff; }
.finding-title { font-weight: bold; margin-bottom: 5px; color: #111827; }
.finding-desc { margin-bottom: 5px; color: #374151; }
.finding-rec { font-weight: 500; color: #1e40af; }
.stat-card { text-align: center; padding: 20px; border-radius: 8px; background: #ffffff; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
.stat-value { font-size: 2em; font-weight: bold; color: #4F46E5; }
.stat-label { font-size: 0.9em; color: #6B7280; text-transform: uppercase; letter-spacing: 1px; }
"""

# ── Handlers ─────────────────────────────────────────────────────────────

def render_report(report) -> str:
    s = report.summary
    risk_color = "#ef4444" if s.risk_score >= 70 else "#eab308" if s.risk_score >= 40 else "#22c55e"
    
    html = f"""
    <div style="display: flex; gap: 20px; margin-bottom: 30px;">
        <div class="stat-card" style="flex: 1;">
            <div class="stat-label">Risk Score</div>
            <div class="stat-value" style="color: {risk_color}">{s.risk_score}/100</div>
        </div>
        <div class="stat-card" style="flex: 1;">
            <div class="stat-label">Total Findings</div>
            <div class="stat-value">{s.total_findings}</div>
        </div>
        <div class="stat-card" style="flex: 1;">
            <div class="stat-label">Critical / High</div>
            <div class="stat-value" style="color: #ef4444">{s.by_severity.get("CRITICAL", 0)} / {s.by_severity.get("HIGH", 0)}</div>
        </div>
    </div>
    """

    for f_result in report.file_results:
        if not f_result.findings:
            continue
        html += f"<h3 style='text-align: left; margin-top: 20px; border-bottom: 1px solid #e5e7eb; padding-bottom: 10px;'>📄 {f_result.file_path}</h3>"
        for f in f_result.findings:
            sev_class = f.severity
            html += f"""
            <div class="finding-box {sev_class}">
                <div class="finding-title" style="font-size: 1.1em; color: #1f2937;">🔴 {f.title}</div>
                <div style="margin-top: 8px;">
                    <strong style="color: #4b5563;">🤔 What is the bug?</strong>
                    <div class="finding-desc" style="margin-top: 2px;">{f.description}</div>
                </div>
                <div style="margin-top: 8px;">
                    <strong style="color: #4b5563;">✅ How to fix it:</strong>
                    <div class="finding-rec" style="margin-top: 2px;">{f.recommendation}</div>
                </div>
            </div>
            """
    return html



def run_static(file_obj):
    if file_obj is None:
        return "⚠️ Please upload a ZIP file.", None
    
    try:
        files = load_zip(file_obj.name)
        if not files:
            return "⚠️ No valid source files found in ZIP.", None, None
            
        agent = RootAgent(max_workers=4)
        report = agent.scan(files, source=file_obj.name, source_type="zip")
        
        # Deduplicate findings by title and line number
        for f_result in report.file_results:
            seen = set()
            unique_findings = []
            for finding in f_result.findings:
                key = (finding.title, finding.location.line_start if finding.location else 0)
                if key not in seen:
                    seen.add(key)
                    unique_findings.append(finding)
            f_result.findings = unique_findings
            
        # Re-calculate summary after deduplication
        report.summary = agent._build_summary(report.file_results)
        
        # Generate PDF
        try:
            from rlm.output import generate_pdf
            import tempfile
            pdf_path = os.path.join(tempfile.gettempdir(), f"scan_report_{uuid.uuid4().hex[:8]}.pdf")
            generate_pdf(report, pdf_path)
            pdf_out = pdf_path
        except Exception as e:
            print("PDF generation error:", e)
            pdf_out = None
        
        return render_report(report), report.model_dump_json(indent=2), pdf_out
    except Exception as e:
        return f"<div style='color: red; padding: 20px;'>❌ Error during static scan: {str(e)}</div>", None, None


# ── UI Layout ────────────────────────────────────────────────────────────

with gr.Blocks(theme=theme, css=css, title="RLM Security Scanner") as demo:
    gr.HTML("<h1>🔒 RLM Security Scanner</h1>")
    gr.HTML("<h3>Source Code Vulnerability Scanner (SAST)</h3>")
    
    with gr.Tabs():
        # Static Tab
        with gr.Tab("📁 Source Code Scanner"):
            gr.Markdown("Upload a `.zip` file containing your source code to scan it against our deep vulnerability analyzers.")
            file_input = gr.File(label="Upload Project ZIP", file_types=[".zip"])
            static_btn = gr.Button("🚀 Start Scan", variant="primary")
            
    # Results Area
    gr.Markdown("---")
    gr.HTML("<h2 style='text-align: center;'>📊 Scan Results</h2>")
    
    with gr.Tabs():
        with gr.Tab("Dashboard View"):
            results_html = gr.HTML("<div style='text-align: center; color: #6B7280; padding: 40px;'>Results will appear here after scanning.</div>")
        with gr.Tab("Raw JSON Report"):
            results_json = gr.Code(language="json", label="JSON Report")
        with gr.Tab("Download PDF"):
            results_pdf = gr.File(label="Download PDF Report")

    # Wire up buttons
    static_btn.click(fn=run_static, inputs=[file_input], outputs=[results_html, results_json, results_pdf])


if __name__ == "__main__":
    # Render assigns a port dynamically via the PORT environment variable
    port = int(os.environ.get("PORT", 7860))
    demo.launch(server_name="0.0.0.0", server_port=port)


