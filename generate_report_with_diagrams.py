from __future__ import annotations

from datetime import datetime
from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Image, ListFlowable, ListItem, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

ROOT = Path(__file__).resolve().parent
ASSETS = ROOT / "report_assets"
ASSETS.mkdir(exist_ok=True)

BLUE_TITLE = colors.HexColor("#074994")
BLUE_SUB = colors.HexColor("#3067A6")
TEXT = colors.HexColor("#1c1c1c")


def draw_flow_diagram(path: Path) -> None:
    fig, ax = plt.subplots(figsize=(14, 7), dpi=180)
    ax.set_xlim(0, 16)
    ax.set_ylim(0, 10)
    ax.axis("off")

    boxes = [
        (0.7, 7.5, "Raw IP Input\n(Streamlit Text Area)"),
        (3.7, 7.5, "Validation +\nDeduplication"),
        (6.7, 7.5, "Whitelist +\nMaster Sheet Filtering"),
        (9.7, 7.5, "AbuseIPDB\nEnrichment"),
        (12.7, 7.5, "SQLite Upsert\n(Scan Results)"),
        (3.7, 4.5, "Threat Threshold\nEvaluation"),
        (6.7, 4.5, "Detected Threats\n(Pending Approval)"),
        (9.7, 4.5, "Approval Workflow +\nEmail Notification"),
        (12.7, 4.5, "Master Block Sheet\nUpdate"),
    ]

    def add_box(x: float, y: float, text: str, w: float = 2.5, h: float = 1.3) -> None:
        patch = FancyBboxPatch(
            (x, y), w, h,
            boxstyle="round,pad=0.08,rounding_size=0.08",
            linewidth=1.5,
            edgecolor="#3067A6",
            facecolor="#E8F0FA",
        )
        ax.add_patch(patch)
        ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=9.5, color="#1c1c1c")

    for x, y, txt in boxes:
        add_box(x, y, txt)

    arrows = [
        ((3.2, 8.15), (3.7, 8.15)),
        ((6.2, 8.15), (6.7, 8.15)),
        ((9.2, 8.15), (9.7, 8.15)),
        ((12.2, 8.15), (12.7, 8.15)),
        ((5.0, 7.5), (5.0, 5.8)),
        ((8.0, 7.5), (8.0, 5.8)),
        ((11.0, 7.5), (11.0, 5.8)),
        ((6.2, 5.15), (6.7, 5.15)),
        ((9.2, 5.15), (9.7, 5.15)),
        ((12.2, 5.15), (12.7, 5.15)),
    ]

    for start, end in arrows:
        ax.add_patch(FancyArrowPatch(start, end, arrowstyle="-|>", mutation_scale=12, color="#074994", linewidth=1.6))

    ax.text(0.7, 1.6, "Passive SOC governance pipeline: validate → enrich → approve → document", fontsize=10.5, color="#074994", weight="bold")
    fig.tight_layout()
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)


def draw_architecture_diagram(path: Path) -> None:
    fig, ax = plt.subplots(figsize=(14, 7), dpi=180)
    ax.set_xlim(0, 15)
    ax.set_ylim(0, 9)
    ax.axis("off")

    layers = [
        (0.8, 6.5, 3.0, 1.4, "Presentation Layer\nStreamlit UI (app.py)", "#E8F0FA"),
        (4.4, 6.5, 3.0, 1.4, "Processing Layer\nip_validator + whitelist\nmaster_sheet", "#EEF5FF"),
        (8.0, 6.5, 3.0, 1.4, "Intelligence Layer\nabuseipdb.py", "#E8F0FA"),
        (11.6, 6.5, 3.0, 1.4, "Persistence Layer\ndatabase.py (SQLite)", "#EEF5FF"),
        (2.6, 3.8, 3.6, 1.4, "Config & Security\nconfig.py + env/config.ini", "#F6F9FF"),
        (7.0, 3.8, 3.6, 1.4, "Notification Layer\nemail_notifier + gmail_auth", "#F6F9FF"),
        (11.4, 3.8, 3.0, 1.4, "External Integration\nAbuseIPDB + Gmail + ngrok", "#F6F9FF"),
    ]

    for x, y, w, h, txt, fc in layers:
        p = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.08,rounding_size=0.08", linewidth=1.4, edgecolor="#3067A6", facecolor=fc)
        ax.add_patch(p)
        ax.text(x + w / 2, y + h / 2, txt, ha="center", va="center", fontsize=9.2)

    lines = [
        ((3.8, 7.2), (4.4, 7.2)),
        ((7.4, 7.2), (8.0, 7.2)),
        ((11.0, 7.2), (11.6, 7.2)),
        ((5.9, 6.5), (4.4, 5.2)),
        ((9.5, 6.5), (8.8, 5.2)),
        ((12.8, 6.5), (12.8, 5.2)),
    ]

    for s, e in lines:
        ax.add_patch(FancyArrowPatch(s, e, arrowstyle="-|>", mutation_scale=12, color="#074994", linewidth=1.6))

    ax.text(0.8, 1.5, "Modular architecture: UI orchestration with isolated integration and persistence responsibilities", fontsize=10.5, color="#074994", weight="bold")
    fig.tight_layout()
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)


def draw_efficiency_chart(path: Path) -> None:
    tasks = ["Validation", "Dedup", "Whitelist Check", "Threat Lookup", "Approval Prep", "Master Update"]
    manual = [12, 8, 15, 30, 20, 10]
    automated = [2, 1, 2, 6, 8, 4]

    fig, ax = plt.subplots(figsize=(12, 6), dpi=180)
    idx = range(len(tasks))
    width = 0.36

    ax.bar([i - width/2 for i in idx], manual, width=width, label="Manual (mins)", color="#9DB4D5")
    ax.bar([i + width/2 for i in idx], automated, width=width, label="Automated (mins)", color="#3067A6")

    ax.set_xticks(list(idx))
    ax.set_xticklabels(tasks, rotation=15, ha="right")
    ax.set_ylabel("Estimated Time (minutes)")
    ax.set_title("Operational Efficiency Comparison", color="#074994", fontsize=14, weight="bold")
    ax.grid(axis="y", alpha=0.2)
    ax.legend()
    fig.tight_layout()
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)


def build_pdf(output_pdf: Path) -> None:
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="CoverTitle", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=24, leading=30, textColor=BLUE_TITLE, alignment=1, spaceAfter=20))
    styles.add(ParagraphStyle(name="CoverSub", parent=styles["Normal"], fontName="Helvetica", fontSize=12, leading=16, textColor=TEXT, alignment=1))
    styles.add(ParagraphStyle(name="H1", parent=styles["Heading1"], fontName="Helvetica-Bold", fontSize=17, leading=22, textColor=BLUE_TITLE, spaceBefore=10, spaceAfter=8))
    styles.add(ParagraphStyle(name="H2", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=14, leading=18, textColor=BLUE_SUB, spaceBefore=8, spaceAfter=6))
    styles.add(ParagraphStyle(name="Body", parent=styles["Normal"], fontName="Helvetica", fontSize=10.5, leading=15, textColor=TEXT, spaceAfter=6))

    story = []
    story.append(Spacer(1, 1.4 * inch))
    story.append(Paragraph("SOC IP Governance Automation System", styles["CoverTitle"]))
    story.append(Paragraph("Detailed Technical Report with Flow Diagrams and Visual Explanations", styles["CoverSub"]))
    story.append(Spacer(1, 0.25 * inch))
    story.append(Paragraph(f"Date: {datetime.now().strftime('%d %B %Y')}", styles["CoverSub"]))
    story.append(Paragraph("Classification: Confidential", styles["CoverSub"]))
    story.append(PageBreak())

    story.append(Paragraph("1. System Overview", styles["H1"]))
    story.append(Paragraph("This SOC IP Governance Automation platform standardizes passive SOC IP handling by combining validation, enrichment, approval, and documentation in one guided workflow. It reduces repetitive manual effort and improves consistency, traceability, and operational control.", styles["Body"]))

    story.append(Paragraph("2. End-to-End Flow Diagram", styles["H1"]))
    story.append(Paragraph("The following flow diagram shows how raw input moves through validation, threat intelligence enrichment, approval gates, and final master-sheet governance updates.", styles["Body"]))
    story.append(Image(str(ASSETS / "flow_pipeline.png"), width=6.8 * inch, height=3.3 * inch))

    story.append(Paragraph("3. Architecture Diagram", styles["H1"]))
    story.append(Paragraph("The architecture is modular to keep responsibilities isolated (UI, processing, integrations, persistence, notifications), making the system easier to maintain and extend.", styles["Body"]))
    story.append(Image(str(ASSETS / "architecture_diagram.png"), width=6.8 * inch, height=3.3 * inch))
    story.append(PageBreak())

    story.append(Paragraph("4. Key Features", styles["H1"]))
    feat = [
        "Strict IPv4/IPv6 input validation and invalid entry isolation",
        "Duplicate removal while preserving original input order",
        "Whitelist filtering with individual IP and CIDR support",
        "Already-blocked filtering from authoritative master sheet",
        "AbuseIPDB enrichment with retry/backoff and 429 handling",
        "SQLite persistence for scan results and detected threats",
        "Approval workflow with status updates and email notifications",
        "Single-command launch and static ngrok public URL support",
    ]
    story.append(ListFlowable([ListItem(Paragraph(f, styles["Body"])) for f in feat], bulletType="bullet"))

    story.append(Paragraph("5. Efficiency Visualization", styles["H1"]))
    story.append(Paragraph("The chart below compares estimated analyst effort for manual handling versus current automated workflow. Actual timings vary with volume and API response time, but the reduction trend is significant.", styles["Body"]))
    story.append(Image(str(ASSETS / "efficiency_chart.png"), width=6.6 * inch, height=3.2 * inch))

    story.append(Paragraph("6. Pros and Cons", styles["H1"]))
    data = [
        ["Pros", "Cons"],
        ["High reduction in repetitive SOC effort", "Depends on external services (AbuseIPDB/ngrok/Gmail)"],
        ["Consistent governance and auditability via SQLite + structured CSV", "Static ngrok domain may conflict if another session is active"],
        ["Improved decision context (score, country, ISP, path)", "Passive mode: no direct firewall automation"],
        ["Simple onboarding via one-click launcher", "CSV can be sensitive to concurrent manual edits"],
    ]
    tbl = Table(data, colWidths=[3.3 * inch, 3.3 * inch])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E8F0FA")),
        ("TEXTCOLOR", (0, 0), (-1, 0), BLUE_TITLE),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 9.3),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#B7C7DD")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F7FAFF")]),
    ]))
    story.append(tbl)

    story.append(Paragraph("7. Process Simplification Impact", styles["H1"]))
    story.append(Paragraph("The automation consolidates multiple tools and manual lookups into one governed SOC interface. Analysts can process candidate IPs, validate risk, and complete approval documentation significantly faster with fewer transcription errors.", styles["Body"]))

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(TEXT)
        canvas.drawString(inch, 0.5 * inch, "SOC IP Governance Automation | Confidential")
        canvas.drawRightString(A4[0] - inch, 0.5 * inch, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(
        str(output_pdf),
        pagesize=A4,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        topMargin=0.8 * inch,
        bottomMargin=0.8 * inch,
    )
    doc.build(story, onFirstPage=footer, onLaterPages=footer)


def main() -> None:
    draw_flow_diagram(ASSETS / "flow_pipeline.png")
    draw_architecture_diagram(ASSETS / "architecture_diagram.png")
    draw_efficiency_chart(ASSETS / "efficiency_chart.png")

    output_pdf = ROOT / "SOC_IP_Governance_Detailed_Report_With_Diagrams.pdf"
    build_pdf(output_pdf)
    print(output_pdf)


if __name__ == "__main__":
    main()
