from __future__ import annotations

from datetime import datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.lib.utils import ImageReader
from reportlab.platypus import Image, ListFlowable, ListItem, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

ROOT = Path(__file__).resolve().parent
ASSETS = ROOT / "report_assets"
UI_DIR = Path("/home/prathameshpendkar/Pictures/Screenshots")

BLUE_TITLE = colors.HexColor("#074994")
BLUE_SUB = colors.HexColor("#3067A6")
TEXT = colors.HexColor("#1c1c1c")

UI_IMAGES = [
    ("Screenshot from 2026-02-21 18-51-54.png", "Login and secure access page", "Users first authenticate with Gmail before entering the dashboard. This ensures sender identity and secure access control."),
    ("Screenshot from 2026-02-21 18-53-23.png", "Raw Input Processing tab", "Analyst pastes IP list here. The tool validates data, removes bad lines and duplicates, and prepares clean candidates for checks."),
    ("Screenshot from 2026-02-21 18-52-56.png", "Detected Threats analysis table", "Shows enriched threat data (abuse score, country, ISP, path) so analysts can make informed decisions quickly."),
    ("Screenshot from 2026-02-21 18-52-50.png", "Approval Actions and status updates", "Each IP can be approved/rejected individually. This keeps decisions transparent and auditable."),
    ("Screenshot from 2026-02-21 18-52-43.png", "Bulk approval and add-to-master action", "When ready, all approved IPs are added to the master block list in one safe bulk action."),
    ("Screenshot from 2026-02-21 18-53-09.png", "Master Blocking Sheet view", "Displays authoritative blocked records and historical entries for governance and review."),
    ("Screenshot from 2026-02-21 18-53-15.png", "Edit or delete master entries", "Allows correction of mistakes and lifecycle management of entries without manual spreadsheet work."),
    ("Screenshot from 2026-02-21 18-52-07.png", "Authenticated dashboard home", "Once logged in, users access the complete SOC workflow with clear tabs and guided steps."),
    ("Screenshot from 2026-02-21 18-52-34.png", "Whitelisted IPs and CIDR view", "Trusted IPs/ranges are protected from accidental blocking through a dedicated whitelist control panel."),
]


def scaled_image(path: Path, max_width: float, max_height: float) -> Image:
    reader = ImageReader(str(path))
    iw, ih = reader.getSize()
    ratio = min(max_width / iw, max_height / ih)
    width = iw * ratio
    height = ih * ratio
    return Image(str(path), width=width, height=height)


def build_report(output_pdf: Path) -> None:
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="CoverTitle", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=24, leading=30, textColor=BLUE_TITLE, alignment=1, spaceAfter=20))
    styles.add(ParagraphStyle(name="CoverSub", parent=styles["Normal"], fontName="Helvetica", fontSize=12, leading=16, textColor=TEXT, alignment=1))
    styles.add(ParagraphStyle(name="H1", parent=styles["Heading1"], fontName="Helvetica-Bold", fontSize=17, leading=22, textColor=BLUE_TITLE, spaceBefore=10, spaceAfter=8))
    styles.add(ParagraphStyle(name="H2", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=14, leading=18, textColor=BLUE_SUB, spaceBefore=8, spaceAfter=6))
    styles.add(ParagraphStyle(name="Body", parent=styles["Normal"], fontName="Helvetica", fontSize=10.5, leading=15, textColor=TEXT, spaceAfter=6))

    story = []

    story.append(Spacer(1, 1.3 * inch))
    story.append(Paragraph("SOC IP Governance Automation System", styles["CoverTitle"]))
    story.append(Paragraph("All-in-One Report: UI/UX, Features, Flow, Architecture, Statistics, Pros & Cons", styles["CoverSub"]))
    story.append(Spacer(1, 0.2 * inch))
    story.append(Paragraph(f"Date: {datetime.now().strftime('%d %B %Y')}", styles["CoverSub"]))
    story.append(Paragraph("Confidential", styles["CoverSub"]))
    story.append(PageBreak())

    story.append(Paragraph("1. Simple Overview (Layman Friendly)", styles["H1"]))
    story.append(Paragraph("This system helps SOC teams process suspicious IP addresses safely and quickly. Instead of checking everything manually, the platform automatically cleans data, checks threat score, shows approval options, and records final actions in the master block list.", styles["Body"]))
    story.append(Paragraph("In simple terms: paste IPs → system checks them → analyst approves → records are updated correctly.", styles["Body"]))

    story.append(Paragraph("2. End-to-End Flow", styles["H1"]))
    story.append(Paragraph("The flow diagram below explains how input data moves through validation, threat checks, and governance updates.", styles["Body"]))
    story.append(scaled_image(ASSETS / "flow_pipeline.png", max_width=6.8 * inch, max_height=3.5 * inch))

    story.append(Paragraph("3. Architecture (How the system is built)", styles["H1"]))
    story.append(Paragraph("The architecture is modular, so each component has a clear job. This makes the solution stable and easier to maintain.", styles["Body"]))
    story.append(scaled_image(ASSETS / "architecture_diagram.png", max_width=6.8 * inch, max_height=3.5 * inch))
    story.append(PageBreak())

    story.append(Paragraph("4. UI/UX Walkthrough with Screenshots", styles["H1"]))
    story.append(Paragraph("This section explains each screen in plain language for both technical and non-technical stakeholders.", styles["Body"]))

    for idx, (name, title, desc) in enumerate(UI_IMAGES, start=1):
        img_path = UI_DIR / name
        if not img_path.exists():
            continue
        story.append(Paragraph(f"4.{idx} {title}", styles["H2"]))
        story.append(Paragraph(desc, styles["Body"]))
        story.append(scaled_image(img_path, max_width=6.8 * inch, max_height=3.6 * inch))
        story.append(Spacer(1, 0.1 * inch))

    story.append(PageBreak())

    story.append(Paragraph("5. Main Features", styles["H1"]))
    features = [
        "Gmail-authenticated access for controlled usage",
        "IP validation (IPv4 and IPv6), invalid line removal, and deduplication",
        "Whitelist protection (individual IP and CIDR ranges)",
        "Already-blocked filtering using master sheet",
        "AbuseIPDB enrichment (score, country, ISP)",
        "Threat approval workflow with individual and bulk actions",
        "Master sheet management with edit/delete support",
        "SQLite tracking for scan and threat records",
        "Single-launch operation with Streamlit + ngrok",
    ]
    story.append(ListFlowable([ListItem(Paragraph(item, styles["Body"])) for item in features], bulletType="bullet"))

    story.append(Paragraph("6. Statistics and Efficiency", styles["H1"]))
    story.append(Paragraph("The chart below shows why this process is faster than manual handling. Most repetitive tasks are reduced significantly.", styles["Body"]))
    story.append(scaled_image(ASSETS / "efficiency_chart.png", max_width=6.6 * inch, max_height=3.3 * inch))

    stats_table = Table([
        ["What improves", "Impact"],
        ["Validation speed", "Automatic checks replace manual line-by-line review"],
        ["Accuracy", "Fewer human errors due to structured workflow"],
        ["Audit readiness", "All key actions are stored in SQLite + master records"],
        ["Decision quality", "Analyst sees score + country + ISP + path before approval"],
        ["Operational effort", "Bulk approval and update actions reduce repetitive clicks"],
    ], colWidths=[2.1 * inch, 4.5 * inch])
    stats_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E8F0FA")),
        ("TEXTCOLOR", (0, 0), (-1, 0), BLUE_TITLE),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 9.5),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#B7C7DD")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F7FAFF")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(stats_table)

    story.append(Paragraph("7. Pros and Cons", styles["H1"]))
    pros_cons = Table([
        ["Pros", "Cons"],
        ["Saves analyst time", "Depends on external APIs/services"],
        ["Simple UI for day-to-day SOC work", "Static ngrok endpoint can conflict if active elsewhere"],
        ["Improved traceability and governance", "Still passive mode (not direct firewall automation)"],
        ["Lower risk of accidental trusted-IP blocking", "Spreadsheet-based master source needs disciplined handling"],
    ], colWidths=[3.3 * inch, 3.3 * inch])
    pros_cons.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E8F0FA")),
        ("TEXTCOLOR", (0, 0), (-1, 0), BLUE_TITLE),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 9.3),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#B7C7DD")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F7FAFF")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(pros_cons)

    story.append(Paragraph("8. Conclusion", styles["H1"]))
    story.append(Paragraph("This solution makes SOC IP governance faster, safer, and easier to manage. The interface is straightforward for non-technical users, while the backend controls (validation, filtering, enrichment, audit storage) provide technical reliability for SOC teams.", styles["Body"]))

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
        title="SOC IP Governance Automation - All In One Report",
    )
    doc.build(story, onFirstPage=footer, onLaterPages=footer)


if __name__ == "__main__":
    output = ROOT / "SOC_IP_Governance_All_In_One_Report.pdf"
    build_report(output)
    print(output)
