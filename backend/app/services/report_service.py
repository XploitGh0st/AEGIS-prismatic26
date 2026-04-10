"""
Report Service — generates professional PDF investigation reports using reportlab.

Each report contains:
1. Cover page with AEGIS branding
2. Executive Summary
3. Incident Metadata
4. Entity Inventory
5. Attack Timeline
6. MITRE ATT&CK Mapping
7. Correlation Analysis
8. Observed Facts
9. Root Cause Hypothesis
10. Recommended Actions
11. MemPalace Context (if available)
12. Raw Evidence Appendix
"""

from __future__ import annotations

import io
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.core.logging import get_logger

log = get_logger("report")

# ── Color palette ────────────────────────────────────────
AEGIS_DARK = colors.HexColor("#0a0e1a")
AEGIS_PANEL = colors.HexColor("#111827")
AEGIS_CYAN = colors.HexColor("#27f5ff")
AEGIS_PINK = colors.HexColor("#ff2fbf")
AEGIS_PURPLE = colors.HexColor("#8e4dff")
AEGIS_WHITE = colors.HexColor("#f1f5f9")
AEGIS_GRAY = colors.HexColor("#94a3b8")
AEGIS_BORDER = colors.HexColor("#1e293b")
SEVERITY_COLORS = {
    "critical": colors.HexColor("#ff4d6d"),
    "high": colors.HexColor("#ffb020"),
    "medium": colors.HexColor("#27f5ff"),
    "low": colors.HexColor("#8bff3a"),
}

# ── Custom styles ────────────────────────────────────────
def _build_styles():
    """Create custom paragraph styles."""
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name="CoverTitle",
        fontSize=36,
        leading=42,
        textColor=AEGIS_WHITE,
        alignment=TA_CENTER,
        fontName="Helvetica-Bold",
        spaceAfter=12,
    ))
    styles.add(ParagraphStyle(
        name="CoverSubtitle",
        fontSize=14,
        leading=20,
        textColor=AEGIS_CYAN,
        alignment=TA_CENTER,
        fontName="Helvetica",
        spaceAfter=8,
    ))
    styles.add(ParagraphStyle(
        name="CoverMeta",
        fontSize=11,
        leading=16,
        textColor=AEGIS_GRAY,
        alignment=TA_CENTER,
        fontName="Helvetica",
    ))
    styles.add(ParagraphStyle(
        name="SectionTitle",
        fontSize=18,
        leading=24,
        textColor=AEGIS_CYAN,
        fontName="Helvetica-Bold",
        spaceBefore=24,
        spaceAfter=10,
        borderWidth=0,
        borderPadding=0,
    ))
    styles.add(ParagraphStyle(
        name="SubSectionTitle",
        fontSize=13,
        leading=18,
        textColor=AEGIS_WHITE,
        fontName="Helvetica-Bold",
        spaceBefore=14,
        spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        name="BodyText2",
        fontSize=10,
        leading=15,
        textColor=AEGIS_WHITE,
        fontName="Helvetica",
        alignment=TA_JUSTIFY,
        spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        name="BulletItem",
        fontSize=10,
        leading=15,
        textColor=AEGIS_WHITE,
        fontName="Helvetica",
        leftIndent=18,
        spaceAfter=4,
        bulletFontName="Helvetica",
        bulletFontSize=10,
        bulletIndent=6,
    ))
    styles.add(ParagraphStyle(
        name="CodeText",
        fontSize=9,
        leading=13,
        textColor=AEGIS_CYAN,
        fontName="Courier",
        leftIndent=12,
        spaceAfter=4,
    ))
    styles.add(ParagraphStyle(
        name="MetaLabel",
        fontSize=9,
        leading=13,
        textColor=AEGIS_GRAY,
        fontName="Helvetica",
    ))
    styles.add(ParagraphStyle(
        name="MetaValue",
        fontSize=10,
        leading=14,
        textColor=AEGIS_WHITE,
        fontName="Helvetica-Bold",
    ))
    styles.add(ParagraphStyle(
        name="FooterStyle",
        fontSize=8,
        leading=10,
        textColor=AEGIS_GRAY,
        fontName="Helvetica",
        alignment=TA_CENTER,
    ))
    return styles


# ── Page backgrounds ─────────────────────────────────────
def _cover_page_bg(canvas, doc):
    """Draw the cover page background."""
    w, h = A4
    canvas.saveState()
    canvas.setFillColor(AEGIS_DARK)
    canvas.rect(0, 0, w, h, fill=1)

    # Top accent line
    canvas.setStrokeColor(AEGIS_CYAN)
    canvas.setLineWidth(3)
    canvas.line(40, h - 40, w - 40, h - 40)

    # Bottom accent
    canvas.setStrokeColor(AEGIS_PINK)
    canvas.setLineWidth(2)
    canvas.line(40, 60, w - 40, 60)

    # Footer
    canvas.setFillColor(AEGIS_GRAY)
    canvas.setFont("Helvetica", 8)
    canvas.drawCentredString(w / 2, 35, f"AEGIS Investigation Report • Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
    canvas.drawCentredString(w / 2, 24, "CONFIDENTIAL — FOR AUTHORIZED PERSONNEL ONLY")
    canvas.restoreState()


def _content_page_bg(canvas, doc):
    """Draw the content page background."""
    w, h = A4
    canvas.saveState()
    canvas.setFillColor(AEGIS_DARK)
    canvas.rect(0, 0, w, h, fill=1)

    # Top bar
    canvas.setStrokeColor(AEGIS_BORDER)
    canvas.setLineWidth(1)
    canvas.line(40, h - 35, w - 40, h - 35)

    # Header
    canvas.setFillColor(AEGIS_CYAN)
    canvas.setFont("Helvetica-Bold", 9)
    canvas.drawString(40, h - 28, "AEGIS INVESTIGATION REPORT")

    canvas.setFillColor(AEGIS_GRAY)
    canvas.setFont("Helvetica", 8)
    canvas.drawRightString(w - 40, h - 28, f"Page {doc.page}")

    # Footer
    canvas.setStrokeColor(AEGIS_BORDER)
    canvas.line(40, 40, w - 40, 40)
    canvas.setFillColor(AEGIS_GRAY)
    canvas.setFont("Helvetica", 7)
    canvas.drawCentredString(w / 2, 28, "CONFIDENTIAL • AEGIS Cybersecurity Incident Triage Platform")
    canvas.restoreState()


# ── Report generation ────────────────────────────────────

def generate_incident_pdf(
    incident_detail: dict,
    rca_bundle: dict,
) -> bytes:
    """
    Generate a comprehensive PDF investigation report.

    Args:
        incident_detail: Full incident detail dict (from API response)
        rca_bundle: RCA bundle dict (from rca_service.build_rca_bundle)

    Returns:
        PDF file as bytes
    """
    buffer = io.BytesIO()
    styles = _build_styles()
    w, h = A4

    doc = BaseDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=40,
        rightMargin=40,
        topMargin=50,
        bottomMargin=55,
    )

    # Page templates
    cover_frame = Frame(40, 55, w - 80, h - 110, id="cover")
    content_frame = Frame(40, 55, w - 80, h - 110, id="content")

    doc.addPageTemplates([
        PageTemplate(id="cover", frames=[cover_frame], onPage=_cover_page_bg),
        PageTemplate(id="content", frames=[content_frame], onPage=_content_page_bg),
    ])

    story = []

    # ── 1. Cover Page ────────────────────────────────────
    story.append(Spacer(1, 120))
    story.append(Paragraph("AEGIS", styles["CoverTitle"]))
    story.append(Spacer(1, 8))
    story.append(Paragraph("CYBERSECURITY INVESTIGATION REPORT", styles["CoverSubtitle"]))
    story.append(Spacer(1, 30))

    inc_number = incident_detail.get("incident_number", "N/A")
    title = incident_detail.get("title", "Untitled Incident")
    severity = incident_detail.get("severity", "unknown").upper()
    classification = incident_detail.get("classification", "unknown")
    score = incident_detail.get("severity_score", 0)

    story.append(Paragraph(f"Incident: {inc_number}", styles["CoverMeta"]))
    story.append(Spacer(1, 6))
    story.append(Paragraph(title, styles["CoverSubtitle"]))
    story.append(Spacer(1, 20))
    story.append(Paragraph(f"Classification: {classification.replace('_', ' ').title()}", styles["CoverMeta"]))
    story.append(Paragraph(f"Severity: {severity} (Score: {score}/100)", styles["CoverMeta"]))
    story.append(Spacer(1, 8))
    story.append(Paragraph(f"Status: {incident_detail.get('status', 'new').replace('_', ' ').title()}", styles["CoverMeta"]))
    story.append(Spacer(1, 30))

    first_seen = incident_detail.get("first_seen_at", "")
    last_seen = incident_detail.get("last_seen_at", "")
    story.append(Paragraph(f"First Seen: {first_seen}", styles["CoverMeta"]))
    story.append(Paragraph(f"Last Seen: {last_seen}", styles["CoverMeta"]))
    story.append(Paragraph(f"Report Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}", styles["CoverMeta"]))

    story.append(NextPageTemplate("content"))
    story.append(PageBreak())

    # ── 2. Executive Summary ─────────────────────────────
    story.append(Paragraph("1. EXECUTIVE SUMMARY", styles["SectionTitle"]))
    summaries = incident_detail.get("summaries", [])
    if summaries:
        latest = summaries[0]
        exec_text = latest.get("executive_summary", "No summary available.")
        story.append(Paragraph(exec_text, styles["BodyText2"]))

        root_cause = latest.get("root_cause")
        if root_cause:
            story.append(Spacer(1, 6))
            story.append(Paragraph("Root Cause Hypothesis:", styles["SubSectionTitle"]))
            story.append(Paragraph(root_cause, styles["BodyText2"]))

        confidence = latest.get("confidence_notes")
        if confidence:
            story.append(Spacer(1, 4))
            story.append(Paragraph(f"<i>Confidence: {confidence}</i>", styles["MetaLabel"]))
    else:
        # Use RCA bundle deterministic content
        rca_facts = rca_bundle.get("observed_facts", [])
        root_cause = rca_bundle.get("root_cause_hypothesis", "")
        story.append(Paragraph(
            f"This {severity.lower()}-severity {classification.replace('_', ' ')} incident "
            f"involves {incident_detail.get('alert_count', 0)} correlated alerts. "
            f"{root_cause}",
            styles["BodyText2"]
        ))

    # ── 3. Incident Metadata ─────────────────────────────
    story.append(Paragraph("2. INCIDENT METADATA", styles["SectionTitle"]))

    meta_data = [
        ["Field", "Value"],
        ["Incident Number", inc_number],
        ["Title", title],
        ["Classification", classification.replace("_", " ").title()],
        ["Severity", f"{severity} (Score: {score})"],
        ["Confidence", f"{incident_detail.get('confidence', 0):.0%}"],
        ["Status", incident_detail.get("status", "new").replace("_", " ").title()],
        ["Alert Count", str(incident_detail.get("alert_count", 0))],
        ["Primary User", incident_detail.get("primary_user") or "—"],
        ["Primary Host", incident_detail.get("primary_host") or "—"],
        ["Primary Source IP", incident_detail.get("primary_src_ip") or "—"],
        ["Primary Destination IP", incident_detail.get("primary_dst_ip") or "—"],
        ["First Seen", first_seen or "—"],
        ["Last Seen", last_seen or "—"],
        ["Source Families", ", ".join(incident_detail.get("source_families") or [])],
    ]

    meta_table = Table(meta_data, colWidths=[150, 360])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), AEGIS_BORDER),
        ("TEXTCOLOR", (0, 0), (-1, 0), AEGIS_CYAN),
        ("TEXTCOLOR", (0, 1), (0, -1), AEGIS_GRAY),
        ("TEXTCOLOR", (1, 1), (1, -1), AEGIS_WHITE),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [AEGIS_DARK, AEGIS_PANEL]),
        ("GRID", (0, 0), (-1, -1), 0.5, AEGIS_BORDER),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(meta_table)

    # Scoring breakdown
    scoring = incident_detail.get("scoring_breakdown")
    if scoring:
        story.append(Paragraph("Scoring Breakdown:", styles["SubSectionTitle"]))
        for key, value in scoring.items():
            story.append(Paragraph(f"• {key}: {value}", styles["BulletItem"]))

    # ── 4. Entity Inventory ──────────────────────────────
    story.append(Paragraph("3. ENTITY INVENTORY", styles["SectionTitle"]))
    entities = rca_bundle.get("entities", {})

    entity_sections = [
        ("Users", entities.get("users", [])),
        ("Hosts", entities.get("hosts", [])),
        ("Source IPs", entities.get("source_ips", [])),
        ("Destination IPs", entities.get("destination_ips", [])),
        ("Sessions", entities.get("sessions", [])),
    ]

    for label, items in entity_sections:
        if items:
            story.append(Paragraph(f"{label}:", styles["SubSectionTitle"]))
            for item in items:
                story.append(Paragraph(f"• {item}", styles["BulletItem"]))

    # ── 5. Attack Timeline ───────────────────────────────
    story.append(Paragraph("4. ATTACK TIMELINE", styles["SectionTitle"]))
    timeline = rca_bundle.get("timeline", [])

    if timeline:
        tl_data = [["Time", "Source", "Event", "Severity"]]
        for entry in timeline:
            t = entry.get("time", "")
            if len(t) > 19:
                t = t[:19]
            tl_data.append([
                t,
                entry.get("source", ""),
                entry.get("event", "")[:50],
                entry.get("severity", ""),
            ])

        tl_table = Table(tl_data, colWidths=[120, 60, 240, 60])
        tl_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), AEGIS_BORDER),
            ("TEXTCOLOR", (0, 0), (-1, 0), AEGIS_CYAN),
            ("TEXTCOLOR", (0, 1), (-1, -1), AEGIS_WHITE),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [AEGIS_DARK, AEGIS_PANEL]),
            ("GRID", (0, 0), (-1, -1), 0.5, AEGIS_BORDER),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(tl_table)

        # Commands executed
        commands = [e.get("command") for e in timeline if e.get("command")]
        if commands:
            story.append(Paragraph("Commands Observed:", styles["SubSectionTitle"]))
            for cmd in commands[:20]:
                story.append(Paragraph(cmd, styles["CodeText"]))
    else:
        story.append(Paragraph("No timeline events available.", styles["BodyText2"]))

    # ── 6. MITRE ATT&CK Mapping ─────────────────────────
    story.append(Paragraph("5. MITRE ATT&CK MAPPING", styles["SectionTitle"]))
    mitre = rca_bundle.get("mitre_techniques", [])

    if mitre:
        mitre_data = [["Technique ID", "Name"]]
        for tech in mitre:
            mitre_data.append([
                tech.get("id", ""),
                tech.get("name", "Unknown"),
            ])

        mitre_table = Table(mitre_data, colWidths=[120, 390])
        mitre_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), AEGIS_BORDER),
            ("TEXTCOLOR", (0, 0), (-1, 0), AEGIS_CYAN),
            ("TEXTCOLOR", (0, 1), (-1, -1), AEGIS_WHITE),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [AEGIS_DARK, AEGIS_PANEL]),
            ("GRID", (0, 0), (-1, -1), 0.5, AEGIS_BORDER),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(mitre_table)

        tactics = incident_detail.get("mitre_tactics", [])
        if tactics:
            story.append(Paragraph(f"Tactics: {', '.join(tactics)}", styles["MetaLabel"]))
    else:
        story.append(Paragraph("No MITRE ATT&CK techniques mapped.", styles["BodyText2"]))

    # ── 7. Correlation Analysis ──────────────────────────
    story.append(Paragraph("6. CORRELATION ANALYSIS", styles["SectionTitle"]))
    corr_explanation = rca_bundle.get("correlation_explanation", [])

    if corr_explanation:
        story.append(Paragraph(
            "The following correlation rules matched to group alerts into this incident:",
            styles["BodyText2"]
        ))
        for match in corr_explanation:
            story.append(Paragraph(
                f"Match Score: {match.get('total_score', 0)} | "
                f"Type: {match.get('type', 'unknown')} | "
                f"Entity: {match.get('matched_entity', '—')}",
                styles["SubSectionTitle"]
            ))
            reasons = match.get("reasons", {})
            if isinstance(reasons, dict):
                for rule, points in reasons.items():
                    story.append(Paragraph(f"• {rule}: +{points} points", styles["BulletItem"]))
    else:
        story.append(Paragraph("Single-alert incident — no correlation matches.", styles["BodyText2"]))

    # ── 8. Observed Facts ────────────────────────────────
    story.append(Paragraph("7. OBSERVED FACTS", styles["SectionTitle"]))
    facts = rca_bundle.get("observed_facts", [])

    if facts:
        story.append(Paragraph(
            "The following facts were deterministically derived from the alert evidence (no AI speculation):",
            styles["BodyText2"]
        ))
        for fact in facts:
            story.append(Paragraph(f"• {fact}", styles["BulletItem"]))
    else:
        story.append(Paragraph("No deterministic facts extracted.", styles["BodyText2"]))

    # ── 9. Root Cause Hypothesis ─────────────────────────
    story.append(Paragraph("8. ROOT CAUSE HYPOTHESIS", styles["SectionTitle"]))
    root_cause = rca_bundle.get("root_cause_hypothesis", "")
    if root_cause:
        story.append(Paragraph(root_cause, styles["BodyText2"]))
    else:
        story.append(Paragraph("No root cause hypothesis generated.", styles["BodyText2"]))

    # ── 10. Recommended Actions ──────────────────────────
    story.append(Paragraph("9. RECOMMENDED ACTIONS", styles["SectionTitle"]))
    actions = rca_bundle.get("recommended_actions", [])

    if actions:
        for i, action in enumerate(actions, 1):
            story.append(Paragraph(f"{i}. {action}", styles["BulletItem"]))
    else:
        story.append(Paragraph("No specific actions recommended.", styles["BodyText2"]))

    # ── 11. MemPalace Context ────────────────────────────
    attacker_history = rca_bundle.get("attacker_history", [])
    prior_memory = rca_bundle.get("prior_memory_verbatim", [])
    prior_incidents = rca_bundle.get("prior_incidents_memory", [])

    if attacker_history or prior_memory or prior_incidents:
        story.append(Paragraph("10. INTELLIGENCE CONTEXT (MemPalace)", styles["SectionTitle"]))

        if attacker_history:
            story.append(Paragraph("Attacker Knowledge Graph:", styles["SubSectionTitle"]))
            for triple in attacker_history:
                story.append(Paragraph(
                    f"• {triple.get('predicate', '')}: {triple.get('object', '')} "
                    f"(since {triple.get('valid_from', 'unknown')})",
                    styles["BulletItem"]
                ))

        if prior_memory:
            story.append(Paragraph("Prior Intelligence:", styles["SubSectionTitle"]))
            for mem in prior_memory:
                text = mem.get("text", "")[:300]
                story.append(Paragraph(f"• {text}", styles["BulletItem"]))

        if prior_incidents:
            story.append(Paragraph("Similar Past Incidents:", styles["SubSectionTitle"]))
            for inc in prior_incidents:
                text = inc.get("text", "")[:200]
                story.append(Paragraph(f"• {text}", styles["BulletItem"]))

    # ── 12. Evidence Appendix ────────────────────────────
    story.append(Paragraph("APPENDIX: RAW ALERT EVIDENCE", styles["SectionTitle"]))
    alerts = incident_detail.get("alerts", [])

    if alerts:
        for i, alert in enumerate(alerts, 1):
            story.append(Paragraph(
                f"Alert {i}: {alert.get('event_name', 'unknown')}",
                styles["SubSectionTitle"]
            ))
            alert_info = [
                f"ID: {alert.get('id', '')}",
                f"Severity: {alert.get('severity', '')}",
                f"Time: {alert.get('event_time', '')}",
            ]
            for info in alert_info:
                story.append(Paragraph(info, styles["MetaLabel"]))
            story.append(Spacer(1, 4))
    else:
        story.append(Paragraph("No alert evidence attached.", styles["BodyText2"]))

    # ── Build PDF ────────────────────────────────────────
    try:
        doc.build(story)
    except Exception as e:
        log.error("pdf_build_error", error=str(e))
        raise

    pdf_bytes = buffer.getvalue()
    buffer.close()

    log.info("pdf_generated", incident=inc_number, size=len(pdf_bytes))
    return pdf_bytes
