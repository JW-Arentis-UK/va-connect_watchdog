from __future__ import annotations

from datetime import datetime
from io import BytesIO
from typing import Any

from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.shapes import Drawing, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


GREEN = colors.HexColor("#168A3A")
BLUE = colors.HexColor("#1D64D8")
INK = colors.HexColor("#182230")
MUTED = colors.HexColor("#526173")
LINE = colors.HexColor("#C9D5E2")
PALE = colors.HexColor("#EDF4FB")
RED = colors.HexColor("#C6283A")


def build_people_counting_pdf(
    identity: dict[str, Any],
    camera: dict[str, Any],
    summary: dict[str, Any],
    daily_rows: list[dict[str, Any]],
    generated_at: datetime | None = None,
) -> bytes:
    """Build an operator-safe count report without camera media or credentials."""
    generated_at = generated_at or datetime.now().astimezone()
    output = BytesIO()
    document = SimpleDocTemplate(
        output,
        pagesize=A4,
        rightMargin=16 * mm,
        leftMargin=16 * mm,
        topMargin=18 * mm,
        bottomMargin=16 * mm,
        title="People Counting Report",
        author="VA-Connect Watchdog",
    )
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="ReportTitle", parent=styles["Title"], fontName="Helvetica-Bold",
                              fontSize=22, leading=25, textColor=INK, spaceAfter=4))
    styles.add(ParagraphStyle(name="Kicker", parent=styles["Normal"], fontName="Helvetica-Bold",
                              fontSize=8, leading=10, textColor=BLUE, spaceAfter=4))
    styles.add(ParagraphStyle(name="Small", parent=styles["Normal"], fontSize=8, leading=10, textColor=MUTED))
    styles.add(ParagraphStyle(name="Section", parent=styles["Heading2"], fontName="Helvetica-Bold",
                              fontSize=13, leading=16, textColor=INK, spaceBefore=10, spaceAfter=6))
    styles.add(ParagraphStyle(name="RightSmall", parent=styles["Small"], alignment=TA_RIGHT))

    forward_label = str(camera.get("forward_label") or "Camera forward")
    back_label = str(camera.get("back_label") or "Camera back")
    current = summary.get("last_reported_counts", {}) if isinstance(summary.get("last_reported_counts"), dict) else {}
    recent = daily_rows[-7:]
    today = daily_rows[-1] if daily_rows else {}
    stale = bool(summary.get("stale"))
    status = "ATTENTION - NO RECENT MESSAGES" if stale else "LISTENING"
    status_color = RED if stale else GREEN

    story = [
        Paragraph("GATEWAY REPORT", styles["Kicker"]),
        Paragraph("People Counting", styles["ReportTitle"]),
        Table([
            [Paragraph(f"<b>{_safe(identity.get('display_name') or identity.get('site_name') or 'Site not configured')}</b><br/>"
                       f"Asset: {_safe(identity.get('asset_id') or '-')}", styles["Normal"]),
             Paragraph(f"Generated<br/><b>{generated_at.strftime('%Y-%m-%d %H:%M %Z')}</b>", styles["RightSmall"])],
        ], colWidths=[120 * mm, 42 * mm], style=TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("LINEBELOW", (0, 0), (-1, -1), 1, LINE),
        ])),
        Spacer(1, 6 * mm),
        _summary_table(forward_label, back_label, current, today, status, status_color, styles),
        Spacer(1, 3 * mm),
        _category_summary_table(today, styles),
        Paragraph("Seven-Day Overview", styles["Section"]),
        Paragraph("Daily cumulative human totals by camera direction. The camera's midnight counter reset starts each new day.", styles["Small"]),
        Spacer(1, 2 * mm),
        _count_chart(recent, forward_label, back_label),
        Paragraph("Daily Totals", styles["Section"]),
        _daily_table(daily_rows, forward_label, back_label, styles),
        KeepTogether([
            Paragraph("Collection Notes", styles["Section"]),
            Paragraph(
                "The camera resets cumulative counters at midnight; that date-boundary reset is expected. "
                "A counter drop during the same day is marked as unexpected and the report adds the segments together. "
                "Direction names are neutral until physically calibrated. Counts only are retained; images, video, media URLs, credentials and raw payloads are excluded.",
                styles["Small"],
            ),
        ]),
    ]

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setStrokeColor(LINE)
        canvas.line(16 * mm, 12 * mm, A4[0] - 16 * mm, 12 * mm)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(MUTED)
        canvas.drawString(16 * mm, 8 * mm, "VA-Connect Watchdog - People Counting")
        canvas.drawRightString(A4[0] - 16 * mm, 8 * mm, f"Page {doc.page}")
        canvas.restoreState()

    document.build(story, onFirstPage=footer, onLaterPages=footer)
    return output.getvalue()


def _summary_table(forward_label, back_label, current, today, status, status_color, styles):
    values = [
        (forward_label, current.get("forward", "-"), "Current camera counter"),
        (back_label, current.get("back", "-"), "Current camera counter"),
        ("Today", today.get("bothway") if today.get("bothway") is not None else "-", "Both directions"),
        ("Receiver", status, "HTTP push"),
    ]
    cells = []
    for label, value, detail in values:
        value_color = status_color if label == "Receiver" else GREEN
        cells.append(Paragraph(
            f"<font color='{MUTED.hexval()}' size='8'>{_safe(label)}</font><br/>"
            f"<font color='{value_color.hexval()}' size='15'><b>{_safe(value)}</b></font><br/>"
            f"<font color='{MUTED.hexval()}' size='7'>{_safe(detail)}</font>", styles["Normal"]
        ))
    return Table([cells], colWidths=[40.5 * mm] * 4, style=TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), PALE),
        ("BOX", (0, 0), (-1, -1), 0.7, LINE),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, LINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))


def _category_summary_table(today, styles):
    cells = []
    for label, key, color in (
        ("Human today", "bothway", GREEN),
        ("Non-motor today", "non_motor_bothway", BLUE),
        ("Vehicle today", "vehicle_bothway", colors.HexColor("#A86700")),
    ):
        cells.append(Paragraph(
            f"<font color='{MUTED.hexval()}' size='8'>{label}</font><br/>"
            f"<font color='{color.hexval()}' size='14'><b>{_safe(_display(today.get(key)))}</b></font><br/>"
            "<font color='#526173' size='7'>Both directions</font>", styles["Normal"]
        ))
    return Table([cells], colWidths=[54 * mm] * 3, style=TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.white),
        ("BOX", (0, 0), (-1, -1), 0.7, LINE),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, LINE),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))


def _count_chart(rows, forward_label, back_label):
    drawing = Drawing(465, 170)
    if not rows or not any(row.get("bothway") is not None for row in rows):
        drawing.add(String(10, 80, "No daily count history is available yet.", fontName="Helvetica", fontSize=10, fillColor=MUTED))
        return drawing
    chart = VerticalBarChart()
    chart.x = 42
    chart.y = 28
    chart.height = 115
    chart.width = 400
    chart.data = [
        [int(row.get("forward") or 0) for row in rows],
        [int(row.get("back") or 0) for row in rows],
    ]
    chart.categoryAxis.categoryNames = [str(row.get("date") or "")[5:] for row in rows]
    chart.categoryAxis.labels.fontName = "Helvetica"
    chart.categoryAxis.labels.fontSize = 7
    chart.valueAxis.labels.fontName = "Helvetica"
    chart.valueAxis.labels.fontSize = 7
    chart.valueAxis.valueMin = 0
    chart.valueAxis.valueMax = max(1, max(max(series) for series in chart.data)) * 1.1
    chart.valueAxis.valueStep = max(1, int(chart.valueAxis.valueMax / 4))
    chart.bars[0].fillColor = GREEN
    chart.bars[1].fillColor = BLUE
    chart.barSpacing = 1
    chart.groupSpacing = 7
    drawing.add(chart)
    drawing.add(String(42, 156, forward_label, fontName="Helvetica-Bold", fontSize=8, fillColor=GREEN))
    drawing.add(String(180, 156, back_label, fontName="Helvetica-Bold", fontSize=8, fillColor=BLUE))
    return drawing


def _daily_table(rows, forward_label, back_label, styles):
    data = [["Date", "Human F", "Human B", "Human", "Non-motor", "Vehicle", "Reset", "Day"]]
    for row in reversed(rows):
        reset = (f"Unexpected ({row.get('unexpected_resets')})" if row.get("unexpected_resets")
                 else "Midnight observed" if row.get("scheduled_resets") else "Normal")
        data.append([
            str(row.get("date") or "-"), _display(row.get("forward")), _display(row.get("back")),
            _display(row.get("bothway")), _display(row.get("non_motor_bothway")),
            _display(row.get("vehicle_bothway")), reset, "Complete" if row.get("complete") else "In progress",
        ])
    table = Table(data, repeatRows=1, colWidths=[24 * mm, 19 * mm, 19 * mm, 18 * mm, 23 * mm, 21 * mm, 31 * mm, 23 * mm])
    commands = [
        ("BACKGROUND", (0, 0), (-1, 0), INK),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("GRID", (0, 0), (-1, -1), 0.4, LINE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PALE]),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    for index, row in enumerate(reversed(rows), 1):
        if row.get("unexpected_resets"):
            commands.append(("TEXTCOLOR", (6, index), (6, index), RED))
    table.setStyle(TableStyle(commands))
    return table


def _display(value):
    return "-" if value is None else str(value)


def _safe(value):
    return (str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "&#39;"))
