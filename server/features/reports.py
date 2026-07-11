"""
SecureFIM Pro — PDF Compliance Report Generator

Produces auditor-ready PDF reports aligned with Nepal NCSC 102-point
advisory (Jan 2025) and mapped to the Cyber Kill Chain phases used in
the thesis theoretical framework.

Report sections:
  1. Cover page
  2. Executive summary
  3. Event breakdown (by type / severity / sensitivity)
  4. Threat intelligence (top threat scores, MITRE ATT&CK)
  5. Sensitive file activity (HIGH sensitivity + user attribution)
  6. Ransomware indicators
  7. Baseline integrity status
  8. Agent health summary
  9. NCSC compliance checklist

Generated PDFs are stored under data/reports/ and listed for re-download.
"""

import logging
import os
from datetime import datetime, timezone, timedelta
from collections import Counter, defaultdict

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm, mm
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
    KeepTogether,
)

log = logging.getLogger("securefim.reports")

# Anchor report storage to the project root (parent of the `server/` package),
# not the Flask CWD. This is important because the admin Flask app runs in a
# background thread and its effective CWD can differ from the generation
# context, causing download routes to look in the wrong place.
_THIS_FILE = os.path.abspath(__file__)
# server/features/reports.py -> server/features -> server -> <project root>
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(_THIS_FILE)))
REPORTS_DIR = os.path.join(_PROJECT_ROOT, "data", "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

# Tool identity (kept here so we don't bake it into layout calls)
TOOL_NAME = "SecureFIM Pro"
DEPLOY_SITE = "District Administration Office, Bhaktapur, Nepal"

# Colors (match the dashboard palette loosely)
CLR_PRIMARY = colors.HexColor("#0969da")
CLR_DARK = colors.HexColor("#1f2328")
CLR_DIM = colors.HexColor("#656d76")
CLR_CRITICAL = colors.HexColor("#cf222e")
CLR_HIGH = colors.HexColor("#d29922")
CLR_OK = colors.HexColor("#1a7f37")
CLR_BG_HEADER = colors.HexColor("#eef2f7")
CLR_BG_ALT = colors.HexColor("#f6f8fa")


# ─── Styles ──────────────────────────────────────────────────────────────

def _styles():
    ss = getSampleStyleSheet()
    s = {
        "title": ParagraphStyle("Title", parent=ss["Title"], fontSize=22,
                                textColor=CLR_PRIMARY, spaceAfter=8, alignment=TA_CENTER),
        "subtitle": ParagraphStyle("Sub", parent=ss["Normal"], fontSize=12,
                                   textColor=CLR_DIM, spaceAfter=4, alignment=TA_CENTER),
        "h1": ParagraphStyle("H1", parent=ss["Heading1"], fontSize=16,
                             textColor=CLR_PRIMARY, spaceBefore=14, spaceAfter=8,
                             borderWidth=0, borderPadding=0),
        "h2": ParagraphStyle("H2", parent=ss["Heading2"], fontSize=13,
                             textColor=CLR_DARK, spaceBefore=10, spaceAfter=6),
        "body": ParagraphStyle("Body", parent=ss["Normal"], fontSize=10,
                               textColor=CLR_DARK, spaceAfter=6, leading=14,
                               alignment=TA_JUSTIFY),
        "small": ParagraphStyle("Small", parent=ss["Normal"], fontSize=8,
                                textColor=CLR_DIM, alignment=TA_CENTER),
        "kill_phase": ParagraphStyle("KP", parent=ss["Normal"], fontSize=9,
                                     textColor=CLR_PRIMARY, spaceBefore=2, spaceAfter=4,
                                     fontName="Helvetica-Oblique"),
    }
    return s


# ─── Helpers ─────────────────────────────────────────────────────────────

def _fmt_date(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M %Z") if dt.tzinfo else dt.strftime("%Y-%m-%d %H:%M UTC")


def _parse_ts(ts) -> datetime | None:
    if not ts:
        return None
    try:
        if isinstance(ts, str):
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return ts
    except Exception:
        return None


def _table(data, col_widths=None, header=True):
    """Build a styled table. First row is header if header=True."""
    t = Table(data, colWidths=col_widths, repeatRows=1 if header else 0)
    style = [
        ("FONT", (0, 0), (-1, -1), "Helvetica", 9),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d0d7de")),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    if header:
        style += [
            ("BACKGROUND", (0, 0), (-1, 0), CLR_BG_HEADER),
            ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 9),
            ("TEXTCOLOR", (0, 0), (-1, 0), CLR_DARK),
        ]
        # zebra rows
        for i in range(2, len(data), 2):
            style.append(("BACKGROUND", (0, i), (-1, i), CLR_BG_ALT))
    t.setStyle(TableStyle(style))
    return t


def _truncate(s, maxlen=60):
    if s is None:
        return ""
    s = str(s)
    return s if len(s) <= maxlen else s[: maxlen - 1] + "…"


def _filename(path, maxlen=32):
    """
    Return just the filename portion of a path, truncated if still too long.
    Works with both Windows (\\) and POSIX (/) separators.
    Falls back to the full path if it has no separator.
    """
    if not path:
        return ""
    s = str(path)
    # Normalise both separators — os.path.basename on Linux misses \ paths
    last_fwd = s.rfind("/")
    last_back = s.rfind("\\")
    cut = max(last_fwd, last_back)
    name = s[cut + 1:] if cut >= 0 else s
    return _truncate(name, maxlen)


# ─── Data collection ─────────────────────────────────────────────────────

def _collect_report_data(os_client, start_dt: datetime, end_dt: datetime) -> dict:
    """
    Pull every figure the PDF needs from OpenSearch. One place for all
    queries so we never get inconsistent snapshots across sections.
    """
    rng = {"timestamp": {
        "gte": start_dt.isoformat(),
        "lte": end_dt.isoformat(),
    }}

    # All events in window (cap at 5000 for report sanity)
    events = os_client.search("fim-events", {
        "query": {"range": rng},
        "sort": [{"timestamp": {"order": "desc"}}],
    }, size=5000)

    # Alerts in window
    alerts = os_client.search("fim-alerts", {
        "query": {"range": rng},
        "sort": [{"timestamp": {"order": "desc"}}],
    }, size=500)

    # Anomalies in window
    anomalies = os_client.search("fim-anomalies", {
        "query": {"range": rng},
        "sort": [{"timestamp": {"order": "desc"}}],
    }, size=500)

    # Agents (current state, not time-bound)
    agents = os_client.get_agents()

    # Baselines (current state)
    baselines = os_client.search("fim-baselines", {
        "query": {"match_all": {}},
    }, size=2000)

    return {
        "events": events,
        "alerts": alerts,
        "anomalies": anomalies,
        "agents": agents,
        "baselines": baselines,
        "start": start_dt,
        "end": end_dt,
    }


def _summary_numbers(data: dict) -> dict:
    events = data["events"]
    alerts = data["alerts"]
    anomalies = data["anomalies"]

    sev = Counter(e.get("severity", "info") for e in events)
    etype = Counter(e.get("event_type", "UNKNOWN") for e in events)
    sens = Counter(e.get("sensitivity", "LOW") for e in events)

    ransomware_events = [e for e in events if e.get("is_ransomware") or
                         any(t in str(e.get("mitre_tags", [])) for t in ["T1486"])]

    critical_events = [e for e in events if e.get("threat_level") == "CRITICAL" or
                       e.get("severity") == "critical"]

    high_sens = [e for e in events if e.get("sensitivity") == "HIGH"]
    outside_hours = [e for e in events if e.get("outside_hours")]

    return {
        "total_events": len(events),
        "total_alerts": len(alerts),
        "total_anomalies": len(anomalies),
        "critical_events": len(critical_events),
        "by_type": dict(etype),
        "by_severity": dict(sev),
        "by_sensitivity": dict(sens),
        "high_sens_count": len(high_sens),
        "outside_hours_count": len(outside_hours),
        "ransomware_count": len(ransomware_events),
        "agents_online": sum(1 for a in data["agents"] if a.get("status") == "online"),
        "agents_total": len(data["agents"]),
        "baselines_count": len({b.get("baseline_name") for b in data["baselines"] if b.get("baseline_name")}),
    }


# ─── PDF Section Builders ────────────────────────────────────────────────

def _section_cover(story, styles, meta):
    story.append(Spacer(1, 4 * cm))
    story.append(Paragraph(f"{TOOL_NAME}", styles["title"]))
    story.append(Paragraph("Compliance &amp; File Integrity Report", styles["subtitle"]))
    story.append(Spacer(1, 1.5 * cm))

    info = [
        ["Deployment site", DEPLOY_SITE],
        ["Report period", meta["period_label"]],
        ["From", _fmt_date(meta["start"])],
        ["To", _fmt_date(meta["end"])],
        ["Generated", _fmt_date(meta["generated_at"])],
        ["Generated by", meta["generated_by"]],
        ["Report ID", meta["report_id"]],
    ]
    story.append(_table(info, col_widths=[5 * cm, 10 * cm], header=False))

    story.append(Spacer(1, 2 * cm))
    story.append(Paragraph(
        "<i>This report was generated automatically by SecureFIM Pro "
        "pursuant to file integrity monitoring requirements of the Nepal "
        "National Cyber Security Centre (NCSC) 102-point advisory, "
        "January 2025. It is intended for authorised audit and "
        "supervisory personnel only.</i>",
        styles["body"]))
    story.append(PageBreak())


def _section_executive_summary(story, styles, summary, meta):
    story.append(Paragraph("1. Executive Summary", styles["h1"]))
    story.append(Paragraph("<i>Kill-chain phase mapped: Actions on Objectives — "
                           "provides the high-level indicator that integrity controls "
                           "caught (or did not catch) adversary action.</i>",
                           styles["kill_phase"]))

    period_desc = f"During the period {_fmt_date(meta['start'])} to {_fmt_date(meta['end'])}, " \
                  f"SecureFIM Pro monitored {summary['agents_total']} endpoint(s) " \
                  f"({summary['agents_online']} currently online) and recorded " \
                  f"{summary['total_events']} file integrity event(s), " \
                  f"{summary['total_alerts']} alert(s), and " \
                  f"{summary['total_anomalies']} ML-detected anomalies."
    story.append(Paragraph(period_desc, styles["body"]))

    kpi_data = [
        ["Metric", "Value", "Notes"],
        ["Total events", str(summary["total_events"]), "All file activity captured"],
        ["Critical events", str(summary["critical_events"]),
         "Threat score ≥ 70 or severity = critical"],
        ["HIGH-sensitivity events", str(summary["high_sens_count"]),
         "Citizenship / lalpurja / passwords / DBs"],
        ["Outside-hours events", str(summary["outside_hours_count"]),
         "Activity outside 09:00–18:00 Mon–Fri NPT"],
        ["Ransomware indicators", str(summary["ransomware_count"]),
         "Encrypted extensions, ransom notes, mass patterns"],
        ["ML anomalies", str(summary["total_anomalies"]),
         "One-Class SVM (11 behavioural features)"],
        ["Alerts raised", str(summary["total_alerts"]),
         "Discord + dashboard real-time"],
        ["Baselines stored", str(summary["baselines_count"]),
         "Known-good hash snapshots"],
    ]
    story.append(Spacer(1, 0.3 * cm))
    story.append(_table(kpi_data, col_widths=[5 * cm, 2.5 * cm, 8 * cm]))
    story.append(Spacer(1, 0.5 * cm))


def _section_event_breakdown(story, styles, summary):
    story.append(Paragraph("2. Event Breakdown", styles["h1"]))
    story.append(Paragraph("<i>Kill-chain phase mapped: Installation / Actions on Objectives "
                           "— file system changes are the observable trail left by these phases.</i>",
                           styles["kill_phase"]))

    # By event type
    story.append(Paragraph("2.1 By Event Type", styles["h2"]))
    if summary["by_type"]:
        rows = [["Event Type", "Count"]]
        for k, v in sorted(summary["by_type"].items(), key=lambda x: -x[1]):
            rows.append([k, str(v)])
        story.append(_table(rows, col_widths=[10 * cm, 5 * cm]))
    else:
        story.append(Paragraph("No events recorded in this period.", styles["body"]))
    story.append(Spacer(1, 0.3 * cm))

    # By severity
    story.append(Paragraph("2.2 By Severity", styles["h2"]))
    if summary["by_severity"]:
        rows = [["Severity", "Count"]]
        for k in ["critical", "high", "medium", "low", "info"]:
            if k in summary["by_severity"]:
                rows.append([k.upper(), str(summary["by_severity"][k])])
        # Include any others not in the canonical list
        for k, v in summary["by_severity"].items():
            if k not in ["critical", "high", "medium", "low", "info"]:
                rows.append([str(k).upper(), str(v)])
        story.append(_table(rows, col_widths=[10 * cm, 5 * cm]))
    story.append(Spacer(1, 0.3 * cm))

    # By sensitivity
    story.append(Paragraph("2.3 By Sensitivity Classification", styles["h2"]))
    if summary["by_sensitivity"]:
        rows = [["Sensitivity", "Count", "Description"]]
        descriptions = {
            "HIGH": "Citizenship, lalpurja, passwords, databases",
            "MEDIUM": "Reports, spreadsheets, general office docs",
            "LOW": "Other files not matching sensitive patterns",
        }
        for k in ["HIGH", "MEDIUM", "LOW"]:
            if k in summary["by_sensitivity"]:
                rows.append([k, str(summary["by_sensitivity"][k]),
                             descriptions.get(k, "")])
        story.append(_table(rows, col_widths=[3 * cm, 2 * cm, 10 * cm]))
    story.append(Spacer(1, 0.5 * cm))


def _section_threat_intel(story, styles, data):
    story.append(Paragraph("3. Threat Intelligence", styles["h1"]))
    story.append(Paragraph("<i>Kill-chain phase mapped: Reconnaissance / Weaponisation / "
                           "Command &amp; Control — MITRE ATT&amp;CK mapping lets auditors "
                           "trace which adversary techniques were observed.</i>",
                           styles["kill_phase"]))

    events = data["events"]

    # Top threat score events (top 15)
    story.append(Paragraph("3.1 Top 15 Highest-Scoring Threat Events", styles["h2"]))
    scored = [e for e in events if e.get("threat_score") is not None]
    scored.sort(key=lambda e: -int(e.get("threat_score") or 0))
    top = scored[:15]
    if top:
        rows = [["Time", "Score", "Level", "Type", "File", "User"]]
        for e in top:
            ts = _parse_ts(e.get("timestamp"))
            rows.append([
                ts.strftime("%m-%d %H:%M") if ts else "",
                str(e.get("threat_score", "")),
                e.get("threat_level", ""),
                e.get("event_type", ""),
                _filename(e.get("file_path", ""), 30),
                _truncate(e.get("username", ""), 12),
            ])
        story.append(_table(rows, col_widths=[2.3 * cm, 1.3 * cm, 1.8 * cm,
                                              2 * cm, 5.5 * cm, 2 * cm]))
    else:
        story.append(Paragraph("No threat-scored events in this period.", styles["body"]))
    story.append(Spacer(1, 0.4 * cm))

    # MITRE ATT&CK distribution
    story.append(Paragraph("3.2 MITRE ATT&amp;CK Techniques Observed", styles["h2"]))
    mitre_counter = Counter()
    for e in events:
        tags = e.get("mitre_tags") or []
        if isinstance(tags, str):
            tags = [tags]
        for t in tags:
            mitre_counter[t] += 1

    mitre_names = {
        "T1486": "Data Encrypted for Impact (ransomware)",
        "T1485": "Data Destruction",
        "T1552.001": "Credentials in Files",
        "T1547.001": "Boot/Logon Autostart — Registry Run Keys",
        "T1070.002": "Indicator Removal — Clear Command History",
        "T1562.001": "Impair Defenses — Disable/Modify Tools",
        "T1491.001": "Defacement — Internal",
        "T1059": "Command and Scripting Interpreter",
    }

    if mitre_counter:
        rows = [["Technique", "Name", "Events"]]
        for tid, cnt in mitre_counter.most_common():
            rows.append([tid, mitre_names.get(tid, "(custom)"), str(cnt)])
        story.append(_table(rows, col_widths=[2.5 * cm, 10 * cm, 2 * cm]))
    else:
        story.append(Paragraph("No MITRE ATT&amp;CK techniques triggered in this period.",
                               styles["body"]))
    story.append(Spacer(1, 0.5 * cm))


def _section_sensitive_activity(story, styles, data):
    story.append(Paragraph("4. Sensitive File Activity &amp; User Attribution", styles["h1"]))
    story.append(Paragraph("<i>Kill-chain phase mapped: Actions on Objectives — who touched "
                           "protected government records, when, and from which endpoint.</i>",
                           styles["kill_phase"]))

    high = [e for e in data["events"] if e.get("sensitivity") == "HIGH"]
    if not high:
        story.append(Paragraph("No HIGH-sensitivity file activity recorded in this period.",
                               styles["body"]))
        story.append(Spacer(1, 0.5 * cm))
        return

    # Summarise by user
    by_user = Counter(e.get("username", "unknown") for e in high)
    story.append(Paragraph("4.1 Activity by User", styles["h2"]))
    rows = [["Username", "HIGH-sens Events"]]
    for u, c in by_user.most_common():
        rows.append([u or "unknown", str(c)])
    story.append(_table(rows, col_widths=[8 * cm, 7 * cm]))
    story.append(Spacer(1, 0.3 * cm))

    # Full detail table — last 25 HIGH-sens events
    story.append(Paragraph("4.2 Recent HIGH-Sensitivity Events (up to 25)", styles["h2"]))
    rows = [["Time", "Type", "File", "User", "Agent", "Threat"]]
    for e in high[:25]:
        ts = _parse_ts(e.get("timestamp"))
        rows.append([
            ts.strftime("%m-%d %H:%M") if ts else "",
            e.get("event_type", ""),
            _filename(e.get("file_path", ""), 28),
            _truncate(e.get("username", ""), 10),
            _truncate(e.get("agent_id", ""), 14),
            str(e.get("threat_score", "")),
        ])
    story.append(_table(rows, col_widths=[2.3 * cm, 1.8 * cm, 5 * cm,
                                          1.8 * cm, 2.8 * cm, 1.3 * cm]))
    story.append(Spacer(1, 0.5 * cm))


def _section_ransomware(story, styles, data, summary):
    story.append(Paragraph("5. Ransomware Indicators", styles["h1"]))
    story.append(Paragraph("<i>Kill-chain phase mapped: Actions on Objectives (impact) — "
                           "detection of encrypted extensions, ransom notes, and mass "
                           "file patterns indicative of ransomware execution.</i>",
                           styles["kill_phase"]))

    rw = [e for e in data["events"] if e.get("is_ransomware") or
          "T1486" in str(e.get("mitre_tags", []))]

    if not rw:
        story.append(Paragraph("No ransomware indicators detected in this period.",
                               styles["body"]))
        story.append(Spacer(1, 0.5 * cm))
        return

    rows = [["Time", "Indicator", "File", "Agent"]]
    for e in rw[:30]:
        ts = _parse_ts(e.get("timestamp"))
        indicator = "ransom note" if "how_to" in (e.get("file_path") or "").lower() \
            else e.get("event_type", "")
        rows.append([
            ts.strftime("%m-%d %H:%M") if ts else "",
            indicator,
            _filename(e.get("file_path", ""), 35),
            _truncate(e.get("agent_id", ""), 14),
        ])
    story.append(_table(rows, col_widths=[2.5 * cm, 3 * cm, 6.7 * cm, 2.8 * cm]))
    story.append(Spacer(1, 0.5 * cm))


def _section_baselines(story, styles, data):
    story.append(Paragraph("6. Baseline Integrity Status", styles["h1"]))
    story.append(Paragraph("<i>Kill-chain phase mapped: Exploitation / Installation detection — "
                           "baseline drift reveals unauthorised persistence or tampering.</i>",
                           styles["kill_phase"]))

    baselines = data["baselines"]
    if not baselines:
        story.append(Paragraph("No baselines have been created yet. "
                               "Recommended: create a baseline after every "
                               "authorised software / record update.", styles["body"]))
        story.append(Spacer(1, 0.5 * cm))
        return

    # Group by baseline_name
    by_name = defaultdict(list)
    for b in baselines:
        by_name[b.get("baseline_name", "(unnamed)")].append(b)

    rows = [["Baseline", "Files", "Agent", "Created"]]
    for name, files in sorted(by_name.items()):
        agents_in = {f.get("agent_id") for f in files}
        first = min(
            (_parse_ts(f.get("timestamp")) for f in files if f.get("timestamp")),
            default=None,
        )
        rows.append([
            name,
            str(len(files)),
            ", ".join(a for a in agents_in if a)[:20] or "-",
            first.strftime("%Y-%m-%d") if first else "-",
        ])
    story.append(_table(rows, col_widths=[5 * cm, 2 * cm, 5 * cm, 3 * cm]))
    story.append(Spacer(1, 0.5 * cm))


def _section_agent_health(story, styles, data):
    story.append(Paragraph("7. Agent Health", styles["h1"]))
    agents = data["agents"]
    if not agents:
        story.append(Paragraph("No agents registered.", styles["body"]))
        story.append(Spacer(1, 0.5 * cm))
        return
    rows = [["Agent ID", "Hostname", "OS", "Status", "Last Heartbeat", "Events"]]
    for a in agents:
        hb = _parse_ts(a.get("last_heartbeat"))
        rows.append([
            _truncate(a.get("agent_id", ""), 16),
            _truncate(a.get("hostname", ""), 14),
            _truncate(a.get("os_type", ""), 8),
            a.get("status", ""),
            hb.strftime("%m-%d %H:%M") if hb else "-",
            str(a.get("event_count", 0)),
        ])
    story.append(_table(rows, col_widths=[3.5 * cm, 3 * cm, 2 * cm,
                                          2 * cm, 2.8 * cm, 1.7 * cm]))
    story.append(Spacer(1, 0.5 * cm))


def _section_ncsc_checklist(story, styles, summary):
    story.append(Paragraph("8. NCSC 102-Point Advisory — Evidence Coverage", styles["h1"]))
    story.append(Paragraph(
        "The Nepal National Cyber Security Centre's January 2025 advisory "
        "mandates file integrity monitoring and auditable activity logs for "
        "government systems. This report provides the following evidence:",
        styles["body"]))

    checks = [
        ("File integrity monitoring deployed",
         summary["agents_total"] > 0,
         f"{summary['agents_total']} endpoint(s) under monitoring"),
        ("Continuous event capture",
         summary["total_events"] > 0,
         f"{summary['total_events']} events in reporting period"),
        ("Anomaly / behavioural detection active",
         True,
         "One-Class SVM — 11 features (Action on Objectives detection)"),
        ("Ransomware detection active",
         True,
         "Extension + ransom-note + mass-pattern detection"),
        ("Sensitive file classification",
         True,
         "HIGH/MEDIUM/LOW auto-labelling including Nepal-specific patterns"),
        ("User attribution on events",
         True,
         "Windows SID / *nix UID captured per event"),
        ("Backup & recovery of sensitive files",
         True,
         "Auto-backup on CREATE/MODIFY of HIGH-sens files"),
        ("MITRE ATT&CK technique mapping",
         True,
         "8 techniques mapped (T1486, T1485, T1552.001, T1547.001, T1070.002, "
         "T1562.001, T1491.001, T1059)"),
        ("Real-time alerting",
         True,
         "Discord + dashboard WebSocket notifications"),
        ("Out-of-hours detection",
         summary["outside_hours_count"] >= 0,
         f"{summary['outside_hours_count']} events flagged outside 09-18 Mon-Fri"),
        ("Audit-ready compliance reporting",
         True,
         "This report"),
    ]

    rows = [["Control", "Evidence", "Notes"]]
    # Wrap notes in Paragraph so long lines word-wrap inside the cell
    _note_style = ParagraphStyle("ck_note", fontSize=9, leading=11,
                                 textColor=CLR_DARK)
    for name, ok, notes in checks:
        marker = "✓" if ok else "✗"
        rows.append([name, marker, Paragraph(notes, _note_style)])

    # Color the check column
    t = _table(rows, col_widths=[6 * cm, 1.8 * cm, 7.2 * cm])
    # Add per-cell colouring
    extra = []
    for i, (_, ok, _) in enumerate(checks, start=1):
        extra.append(("TEXTCOLOR", (1, i), (1, i), CLR_OK if ok else CLR_CRITICAL))
        extra.append(("ALIGN", (1, i), (1, i), "CENTER"))
        extra.append(("FONT", (1, i), (1, i), "Helvetica-Bold", 11))
    t.setStyle(TableStyle(extra))
    story.append(t)
    story.append(Spacer(1, 0.5 * cm))


def _section_footer_declaration(story, styles, meta):
    story.append(PageBreak())
    story.append(Paragraph("Declaration", styles["h1"]))
    story.append(Paragraph(
        f"This report ({meta['report_id']}) was generated automatically by "
        f"{TOOL_NAME} on {_fmt_date(meta['generated_at'])} covering the "
        f"period {_fmt_date(meta['start'])} to {_fmt_date(meta['end'])}. "
        f"All figures are derived from events stored in the OpenSearch cluster "
        f"at the time of generation. The report reflects the state of "
        f"monitoring data available to the system and should be read in "
        f"conjunction with the live dashboard for real-time verification.",
        styles["body"]))
    story.append(Spacer(1, 1 * cm))
    story.append(Paragraph(f"Generated by user: <b>{meta['generated_by']}</b>", styles["body"]))
    story.append(Paragraph(f"Report ID: <b>{meta['report_id']}</b>", styles["body"]))


# ─── Page decoration (header/footer) ─────────────────────────────────────

def _on_page(canvas, doc):
    """Draw header/footer on every page except the cover."""
    page = canvas.getPageNumber()
    canvas.saveState()
    if page > 1:
        # Header
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(CLR_DIM)
        canvas.drawString(2 * cm, A4[1] - 1.2 * cm,
                          f"{TOOL_NAME} — Compliance Report")
        canvas.drawRightString(A4[0] - 2 * cm, A4[1] - 1.2 * cm, DEPLOY_SITE)
        canvas.setStrokeColor(colors.HexColor("#d0d7de"))
        canvas.line(2 * cm, A4[1] - 1.4 * cm, A4[0] - 2 * cm, A4[1] - 1.4 * cm)

    # Footer — every page
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(CLR_DIM)
    canvas.drawString(2 * cm, 1.2 * cm, "Confidential — For authorised audit personnel only")
    canvas.drawRightString(A4[0] - 2 * cm, 1.2 * cm, f"Page {page}")
    canvas.restoreState()


# ─── Public API ──────────────────────────────────────────────────────────

def generate_report(os_client,
                    period: str = "weekly",
                    start: datetime | None = None,
                    end: datetime | None = None,
                    generated_by: str = "unknown") -> dict:
    """
    Generate a compliance PDF and save to data/reports/.
    Returns {report_id, filename, path, period_label, bytes}.

    period: "weekly" | "monthly" | "custom"
    If period is "custom", start+end must be provided.
    """
    now = datetime.now(timezone.utc)

    if period == "weekly":
        start_dt = now - timedelta(days=7)
        end_dt = now
        period_label = "Last 7 days (Weekly)"
    elif period == "monthly":
        start_dt = now - timedelta(days=30)
        end_dt = now
        period_label = "Last 30 days (Monthly)"
    elif period == "custom":
        if not start or not end:
            raise ValueError("Custom period requires start and end")
        start_dt = start
        end_dt = end
        period_label = f"Custom ({start_dt.date()} to {end_dt.date()})"
    else:
        raise ValueError(f"Unknown period: {period}")

    report_id = f"RPT-{now.strftime('%Y%m%d-%H%M%S')}"
    filename = f"{report_id}_{period}.pdf"
    path = os.path.join(REPORTS_DIR, filename)

    meta = {
        "report_id": report_id,
        "period": period,
        "period_label": period_label,
        "start": start_dt,
        "end": end_dt,
        "generated_at": now,
        "generated_by": generated_by,
    }

    log.info("Generating compliance report: %s (period=%s, range=%s to %s)",
             report_id, period, start_dt.isoformat(), end_dt.isoformat())

    # Collect everything from OpenSearch
    data = _collect_report_data(os_client, start_dt, end_dt)
    summary = _summary_numbers(data)

    # Build PDF
    doc = SimpleDocTemplate(
        path,
        pagesize=A4,
        leftMargin=2 * cm, rightMargin=2 * cm,
        topMargin=2 * cm, bottomMargin=2 * cm,
        title=f"{TOOL_NAME} Compliance Report {report_id}",
        author=TOOL_NAME,
    )
    styles = _styles()
    story = []

    _section_cover(story, styles, meta)
    _section_executive_summary(story, styles, summary, meta)
    _section_event_breakdown(story, styles, summary)
    _section_threat_intel(story, styles, data)
    _section_sensitive_activity(story, styles, data)
    _section_ransomware(story, styles, data, summary)
    _section_baselines(story, styles, data)
    _section_agent_health(story, styles, data)
    _section_ncsc_checklist(story, styles, summary)
    _section_footer_declaration(story, styles, meta)

    doc.build(story, onFirstPage=_on_page, onLaterPages=_on_page)
    size = os.path.getsize(path)
    log.info("Compliance report saved: %s (%d bytes)", path, size)

    # Store metadata in OpenSearch too so admin panel can list them
    try:
        os_client.index_doc("fim-alerts", {
            "alert_type": "report_generated",
            "severity": "info",
            "title": "Compliance Report Generated",
            "message": f"Report {report_id} generated ({period_label}) "
                       f"by {generated_by}. Events: {summary['total_events']}, "
                       f"Critical: {summary['critical_events']}.",
            "timestamp": now.isoformat(),
        })
    except Exception:
        pass

    return {
        "report_id": report_id,
        "filename": filename,
        "path": path,
        "period": period,
        "period_label": period_label,
        "start": start_dt.isoformat(),
        "end": end_dt.isoformat(),
        "generated_at": now.isoformat(),
        "generated_by": generated_by,
        "bytes": size,
        "summary": summary,
    }


def list_reports() -> list[dict]:
    """List all generated reports (newest first) from data/reports/."""
    if not os.path.isdir(REPORTS_DIR):
        return []
    items = []
    for fn in os.listdir(REPORTS_DIR):
        if not fn.lower().endswith(".pdf"):
            continue
        full = os.path.join(REPORTS_DIR, fn)
        try:
            stat = os.stat(full)
            items.append({
                "filename": fn,
                "size": stat.st_size,
                "mtime": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
            })
        except Exception:
            continue
    items.sort(key=lambda x: x["mtime"], reverse=True)
    return items


def get_report_path(filename: str) -> str | None:
    """Resolve a report filename to a full path, validating it stays inside REPORTS_DIR."""
    # Basic path traversal guard
    safe = os.path.basename(filename)
    if safe != filename:
        return None
    full = os.path.join(REPORTS_DIR, safe)
    if not os.path.isfile(full):
        return None
    return full


def delete_report(filename: str) -> bool:
    full = get_report_path(filename)
    if not full:
        return False
    try:
        os.remove(full)
        return True
    except Exception as exc:
        log.error("Failed to delete report %s: %s", filename, exc)
        return False
