"""Generate Warden-Hackathon-Audit.pdf with tight, executive 4-page styling."""

import os
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    HRFlowable,
)
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super(NumberedCanvas, self).__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def draw_page_decorations(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))

        # Header (pages > 1)
        if self._pageNumber > 1:
            self.drawString(54, 752, "WARDEN // HACKATHON AUDIT & STRATEGIC REVIEW")
            self.drawRightString(612 - 54, 752, "Fortified Enterprise Fleet Track ($20,000)")
            self.setStrokeColor(colors.HexColor("#cbd5e1"))
            self.setLineWidth(0.5)
            self.line(54, 746, 612 - 54, 746)

        # Footer
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawString(54, 34, "CONFIDENTIAL // All Things Agentic Hackathon Strategy Audit")
        self.drawRightString(612 - 54, 34, page_str)
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(54, 44, 612 - 54, 44)

        self.restoreState()


def build_pdf(filename: str):
    doc = SimpleDocTemplate(
        filename,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=50,
        bottomMargin=50,
    )

    styles = getSampleStyleSheet()

    # Palette
    primary_color = colors.HexColor("#0f172a")  # Slate 900
    brand_indigo = colors.HexColor("#4338ca")   # Indigo 700
    text_dark = colors.HexColor("#0f172a")      # Slate 900
    text_muted = colors.HexColor("#475569")     # Slate 600

    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=brand_indigo,
        spaceAfter=2,
    )

    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=text_muted,
        spaceAfter=8,
    )

    h1_style = ParagraphStyle(
        'H1Style',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=14,
        textColor=primary_color,
        spaceBefore=10,
        spaceAfter=5,
        keepWithNext=True,
    )

    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=11,
        textColor=text_dark,
    )

    table_header_style = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=10.5,
        textColor=colors.white,
    )

    table_cell_style = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=7.5,
        leading=10,
        textColor=text_dark,
    )

    table_cell_bold = ParagraphStyle(
        'TableCellBold',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=7.5,
        leading=10,
        textColor=text_dark,
    )

    callout_text_style = ParagraphStyle(
        'CalloutText',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=11.5,
        textColor=colors.HexColor("#7c2d12"),
    )

    callout_bold_style = ParagraphStyle(
        'CalloutBold',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#9a3412"),
    )

    story = []

    # ================= PAGE 1 =================
    story.append(Paragraph("Warden vs Fortified Enterprise Fleet", title_style))
    story.append(Paragraph(
        "<b>Judge-style audit of local main at 44e0fbd against Devpost criteria (2026-08-21).</b><br/>"
        "Track prize: $20,000. Official judging weights: 40% Innovation / 30% Architecture / 30% Demo readiness.",
        subtitle_style
    ))
    story.append(HRFlowable(width="100%", thickness=1.2, color=brand_indigo, spaceAfter=8))

    # Headline Verdict Callout
    verdict_content = [
        [Paragraph("⚠️ <b>HEADLINE VERDICT</b>", callout_bold_style)],
        [Paragraph(
            "<b>Strong enough to be a finalist if the demo is a completed governed job on Cloud Run.</b> "
            "Not a clear winner yet: the current story overweights homemade governance theater, the red-team grade "
            "is not a live LLM test, and official Innovation scoring can penalize a product whose only wow moment is blocking the agent.",
            callout_text_style
        )]
    ]
    verdict_table = Table(verdict_content, colWidths=[504])
    verdict_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#fffbeb")),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#f59e0b")),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(verdict_table)
    story.append(Spacer(1, 8))

    # Stat Cards
    stat_data = [
        [
            Paragraph("<font size=13><b>7.2 / 10</b></font><br/><font color='#64748b' size=7>Weighted Overall</font>", body_style),
            Paragraph("<font size=13><b>7.5 / 10</b></font><br/><font color='#64748b' size=7>Google Stack</font>", body_style),
            Paragraph("<font size=13 color='#d97706'><b>6.5 / 10</b></font><br/><font color='#64748b' size=7>Zero-Trust Honesty</font>", body_style),
            Paragraph("<font size=13 color='#d97706'><b>7.0 / 10</b></font><br/><font color='#64748b' size=7>Innovation Bucket</font>", body_style),
        ]
    ]
    stat_table = Table(stat_data, colWidths=[126, 126, 126, 126])
    stat_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f8fafc")),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#e2e8f0")),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(stat_table)
    story.append(Spacer(1, 8))

    # Section 1: Official Devpost Weights Table
    story.append(Paragraph("1. Official Devpost Weights & Skeptical Judge Reading", h1_style))
    official_data = [
        [Paragraph("Criterion", table_header_style), Paragraph("Weight", table_header_style), Paragraph("Risk", table_header_style), Paragraph("How a Skeptical Judge Reads Warden", table_header_style)]
    ]
    official_rows = [
        ("Innovation & Operational Utility", "40%", "High", "Official scoring rewards agents that complete high-value work with little hand-holding. Warden's current narrative is a governor that stops work. That is a real enterprise need, but it can lose this bucket unless the demo shows a GPU job actually finishing after a single human grant."),
        ("Architectural Discipline & Tech Stack", "30%", "Medium", "ADK BasePlugin interception, Firestore transactions, Cloud Tasks OIDC resume, and a dedicated runtime SA are production-minded. Homemade Registry / Memory Bank / Model Armor analogs, InMemory ADK sessions, and unused Cloud client libraries weaken the 'Gemini Enterprise Agent Platform' mapping."),
        ("Demo & Production Readiness", "30%", "Medium", "Repo has architecture SVG, Cloud Run deploy script, CLI, dashboard, and a dense test suite. Proof still depends on an unedited video that shows Cloud Run, Trace, Firestore, and a live Model Armor template, not only localhost mock mode."),
    ]
    for c, w, r, text in official_rows:
        official_data.append([
            Paragraph(f"<b>{c}</b>", table_cell_bold),
            Paragraph(w, table_cell_bold),
            Paragraph(f"<font color='{'#dc2626' if r=='High' else '#d97706'}'><b>{r}</b></font>", table_cell_style),
            Paragraph(text, table_cell_style),
        ])

    t_official = Table(official_data, colWidths=[115, 45, 45, 299])
    t_official.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), primary_color),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#f8fafc")]),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('TOPPADDING', (0,0), (-1,-1), 3.5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3.5),
    ]))
    story.append(t_official)
    story.append(Spacer(1, 8))

    # Section 2: Platform Primitives vs Repo
    story.append(Paragraph("2. Gemini Enterprise Agent Platform Primitives vs Reality", h1_style))
    plat_data = [
        [Paragraph("Track / Rules Item", table_header_style), Paragraph("Status", table_header_style), Paragraph("Evidence in this Repository", table_header_style)]
    ]
    plat_rows = [
        ("Gemini 3.5+ via API / Vertex", "Partial", "Default model is gemini-3.7-flash. Rules say 'Gemini 3.5 Flash' in What to Build. Safer: default to 3.5 Flash, document 3.7 as optional."),
        ("Google Agent Framework (ADK)", "Met", "google-adk >= 2.7.1, App + Runner + BasePlugin, context cache, resumability config."),
        ("Google Cloud Infrastructure", "Met", "Cloud Run, Firestore, Cloud Tasks, Cloud Trace, Model Armor API enablement. Pub/Sub and Compute clients are declared but unused."),
        ("Agent Registry", "Analog", "GET /registry/agents is a static metadata overlay on the live ADK tree. Not Gemini Enterprise Agent Registry."),
        ("Agent Runtime (Weeks of Async)", "Partial", "Firestore workflow + Cloud Tasks resume. ADK sessions stay InMemorySessionService, so Cloud Run recycle drops model context."),
        ("Memory Bank (Cross-Session)", "Analog", "Operator POST /memory with hashed subject + 30-day TTL, then prompt stuffing. Not Vertex/Agent Platform Memory Bank extraction."),
        ("Agent Identity (Zero-Trust)", "Partial", "Human identity via Cloud Run OIDC. Agents share one runtime SA. No per-agent IAM principal."),
        ("Agent Gateway", "Analog", "WardenPlugin is a real enforcement point in ADK. It is not Agent Gateway + Model Armor inline on tool I/O."),
        ("Model Armor", "Optional", "REST sanitizeUserPrompt when WARDEN_MODEL_ARMOR_TEMPLATE is set. Default path is NOT_CONFIGURED / allow."),
        ("OpenTelemetry / Observability", "Optional", "WARDEN_ENABLE_CLOUD_TRACE=true wires ADK GCP exporters. Demo must show Trace Explorer or it does not count."),
    ]
    for item, status, evid in plat_rows:
        status_color = "#16a34a" if status == "Met" else ("#d97706" if status == "Partial" else "#475569")
        plat_data.append([
            Paragraph(f"<b>{item}</b>", table_cell_bold),
            Paragraph(f"<font color='{status_color}'><b>{status}</b></font>", table_cell_bold),
            Paragraph(evid, table_cell_style),
        ])

    t_plat = Table(plat_data, colWidths=[130, 48, 326])
    t_plat.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), primary_color),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#f8fafc")]),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('TOPPADDING', (0,0), (-1,-1), 2.5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2.5),
    ]))
    story.append(t_plat)

    story.append(PageBreak())

    # ================= PAGE 2 =================
    story.append(Paragraph("3. Rubric Breakdown & Architectural Authenticity", h1_style))
    rubric_data = [
        [Paragraph("Dimension", table_header_style), Paragraph("Score", table_header_style), Paragraph("Weight / Notes", table_header_style)]
    ]
    for r in [
        ("Technical sophistication / Google stack", "7.5 / 10", "Track-specific core requirement"),
        ("Innovation / problem-solution fit", "7.0 / 10", "40% overall Devpost score"),
        ("Security / zero-trust hardening", "6.5 / 10", "Track-specific core requirement"),
        ("UX / polish / demo readiness", "7.5 / 10", "30% overall Devpost score"),
    ]:
        rubric_data.append([
            Paragraph(f"<b>{r[0]}</b>", table_cell_bold),
            Paragraph(f"<b>{r[1]}</b>", table_cell_style),
            Paragraph(r[2], table_cell_style),
        ])

    t_rubric = Table(rubric_data, colWidths=[190, 60, 254])
    t_rubric.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), primary_color),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#f8fafc")]),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
    ]))
    story.append(t_rubric)
    story.append(Spacer(1, 8))

    # Side-by-Side Cards: Strong vs Theater
    strong_text = (
        "• <b>WardenPlugin at Runner scope:</b> Returned dict short-circuits tool calls. Real zero-trust relative to prompt-only policy.<br/>"
        "• <b>Production-grade Approvals:</b> Claim/consume, args digest, OIDC verification on decide, Cloud Tasks resume, and transactional Firestore appends.<br/>"
        "• <b>Clean GCP artifacts:</b> Dedicated <code>warden-runtime</code> SA, Model Armor enablement in deploy script, and clean architecture diagram."
    )
    theater_text = (
        "• <b>Scorecard ahead of implementation:</b> Grade A+ 5/5, 47-tool MCP coverage, and Memory Bank / Agent Registry labels overclaim.<br/>"
        "• <b>Default Live Path:</b> Still uses FunctionTools + Manifold REST, not a full 47-tool MCP dynamic mesh.<br/>"
        "• <b>Dead Dependencies:</b> <code>google-cloud-pubsub</code> and <code>google-cloud-compute</code> in pyproject.toml have no call sites."
    )

    card_data = [
        [Paragraph("<b>✅ What is Actually Strong</b>", table_cell_bold), Paragraph("<b>⚠️ What Looks Like Theater</b>", table_cell_bold)],
        [Paragraph(strong_text, table_cell_style), Paragraph(theater_text, table_cell_style)],
    ]
    t_cards = Table(card_data, colWidths=[246, 246])
    t_cards.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,0), colors.HexColor("#f0fdf4")),
        ('BACKGROUND', (1,0), (1,0), colors.HexColor("#fff1f2")),
        ('BACKGROUND', (0,1), (0,1), colors.HexColor("#f8fafc")),
        ('BACKGROUND', (1,1), (1,1), colors.HexColor("#f8fafc")),
        ('BOX', (0,0), (0,1), 1, colors.HexColor("#86efac")),
        ('BOX', (1,0), (1,1), 1, colors.HexColor("#fca5a5")),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
        ('RIGHTPADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(t_cards)
    story.append(Spacer(1, 8))

    # Section 4: Blind Spots Table
    story.append(Paragraph("4. Blind Spots a Google Judge Will Poke", h1_style))
    gaps_data = [
        [Paragraph("ID", table_header_style), Paragraph("Severity", table_header_style), Paragraph("Issue", table_header_style), Paragraph("Why It Matters & Fix Required", table_header_style)]
    ]
    gaps_rows = [
        ("G1", "Critical", "Red team never talks to Gemini", "warden/security/redteam.py calls WardenPlugin.before_tool_callback with DummyAgentContext. 5/5 A+ is a unit-test of policy.evaluate, not prompt-injection resistance. A judge who opens that file will discount the badge."),
        ("G2", "Critical", "Autonomy vs governance narrative collision", "40% of official points go to operational utility: the agent removing friction on its own. If the video is mostly Deny / Pending / Grade A+, Warden looks like a security lab, not a fleet that ships work."),
        ("G3", "High", "Cost ceiling trusts the model", "estimated_usd is a tool argument. Policy blocks over-quote, but an agent can under-quote a $200 GPU as $2.00 and pass the $25 run cap. There is no independent price table or billing API check."),
        ("G4", "High", "TTL is declared, not enforced by Warden", "Policy requires max_lifetime_minutes and forwards it to Manifold. There is no Cloud Scheduler / Tasks watchdog that terminates if the provider ignores TTL. Dashboard copy overclaims 'Warden enforces the requested TTL'."),
        ("G5", "High", "run_command is allow", "policy.yaml sets run_command, run_job, run_detached, upload_file, download_file, dispatch_local_subagent to allow. After a GPU exists, a prompt-injected provisioner can run arbitrary commands without a ticket."),
        ("G6", "High", "IAP header trust and open control-plane GETs", "WARDEN_TRUST_IAP_HEADERS=true accepts X-Goog-Authenticated-User-Email with no JWT verify. /policy, /spend, /audit, /approvals/pending, /redteam/run have no operator dependency. Live Cloud Run that is not IAM-locked is an easy skeptic question."),
        ("G7", "Med", "Firestore hash chain is app-level only", "SHA-256 chaining is real and well tested. The runtime SA has roles/datastore.user, which can rewrite documents. An admin or compromised SA can edit history; verify() only catches in-app inconsistency."),
        ("G8", "Med", "Platform name collision", "README maps homemade endpoints onto Agent Registry, Memory Bank, Agent Gateway, and Model Armor. Judges from Google will know the products. Analog is fine if labeled analog."),
    ]
    for gid, sev, title, detail in gaps_rows:
        sev_color = "#dc2626" if "Critical" in sev else ("#d97706" if sev=="High" else "#475569")
        gaps_data.append([
            Paragraph(f"<b>{gid}</b>", table_cell_bold),
            Paragraph(f"<font color='{sev_color}'><b>{sev}</b></font>", table_cell_bold),
            Paragraph(f"<b>{title}</b>", table_cell_bold),
            Paragraph(detail, table_cell_style),
        ])

    t_gaps = Table(gaps_data, colWidths=[22, 44, 120, 318])
    t_gaps.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), primary_color),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#f8fafc")]),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('TOPPADDING', (0,0), (-1,-1), 2.5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2.5),
    ]))
    story.append(t_gaps)

    story.append(PageBreak())

    # ================= PAGE 3 =================
    story.append(Paragraph("5. Likely Judge Questions & The Honest Answers", h1_style))
    faqs = [
        ("Does this use Gemini Enterprise Agent Platform?", "No. It uses ADK on Cloud Run with first-party analogs. Say that out loud. Then show why an interceptor in before_tool_callback is the right control for GPU spend even if Agent Gateway is not in the path yet."),
        ("Can the agent still burn money?", "Yes, via understated estimated_usd and ungated run_command after a blessed launch. Preempt by quoting from a rate card and gating shell/job tools, or show Manifold-side TTL plus a Warden watchdog task."),
        ("Is the audit log tamper-proof?", "It is tamper-evident inside the application, not tamper-proof against Firestore IAM. Compare it to Cloud Audit Logs / CMEK / restricted SA. Do not say blockchain."),
        ("Why is Manifold in the story?", "Disclose it as MIT compute substrate, Warden as Apache-2.0 governance. Judges care that the original work is the control plane. Keep Manifold off the title slide."),
    ]
    faq_data = []
    for q, a in faqs:
        faq_data.append([
            Paragraph(f"<b>Q: {q}</b><br/><font color='#334155'>{a}</font>", table_cell_style)
        ])
    t_faq = Table(faq_data, colWidths=[504])
    t_faq.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f8fafc")),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
        ('RIGHTPADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(t_faq)
    story.append(Spacer(1, 8))

    # Section 6: Video Demo Plan
    story.append(Paragraph("6. Winning 3.5 – 4.0 Minute Video Storyboard", h1_style))
    demo_data = [
        [Paragraph("Time", table_header_style), Paragraph("Beat", table_header_style), Paragraph("What the Camera Must Show", table_header_style)]
    ]
    demo_rows = [
        ("0:00-0:25", "Problem, not product", "Overnight GPU bill + rogue teardown. One sentence: Warden is the interceptor that lets Gemini fleets act on cloud without becoming the billing owner."),
        ("0:25-0:50", "Live Cloud proof", "Cloud Run service page (.run.app), Firestore collections, Cloud Tasks queue, Trace span for warden.workflow.run. Pause long enough to read the project ID."),
        ("0:50-1:40", "Happy path autonomy", "Prompt: launch g2-standard-8 in us-west1, run a 2-minute job, report spend. Fleet plans, parks launch, you Approve once, Cloud Tasks resumes, mock or real instance appears, auditor reports cost. This is the 40% bucket."),
        ("1:40-2:20", "One real attack through Gemini", "Type a jailbreak in the dashboard terminal. Show the model trying terminate_cluster / europe-west4. Show awaiting_human_approval or denied_by_policy in the live response, then the new ledger row. Do not lead with warden redteam."),
        ("2:20-2:50", "Identity + ledger", "Approve as verified OIDC principal (not a typed name). Click verify. Optionally flip one Firestore field in a throwaway doc and show verify() fail, then restore."),
        ("2:50-3:40", "Close on enterprise", "Registry table, memory scoped to operator, Model Armor template in console if enabled. Architecture SVG. One line: Apache-2.0, Manifold disclosed as compute substrate."),
    ]
    for t, b, s in demo_rows:
        demo_data.append([
            Paragraph(f"<b>{t}</b>", table_cell_bold),
            Paragraph(f"<b>{b}</b>", table_cell_bold),
            Paragraph(s, table_cell_style),
        ])
    t_demo = Table(demo_data, colWidths=[55, 105, 344])
    t_demo.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), primary_color),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#f8fafc")]),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
    ]))
    story.append(t_demo)

    story.append(PageBreak())

    # ================= PAGE 4 =================
    story.append(Paragraph("7. High-Leverage Polish Checklist (Priority Order)", h1_style))
    prep_data = [
        [Paragraph("Priority", table_header_style), Paragraph("Action Item", table_header_style)]
    ]
    prep_rows = [
        ("Must ship before video", "Default WARDEN_MODEL to gemini-3.5-flash; keep 3.7 as override. Say 3.5+ in Devpost."),
        ("Must ship before video", "Gate run_command / run_job as approve, or add a command allowlist. Judges will ask."),
        ("Must ship before video", "Price launches from a static machine-rate table, ignore agent estimated_usd except as a display hint."),
        ("Must ship before video", "Add one red-team vector that goes through execute_turn() with a real Gemini prompt. Keep the plugin tests, stop leading with A+ 5/5."),
        ("Must ship before video", "Live: disable header-only IAP trust; require OIDC. Protect /redteam/run and /approvals/pending."),
        ("High leverage (1 day)", "Create a Model Armor template, set WARDEN_MODEL_ARMOR_TEMPLATE, screenshot console findings."),
        ("High leverage (1 day)", "Vertex or Firestore ADK SessionService so 'weeks of async' is not just a stored prompt string."),
        ("High leverage (copy)", "Rename README rows to 'ADK-native analog of X' unless the Google product is actually configured."),
        ("Submission extras", "Public blog/dev.to with required hackathon sentence; LinkedIn/X with #AllThingsAgenticHackathon. Architecture diagram at assets/warden-system-architecture.svg."),
        ("Do not do", "Do not inflate 47 MCP tools as live demo path. Default factory wires FunctionTool subset. Do not claim TTL enforcement Warden does not schedule."),
    ]
    for prio, item in prep_rows:
        p_color = "#dc2626" if "Must" in prio else ("#d97706" if "1 day" in prio else "#475569")
        prep_data.append([
            Paragraph(f"<font color='{p_color}'><b>{prio}</b></font>", table_cell_bold),
            Paragraph(item, table_cell_style),
        ])
    t_prep = Table(prep_data, colWidths=[105, 399])
    t_prep.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), primary_color),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#f8fafc")]),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('TOPPADDING', (0,0), (-1,-1), 2.5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2.5),
    ]))
    story.append(t_prep)
    story.append(Spacer(1, 10))

    # Section 8: Devpost Framing
    story.append(Paragraph("8. Devpost Write-up Framing Strategy", h1_style))
    framing_text = (
        "<b>Lead with:</b> Autonomous Gemini fleets that provision GPUs, under a control plane that cannot be talked out of policy.<br/>"
        "<b>Do not lead with:</b> Glassmorphism or A+ badges.<br/>"
        "<b>Name the operator:</b> SRE / FinOps.<br/>"
        "<b>Name the failure:</b> Overnight bill, rogue teardown, secret in LLM context.<br/>"
        "<b>Name the proof:</b> Cloud Run + Firestore + one granted launch that finishes.<br/>"
        "<b>Features list:</b> Must match live-mode health fields: ledger, workflow store, resume transport, model_armor, cloud_trace.<br/>"
        "<b>Spin-up instructions:</b> Must include mock (zero billing) and live (project, Firestore, Tasks queue, IAP or authenticated Cloud Run)."
    )
    t_frame = Table([[Paragraph(framing_text, table_cell_style)]], colWidths=[504])
    t_frame.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f1f5f9")),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(t_frame)
    story.append(Spacer(1, 8))

    story.append(Paragraph(
        "<font color='#64748b' size=6.5><b>Sources:</b> https://allthingsagenticHackathon.devpost.com/ (2026-08-21), Warden repository at /Users/jamesmcshane/Desktop/Warden, HEAD 44e0fbd. Re-run pytest before quoting total test count.</font>",
        body_style
    ))

    # Build document
    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"✅ Generated PDF at: {filename}")


if __name__ == "__main__":
    out1 = "/Users/jamesmcshane/Desktop/Warden/Warden-Hackathon-Audit.pdf"
    out2 = "/Users/jamesmcshane/.cursor/projects/Users-jamesmcshane-Desktop-Warden/canvases/warden-hackathon-audit.pdf"
    build_pdf(out1)
    os.makedirs(os.path.dirname(out2), exist_ok=True)
    build_pdf(out2)
