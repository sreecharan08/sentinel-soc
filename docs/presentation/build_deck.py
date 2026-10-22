"""Builds the Sentinel project deck on the AD 3-1 template, following the section order of the reference deck.
Every image is a live screenshot from the running system (see docs/test-report/UI-TEST-REPORT.md)."""
from pathlib import Path

from pptx import Presentation
from pptx.util import Inches, Pt

HERE = Path(__file__).resolve().parent
PROJECT_TITLE = ("Agentic AI Framework for Autonomous Threat Detection, Analysis, and Remediation "
                 "in a Mobile-Integrated Security Operations Center")
# Read the untouched original; write the result back over the user's AD 3-1.pptx.
TEMPLATE = Path(r"C:\Users\lenovo\Desktop\Miscellaneous\proj\AD(3-1)\AD 3-1 (original backup).pptx")
SHOTS = HERE.parent / "test-report" / "screenshots"
OUT = Path(r"C:\Users\lenovo\Desktop\Miscellaneous\proj\AD(3-1)\AD 3-1 (updated).pptx")

prs = Presentation(str(TEMPLATE))

# Your original design lives on the slides themselves: the title slide (logo, frame, names) and a freeform border
# drawn on every content slide. Keep the border shape to copy it onto the new slides, and keep the title slide.
from copy import deepcopy
from pptx.enum.shapes import MSO_SHAPE_TYPE

FRAME = None
for shape in prs.slides[1].shapes:
    if shape.shape_type == MSO_SHAPE_TYPE.FREEFORM:
        FRAME = deepcopy(shape._element)
        break

id_list = prs.slides._sldIdLst
for sld in list(id_list)[1:]:
    prs.part.drop_rel(sld.rId)
    id_list.remove(sld)


def add_frame(slide):
    if FRAME is not None:
        slide.shapes._spTree.insert(2, deepcopy(FRAME))  # index 2: behind the content

LAYOUT = {l.name: l for l in prs.slide_layouts}
TITLE_CONTENT = LAYOUT["Title and Content"]
TITLE_ONLY = LAYOUT["Title Only"]
TITLE_SLIDE = LAYOUT["Title Slide"]
SECTION = LAYOUT["Section Header"]


def set_title(slide, text):
    slide.shapes.title.text = text


def bullets(title, items, size=20):
    s = prs.slides.add_slide(TITLE_CONTENT)
    add_frame(s)
    set_title(s, title)
    body = s.placeholders[1].text_frame
    body.clear()
    for i, item in enumerate(items):
        level = 0
        if isinstance(item, tuple):
            level, item = item
        para = body.paragraphs[0] if i == 0 else body.add_paragraph()
        para.text = item
        para.level = level
        for run in para.runs:
            run.font.size = Pt(size - 2 * level)
    return s


def picture(title, image, caption):
    s = prs.slides.add_slide(TITLE_ONLY)
    add_frame(s)
    set_title(s, title)
    path = SHOTS / image
    max_w, max_h = Inches(12.2), Inches(5.3)
    pic = s.shapes.add_picture(str(path), Inches(0.55), Inches(1.6))
    ratio = min(max_w / pic.width, max_h / pic.height)
    pic.width, pic.height = int(pic.width * ratio), int(pic.height * ratio)
    pic.left = int((prs.slide_width - pic.width) / 2)
    box = s.shapes.add_textbox(Inches(0.55), Inches(6.85), Inches(12.2), Inches(0.4))
    box.text_frame.text = caption
    box.text_frame.paragraphs[0].runs[0].font.size = Pt(14)
    return s


def section(title, subtitle=""):
    s = prs.slides.add_slide(SECTION)
    add_frame(s)
    s.shapes.title.text = title
    s.placeholders[1].text = subtitle
    return s


# 1. Title
# Title slide: your original slide, with only its title text replaced (logo, names and guidance are kept).
title_slide = prs.slides[0]
for shape in title_slide.shapes:
    if shape.has_text_frame and shape.text_frame.text.startswith("AI"):
        paragraph = shape.text_frame.paragraphs[0]
        paragraph.runs[0].text = PROJECT_TITLE
        for extra_run in paragraph.runs[1:]:
            extra_run.text = ""
        for run in paragraph.runs:
            run.font.size = Pt(24)  # the long project title needs a smaller size to fit the slide
        break

bullets("Abstract", [
    "Sentinel is a mobile-integrated SOC. An Android app detects every new install on a paired phone, sends the app's "
    "fingerprint and file to a laptop server, and shows the verdict to the user.",
    "The server runs a static analysis pipeline (manifest, certificates, code API references, strings and IOCs, YARA), "
    "scores the evidence, and drafts YARA and Sigma rules for the analyst to review.",
    "An analyst dashboard shows the live evidence chain. The analyst can override a verdict, and the phone is told.",
    "Uninstalls are never silent: the user always confirms in Android's own dialog.",
], size=20)

bullets("Introduction", [
    "Mobile apps are installed far faster than they are reviewed, and a malicious app can read messages or run hidden code.",
    "A Security Operations Centre normally watches servers and networks, not the phones its users carry.",
    "Sentinel brings the SOC workflow to the phone: detection on install, evidence-based verdicts, and a controlled response.",
])

bullets("Problem Statement", [
    "Manual malware triage is slow and needs specialist skill.",
    "Automated tools produce many technical findings that the user cannot act on.",
    "Phones have no SOC of their own: a user who installs a risky app is alone with the decision.",
    "Goal: detect risky Android apps at install time, explain why in plain language, and let the user act with one confirmed tap.",
])

bullets("Literature Survey", [
    "Static analysis of Android packages (manifest permissions, certificates, DEX references) is established practice; "
    "androguard is an open tool for it.",
    "YARA rules describe byte patterns and are widely used for malware family matching.",
    "Sigma is a generic, vendor-neutral format for detection rules.",
    "MITRE ATT&CK for Mobile gives a shared vocabulary for mobile behaviour, used here to tag every signal.",
    "Sandbox-based dynamic analysis (CAPE, emulators) is the usual next step; it is a stretch goal in this project.",
])

bullets("2. System Analysis: Existing System", [
    "Security tools on the phone scan files but do not give evidence the user can read.",
    "Enterprise SOC platforms need a server agent and are not built for personal or small-team phones.",
    "Analysts lose time correlating results from several tools by hand.",
])

bullets("2. System Analysis: Proposed System", [
    "One pipeline from install event to verdict, with every step stored as an event (the evidence chain).",
    "Static analysis produces explainable signals with severity and ATT&CK mapping.",
    "Verdicts are rule-based today; the reasoning stage is a seam for a later model (on hold).",
    "The phone never removes anything silently, and every decision is audited.",
])

bullets("2. System Analysis: Requirements", [
    "Server: Python 3.13, Django 5, Django REST Framework, Channels (Daphne), Celery, Redis, SQLite (Postgres optional).",
    "Analysis: androguard 4.1, yara-python, lxml, cryptography, jsonschema, PyYAML.",
    "Dashboard: server-rendered Django templates with plain JavaScript and CSS; no framework.",
    "Phone: Android (minSdk 26), Kotlin, AppCompat, OkHttp, WorkManager, SQLite. No Compose, no Material.",
    "Hardware: a Windows laptop with 8 GB RAM and 10 GB free disk; an Android phone connected by USB or Wi-Fi.",
], size=18)

bullets("2. System Analysis: Feasibility", [
    "Technical: every component is open source and runs locally; no cloud service is needed.",
    "Operational: the phone and laptop only need to reach each other, by USB tunnel or on the same Wi-Fi.",
    "Economic: no paid licences; the test samples are harmless fixtures and apps the team already owns.",
    "Legal and safety: samples are never executed on the laptop; the test malware is a harmless fixture.",
])

bullets("3. Architectural Design: Modules", [
    "Install detection and upload (Android app): watches installs, hashes the APK, submits it, polls for verdicts.",
    "Ingestion API (Django): device pairing, submission and upload checks (hash, ZIP magic, size limit).",
    "Static analysis engine: manifest, certificates, DEX API references, native libraries, entropy, strings and IOCs, YARA.",
    "Signal engine and reasoner seam: explainable signals; a placeholder rule engine produces the verdict.",
    "Remediation policy: guardrails decide whether an uninstall proposal is allowed; the phone confirms it.",
    "Rules: YARA and Sigma drafts with self-test and false-positive test; approval before activation.",
    "SOC dashboard: overview, submissions, evidence, verdicts, overrides, remediation, rules, settings.",
], size=18)

bullets("3. Architectural Design: Pipeline", [
    "1. Phone detects an install and computes the SHA-256 of the base APK.",
    "2. Server stores the submission; the phone uploads the APK if the server asks.",
    "3. Worker runs static analysis, stores the Evidence, and validates it against the JSON schema.",
    "4. Reasoner scores the signals; the verdict is stored with its provider name and version.",
    "5. Phone is notified through its command queue; malicious and suspicious verdicts raise an alert.",
    "6. Analyst can override, propose an uninstall, or generate rules. Each action is an event.",
], size=20)

bullets("3. Architectural Design: Technologies", [
    "Django + DRF + Channels + Celery + Redis: API, realtime events and the background pipeline.",
    "Android (Kotlin) + WorkManager: install detection and reliable uploads that survive network drops.",
    "androguard + yara-python: static analysis of APK structure and rule matching.",
    "JSON schemas shared by both sides: every Evidence and Verdict is validated before it is stored.",
], size=20)

section("4. Implementation and Testing", "Backend tests, live end-to-end checks and UI test cases")

bullets("4. Testing: Automated Tests", [
    "Backend unit tests: 16 (guardrails, Sigma evaluator, signal catalogue, archive safety).",
    "Backend integration tests: 31 (device API, pipeline, remediation lifecycle, roles, rules, security headers).",
    "Live end-to-end script: 27 checks over real HTTP, playing the phone and the analyst against the running stack.",
    "All 47 pytest tests pass.",
])

def test_case(number, title, objective, scenario, steps, expected, actual, status="Pass"):
    s = prs.slides.add_slide(TITLE_CONTENT)
    add_frame(s)
    set_title(s, f"4.{number} Test Case: {title}")
    body = s.placeholders[1].text_frame
    body.clear()
    lines = [f"Test objective: {objective}", f"Test Scenario: {scenario}", "Test Steps:"]
    lines += [f"   {i}. {step}" for i, step in enumerate(steps, 1)]
    lines += [f"Expected Result: {expected}", f"Actual Result: {actual}", f"Status: {status}"]
    for i, text in enumerate(lines):
        para = body.paragraphs[0] if i == 0 else body.add_paragraph()
        para.text = text
        for run in para.runs:
            run.font.size = Pt(15)
            run.font.bold = text.startswith(("Expected Result", "Actual Result", "Status"))


test_case(1, "Recent scans list", "To view the recent scans with safe, malicious and suspicious verdicts.",
          "Open the SOC dashboard and read the Submissions list.",
          ["Open the SOC dashboard at http://127.0.0.1:8000 and sign in as an analyst.",
           "Open the Submissions page.",
           "Read the verdict chip and confidence of each row."],
          "Three rows, each with a verdict chip (icon and text) and a confidence: SAFE, MALICIOUS and SUSPICIOUS.",
          "HappyMod: SUSPICIOUS 95%. Sentinel FIXTURE: MALICIOUS 95%. Duo Mobile: SAFE 70%.")

test_case(2, "Verdict display of a malicious file", "To check that the malicious APK shows its verdict and reasons.",
          "Open the malicious fixture's submission page and read the Summary.",
          ["From the Submissions list, open Sentinel FIXTURE (harmless).",
           "Read the verdict chip, the explanation and the top signals.",
           "Check the recommended action and the ATT&CK tags."],
          "MALICIOUS chip with confidence, an explanation, the top signals, recommended action uninstall, and ATT&CK tags.",
          "MALICIOUS 95%. Risk score 1.00 from 8 signals (SMS access, shell commands, debuggable build). Recommended action: uninstall. Tags T1636 and T1417.")

test_case(3, "YARA and Sigma rules of a malicious file", "To check that rules are drafted from the malicious APK.",
          "On the malicious submission, generate rules and open each draft.",
          ["Open the Rules tab of the Sentinel FIXTURE submission.",
           "Press Generate rules.",
           "Open the YARA rule and both Sigma rules and read their content."],
          "Three draft rules (two Sigma, one YARA) with content and a false-positive test status.",
          "Three drafts created: two Sigma (hash and permission rules) and one YARA. FP test shows not_run, because no benign corpus is built yet.")

test_case(4, "Analysis page of a malicious APK", "To check that the static analysis evidence is shown.",
          "Open the Analysis tab of the malicious submission.",
          ["Open the Sentinel FIXTURE submission.",
           "Open the Analysis tab.",
           "Read the signal list: ID, severity, signal name, detail and ATT&CK."],
          "The stored signals appear with severity, detail and ATT&CK mapping.",
          "Eight signals listed, from sig_1 (high, SMS access, T1636) to medium signals such as shell commands and the debug signing certificate.")

test_case(5, "Override from the laptop (5.1)", "To check that an analyst can override a verdict from the dashboard.",
          "Override the fixture's verdict to Suspicious with a reason.",
          ["Open the Sentinel FIXTURE submission and press Override verdict.",
           "Select Suspicious, type a reason, keep Notify the device checked.",
           "Press Save override and read the header."],
          "The header shows the new verdict with the ANALYST OVERRIDE tag.",
          "SUSPICIOUS 95% with the ANALYST OVERRIDE tag shown in the header.")

test_case(6, "Override notification on the phone (5.2)", "To check that the phone is told about the override.",
          "After the override, check the phone's notifications.",
          ["Save the override on the laptop (test 5).",
           "Wait for the phone's command poll (about 5 seconds).",
           "Pull down the notification shade on the phone."],
          "A notification on the phone with the analyst's reason.",
          "The phone shows \"Suspicious app\" with \"Analyst review: suspicious.\"")

section("5. Results", "Live screenshots from the running system")

picture("5.1 SOC Dashboard: Overview (live)", "dash-overview-live.jpg",
        "Live overview: devices online, scans today, verdict breakdown and the pipeline feed.")
picture("5.2 Recent scans: safe, malicious and suspicious (live)", "tc1-recent-scans-list.jpg",
        "Three analysed apps with verdicts, confidence, status and device.")
picture("5.3 Verdict display of a malicious file (live)", "tc2-malicious-verdict.jpg",
        "MALICIOUS 95% with explanation, risk score, recommended action and ATT&CK tags.")
picture("5.4 Analysis page of the malicious APK (live)", "tc4-analysis-page.jpg",
        "Signals with severity, detail and ATT&CK mapping, as stored in the Evidence.")
picture("5.5 YARA rule generated from the malicious APK (live)", "tc3-yara-rule.jpg",
        "Draft rule: DEX magic, beacon URL and class names, condition and metadata.")
picture("5.6 Sigma rule generated from the malicious APK (live)", "tc3-sigma-rule.jpg",
        "Draft Sigma rule matching the file's SHA-256 (custom log source sentinel_soc/android_install).")
picture("5.7 Override from the laptop (live)", "tc5-1-override-saved.jpg",
        "Verdict overridden to Suspicious with a reason; the header shows the Analyst override tag.")
picture("5.8 Override notification on the phone (live)", "tc5-2-phone-notification-unlocked.png",
        "The phone's notification shade shows \"Suspicious app: Analyst review: suspicious.\" from the override.")
picture("5.9 Phone app: live main screen", "phone-live-main.png",
        "Protected and synced; Recent scans show the verdicts; the report reads 1 malicious app found.")

bullets("6. Results: Discussion", [
    "The end-to-end flow works on a real phone: install, upload, verdict, notification and override.",
    "Verdicts are explainable: every verdict lists the signals, their severity and their ATT&CK tags.",
    "Rule drafts are created with a self-test; the false-positive test needs a benign corpus that is not built yet.",
    "Uninstall is always confirmed by the user in Android's own dialog.",
])

bullets("6. Results: Limitations", [
    "Verdict weights are a placeholder. Large, legitimate apps can be flagged suspicious because they use common library code.",
    "The reasoning stage (agent-based explanation) is on hold; only the rule-based reasoner is built.",
    "Dynamic analysis in an emulator is not built; the analysis is static only.",
    "The false-positive test runs against an empty benign corpus, so it reports not_run.",
    "Third-party antivirus (Kaspersky) flags the harmless test APK; an exclusion is needed for demos.",
    "Phone-to-laptop link needs the USB tunnel or the same Wi-Fi network.",
], size=18)

bullets("7. Future Work", [
    "Calibrate scoring against a labelled corpus of benign and malicious apps; filter known library code.",
    "Add the reasoning stage: an explanation model that cites the evidence it used.",
    "Add emulator-based dynamic analysis for uncertain verdicts.",
    "Build the benign corpus so the rule false-positive test can run.",
    "Package the phone app for release and use HTTPS instead of plain HTTP.",
])

bullets("8. References", [
    "androguard: Android APK analysis library (androguard.readthedocs.io).",
    "YARA: pattern matching for malware research (virustotal.github.io/yara).",
    "Sigma: generic signature format for log events (github.com/SigmaHQ/sigma).",
    "MITRE ATT&CK for Mobile (attack.mitre.org/matrices/mobile).",
    "Android developer documentation: package visibility, foreground services, WorkManager (developer.android.com).",
    "Django, Django REST Framework, Channels and Celery documentation.",
], size=18)

s = prs.slides.add_slide(TITLE_SLIDE)
add_frame(s)
s.shapes.title.text = "Thank You"
s.placeholders[1].text = "Sentinel SOC"

prs.save(str(OUT))
print("saved", OUT, "slides:", len(prs.slides))
